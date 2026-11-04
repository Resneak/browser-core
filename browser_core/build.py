from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .bounded_process import run_with_bounded_stdout
from .control_files import (
    BoundedControlSnapshot,
    PublishedControlSnapshot,
    decode_strict_json_bytes,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
    replace_json_conditionally_result,
)
from .contracts import ContractError, REVISION_RE
from .git_executable import (
    git_executable_binding,
    isolated_git_environment,
    pinned_git_executable,
    select_git_executable,
)
from .owned_paths import directory_ancestry_binding
from .upstream import (
    MAX_UPSTREAM_MANIFEST_BYTES,
    patch_series_digest,
    verify_depot_tools_checkout,
    verify_patched_checkout,
    verify_upstream,
)


BUILD_SCHEMA = "browser-core.build/3"
MAX_BUILD_ATTESTATION_BYTES = 64 * 1024
WINDOWS_RUNTIME_ARTIFACTS = ("chrome.exe", "chrome.dll", "trace_processor_shell.exe")
MAX_GIT_REVISION_OUTPUT_BYTES = 64
MAX_RUNTIME_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_GN_ARGS_BYTES = 1024 * 1024


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_regular_file(
    path: Path,
    *,
    label: str,
    maximum: int | None = None,
) -> tuple[str, int]:
    if not isinstance(path, Path):
        raise ContractError(f"{label} path must be a Path")
    if maximum is None:
        maximum = MAX_RUNTIME_ARTIFACT_BYTES
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= MAX_RUNTIME_ARTIFACT_BYTES
    ):
        raise ContractError(f"{label} byte limit is invalid")
    digest = hashlib.sha256()
    count = 0
    try:
        path_before = os.lstat(path)
        if not stat.S_ISREG(path_before.st_mode) or bool(
            getattr(path_before, "st_file_attributes", 0) & 0x400
        ):
            raise ContractError(f"{label} is not a regular file")
        if path_before.st_nlink != 1:
            raise ContractError(f"{label} must not have additional hard links")
        if path_before.st_size > maximum:
            raise ContractError(f"{label} exceeds {maximum} bytes")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", buffering=0) as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or bool(
                getattr(before, "st_file_attributes", 0) & 0x400
            ):
                raise ContractError(f"{label} is not a regular file")
            if before.st_nlink != 1:
                raise ContractError(f"{label} must not have additional hard links")
            if before.st_size > maximum:
                raise ContractError(f"{label} exceeds {maximum} bytes")
            # Reuse storage, not verification results. Every invocation still
            # reads and hashes the current bytes through the checked handle.
            # A single buffer avoids allocating a new MiB per read.
            buffer = bytearray(min(1024 * 1024, maximum + 1))
            view = memoryview(buffer)
            while True:
                size = source.readinto(view[:min(len(buffer), maximum + 1 - count)])
                if size == 0:
                    break
                if type(size) is not int or size < 0:
                    raise ContractError(f"{label} read failed")
                count += size
                if count > maximum:
                    raise ContractError(f"{label} exceeds {maximum} bytes")
                digest.update(view[:size])
            after = os.fstat(source.fileno())
            if os.name == "nt" and after.st_size == count:
                # Python 3.10 reports creation time as st_ctime on Windows.
                # Rehash the same bounded handle so a same-size edit with a
                # restored mtime cannot leave a stale artifact digest.
                source.seek(0)
                second_digest = hashlib.sha256()
                reread = 0
                while reread < count:
                    size = source.readinto(view[:min(len(buffer), count - reread)])
                    if type(size) is not int or size <= 0:
                        raise ContractError(f"{label} changed while hashing")
                    second_digest.update(view[:size])
                    reread += size
                if source.read(1) or second_digest.digest() != digest.digest():
                    raise ContractError(f"{label} changed while hashing")
                after = os.fstat(source.fileno())
        path_after = os.lstat(path)
    except FileNotFoundError:
        raise ContractError(f"{label} is missing") from None
    except ContractError:
        raise
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        suffix = f" (os_error={code})" if isinstance(code, int) else ""
        raise ContractError(f"{label} read failed{suffix}") from None
    if (
        _file_identity(path_before) != _file_identity(before)
        or _file_identity(before) != _file_identity(after)
        or _file_identity(after) != _file_identity(path_after)
        or count != after.st_size
        or after.st_nlink != 1
        or path_after.st_nlink != 1
    ):
        raise ContractError(f"{label} changed while hashing")
    return digest.hexdigest(), count


def _sha256(path: Path) -> str:
    return _hash_regular_file(path, label="build artifact")[0]


def _git_revision(path: Path) -> str:
    result = run_with_bounded_stdout(
        [
            str(select_git_executable()), f"--work-tree={path.absolute()}",
            "-C", str(path), "rev-parse", "HEAD",
        ],
        maximum_stdout=MAX_GIT_REVISION_OUTPUT_BYTES,
        timeout_seconds=30.0,
        label="build Git revision",
        environment=isolated_git_environment(),
    )
    try:
        output = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ContractError("cannot verify build Git revision") from None
    match = re.fullmatch(r"([0-9a-f]{40})(?:\r?\n)?", output)
    revision = match.group(1) if match is not None else ""
    if result.returncode or not REVISION_RE.fullmatch(revision):
        raise ContractError("cannot verify build Git revision")
    return revision


def _write_json_atomic(path: Path, document: dict[str, Any]) -> PublishedControlSnapshot:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_BUILD_ATTESTATION_BYTES,
        label="build attestation",
        require_single_link=True,
    )
    if snapshot.state == "missing":
        return publish_json_exclusive_result(
            path,
            document,
            maximum=MAX_BUILD_ATTESTATION_BYTES,
            label="build attestation",
        )
    if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
        raise ContractError(f"build attestation is {snapshot.state}")
    return replace_json_conditionally_result(
        path,
        document,
        expected_body=snapshot.body,
        expected_identity=snapshot.identity,
        maximum=MAX_BUILD_ATTESTATION_BYTES,
        label="build attestation",
    )


def build_attestation_path(executable: Path) -> Path:
    if not isinstance(executable, Path):
        raise ContractError("build executable path must be a Path")
    return executable.parent / "browser-core-build.json"


def _checked_build_path(path: object, *, label: str) -> Path:
    if not isinstance(path, Path):
        raise ContractError(f"{label} path must be a Path")
    if "\x00" in str(path):
        raise ContractError(f"{label} path is invalid")
    return path


def _resolved_build_path(path: Path, *, label: str) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        raise ContractError(f"{label} path is invalid") from None


def _runtime_artifacts(executable: Path) -> list[dict[str, Any]]:
    if executable.name.casefold() != "chrome.exe":
        raise ContractError("the pinned Windows build must attest chrome.exe")
    artifacts: list[dict[str, Any]] = []
    for name in WINDOWS_RUNTIME_ARTIFACTS:
        path = executable.parent / name
        digest, size = _hash_regular_file(path, label=f"runtime artifact {name}")
        artifacts.append({"file": name, "sha256": digest, "size": size})
    return artifacts


def _runtime_bundle_digest(artifacts: list[dict[str, Any]]) -> str:
    payload = json.dumps(artifacts, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _verify_output_gn_args(
    executable: Path, manifest_args: list[str],
) -> BoundedControlSnapshot:
    """Check the generated GN input against the pinned declarations."""
    expected: dict[str, str] = {}

    def assignment(line: str) -> tuple[str, str]:
        name, separator, value = line.partition("=")
        name = name.strip(" \t")
        value = value.strip(" \t")
        if (
            not separator
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
            or not value
        ):
            raise ContractError("build GN arguments are invalid")
        return name, value

    for item in manifest_args:
        name, value = assignment(item)
        if name in expected:
            raise ContractError("build GN arguments are invalid")
        expected[name] = value

    snapshot = read_bounded_control_snapshot_result(
        executable.parent / "args.gn",
        maximum=MAX_GN_ARGS_BYTES,
        label="build GN arguments",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
        raise ContractError(f"build GN arguments are {snapshot.state}")
    try:
        lines = snapshot.body.decode("ascii").replace("\r\n", "\n").split("\n")
    except UnicodeDecodeError:
        raise ContractError("build GN arguments are invalid") from None
    actual: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip(" \t")
        if not line:
            continue
        if "\r" in line:
            raise ContractError("build GN arguments are invalid")
        name, value = assignment(line)
        if name in actual:
            raise ContractError("build GN arguments are invalid")
        actual[name] = value
    if actual != expected:
        raise ContractError("build GN arguments do not match the pin")
    return snapshot


def _validate_build_attestation_shape(
    document: Any,
    *,
    executable: Path,
) -> dict[str, Any]:
    expected_fields = {
        "schema",
        "created_at",
        "chromium_revision",
        "depot_tools_revision",
        "executable",
        "executable_sha256",
        "runtime_artifacts",
        "runtime_bundle_sha256",
        "patch_series_sha256",
        "patched_sources_sha256",
        "gn_args_sha256",
    }
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise ContractError("build attestation fields are invalid")
    if document.get("schema") != BUILD_SCHEMA:
        raise ContractError("unsupported build attestation")
    created_at = document.get("created_at")
    try:
        parsed = datetime.fromisoformat(
            created_at.replace("Z", "+00:00") if isinstance(created_at, str) else ""
        )
    except ValueError:
        parsed = None
    if (
        not isinstance(created_at, str)
        or len(created_at) > 64
        or parsed is None
        or parsed.utcoffset() is None
    ):
        raise ContractError("build attestation created_at is invalid")
    for field in ("chromium_revision", "depot_tools_revision"):
        if not isinstance(document.get(field), str) or not REVISION_RE.fullmatch(document[field]):
            raise ContractError(f"build attestation {field} is invalid")
    if document.get("executable") != executable.name or executable.name.casefold() != "chrome.exe":
        raise ContractError("build attestation executable name does not match")
    for field in (
        "executable_sha256",
        "runtime_bundle_sha256",
        "patch_series_sha256",
        "patched_sources_sha256",
        "gn_args_sha256",
    ):
        if not isinstance(document.get(field), str) or not re.fullmatch(
            r"[0-9a-f]{64}", document[field]
        ):
            raise ContractError(f"build attestation {field} is invalid")
    artifacts = document.get("runtime_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(WINDOWS_RUNTIME_ARTIFACTS):
        raise ContractError("build attestation runtime artifact set is invalid")
    for expected_name, item in zip(WINDOWS_RUNTIME_ARTIFACTS, artifacts, strict=True):
        if not isinstance(item, dict) or set(item) != {"file", "sha256", "size"}:
            raise ContractError("build attestation runtime artifact is invalid")
        if item.get("file") != expected_name:
            raise ContractError("build attestation runtime artifact set is invalid")
        if not isinstance(item.get("sha256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", item["sha256"]
        ):
            raise ContractError("build attestation runtime artifact digest is invalid")
        if isinstance(item.get("size"), bool) or not isinstance(item.get("size"), int) or item["size"] < 1:
            raise ContractError("build attestation runtime artifact size is invalid")
    if document["executable_sha256"] != artifacts[0]["sha256"]:
        raise ContractError("build executable hash does not match its runtime artifact")
    if document["runtime_bundle_sha256"] != _runtime_bundle_digest(artifacts):
        raise ContractError("runtime bundle hash does not match its attestation")
    return document


def create_build_attestation(
    root: Path,
    workspace: Path,
    executable: Path,
    *,
    expected_manifest_sha256: str | None = None,
    git_executable: Path | None = None,
) -> dict[str, Any]:
    with pinned_git_executable(git_executable) as selected_git:
        return _create_build_attestation_inner(
            root,
            workspace,
            executable,
            expected_manifest_sha256=expected_manifest_sha256,
            git_executable=selected_git,
        )


def _create_build_attestation_inner(
    root: Path,
    workspace: Path,
    executable: Path,
    *,
    expected_manifest_sha256: str | None = None,
    git_executable: Path | None = None,
) -> dict[str, Any]:
    root = _checked_build_path(root, label="upstream root")
    workspace = _checked_build_path(workspace, label="build workspace")
    executable = _checked_build_path(executable, label="build executable")
    if executable.name.casefold() != "chrome.exe":
        raise ContractError("the pinned Windows build must attest chrome.exe")
    if expected_manifest_sha256 is not None and (
        not isinstance(expected_manifest_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256) is None
    ):
        raise ContractError("expected upstream manifest digest is invalid")
    selected_package = root.absolute()
    selected_package_ancestry = directory_ancestry_binding(
        selected_package, label="build package"
    )
    root = _resolved_build_path(root, label="upstream root")
    package_ancestry = directory_ancestry_binding(root, label="build package")
    initial_manifest_digest, _manifest_size = _hash_regular_file(
        root / "upstream.json",
        label="upstream manifest",
        maximum=MAX_UPSTREAM_MANIFEST_BYTES,
    )
    if (
        expected_manifest_sha256 is not None
        and initial_manifest_digest != expected_manifest_sha256
    ):
        raise ContractError("upstream manifest changed during build")

    def require_manifest_unchanged() -> None:
        digest, _size = _hash_regular_file(
            root / "upstream.json",
            label="upstream manifest",
            maximum=MAX_UPSTREAM_MANIFEST_BYTES,
        )
        if digest != initial_manifest_digest:
            raise ContractError("upstream manifest changed during build")

    require_manifest_unchanged()
    manifest = verify_upstream(root)
    if (
        directory_ancestry_binding(selected_package, label="build package")
        != selected_package_ancestry
        or directory_ancestry_binding(root, label="build package") != package_ancestry
    ):
        raise ContractError("build package authority changed")
    require_manifest_unchanged()
    selected_workspace = workspace.absolute()
    selected_workspace_ancestry = directory_ancestry_binding(
        selected_workspace, label="build workspace"
    )
    workspace = _resolved_build_path(workspace, label="build workspace")
    source = workspace / "chromium" / "src"
    depot_tools = workspace / "depot_tools"
    selected_runtime_parent = executable.parent.absolute()
    executable = _resolved_build_path(executable, label="build executable")
    expected = source / manifest["build"]["output_directory"] / executable.name
    if executable != expected:
        raise ContractError("build attestation executable is outside the pinned output directory")
    if not executable.is_file():
        raise ContractError(f"build executable does not exist: {executable}")
    selected_runtime_ancestry = directory_ancestry_binding(
        selected_runtime_parent, label="build runtime directory"
    )
    workspace_ancestry = directory_ancestry_binding(workspace, label="build workspace")
    depot_tools_ancestry = directory_ancestry_binding(
        depot_tools, label="build depot_tools"
    )
    selected_git = select_git_executable(
        git_executable, excluded_checkout=depot_tools,
    )
    selected_git_binding = git_executable_binding(selected_git)
    runtime_ancestry = directory_ancestry_binding(
        executable.parent, label="build runtime directory"
    )

    def require_build_authority() -> None:
        if (
            select_git_executable() != selected_git
            or git_executable_binding(selected_git) != selected_git_binding
        ):
            raise ContractError("build Git executable selection changed")
        for path, label, binding in (
            (selected_package, "build package", selected_package_ancestry),
            (root, "build package", package_ancestry),
            (selected_workspace, "build workspace", selected_workspace_ancestry),
            (workspace, "build workspace", workspace_ancestry),
            (depot_tools, "build depot_tools", depot_tools_ancestry),
            (selected_runtime_parent, "build runtime directory", selected_runtime_ancestry),
            (executable.parent, "build runtime directory", runtime_ancestry),
        ):
            if directory_ancestry_binding(path, label=label) != binding:
                raise ContractError(f"{label} authority changed")
        require_manifest_unchanged()

    require_build_authority()
    verify_depot_tools_checkout(
        depot_tools, manifest["depot_tools"]["revision"],
        git_executable=selected_git,
    )
    chromium_revision = _git_revision(source)
    depot_tools_revision = _git_revision(depot_tools)
    require_build_authority()
    if chromium_revision != manifest["chromium"]["revision"]:
        raise ContractError("Chromium checkout does not match the pinned revision")
    if depot_tools_revision != manifest["depot_tools"]["revision"]:
        raise ContractError("depot_tools checkout does not match the pinned revision")
    patch_state = verify_patched_checkout(root, source)
    require_build_authority()

    def require_patch_series_unchanged() -> None:
        if patch_series_digest(root) != patch_state["patch_series_sha256"]:
            raise ContractError("build patch series changed during attestation")

    def require_checkout_revisions_unchanged() -> None:
        if (
            _git_revision(source) != chromium_revision
            or _git_revision(depot_tools) != depot_tools_revision
        ):
            raise ContractError("build checkout revision changed during attestation")

    def require_patched_checkout_unchanged() -> None:
        if verify_patched_checkout(root, source) != patch_state:
            raise ContractError("patched checkout changed during attestation")

    build_args = manifest["build"]["gn_args"]
    runtime_artifacts = _runtime_artifacts(executable)
    require_build_authority()
    gn_args_snapshot = _verify_output_gn_args(executable, build_args)

    def require_gn_args_unchanged() -> None:
        try:
            current = _verify_output_gn_args(executable, build_args)
        except ContractError:
            raise ContractError("build GN arguments changed during attestation") from None
        if current != gn_args_snapshot:
            raise ContractError("build GN arguments changed during attestation")

    document = {
        "schema": BUILD_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "chromium_revision": chromium_revision,
        "depot_tools_revision": depot_tools_revision,
        "executable": executable.name,
        "executable_sha256": runtime_artifacts[0]["sha256"],
        "runtime_artifacts": runtime_artifacts,
        "runtime_bundle_sha256": _runtime_bundle_digest(runtime_artifacts),
        "patch_series_sha256": patch_state["patch_series_sha256"],
        "patched_sources_sha256": patch_state["patched_sources_sha256"],
        "gn_args_sha256": hashlib.sha256(
            json.dumps(build_args, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest(),
    }
    _validate_build_attestation_shape(document, executable=executable)
    for item in runtime_artifacts:
        observed_digest, observed_size = _hash_regular_file(
            executable.parent / item["file"],
            label=f"runtime artifact {item['file']}",
        )
        if observed_digest != item["sha256"] or observed_size != item["size"]:
            raise ContractError(
                f"runtime artifact changed before attestation: {item['file']}"
            )
    require_build_authority()
    require_patch_series_unchanged()
    require_checkout_revisions_unchanged()
    require_patched_checkout_unchanged()
    require_gn_args_unchanged()
    attestation_path = build_attestation_path(executable)
    publication = _write_json_atomic(attestation_path, document)
    require_build_authority()
    verify_depot_tools_checkout(
        depot_tools, manifest["depot_tools"]["revision"],
        git_executable=selected_git,
    )
    require_patch_series_unchanged()
    require_checkout_revisions_unchanged()
    require_patched_checkout_unchanged()
    require_gn_args_unchanged()
    if _runtime_artifacts(executable) != runtime_artifacts:
        raise ContractError("runtime artifact changed after attestation publication")
    current = read_bounded_control_snapshot_result(
        attestation_path,
        maximum=MAX_BUILD_ATTESTATION_BYTES,
        label="build attestation",
        require_single_link=True,
    )
    if (
        current.state != "complete"
        or current.body != publication.body
        or current.identity != publication.identity
    ):
        raise ContractError("build attestation changed after publication")
    require_build_authority()
    return document


def load_build_attestation(root: Path, executable: Path) -> dict[str, Any]:
    root = _checked_build_path(root, label="upstream root")
    executable = _checked_build_path(executable, label="build executable")
    selected_package = root.absolute()
    selected_package_ancestry = directory_ancestry_binding(
        selected_package, label="build package"
    )
    root = _resolved_build_path(root, label="upstream root")
    path = build_attestation_path(executable)
    package_ancestry = directory_ancestry_binding(root, label="build package")
    runtime_ancestry = directory_ancestry_binding(
        executable.parent.absolute(), label="build runtime directory"
    )
    manifest_digest = _hash_regular_file(
        root / "upstream.json",
        label="upstream manifest",
        maximum=MAX_UPSTREAM_MANIFEST_BYTES,
    )[0]

    def require_attestation_authority() -> None:
        if directory_ancestry_binding(
            selected_package, label="build package"
        ) != selected_package_ancestry:
            raise ContractError("build package authority changed")
        if directory_ancestry_binding(root, label="build package") != package_ancestry:
            raise ContractError("build package authority changed")
        if directory_ancestry_binding(
            executable.parent.absolute(), label="build runtime directory"
        ) != runtime_ancestry:
            raise ContractError("build runtime directory authority changed")
        current_manifest_digest = _hash_regular_file(
            root / "upstream.json",
            label="upstream manifest",
            maximum=MAX_UPSTREAM_MANIFEST_BYTES,
        )[0]
        if current_manifest_digest != manifest_digest:
            raise ContractError("upstream manifest changed during verification")

    manifest = verify_upstream(root)
    require_attestation_authority()
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_BUILD_ATTESTATION_BYTES,
        label="build attestation",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
        raise ContractError(f"build attestation is {snapshot.state}")
    document = decode_strict_json_bytes(snapshot.body, label="build attestation")
    document = _validate_build_attestation_shape(document, executable=executable)
    if document.get("chromium_revision") != manifest["chromium"]["revision"]:
        raise ContractError("build attestation Chromium revision does not match the pin")
    if document.get("depot_tools_revision") != manifest["depot_tools"]["revision"]:
        raise ContractError("build attestation depot_tools revision does not match the pin")
    if document.get("patch_series_sha256") != patch_series_digest(root):
        raise ContractError("build attestation patch series does not match the pin")
    expected_args = hashlib.sha256(
        json.dumps(manifest["build"]["gn_args"], separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    if document.get("gn_args_sha256") != expected_args:
        raise ContractError("build attestation GN arguments do not match the pin")
    if patch_series_digest(root) != document["patch_series_sha256"]:
        raise ContractError("build attestation patch series changed during verification")
    require_attestation_authority()
    artifacts = document.get("runtime_artifacts")
    assert isinstance(artifacts, list)
    for item in artifacts:
        assert isinstance(item, dict)
        # Fresh bytes after package checks, every attestation. A second full
        # runtime pass could read up to three 4 GiB artifacts; this ordering
        # catches edits during those final checks without increasing that cost.
        digest, size = _hash_regular_file(
            executable.parent / item["file"],
            label=f"runtime artifact {item['file']}",
        )
        if digest != item["sha256"] or size != item["size"]:
            if item["file"] == "chrome.exe":
                raise ContractError("build executable hash does not match its attestation")
            raise ContractError(
                f"runtime artifact does not match its attestation: {item['file']}"
            )
    current = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_BUILD_ATTESTATION_BYTES,
        label="build attestation",
        require_single_link=True,
    )
    if (
        current.state != "complete"
        or current.body != snapshot.body
        or current.identity != snapshot.identity
    ):
        raise ContractError("build attestation changed during verification")
    require_attestation_authority()
    return document


def executable_evidence(
    root: Path,
    executable: Path,
    *,
    allow_unverified: bool,
) -> dict[str, Any]:
    if type(allow_unverified) is not bool:
        raise ContractError("unverified executable opt-in must be boolean")
    executable = _checked_build_path(executable, label="build executable")
    try:
        executable = executable.absolute()
    except (OSError, RuntimeError, ValueError):
        raise ContractError("build executable path is invalid") from None
    try:
        document = load_build_attestation(root, executable)
    except ContractError as error:
        if not allow_unverified:
            raise ContractError(
                "executable is not a verified Browser Core build; use --allow-unverified-executable "
                "only for an explicitly labeled stock-browser control"
            ) from None
        if str(error) != "build attestation is missing":
            raise ContractError(
                "cannot classify executable as an unverified external control "
                "because Browser Core verification failed"
            ) from None
        return {
            "provenance": "unverified-external",
            "executable_sha256_16": _sha256(executable)[:16],
        }
    return {
        "provenance": "attested-browser-core",
        "executable_sha256_16": document["executable_sha256"][:16],
        "runtime_bundle_sha256_16": document["runtime_bundle_sha256"][:16],
        "attestation_created_at": document["created_at"],
    }
