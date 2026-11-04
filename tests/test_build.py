from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

import browser_core.build as build_module
import browser_core.upstream as upstream_module
from browser_core.bounded_process import BoundedProcessResult
from browser_core.control_files import canonical_json_bytes
from browser_core.build import executable_evidence, load_build_attestation
from browser_core.contracts import ContractError
from browser_core.upstream import patch_series_digest


ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize('length',[0,1,1024*1024-1,1024*1024,1024*1024+1,2*1024*1024+73])
def test_buffered_artifact_hash_retains_all_bytes_at_chunk_boundaries(tmp_path,length):
    body=(bytes(range(251))*(length//251+1))[:length]
    path=tmp_path/'artifact.bin'
    path.write_bytes(body)
    assert build_module._hash_regular_file(path,label='test artifact')==(hashlib.sha256(body).hexdigest(),length)


def test_artifact_verification_reads_fresh_same_length_bytes_every_time(tmp_path):
    path=tmp_path/'artifact.bin'
    path.write_bytes(b'first')
    original=path.stat()
    first=build_module._hash_regular_file(path,label='test artifact')
    path.write_bytes(b'other')
    os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns))
    second=build_module._hash_regular_file(path,label='test artifact')
    assert first==(hashlib.sha256(b'first').hexdigest(),5)
    assert second==(hashlib.sha256(b'other').hexdigest(),5)


def test_buffered_artifact_hash_preserves_the_explicit_byte_limit(tmp_path):
    path=tmp_path/'artifact.bin'
    path.write_bytes(b'12345')
    with pytest.raises(ContractError,match='exceeds 4 bytes'):
        build_module._hash_regular_file(path,label='test artifact',maximum=4)


def test_build_git_revision_uses_bounded_private_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision = "a" * 40
    observed: dict[str, object] = {}
    selected_git = Path(shutil.which("git.exe") or "")
    assert selected_git.is_absolute()
    monkeypatch.setenv("BROWSER_CORE_GIT_EXE", str(selected_git))

    def bounded(command, **kwargs):
        observed.update({"command": command, **kwargs})
        return BoundedProcessResult(returncode=0, stdout=(revision + "\n").encode())

    monkeypatch.setattr(build_module, "run_with_bounded_stdout", bounded)

    assert build_module._git_revision(tmp_path) == revision
    expected_environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    expected_environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    assert observed.pop("environment") == expected_environment
    assert observed == {
        "command": [
            str(selected_git), f"--work-tree={tmp_path.absolute()}",
            "-C", str(tmp_path), "rev-parse", "HEAD",
        ],
        "maximum_stdout": 64,
        "timeout_seconds": 30.0,
        "label": "build Git revision",
    }


def test_build_git_revision_ignores_inherited_repository_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_git = Path(shutil.which("git.exe") or "")
    assert selected_git.is_absolute()
    heads = []
    for name in ("target", "foreign"):
        checkout = tmp_path / name
        checkout.mkdir()
        subprocess.run([str(selected_git), "init", "-q", str(checkout)], check=True)
        (checkout / "tracked.txt").write_text(name, encoding="utf-8")
        subprocess.run([str(selected_git), "-C", str(checkout), "add", "tracked.txt"], check=True)
        subprocess.run([
            str(selected_git), "-C", str(checkout),
            "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", name,
        ], check=True)
        heads.append(subprocess.check_output([
            str(selected_git), "-C", str(checkout), "rev-parse", "HEAD",
        ]).decode("ascii").strip())
    assert heads[0] != heads[1]
    monkeypatch.setenv("BROWSER_CORE_GIT_EXE", str(selected_git))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "foreign" / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "foreign"))
    assert build_module._git_revision(tmp_path / "target") == heads[0]


def test_build_git_revision_rejects_invalid_utf8_without_value_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = b"private-marker-\xff"
    monkeypatch.setattr(
        build_module,
        "run_with_bounded_stdout",
        lambda *_args, **_kwargs: BoundedProcessResult(
            returncode=0,
            stdout=marker,
        ),
    )

    with pytest.raises(ContractError, match="cannot verify build Git revision") as raised:
        build_module._git_revision(tmp_path)

    assert "private-marker" not in str(raised.value)
    assert str(tmp_path) not in str(raised.value)


@pytest.mark.parametrize(
    "result",
    [
        BoundedProcessResult(returncode=1, stdout=("a" * 40 + "\n").encode()),
        BoundedProcessResult(returncode=0, stdout=("a" * 40 + "\nextra").encode()),
        BoundedProcessResult(returncode=0, stdout=(" A" + "a" * 39 + "\n").encode()),
    ],
)
def test_build_git_revision_requires_one_exact_success_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: BoundedProcessResult,
) -> None:
    monkeypatch.setattr(
        build_module,
        "run_with_bounded_stdout",
        lambda *_args, **_kwargs: result,
    )

    with pytest.raises(ContractError, match="cannot verify build Git revision"):
        build_module._git_revision(tmp_path)


def _gn_args_text(manifest: dict) -> str:
    return "\n".join(
        f"{key.strip()} = {value.strip()}"
        for key, value in (
            item.split("=", 1) for item in manifest["build"]["gn_args"]
        )
    ) + "\n"


def _stub_depot_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        build_module,
        "verify_depot_tools_checkout",
        lambda _checkout, _revision, **_kwargs: {"status": "verified"},
    )


def _creation_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path, Path]:
    manifest_bytes = (ROOT / "upstream.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    package = tmp_path / "package"
    package.mkdir()
    (package / "upstream.json").write_bytes(manifest_bytes)
    workspace = tmp_path / "workspace"
    source = workspace / "chromium" / "src"
    depot_tools = workspace / "depot_tools"
    output = source / manifest["build"]["output_directory"]
    output.mkdir(parents=True)
    depot_tools.mkdir(parents=True)
    executable = output / "chrome.exe"
    for name in build_module.WINDOWS_RUNTIME_ARTIFACTS:
        (output / name).write_bytes(f"fixture-{name}".encode())
    (output / "args.gn").write_text(_gn_args_text(manifest), encoding="ascii")
    monkeypatch.setattr(build_module, "verify_upstream", lambda _root: manifest)
    monkeypatch.setattr(
        build_module, "_git_revision",
        lambda path: manifest["chromium"]["revision"]
        if path == source else manifest["depot_tools"]["revision"],
    )
    patch_state = {
        "patch_series_sha256": "a" * 64,
        "patched_sources_sha256": "b" * 64,
    }
    monkeypatch.setattr(
        build_module, "verify_patched_checkout", lambda _root, _source: patch_state,
    )
    monkeypatch.setattr(build_module, "patch_series_digest", lambda _root: "a" * 64)
    _stub_depot_verifier(monkeypatch)
    return package, workspace, executable, output / "args.gn"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("selection", ["package", "workspace", "executable"])
def test_attestation_creation_rejects_selected_junction_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: str,
) -> None:
    package, workspace, executable, _args_path = _creation_fixture(tmp_path, monkeypatch)
    selected_parent = tmp_path / "selected"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_parent), str(tmp_path)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    selected_package = selected_parent / package.name if selection == "package" else package
    selected_workspace = selected_parent / workspace.name if selection == "workspace" else workspace
    selected_executable = (
        selected_parent / executable.relative_to(tmp_path)
        if selection == "executable" else executable
    )
    receipt = build_module.build_attestation_path(executable)
    try:
        with pytest.raises(ContractError, match="build (package|workspace|runtime directory)"):
            build_module.create_build_attestation(
                selected_package, selected_workspace, selected_executable,
            )
        assert not receipt.exists()
    finally:
        selected_parent.rmdir()


def test_attestation_rechecks_depot_checkout_after_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, workspace, executable, _args_path = _creation_fixture(tmp_path, monkeypatch)
    depot = workspace / "depot_tools"
    marker = depot / "dirty-wrapper"
    checked: list[Path] = []

    def check_depot(checkout: Path, _revision: str, **_kwargs: object) -> dict:
        checked.append(checkout)
        if marker.exists():
            raise ContractError("depot_tools checkout has changes")
        return {"status": "verified"}

    original_publish = build_module._write_json_atomic

    def publish_then_change(path: Path, document: dict):
        result = original_publish(path, document)
        marker.write_bytes(b"replacement")
        return result

    monkeypatch.setattr(build_module, "verify_depot_tools_checkout", check_depot)
    monkeypatch.setattr(build_module, "_write_json_atomic", publish_then_change)
    with pytest.raises(ContractError, match="depot_tools checkout has changes"):
        build_module.create_build_attestation(package, workspace, executable)
    assert checked == [depot, depot]


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("runtime", "runtime artifact changed after attestation publication"),
        ("receipt", "build attestation changed after publication"),
    ],
)
def test_attestation_rechecks_inputs_after_final_depot_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    mutation: str, expected_error: str,
) -> None:
    package, workspace, executable, _args_path = _creation_fixture(tmp_path, monkeypatch)
    receipt = build_module.build_attestation_path(executable)
    checks = 0

    def check_depot(_checkout: Path, _revision: str, **_kwargs: object) -> dict:
        nonlocal checks
        checks += 1
        if checks == 2:
            if mutation == "runtime":
                (executable.parent / "chrome.dll").write_bytes(b"changed-during-depot-scan")
            else:
                competitor = receipt.with_suffix(".competitor")
                competitor.write_bytes(b"{}")
                competitor.replace(receipt)
        return {"status": "verified"}

    monkeypatch.setattr(build_module, "verify_depot_tools_checkout", check_depot)
    with pytest.raises(ContractError, match=expected_error):
        build_module.create_build_attestation(package, workspace, executable)
    assert checks == 2
    if mutation == "receipt":
        assert receipt.read_bytes() == b"{}"


def test_attestation_rejects_initial_depot_checkout_failure_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, workspace, executable, _args_path = _creation_fixture(tmp_path, monkeypatch)

    def reject_depot(*_args: object, **_kwargs: object) -> dict:
        raise ContractError("depot_tools checkout has changes")

    monkeypatch.setattr(build_module, "verify_depot_tools_checkout", reject_depot)
    with pytest.raises(ContractError, match="depot_tools checkout has changes"):
        build_module.create_build_attestation(package, workspace, executable)
    assert not build_module.build_attestation_path(executable).exists()


def test_explicit_build_git_selection_governs_nested_patch_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, workspace, executable, _args_path = _creation_fixture(tmp_path, monkeypatch)
    selected_git = Path(shutil.which("git.exe") or "")
    assert selected_git.is_absolute()
    monkeypatch.setenv("BROWSER_CORE_GIT_EXE", str(tmp_path / "wrong-git.bat"))
    original = upstream_module.run_with_bounded_stdout
    launched: list[str] = []

    def capture_nested(command, **kwargs):
        launched.append(command[0])
        return original(command, **kwargs)

    def check_patch(_root: Path, source: Path) -> dict:
        code, body = upstream_module._run_git_capture(
            source, ["--version"], maximum=128,
        )
        assert code == 0 and body.startswith(b"git version ")
        return {"patch_series_sha256": "a" * 64, "patched_sources_sha256": "b" * 64}

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", capture_nested)
    monkeypatch.setattr(build_module, "verify_patched_checkout", check_patch)
    build_module.create_build_attestation(
        package, workspace, executable, git_executable=selected_git,
    )
    assert launched and set(launched) == {str(selected_git)}
    with pytest.raises(ContractError, match="Git executable"):
        upstream_module.select_git_executable()


@pytest.mark.parametrize("change", ["mismatch", "extra", "missing"])
def test_attestation_creation_requires_actual_pinned_gn_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    package, workspace, executable, args_path = _creation_fixture(tmp_path, monkeypatch)
    if change == "mismatch":
        args_path.write_text(args_path.read_text(encoding="ascii").replace(
            "is_debug = false", "is_debug = true"
        ), encoding="ascii")
    elif change == "extra":
        with args_path.open("a", encoding="ascii") as stream:
            stream.write("is_official_build = true\n")
    else:
        args_path.unlink()

    with pytest.raises(ContractError, match="build GN arguments"):
        build_module.create_build_attestation(package, workspace, executable)
    assert not build_module.build_attestation_path(executable).exists()


def test_attestation_creation_rechecks_actual_gn_arguments_after_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, workspace, executable, args_path = _creation_fixture(tmp_path, monkeypatch)
    original_writer = build_module._write_json_atomic

    def rewrite_args_after_receipt(path: Path, document: dict):
        published = original_writer(path, document)
        args_path.write_text("is_debug = true\n", encoding="ascii")
        return published

    monkeypatch.setattr(build_module, "_write_json_atomic", rewrite_args_after_receipt)
    with pytest.raises(ContractError, match="build GN arguments changed"):
        build_module.create_build_attestation(package, workspace, executable)


def _write_fixture_attestation(tmp_path: Path) -> tuple[Path, Path, dict]:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"verified")
    chrome_dll = tmp_path / "chrome.dll"
    chrome_dll.write_bytes(b"patched-runtime")
    trace_processor = tmp_path / "trace_processor_shell.exe"
    trace_processor.write_bytes(b"trace-processor")
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    artifacts = [
        {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in (executable, chrome_dll, trace_processor)
    ]
    document = {
        "schema": "browser-core.build/3",
        "created_at": "2026-08-10T00:00:00Z",
        "chromium_revision": manifest["chromium"]["revision"],
        "depot_tools_revision": manifest["depot_tools"]["revision"],
        "executable": "chrome.exe",
        "executable_sha256": artifacts[0]["sha256"],
        "runtime_artifacts": artifacts,
        "runtime_bundle_sha256": hashlib.sha256(
            json.dumps(artifacts, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "patch_series_sha256": patch_series_digest(ROOT),
        "patched_sources_sha256": "0" * 64,
        "gn_args_sha256": hashlib.sha256(
            json.dumps(
                manifest["build"]["gn_args"], separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest(),
    }
    attestation_path = tmp_path / "browser-core-build.json"
    attestation_path.write_bytes(canonical_json_bytes(document))
    return executable, attestation_path, document


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_attestation_load_rejects_selected_package_junction(tmp_path: Path) -> None:
    executable, receipt, _document = _write_fixture_attestation(tmp_path)
    original_receipt = receipt.read_bytes()
    selected_package = tmp_path / "selected-package"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_package), str(ROOT)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="build package"):
            load_build_attestation(selected_package, executable)
        assert receipt.read_bytes() == original_receipt
    finally:
        selected_package.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_executable_evidence_rejects_selected_runtime_junction(tmp_path: Path) -> None:
    physical_runtime = tmp_path / "physical-runtime"
    physical_runtime.mkdir()
    executable, receipt, _document = _write_fixture_attestation(physical_runtime)
    original_receipt = receipt.read_bytes()
    selected_runtime = tmp_path / "selected-runtime"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_runtime), str(physical_runtime)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="cannot classify executable"):
            executable_evidence(
                ROOT, selected_runtime / executable.name, allow_unverified=True,
            )
        assert receipt.read_bytes() == original_receipt
    finally:
        selected_runtime.rmdir()


def test_attestation_load_rejects_relocated_runtime_ancestor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outer = tmp_path / 'outer'
    runtime = outer / 'runtime'
    runtime.mkdir(parents=True)
    executable, _path, _document = _write_fixture_attestation(runtime)
    original = build_module._hash_regular_file
    relocated = False

    def hash_then_relocate(path, *, label, maximum=None):
        nonlocal relocated
        result = original(path, label=label, maximum=maximum)
        if path == executable and not relocated:
            retained = tmp_path / 'retained-outer'
            outer.rename(retained)
            outer.mkdir()
            (retained / 'runtime').rename(runtime)
            relocated = True
        return result

    monkeypatch.setattr(build_module, '_hash_regular_file', hash_then_relocate)
    with pytest.raises(ContractError, match='build runtime directory authority changed'):
        load_build_attestation(ROOT, executable)
    assert relocated
    assert executable.read_bytes() == b'verified'


@pytest.mark.parametrize('relocation_stage', ['manifest', 'patch-series'])
def test_attestation_load_rejects_relocated_package_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relocation_stage: str,
) -> None:
    package_outer = tmp_path / 'package-outer'
    package = package_outer / 'package'
    package.mkdir(parents=True)
    (package / 'upstream.json').write_bytes((ROOT / 'upstream.json').read_bytes())
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    executable, _path, document = _write_fixture_attestation(runtime)
    manifest = json.loads((ROOT / 'upstream.json').read_text(encoding='utf-8'))
    relocated = False

    def relocate_package() -> None:
        nonlocal relocated
        if relocated:
            return
        retained = tmp_path / 'retained-package-outer'
        package_outer.rename(retained)
        package_outer.mkdir()
        (retained / 'package').rename(package)
        relocated = True

    def manifest_then_maybe_relocate(_root: Path) -> dict:
        if relocation_stage == 'manifest':
            relocate_package()
        return manifest

    def digest_then_maybe_relocate(_root: Path) -> str:
        if relocation_stage == 'patch-series':
            relocate_package()
        return document['patch_series_sha256']

    monkeypatch.setattr(build_module, 'verify_upstream', manifest_then_maybe_relocate)
    monkeypatch.setattr(build_module, 'patch_series_digest', digest_then_maybe_relocate)
    with pytest.raises(ContractError, match='build package authority changed'):
        load_build_attestation(package, executable)
    assert relocated


def test_attestation_load_rejects_same_size_manifest_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / 'package'
    package.mkdir()
    manifest_path = package / 'upstream.json'
    original = (ROOT / 'upstream.json').read_bytes()
    manifest_path.write_bytes(original)
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    executable, _path, document = _write_fixture_attestation(runtime)
    changed = original.replace(b'"captured_at": "2026-08-02"', b'"captured_at": "2026-08-03"', 1)
    assert changed != original and len(changed) == len(original)

    def rewrite_manifest(_root: Path) -> str:
        before = manifest_path.stat()
        manifest_path.write_bytes(changed)
        os.utime(manifest_path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return document['patch_series_sha256']

    monkeypatch.setattr(build_module, 'patch_series_digest', rewrite_manifest)
    with pytest.raises(ContractError, match='upstream manifest changed during verification'):
        load_build_attestation(package, executable)


def test_attestation_load_rejects_patch_series_change_during_runtime_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, _path, document = _write_fixture_attestation(tmp_path)
    digest_reads = 0

    def changing_patch_digest(_root: Path) -> str:
        nonlocal digest_reads
        digest_reads += 1
        return document['patch_series_sha256'] if digest_reads == 1 else 'f' * 64

    monkeypatch.setattr(build_module, 'patch_series_digest', changing_patch_digest)
    with pytest.raises(ContractError, match='build attestation patch series changed'):
        load_build_attestation(ROOT, executable)
    assert digest_reads >= 2


def test_attestation_load_rejects_runtime_change_during_final_patch_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, _path, _document = _write_fixture_attestation(tmp_path)
    artifact = executable.parent / "chrome.dll"
    original_body = artifact.read_bytes()
    changed_body = b"changed-runtime"
    assert len(changed_body) == len(original_body)
    original_digest = build_module.patch_series_digest
    digest_reads = 0

    def mutate_during_final_digest(root: Path) -> str:
        nonlocal digest_reads
        digest = original_digest(root)
        digest_reads += 1
        if digest_reads == 2:
            before = artifact.stat()
            artifact.write_bytes(changed_body)
            os.utime(artifact, ns=(before.st_atime_ns, before.st_mtime_ns))
        return digest

    monkeypatch.setattr(build_module, "patch_series_digest", mutate_during_final_digest)
    with pytest.raises(ContractError, match="runtime artifact does not match"):
        load_build_attestation(ROOT, executable)
    assert digest_reads == 2
    assert artifact.read_bytes() == changed_body


@pytest.mark.parametrize(
    'relocated_target',
    ['package-ancestor', 'workspace-ancestor', 'depot-tools'],
)
def test_attestation_creation_rejects_relocated_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relocated_target: str,
) -> None:
    manifest = json.loads((ROOT / 'upstream.json').read_text(encoding='utf-8'))
    package_outer = tmp_path / 'package-outer'
    package = package_outer / 'package'
    package.mkdir(parents=True)
    (package / 'upstream.json').write_bytes((ROOT / 'upstream.json').read_bytes())
    outer = tmp_path / 'outer'
    workspace = outer / 'workspace'
    source = workspace / 'chromium' / 'src'
    depot_tools = workspace / 'depot_tools'
    output = source / manifest['build']['output_directory']
    output.mkdir(parents=True)
    depot_tools.mkdir(parents=True)
    executable = output / 'chrome.exe'
    for name in build_module.WINDOWS_RUNTIME_ARTIFACTS:
        (output / name).write_bytes(f'fixture-{name}'.encode())

    monkeypatch.setattr(build_module, 'verify_upstream', lambda _root: manifest)
    _stub_depot_verifier(monkeypatch)
    monkeypatch.setattr(
        build_module,
        '_git_revision',
        lambda path: manifest['chromium']['revision']
        if path == source else manifest['depot_tools']['revision'],
    )
    monkeypatch.setattr(
        build_module,
        'verify_patched_checkout',
        lambda _root, _source: {
            'patch_series_sha256': 'a' * 64,
            'patched_sources_sha256': 'b' * 64,
        },
    )
    original = build_module._runtime_artifacts

    def artifacts_then_relocate(path: Path) -> list[dict]:
        artifacts = original(path)
        if relocated_target == 'package-ancestor':
            retained = tmp_path / 'retained-package-outer'
            package_outer.rename(retained)
            package_outer.mkdir()
            (retained / 'package').rename(package)
        elif relocated_target == 'workspace-ancestor':
            retained = tmp_path / 'retained-outer'
            outer.rename(retained)
            outer.mkdir()
            (retained / 'workspace').rename(workspace)
        else:
            depot_tools.rename(workspace / 'retained-depot-tools')
            depot_tools.mkdir()
        return artifacts

    monkeypatch.setattr(build_module, '_runtime_artifacts', artifacts_then_relocate)
    with pytest.raises(ContractError, match='build (package|workspace|depot_tools) authority changed'):
        build_module.create_build_attestation(package, workspace, executable)
    assert not build_module.build_attestation_path(executable).exists()


def test_attestation_creation_rejects_resolved_output_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = json.loads((ROOT / 'upstream.json').read_text(encoding='utf-8'))
    package = tmp_path / 'package'
    package.mkdir()
    (package / 'upstream.json').write_bytes((ROOT / 'upstream.json').read_bytes())
    workspace = tmp_path / 'workspace'
    source = workspace / 'chromium' / 'src'
    depot_tools = workspace / 'depot_tools'
    output = source / manifest['build']['output_directory']
    output.parent.mkdir(parents=True)
    depot_tools.mkdir(parents=True)
    outside = tmp_path / 'outside'
    outside.mkdir()
    for name in build_module.WINDOWS_RUNTIME_ARTIFACTS:
        (outside / name).write_bytes(f'fixture-{name}'.encode())
    original_resolve = Path.resolve

    def resolve_linked_output(path: Path, *args: object, **kwargs: object) -> Path:
        if path == output / 'chrome.exe':
            return outside / 'chrome.exe'
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'resolve', resolve_linked_output)
    monkeypatch.setattr(build_module, 'verify_upstream', lambda _root: manifest)
    monkeypatch.setattr(
        build_module,
        '_git_revision',
        lambda path: manifest['chromium']['revision']
        if path == source else manifest['depot_tools']['revision'],
    )
    monkeypatch.setattr(
        build_module,
        'verify_patched_checkout',
        lambda _root, _source: {
            'patch_series_sha256': 'a' * 64,
            'patched_sources_sha256': 'b' * 64,
        },
    )
    with pytest.raises(ContractError, match='outside the pinned output directory'):
        build_module.create_build_attestation(package, workspace, output / 'chrome.exe')
    assert not (outside / 'browser-core-build.json').exists()


@pytest.mark.parametrize('invalid_kind', ['workspace-type', 'executable-type', 'executable-name'])
def test_attestation_creation_rejects_invalid_paths_before_package_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_kind: str,
) -> None:
    package = tmp_path / 'package'
    package.mkdir()
    workspace: Path | None = tmp_path / 'workspace'
    executable: Path | None = workspace / 'chrome.exe'
    if invalid_kind == 'workspace-type':
        workspace = None
    elif invalid_kind == 'executable-type':
        executable = None
    else:
        executable = tmp_path / 'other.exe'

    def forbidden(_root: Path) -> dict:
        raise AssertionError('invalid build input reached package scan')

    monkeypatch.setattr(build_module, 'verify_upstream', forbidden)
    with pytest.raises(ContractError, match='build (workspace|executable) path|pinned Windows build'):
        build_module.create_build_attestation(package, workspace, executable)  # type: ignore[arg-type]


def test_attestation_creation_rejects_manifest_change_after_pin_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / 'package'
    package.mkdir()
    manifest_path = package / 'upstream.json'
    original = b'{"build":1}'
    manifest_path.write_bytes(original)
    workspace = tmp_path / 'workspace'
    executable = workspace / 'chromium' / 'src' / 'out' / 'BrowserCore' / 'chrome.exe'

    def rewrite_manifest(_root: Path) -> dict:
        manifest_path.write_bytes(b'{"build":2}')
        return {}

    monkeypatch.setattr(build_module, 'verify_upstream', rewrite_manifest)
    with pytest.raises(ContractError, match='upstream manifest changed during build'):
        build_module.create_build_attestation(
            package,
            workspace,
            executable,
            expected_manifest_sha256=hashlib.sha256(original).hexdigest(),
        )
    assert not build_module.build_attestation_path(executable).exists()


@pytest.mark.parametrize('prebound_manifest', [False, True])
def test_attestation_creation_rejects_manifest_change_after_runtime_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prebound_manifest: bool,
) -> None:
    package = tmp_path / 'package'
    package.mkdir()
    manifest_path = package / 'upstream.json'
    original = (ROOT / 'upstream.json').read_bytes()
    manifest_path.write_bytes(original)
    manifest = json.loads(original)
    workspace = tmp_path / 'workspace'
    source = workspace / 'chromium' / 'src'
    depot_tools = workspace / 'depot_tools'
    output = source / manifest['build']['output_directory']
    output.mkdir(parents=True)
    depot_tools.mkdir(parents=True)
    executable = output / 'chrome.exe'
    for name in build_module.WINDOWS_RUNTIME_ARTIFACTS:
        (output / name).write_bytes(f'fixture-{name}'.encode())
    monkeypatch.setattr(build_module, 'verify_upstream', lambda _root: manifest)
    _stub_depot_verifier(monkeypatch)
    monkeypatch.setattr(
        build_module,
        '_git_revision',
        lambda path: manifest['chromium']['revision']
        if path == source else manifest['depot_tools']['revision'],
    )
    monkeypatch.setattr(
        build_module,
        'verify_patched_checkout',
        lambda _root, _source: {
            'patch_series_sha256': 'a' * 64,
            'patched_sources_sha256': 'b' * 64,
        },
    )
    original_artifacts = build_module._runtime_artifacts

    def artifacts_then_rewrite(path: Path) -> list[dict]:
        artifacts = original_artifacts(path)
        previous = manifest_path.stat()
        changed = bytearray(original)
        changed[0] = ord('[')
        manifest_path.write_bytes(changed)
        os.utime(manifest_path, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        return artifacts

    monkeypatch.setattr(build_module, '_runtime_artifacts', artifacts_then_rewrite)
    with pytest.raises(ContractError, match='upstream manifest changed during build'):
        build_module.create_build_attestation(
            package,
            workspace,
            executable,
            expected_manifest_sha256=(
                hashlib.sha256(original).hexdigest() if prebound_manifest else None
            ),
        )
    assert not build_module.build_attestation_path(executable).exists()


@pytest.mark.parametrize('change', [
    'content', 'replacement', 'patch-series',
    'patched-sources-before-publication', 'patched-sources-after-publication',
    'depot-revision-before-publication', 'depot-revision-after-publication',
    'runtime-after-publication',
])
def test_attestation_creation_rejects_authority_changed_during_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    manifest = json.loads((ROOT / 'upstream.json').read_text(encoding='utf-8'))
    package = tmp_path / 'package'
    package.mkdir()
    (package / 'upstream.json').write_bytes((ROOT / 'upstream.json').read_bytes())
    workspace = tmp_path / 'workspace'
    source = workspace / 'chromium' / 'src'
    depot_tools = workspace / 'depot_tools'
    output = source / manifest['build']['output_directory']
    output.mkdir(parents=True)
    depot_tools.mkdir(parents=True)
    executable = output / 'chrome.exe'
    for name in build_module.WINDOWS_RUNTIME_ARTIFACTS:
        (output / name).write_bytes(f'fixture-{name}'.encode())
    (output / 'args.gn').write_text(_gn_args_text(manifest), encoding='ascii')
    monkeypatch.setattr(build_module, 'verify_upstream', lambda _root: manifest)
    _stub_depot_verifier(monkeypatch)
    depot_revision = {'current': manifest['depot_tools']['revision']}
    monkeypatch.setattr(
        build_module,
        '_git_revision',
        lambda path: manifest['chromium']['revision']
        if path == source else depot_revision['current'],
    )
    source_digest = {'current': 'b' * 64}
    monkeypatch.setattr(
        build_module,
        'verify_patched_checkout',
        lambda _root, _source: {
            'patch_series_sha256': 'a' * 64,
            'patched_sources_sha256': source_digest['current'],
        },
    )
    patch_digest = {'current': 'a' * 64}
    monkeypatch.setattr(
        build_module,
        'patch_series_digest',
        lambda _root: patch_digest['current'],
    )
    original_artifacts = build_module._runtime_artifacts

    def artifacts_then_change_source(path: Path) -> list[dict]:
        artifacts = original_artifacts(path)
        if change == 'patched-sources-before-publication':
            source_digest['current'] = 'c' * 64
        elif change == 'depot-revision-before-publication':
            depot_revision['current'] = 'f' * 40
        return artifacts

    monkeypatch.setattr(build_module, '_runtime_artifacts', artifacts_then_change_source)
    original_writer = build_module._write_json_atomic

    def change_after_write(path: Path, document: dict):
        published = original_writer(path, document)
        if change == 'content':
            path.write_bytes(b'{}')
        elif change == 'replacement':
            replacement = path.with_suffix('.replacement')
            replacement.write_bytes(path.read_bytes())
            replacement.replace(path)
        else:
            if change == 'patch-series':
                patch_digest['current'] = 'f' * 64
            elif change == 'patched-sources-after-publication':
                source_digest['current'] = 'c' * 64
            elif change == 'depot-revision-after-publication':
                depot_revision['current'] = 'f' * 40
            elif change == 'runtime-after-publication':
                (output / 'chrome.dll').write_bytes(b'mutated-after-publication')
        return published

    monkeypatch.setattr(build_module, '_write_json_atomic', change_after_write)
    expected = ('build patch series changed during attestation'
                if change == 'patch-series' else
                'patched checkout changed during attestation'
                if change.startswith('patched-sources') else
                'build checkout revision changed during attestation'
                if change.startswith('depot-revision') else
                'runtime artifact changed after attestation publication'
                if change == 'runtime-after-publication' else
                'build attestation changed after publication')
    with pytest.raises(ContractError, match=expected):
        build_module.create_build_attestation(package, workspace, executable)
    if change.endswith('before-publication'):
        assert not build_module.build_attestation_path(executable).exists()


def test_attestation_creation_rejects_invalid_manifest_digest_before_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / 'package'
    package.mkdir()

    def forbidden(_root: Path) -> dict:
        raise AssertionError('invalid manifest digest reached package scan')

    monkeypatch.setattr(build_module, 'verify_upstream', forbidden)
    with pytest.raises(ContractError, match='expected upstream manifest digest is invalid'):
        build_module.create_build_attestation(
            package,
            tmp_path / 'workspace',
            tmp_path / 'chrome.exe',
            expected_manifest_sha256='A' * 64,
        )


def test_build_script_rejects_source_state_changes_during_compile() -> None:
    source = (ROOT / "scripts" / "build.ps1").read_text(encoding="utf-8")
    assert "$sourceStateBefore" in source
    assert "$sourceStateAfter" in source
    assert "patched_sources_sha256" in source
    assert "source state changed during the Chromium build" in source


def test_build_script_binds_attestation_to_loaded_manifest_bytes() -> None:
    source = (ROOT / 'scripts' / 'build.ps1').read_text(encoding='utf-8')
    assert 'ReadBytes($maxManifestBytes + 1)' in source
    assert '$manifestBytes.Length -gt $maxManifestBytes' in source
    assert 'ComputeHash($manifestBytes)' in source
    assert '--expected-manifest-sha256 $manifestSha256' in source


def test_build_script_validates_loaded_manifest_before_native_commands() -> None:
    source = (ROOT / 'scripts' / 'build.ps1').read_text(encoding='utf-8')
    assert 'upstream verify --expected-manifest-sha256 $digest' in source
    assert source.count('Assert-PinnedUpstreamManifest $repoRoot $manifestSha256') == 3
    assert source.index('Assert-PinnedUpstreamManifest $repoRoot $manifestSha256') < source.index('& $pinnedGclient runhooks')


def test_build_script_invokes_the_pinned_gn_binary() -> None:
    source = (ROOT / 'scripts' / 'build.ps1').read_text(encoding='utf-8')
    assert '$pinnedGnExe = Join-Path $pinnedGn "gn.exe"' in source
    assert '$env:PATH = "$pinnedGn;$depotTools;$env:PATH"' in source
    assert '& $pinnedGnExe gen $manifest.build.output_directory --args=$argsText' in source


def test_build_script_invokes_the_pinned_autoninja_wrapper() -> None:
    source = (ROOT / 'scripts' / 'build.ps1').read_text(encoding='utf-8')
    assert '$pinnedAutoninja = Join-Path $depotTools "autoninja.bat"' in source
    assert '& $pinnedAutoninja -C $manifest.build.output_directory $targets' in source


@pytest.mark.parametrize("script_name", ["bootstrap.ps1", "build.ps1"])
def test_setup_scripts_invoke_selected_gclient_wrapper(script_name: str) -> None:
    source = (ROOT / 'scripts' / script_name).read_text(encoding='utf-8')
    assert '$pinnedGclient = Join-Path $depotTools "gclient.bat"' in source
    assert '& $pinnedGclient ' in source
    assert all(not line.lstrip().startswith('gclient ') for line in source.splitlines())


def test_bootstrap_verifies_existing_gclient_before_each_sync() -> None:
    source = (ROOT / 'scripts' / 'bootstrap.ps1').read_text(encoding='utf-8')
    assert '$gclientText.Contains($manifest.chromium.repository)' not in source
    assert 'upstream verify-gclient --config $config --expected-manifest-sha256 $manifestSha256' in source
    assert source.count('Assert-PinnedGclientConfig $gclientFile $manifestSha256') == 3
    assert source.count('& $pinnedGclient sync') == 2
    assert source.rindex('Assert-PinnedGclientConfig $gclientFile $manifestSha256') > source.rindex('& $pinnedGclient sync')


def test_bootstrap_binds_initial_manifest_bytes_to_verification() -> None:
    source = (ROOT / 'scripts' / 'bootstrap.ps1').read_text(encoding='utf-8')
    assert 'ReadBytes($maxManifestBytes + 1)' in source
    assert 'ComputeHash($manifestBytes)' in source
    assert 'upstream verify --expected-manifest-sha256 $manifestSha256' in source


def test_build_verifies_gclient_before_hooks() -> None:
    source = (ROOT / 'scripts' / 'build.ps1').read_text(encoding='utf-8')
    assert 'upstream verify-gclient --config $gclientFile --expected-manifest-sha256 $manifestSha256' in source
    assert source.index('upstream verify-gclient --config $gclientFile') < source.index('& $pinnedGclient runhooks')


def test_bootstrap_verifies_depot_tools_before_invoked_wrappers() -> None:
    source = (ROOT / 'scripts' / 'bootstrap.ps1').read_text(encoding='utf-8')
    assert 'upstream verify-depot-tools --checkout $checkout --expected-manifest-sha256 $digest' in source
    assert source.count('Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256') == 5
    assert source.index('Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256') < source.index('& $pinnedWinTools')
    assert source.index('Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256', source.index('& $pinnedWinTools')) < source.index('& $pinnedGclient config')
    assert source.index('Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256', source.index('& $pinnedGclient config')) < source.index('& $pinnedGclient sync')
    assert source.rindex('Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256') > source.rindex('& $pinnedGclient sync')


def test_bootstrap_rechecks_chromium_revision_after_final_sync() -> None:
    source = (ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
    final_sync = source.rindex('& $pinnedGclient sync')
    assert source.index('rev-parse --verify HEAD', final_sync) > final_sync
    assert source.index('$manifest.chromium.revision', source.index('rev-parse --verify HEAD', final_sync)) > final_sync


def test_setup_scripts_reject_chromium_worktree_override_around_gclient() -> None:
    bootstrap = (ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
    build = (ROOT / "scripts" / "build.ps1").read_text(encoding="utf-8")
    check = "Assert-BrowserCoreNoGitWorktreeOverride $src $pinnedGit"
    assert bootstrap.count(check) == 3
    assert bootstrap.index(check) < bootstrap.index(
        '& $pinnedGit -c core.hooksPath=NUL "--work-tree=$src" -C $src fetch'
    )
    assert bootstrap.rindex(check) > bootstrap.rindex("& $pinnedGclient sync")
    assert build.count(check) == 2
    assert build.index(check) < build.index("& $pinnedGclient runhooks")
    assert build.rindex(check) > build.index("& $pinnedGclient runhooks")


def test_build_verifies_depot_tools_before_hooks_and_builder() -> None:
    source = (ROOT / 'scripts' / 'build.ps1').read_text(encoding='utf-8')
    assert 'upstream verify-depot-tools --checkout $checkout --expected-manifest-sha256 $digest' in source
    assert source.count('Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256') == 2
    assert source.index('Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256') < source.index('& $pinnedGclient runhooks')
    assert source.rindex('Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256') < source.index('& $pinnedAutoninja -C')


@pytest.mark.parametrize("script_name", ["bootstrap.ps1", "build.ps1", "apply-patches.ps1"])
def test_setup_scripts_pin_python_before_using_the_depot_path(script_name: str) -> None:
    source = (ROOT / 'scripts' / script_name).read_text(encoding='utf-8')
    assert 'Get-Command python.exe -CommandType Application' in source
    assert '& $pinnedPython -m browser_core ' in source
    assert all(not line.lstrip().startswith('python -m browser_core ') for line in source.splitlines())
    if script_name != 'apply-patches.ps1':
        assert source.index('Get-Command python.exe -CommandType Application') < source.index('$env:PATH = ')
    else:
        assert '$env:BROWSER_CORE_GIT_EXE = $pinnedGit' in source
        assert "Restore-BrowserCoreEnvironmentVariable 'BROWSER_CORE_GIT_EXE' $previousBrowserCoreGitExe" in source


def test_bootstrap_uses_selected_git_executable_without_checkout_hooks() -> None:
    source = (ROOT / 'scripts' / 'bootstrap.ps1').read_text(encoding='utf-8')
    assert 'Get-Command git.exe -CommandType Application' in source
    assert source.count('& $pinnedGit -c core.hooksPath=NUL ') == 6
    assert all(not line.lstrip().startswith('git ') for line in source.splitlines())
    assert source.index('Get-Command git.exe -CommandType Application') < source.index('$env:PATH = ')


def test_bootstrap_anchors_direct_git_operations_to_their_worktrees() -> None:
    source = (ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
    direct = [
        line.strip() for line in source.splitlines()
        if "& $pinnedGit " in line and " clone " not in line
    ]
    assert len(direct) == 5
    for line in direct:
        expected = "$src" if "-C $src " in line else "$depotTools"
        assert f'"--work-tree={expected}"' in line


@pytest.mark.parametrize("script_name", ["bootstrap.ps1", "build.ps1"])
def test_setup_scripts_pass_selected_git_to_python_and_scope_gclient_hooks(script_name: str) -> None:
    source = (ROOT / 'scripts' / script_name).read_text(encoding='utf-8')
    assert '. (Join-Path $PSScriptRoot "git-hooks.ps1")' in source
    assert '$env:BROWSER_CORE_GIT_EXE = $pinnedGit' in source
    assert "Restore-BrowserCoreEnvironmentVariable 'BROWSER_CORE_GIT_EXE' $previousBrowserCoreGitExe" in source
    assert 'upstream verify-depot-tools --checkout $checkout --expected-manifest-sha256 $digest --git-executable $pinnedGit' in source
    assert source.count('Invoke-BrowserCoreGitHooksDisabled {') == (3 if script_name == 'bootstrap.ps1' else 1)


@pytest.mark.parametrize("script_name", ["bootstrap.ps1", "build.ps1", "apply-patches.ps1"])
def test_setup_scripts_isolate_git_environment_and_restore_selection(script_name: str) -> None:
    source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
    assert '. (Join-Path $PSScriptRoot "git-hooks.ps1")' in source
    assert 'Invoke-BrowserCoreGitEnvironment {' in source
    assert "Restore-BrowserCoreEnvironmentVariable 'BROWSER_CORE_GIT_EXE' $previousBrowserCoreGitExe" in source


def test_git_hook_scope_restores_existing_config_after_success_and_failure() -> None:
    powershell = shutil.which("pwsh")
    if os.name != "nt" or powershell is None:
        pytest.skip("Windows PowerShell Git hook scope")
    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_GIT_HOOK_HELPER
        $env:GIT_CONFIG_COUNT = '1'
        $env:GIT_CONFIG_KEY_0 = 'user.name'
        $env:GIT_CONFIG_VALUE_0 = 'existing'
        $env:GIT_CONFIG_KEY_1 = 'retained-key'
        $env:GIT_CONFIG_VALUE_1 = 'retained-value'
        Invoke-BrowserCoreGitHooksDisabled {
            if ($env:GIT_CONFIG_COUNT -ne '2' -or $env:GIT_CONFIG_KEY_1 -ne 'core.hooksPath' -or $env:GIT_CONFIG_VALUE_1 -ne 'NUL') {
                throw 'Git hook setting was not appended.'
            }
        }
        if ($env:GIT_CONFIG_COUNT -ne '1' -or $env:GIT_CONFIG_KEY_1 -ne 'retained-key' -or $env:GIT_CONFIG_VALUE_1 -ne 'retained-value') {
            throw 'Git hook setting was not restored.'
        }
        try { Invoke-BrowserCoreGitHooksDisabled { throw 'probe failure' } } catch {}
        if ($env:GIT_CONFIG_COUNT -ne '1' -or $env:GIT_CONFIG_KEY_1 -ne 'retained-key' -or $env:GIT_CONFIG_VALUE_1 -ne 'retained-value') {
            throw 'Git hook setting was not restored after failure.'
        }
        $env:GIT_CONFIG_COUNT = 'invalid'
        $rejected = $false
        $script:invoked = $false
        try { Invoke-BrowserCoreGitHooksDisabled { $script:invoked = $true } } catch { $rejected = $true }
        if (-not $rejected -or $script:invoked) { throw 'Malformed Git config count was accepted.' }
        Remove-Item Env:GIT_CONFIG_COUNT
        Invoke-BrowserCoreGitHooksDisabled {}
        if ([Environment]::GetEnvironmentVariables().Contains('GIT_CONFIG_COUNT')) {
            throw 'Absent Git config count was restored as an empty variable.'
        }
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env={**os.environ, "BC_TEST_GIT_HOOK_HELPER": str(ROOT / "scripts" / "git-hooks.ps1")},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_git_hook_scope_suppresses_checkout_hook_in_local_git_fixture(tmp_path: Path) -> None:
    powershell = shutil.which("pwsh")
    git = shutil.which("git.exe")
    if os.name != "nt" or powershell is None or git is None:
        pytest.skip("Windows Git checkout hook scope")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    for command in (
        [git, "init", "-q", str(checkout)],
        [git, "-C", str(checkout), "config", "user.name", "Browser Core Test"],
        [git, "-C", str(checkout), "config", "user.email", "browser-core@example.invalid"],
    ):
        subprocess.run(command, check=True, capture_output=True)
    (checkout / "file.txt").write_text("one", encoding="ascii")
    subprocess.run([git, "-C", str(checkout), "add", "file.txt"], check=True, capture_output=True)
    subprocess.run([git, "-C", str(checkout), "commit", "-qm", "initial"], check=True, capture_output=True)
    hook = checkout / ".git" / "hooks" / "post-checkout"
    hook.write_text("#!/bin/sh\nprintf fired > hook-fired\n", encoding="ascii")
    subprocess.run([git, "-C", str(checkout), "checkout", "-b", "hook-probe"], check=True, capture_output=True)
    marker = checkout / "hook-fired"
    assert marker.read_text(encoding="ascii") == "fired"
    marker.unlink()

    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_GIT_HOOK_HELPER
        Invoke-BrowserCoreGitHooksDisabled {
            & $env:BC_TEST_GIT_EXE -C $env:BC_TEST_GIT_CHECKOUT checkout --detach HEAD | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Git checkout failed.' }
        }
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env={
            **os.environ,
            "BC_TEST_GIT_HOOK_HELPER": str(ROOT / "scripts" / "git-hooks.ps1"),
            "BC_TEST_GIT_EXE": git,
            "BC_TEST_GIT_CHECKOUT": str(checkout),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(checkout / ".git" / "hooks"),
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_git_environment_scope_uses_intended_checkout_and_restores_caller(tmp_path: Path) -> None:
    powershell = shutil.which("pwsh")
    git = shutil.which("git.exe")
    if os.name != "nt" or powershell is None or git is None:
        pytest.skip("Windows Git environment scope")
    intended = tmp_path / "intended"
    foreign = tmp_path / "foreign"
    for checkout in (intended, foreign):
        checkout.mkdir()
        subprocess.run([git, "init", "-q", str(checkout)], check=True, capture_output=True)
    subprocess.run(
        [git, "-C", str(intended), "config", "core.worktree", str(foreign)],
        check=True,
        capture_output=True,
    )
    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_GIT_HOOK_HELPER
        $savedDir = $env:GIT_DIR
        $savedWorkTree = $env:GIT_WORK_TREE
        $savedCount = $env:GIT_CONFIG_COUNT
        $savedKey = $env:GIT_CONFIG_KEY_0
        $savedValue = $env:GIT_CONFIG_VALUE_0
        Invoke-BrowserCoreGitEnvironment {
            if (
                $env:GIT_DIR -or $env:GIT_WORK_TREE -or
                $env:GIT_CONFIG_COUNT -ne '1' -or
                $env:GIT_CONFIG_KEY_0 -ne 'core.fsmonitor' -or
                $env:GIT_CONFIG_VALUE_0 -ne 'false'
            ) {
                throw 'scoped Git environment is invalid'
            }
            $actual = (& $env:BC_TEST_GIT_EXE "--work-tree=$env:BC_TEST_GIT_INTENDED" -C $env:BC_TEST_GIT_INTENDED rev-parse --show-toplevel).Trim()
            if ($LASTEXITCODE -ne 0 -or -not [string]::Equals(
                [System.IO.Path]::GetFullPath($actual),
                [System.IO.Path]::GetFullPath($env:BC_TEST_GIT_INTENDED),
                [System.StringComparison]::OrdinalIgnoreCase
            )) { throw 'Git used a foreign checkout' }
            $env:GIT_TEST_NEW = 'temporary'
        }
        if (
            $env:GIT_DIR -ne $savedDir -or
            $env:GIT_WORK_TREE -ne $savedWorkTree -or
            $env:GIT_CONFIG_COUNT -ne $savedCount -or
            $env:GIT_CONFIG_KEY_0 -ne $savedKey -or
            $env:GIT_CONFIG_VALUE_0 -ne $savedValue -or
            $null -ne [Environment]::GetEnvironmentVariable('GIT_TEST_NEW')
        ) { throw 'Git environment was not restored' }
        try { Invoke-BrowserCoreGitEnvironment { throw 'probe failure' } } catch {}
        if (
            $env:GIT_DIR -ne $savedDir -or $env:GIT_WORK_TREE -ne $savedWorkTree -or
            $env:GIT_CONFIG_COUNT -ne $savedCount -or
            $env:GIT_CONFIG_KEY_0 -ne $savedKey -or
            $env:GIT_CONFIG_VALUE_0 -ne $savedValue
        ) {
            throw 'Git environment was not restored after failure'
        }
        exit 0
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env={
            **os.environ,
            "BC_TEST_GIT_HOOK_HELPER": str(ROOT / "scripts" / "git-hooks.ps1"),
            "BC_TEST_GIT_EXE": git,
            "BC_TEST_GIT_INTENDED": str(intended),
            "GIT_DIR": str(foreign / ".git"),
            "GIT_WORK_TREE": str(foreign),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(foreign / ".git" / "hooks"),
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_git_environment_scope_ignores_replacement_refs(tmp_path: Path) -> None:
    powershell = shutil.which("pwsh")
    git = shutil.which("git.exe")
    if os.name != "nt" or powershell is None or git is None:
        pytest.skip("Windows Git replacement-ref scope")
    checkout = tmp_path / "replaced"
    checkout.mkdir()

    def run_git(*arguments: str) -> str:
        return subprocess.run(
            [git, "-C", str(checkout), *arguments],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    run_git("init", "-q")
    tracked = checkout / "tracked.txt"
    tracked.write_text("original\n", encoding="utf-8")
    run_git("add", "tracked.txt")
    run_git(
        "-c", "user.name=Browser Core Tests",
        "-c", "user.email=browser-core@example.invalid",
        "commit", "-q", "-m", "original",
    )
    revision = run_git("rev-parse", "HEAD")
    tracked.write_text("replacement\n", encoding="utf-8")
    run_git("add", "tracked.txt")
    run_git(
        "-c", "user.name=Browser Core Tests",
        "-c", "user.email=browser-core@example.invalid",
        "commit", "-q", "-m", "replacement",
    )
    replacement = run_git("rev-parse", "HEAD")
    run_git("replace", revision, replacement)
    run_git("reset", "--hard", revision)
    assert tracked.read_text(encoding="utf-8") == "replacement\n"

    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_GIT_HOOK_HELPER
        $before = $env:GIT_NO_REPLACE_OBJECTS
        Invoke-BrowserCoreGitEnvironment {
            if ($env:GIT_NO_REPLACE_OBJECTS -ne '1') {
                throw 'Git replacement refs are enabled inside the scope'
            }
            $body = (& $env:BC_TEST_GIT_EXE -C $env:BC_TEST_GIT_CHECKOUT show HEAD:tracked.txt).Trim()
            if ($LASTEXITCODE -ne 0 -or $body -ne 'original') {
                throw 'Git read a replacement tree'
            }
        }
        if ($env:GIT_NO_REPLACE_OBJECTS -ne $before) {
            throw 'Git replacement setting was not restored'
        }
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env={
            **os.environ,
            "BC_TEST_GIT_HOOK_HELPER": str(ROOT / "scripts" / "git-hooks.ps1"),
            "BC_TEST_GIT_EXE": git,
            "BC_TEST_GIT_CHECKOUT": str(checkout),
            "GIT_NO_REPLACE_OBJECTS": "0",
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_git_environment_scope_disables_repository_fsmonitor(tmp_path: Path) -> None:
    powershell = shutil.which("pwsh")
    git = shutil.which("git.exe")
    if os.name != "nt" or powershell is None or git is None:
        pytest.skip("Windows Git filesystem monitor scope")
    git_environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    for command in (
        [git, "init", "-q", str(checkout)],
        [git, "-C", str(checkout), "config", "user.name", "Browser Core Test"],
        [git, "-C", str(checkout), "config", "user.email", "browser-core@example.invalid"],
    ):
        subprocess.run(command, check=True, capture_output=True, env=git_environment)
    (checkout / "file.txt").write_text("one", encoding="ascii")
    subprocess.run(
        [git, "-C", str(checkout), "add", "file.txt"],
        check=True, capture_output=True, env=git_environment,
    )
    subprocess.run(
        [git, "-C", str(checkout), "commit", "-qm", "initial"],
        check=True, capture_output=True, env=git_environment,
    )
    marker = tmp_path / "fsmonitor-fired.txt"
    monitor = f"sh -c 'echo invoked >> \"{marker.as_posix()}\"; exit 1'"
    subprocess.run(
        [git, "-C", str(checkout), "config", "core.fsmonitor", monitor],
        check=True, capture_output=True, env=git_environment,
    )
    baseline = subprocess.run(
        [git, "--no-optional-locks", "-C", str(checkout), "status", "--porcelain"],
        capture_output=True, text=True, timeout=15, env=git_environment,
    )
    assert baseline.returncode == 0, baseline.stderr
    if not marker.exists():
        pytest.skip("installed Git does not invoke a configured filesystem monitor")
    marker.unlink()

    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_GIT_HOOK_HELPER
        Invoke-BrowserCoreGitEnvironment {
            & $env:BC_TEST_GIT_EXE --no-optional-locks -C $env:BC_TEST_GIT_CHECKOUT status --porcelain | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Git status failed.' }
        }
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env={
            **git_environment,
            "BC_TEST_GIT_HOOK_HELPER": str(ROOT / "scripts" / "git-hooks.ps1"),
            "BC_TEST_GIT_EXE": git,
            "BC_TEST_GIT_CHECKOUT": str(checkout),
        },
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_setup_guard_rejects_chromium_git_worktree_override(tmp_path: Path) -> None:
    powershell = shutil.which("pwsh")
    git = shutil.which("git.exe")
    if os.name != "nt" or powershell is None or git is None:
        pytest.skip("Windows Git worktree guard")
    checkout = tmp_path / "chromium"
    foreign = tmp_path / "foreign"
    checkout.mkdir()
    foreign.mkdir()
    subprocess.run([git, "init", "-q", str(checkout)], check=True, capture_output=True)
    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_GIT_HOOK_HELPER
        Invoke-BrowserCoreGitEnvironment {
            Assert-BrowserCoreNoGitWorktreeOverride $env:BC_TEST_GIT_CHECKOUT $env:BC_TEST_GIT_EXE
        }
        & $env:BC_TEST_GIT_EXE -C $env:BC_TEST_GIT_CHECKOUT config core.worktree $env:BC_TEST_GIT_FOREIGN
        if ($LASTEXITCODE -ne 0) { throw 'failed to set a conflicting worktree' }
        $rejected = $false
        try {
            Invoke-BrowserCoreGitEnvironment {
                Assert-BrowserCoreNoGitWorktreeOverride $env:BC_TEST_GIT_CHECKOUT $env:BC_TEST_GIT_EXE
            }
        } catch {
            if ($_.Exception.Message -notlike '*core.worktree override*') { throw }
            $rejected = $true
        }
        if (-not $rejected) { throw 'conflicting worktree was accepted' }
        exit 0
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env={
            **os.environ,
            "BC_TEST_GIT_HOOK_HELPER": str(ROOT / "scripts" / "git-hooks.ps1"),
            "BC_TEST_GIT_EXE": git,
            "BC_TEST_GIT_CHECKOUT": str(checkout),
            "BC_TEST_GIT_FOREIGN": str(foreign),
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("holder_shell", ["pwsh", "powershell.exe"])
def test_workspace_mutation_lock_blocks_a_second_process_and_releases(
    tmp_path: Path, holder_shell: str,
) -> None:
    powershell = shutil.which("pwsh")
    holder_powershell = shutil.which(holder_shell)
    if os.name != "nt" or powershell is None or holder_powershell is None:
        pytest.skip("Windows setup workspace mutex")
    workspace = tmp_path / "workspace"
    marker = tmp_path / "owned.txt"
    environment = {
        **os.environ,
        "BC_TEST_LOCK_HELPER": str(ROOT / "scripts" / "workspace-lock.ps1"),
        "BC_TEST_LOCK_WORKSPACE": str(workspace),
        "BC_TEST_LOCK_MARKER": str(marker),
        "BROWSER_CORE_WORKSPACE": str(workspace),
    }
    holder_script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_LOCK_HELPER
        $mutex = Enter-BrowserCoreWorkspaceMutation $env:BC_TEST_LOCK_WORKSPACE
        try {
            [System.IO.File]::WriteAllText($env:BC_TEST_LOCK_MARKER, 'owned')
            [void][Console]::ReadLine()
        } finally { Exit-BrowserCoreWorkspaceMutation $mutex }
    """
    holder_command = [holder_powershell, "-NoProfile", "-NonInteractive"]
    if holder_shell == "powershell.exe":
        holder_command.extend(["-ExecutionPolicy", "Bypass"])
    holder = subprocess.Popen(
        [*holder_command, "-Command", holder_script],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and holder.poll() is None and time.monotonic() < deadline:
            time.sleep(0.025)
        assert marker.exists(), holder.communicate(timeout=1)[1] if holder.poll() is not None else "mutex holder did not start"
        contender_script = r"""
            $ErrorActionPreference = 'Stop'
            . $env:BC_TEST_LOCK_HELPER
            $other = Enter-BrowserCoreWorkspaceMutation ($env:BC_TEST_LOCK_WORKSPACE + '-other')
            Exit-BrowserCoreWorkspaceMutation $other
            $rejected = $false
            try {
                $same = Enter-BrowserCoreWorkspaceMutation $env:BC_TEST_LOCK_WORKSPACE
                Exit-BrowserCoreWorkspaceMutation $same
            } catch {
                if ($_.Exception.Message -notlike '*already owns this workspace*') { throw }
                $rejected = $true
            }
            if (-not $rejected) { throw 'second process acquired the same workspace' }
            $caseAliasRejected = $false
            try {
                $alias = Enter-BrowserCoreWorkspaceMutation $env:BC_TEST_LOCK_WORKSPACE.ToUpperInvariant()
                Exit-BrowserCoreWorkspaceMutation $alias
            } catch {
                if ($_.Exception.Message -notlike '*already owns this workspace*') { throw }
                $caseAliasRejected = $true
            }
            if (-not $caseAliasRejected) { throw 'case alias acquired the same workspace' }
        """
        contender = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", contender_script],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert contender.returncode == 0, contender.stderr
        blocked_apply = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-File", str(ROOT / "scripts" / "apply-patches.ps1")],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert blocked_apply.returncode != 0
        assert "Another Browser Core operation already owns this workspace" in blocked_apply.stderr
    finally:
        if holder.poll() is None:
            assert holder.stdin is not None
            holder.stdin.write("\n")
            holder.stdin.flush()
        try:
            holder_stdout, holder_stderr = holder.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder_stdout, holder_stderr = holder.communicate(timeout=5)
        assert holder.returncode == 0, (holder_stdout, holder_stderr)
    released = subprocess.run(
        [
            powershell, "-NoProfile", "-NonInteractive", "-Command",
            ". $env:BC_TEST_LOCK_HELPER; $m = Enter-BrowserCoreWorkspaceMutation $env:BC_TEST_LOCK_WORKSPACE; Exit-BrowserCoreWorkspaceMutation $m",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert released.returncode == 0, released.stderr


@pytest.mark.parametrize("script_name", ["bootstrap.ps1", "build.ps1", "apply-patches.ps1"])
def test_setup_scripts_share_the_workspace_mutation_lock(script_name: str) -> None:
    source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
    assert '. (Join-Path $PSScriptRoot "workspace-lock.ps1")' in source
    assert "$mutex = Enter-BrowserCoreWorkspaceMutation $workspace" in source
    assert "Exit-BrowserCoreWorkspaceMutation $mutex" in source
    first_operation = {
        "bootstrap.ps1": "New-Item -ItemType Directory -Force -Path $workspace",
        "build.ps1": "$sourceStateBefore =",
        "apply-patches.ps1": "-m browser_core patches apply --checkout $checkout",
    }[script_name]
    assert source.index("$mutex = Enter-BrowserCoreWorkspaceMutation $workspace") < source.index(first_operation)


@pytest.mark.parametrize("script_name", ["bootstrap.ps1", "build.ps1"])
def test_setup_scripts_restore_process_tool_environment(script_name: str) -> None:
    source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
    for name in ("PATH", "DEPOT_TOOLS_WIN_TOOLCHAIN", "DEPOT_TOOLS_UPDATE"):
        assert f"GetEnvironmentVariable('{name}')" in source
        assert f"Restore-BrowserCoreEnvironmentVariable '{name}' $previous{name.title().replace('_', '')}" in source
    if script_name == "build.ps1":
        assert "GetEnvironmentVariable('vs2026_install')" in source
        assert "Restore-BrowserCoreEnvironmentVariable 'vs2026_install' $previousVs2026Install" in source


def test_build_script_preserves_pythonpath_on_early_workspace_rejection() -> None:
    powershell = shutil.which("pwsh")
    if os.name != "nt" or powershell is None:
        pytest.skip("Windows PowerShell build environment check")
    script = r"""
        $ErrorActionPreference = 'Stop'
        $env:BROWSER_CORE_WORKSPACE = 'relative'
        $env:PYTHONPATH = 'caller-value'
        try {
            & $env:BC_TEST_BUILD_SCRIPT
            throw 'invalid workspace was accepted'
        } catch {
            if ($_.Exception.Message -notlike 'BROWSER_CORE_WORKSPACE must*') { throw }
        }
        if ($env:PYTHONPATH -ne 'caller-value') {
            throw 'build changed the caller Python search path'
        }
        exit 0
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env={**os.environ, "BC_TEST_BUILD_SCRIPT": str(ROOT / "scripts" / "build.ps1")},
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr


def test_build_script_restores_environment_after_visual_studio_preflight_failure(
    tmp_path: Path,
) -> None:
    powershell = shutil.which("pwsh")
    if os.name != "nt" or powershell is None:
        pytest.skip("Windows PowerShell build environment check")
    workspace = tmp_path / "workspace"
    (workspace / "chromium" / "src" / ".git").mkdir(parents=True)
    script = r"""
        $ErrorActionPreference = 'Stop'
        ${env:ProgramFiles(x86)} = $env:BC_TEST_MISSING_PROGRAM_FILES
        $names = @(
            'PATH', 'DEPOT_TOOLS_WIN_TOOLCHAIN', 'DEPOT_TOOLS_UPDATE',
            'vs2026_install', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_COUNT'
        )
        $before = @{}
        foreach ($name in $names) { $before[$name] = [Environment]::GetEnvironmentVariable($name) }
        try {
            & $env:BC_TEST_BUILD_SCRIPT
            throw 'missing Visual Studio locator was accepted'
        } catch {
            if ($_.Exception.Message -notlike 'Visual Studio locator is missing:*') { throw }
        }
        foreach ($name in $names) {
            if ([Environment]::GetEnvironmentVariable($name) -cne $before[$name]) {
                throw "build changed caller environment: $name"
            }
        }
        exit 0
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env={
            **os.environ,
            "BC_TEST_BUILD_SCRIPT": str(ROOT / "scripts" / "build.ps1"),
            "BROWSER_CORE_WORKSPACE": str(workspace),
            "BC_TEST_MISSING_PROGRAM_FILES": str(tmp_path / "missing-program-files"),
            "DEPOT_TOOLS_WIN_TOOLCHAIN": "caller-toolchain",
            "DEPOT_TOOLS_UPDATE": "caller-update",
            "vs2026_install": "caller-vs",
            "GIT_DIR": str(tmp_path / "foreign" / ".git"),
            "GIT_WORK_TREE": str(tmp_path / "foreign"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(tmp_path / "foreign" / "hooks"),
        },
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr


def test_apply_script_removes_absent_git_selection_after_preflight_failure(
    tmp_path: Path,
) -> None:
    powershell = shutil.which("pwsh")
    if os.name != "nt" or powershell is None:
        pytest.skip("Windows PowerShell patch environment check")
    workspace = tmp_path / "unused-workspace"
    environment = {
        **os.environ,
        "BC_TEST_APPLY_SCRIPT": str(ROOT / "scripts" / "apply-patches.ps1"),
        "BC_TEST_LOCK_HELPER": str(ROOT / "scripts" / "workspace-lock.ps1"),
        "BROWSER_CORE_WORKSPACE": str(workspace),
        "GIT_DIR": str(tmp_path / "foreign" / ".git"),
    }
    script = r"""
        $ErrorActionPreference = 'Stop'
        Remove-Item Env:BROWSER_CORE_GIT_EXE -ErrorAction SilentlyContinue
        $savedGitDir = $env:GIT_DIR
        try {
            & $env:BC_TEST_APPLY_SCRIPT | Out-Null
            throw 'missing checkout was accepted'
        } catch {
            if ($_.Exception.Message -notlike 'Patch preflight failed*') { throw }
        }
        if ([Environment]::GetEnvironmentVariables().Contains('BROWSER_CORE_GIT_EXE')) {
            throw 'absent Git selection was restored as an empty variable'
        }
        if ($env:GIT_DIR -ne $savedGitDir) { throw 'caller Git environment changed' }
        exit 0
    """
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    released = subprocess.run(
        [
            powershell, "-NoProfile", "-NonInteractive", "-Command",
            ". $env:BC_TEST_LOCK_HELPER; $m = Enter-BrowserCoreWorkspaceMutation $env:BROWSER_CORE_WORKSPACE; Exit-BrowserCoreWorkspaceMutation $m",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert released.returncode == 0, released.stderr


def test_workspace_script_rejects_repository_and_relative_paths() -> None:
    powershell = shutil.which("pwsh")
    if os.name != "nt" or powershell is None:
        pytest.skip("Windows PowerShell workspace path check")
    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_WORKSPACE_HELPER
        $repo = $env:BC_TEST_REPO
        $invalid = @(
            'relative\bc',
            'C:relative',
            $repo,
            ($repo + ':stream'),
            ($repo + '*wildcard'),
            (Join-Path $repo 'scratch'),
            (Split-Path $repo),
            [System.IO.Path]::GetPathRoot($repo)
        )
        foreach ($candidate in $invalid) {
            $rejected = $false
            try {
                Get-BrowserCoreWorkspacePath -RawPath $candidate -RepositoryRoot $repo | Out-Null
            } catch { $rejected = $true }
            if (-not $rejected) { throw 'Accepted an unsafe workspace path.' }
        }
        $outside = Join-Path ([System.IO.Path]::GetPathRoot($repo)) 'browser-core-external-test'
        $accepted = Get-BrowserCoreWorkspacePath -RawPath $outside -RepositoryRoot $repo
        if ($accepted -ne $outside) { throw 'Rejected an absolute external workspace path.' }
    """
    environment = {
        **os.environ,
        "BC_TEST_WORKSPACE_HELPER": str(ROOT / "scripts" / "workspace-path.ps1"),
        "BC_TEST_REPO": str(ROOT),
    }
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_workspace_script_rejects_junction_into_repository() -> None:
    powershell = shutil.which("pwsh")
    if os.name != "nt" or powershell is None:
        pytest.skip("Windows PowerShell workspace path check")
    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_WORKSPACE_HELPER
        $repo = $env:BC_TEST_REPO
        $tempRoot = [System.IO.Path]::GetTempPath()
        $probe = Join-Path $tempRoot ('browser-core-workspace-link-' + [guid]::NewGuid().ToString('N'))
        if (-not $probe.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Unexpected workspace test location.'
        }
        New-Item -ItemType Directory -Path $probe | Out-Null
        try {
            $alias = Join-Path $probe 'alias'
            New-Item -ItemType Junction -Path $alias -Target $repo | Out-Null
            foreach ($candidate in @($alias, (Join-Path $alias 'scripts'))) {
                $rejected = $false
                try {
                    Get-BrowserCoreWorkspacePath -RawPath $candidate -RepositoryRoot $repo | Out-Null
                } catch { $rejected = $true }
                if (-not $rejected) { throw 'Accepted a linked workspace path into the repository.' }
            }
        } finally {
            $alias = Join-Path $probe 'alias'
            if (Test-Path -LiteralPath $alias) { Remove-Item -LiteralPath $alias -Force }
            Remove-Item -LiteralPath $probe -Force
        }
    """
    environment = {
        **os.environ,
        "BC_TEST_WORKSPACE_HELPER": str(ROOT / "scripts" / "workspace-path.ps1"),
        "BC_TEST_REPO": str(ROOT),
    }
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_workspace_script_rejects_windows_normalized_repository_aliases() -> None:
    powershell = shutil.which("pwsh")
    if os.name != "nt" or powershell is None:
        pytest.skip("Windows PowerShell workspace path check")
    script = r"""
        $ErrorActionPreference = 'Stop'
        . $env:BC_TEST_WORKSPACE_HELPER
        $repo = $env:BC_TEST_REPO
        foreach ($candidate in @(($repo + ' \scratch'), ($repo + '..\scratch'))) {
            $parent = Split-Path $candidate
            if ((Get-Item -LiteralPath $parent).FullName -ne $repo) {
                throw 'The Windows path alias fixture did not resolve to the repository.'
            }
            $rejected = $false
            try {
                Get-BrowserCoreWorkspacePath -RawPath $candidate -RepositoryRoot $repo | Out-Null
            } catch { $rejected = $true }
            if (-not $rejected) { throw 'Accepted a normalized alias into the repository.' }
        }
    """
    environment = {
        **os.environ,
        "BC_TEST_WORKSPACE_HELPER": str(ROOT / "scripts" / "workspace-path.ps1"),
        "BC_TEST_REPO": str(ROOT),
    }
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_build_attest_cli_forwards_loaded_manifest_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import browser_core.cli as cli

    observed: dict[str, object] = {}

    def attest(
        root: Path, workspace: Path, executable: Path, *,
        expected_manifest_sha256: str, git_executable: Path | None,
    ) -> dict:
        observed.update(
            root=root,
            workspace=workspace,
            executable=executable,
            expected_manifest_sha256=expected_manifest_sha256,
            git_executable=git_executable,
        )
        return {'schema': 'test/1'}

    monkeypatch.setattr(cli, 'create_build_attestation', attest)
    digest = 'a' * 64
    executable = tmp_path / 'chrome.exe'
    git_executable = tmp_path / 'git.exe'
    assert cli.main([
        'build', 'attest', '--workspace', str(tmp_path),
        '--executable', str(executable), '--expected-manifest-sha256', digest,
        '--git-executable', str(git_executable),
    ]) == 0
    assert json.loads(capsys.readouterr().out) == {'schema': 'test/1'}
    assert observed['workspace'] == tmp_path
    assert observed['executable'] == executable
    assert observed['expected_manifest_sha256'] == digest
    assert observed['git_executable'] == git_executable


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_build_attest_cli_preserves_selected_executable_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    import browser_core.cli as cli

    physical_runtime = tmp_path / "physical-runtime"
    physical_runtime.mkdir()
    (physical_runtime / "chrome.exe").write_bytes(b"fixture")
    selected_runtime = tmp_path / "selected-runtime"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_runtime), str(physical_runtime)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    observed: list[Path] = []

    def attest(_root: Path, _workspace: Path, executable: Path, **_kwargs: object) -> dict:
        observed.append(executable)
        return {"schema": "test/1"}

    monkeypatch.setattr(cli, "create_build_attestation", attest)
    selected_executable = selected_runtime / "chrome.exe"
    try:
        assert cli.main([
            "build", "attest", "--workspace", str(tmp_path),
            "--executable", str(selected_executable),
        ]) == 0
        assert observed == [selected_executable]
        assert json.loads(capsys.readouterr().out) == {"schema": "test/1"}
    finally:
        selected_runtime.rmdir()


def test_unattested_executable_fails_closed(tmp_path: Path) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"stock-control")
    with pytest.raises(ContractError, match="not a verified Browser Core build"):
        executable_evidence(ROOT, executable, allow_unverified=False)
    evidence = executable_evidence(ROOT, executable, allow_unverified=True)
    assert evidence == {
        "provenance": "unverified-external",
        "executable_sha256_16": hashlib.sha256(b"stock-control").hexdigest()[:16],
    }


@pytest.mark.parametrize("allow_unverified", ["false", 1, None])
def test_unverified_control_requires_boolean_opt_in(
    tmp_path: Path, allow_unverified: object,
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"stock-control")
    with pytest.raises(ContractError, match="unverified executable opt-in must be boolean"):
        executable_evidence(ROOT, executable, allow_unverified=allow_unverified)


@pytest.mark.parametrize("executable", [None, "chrome.exe"])
def test_executable_evidence_rejects_non_path_input(executable: object) -> None:
    with pytest.raises(ContractError, match="build executable path must be a Path"):
        executable_evidence(ROOT, executable, allow_unverified=True)


def test_executable_evidence_rejects_invalid_path_input() -> None:
    with pytest.raises(ContractError, match="build executable path is invalid"):
        executable_evidence(ROOT, Path("C:\\bad\x00chrome.exe"), allow_unverified=True)


@pytest.mark.parametrize("entrypoint", ["create-root", "create-workspace", "load-root", "load-executable"])
def test_build_attestation_entrypoints_reject_embedded_nul_paths(entrypoint: str) -> None:
    bad_root = Path("C:\\bad\x00package")
    bad_workspace = Path("C:\\bad\x00workspace")
    bad_executable = Path("C:\\bad\x00folder\\chrome.exe")
    with pytest.raises(ContractError, match="path is invalid"):
        if entrypoint == "create-root":
            build_module.create_build_attestation(bad_root, ROOT, ROOT / "chrome.exe")
        elif entrypoint == "create-workspace":
            build_module.create_build_attestation(ROOT, bad_workspace, ROOT / "chrome.exe")
        elif entrypoint == "load-root":
            load_build_attestation(bad_root, ROOT / "chrome.exe")
        else:
            load_build_attestation(ROOT, bad_executable)


@pytest.mark.parametrize("change", ["runtime", "receipt"])
def test_unverified_control_cannot_relabel_invalid_attested_build(
    tmp_path: Path, change: str,
) -> None:
    executable, receipt_path, _document = _write_fixture_attestation(tmp_path)
    if change == "runtime":
        (tmp_path / "chrome.dll").write_bytes(b"changed-runtime")
    else:
        receipt_path.write_bytes(b"{broken")

    with pytest.raises(ContractError, match="cannot classify executable as an unverified external control"):
        executable_evidence(ROOT, executable, allow_unverified=True)


def test_attestation_detects_binary_tampering(tmp_path: Path) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"verified")
    chrome_dll = tmp_path / "chrome.dll"
    chrome_dll.write_bytes(b"patched-runtime")
    trace_processor = tmp_path / "trace_processor_shell.exe"
    trace_processor.write_bytes(b"trace-processor")
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    artifacts = [
        {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in (executable, chrome_dll, trace_processor)
    ]
    attestation = {
        "schema": "browser-core.build/3",
        "created_at": "2026-08-02T00:00:00Z",
        "chromium_revision": manifest["chromium"]["revision"],
        "depot_tools_revision": manifest["depot_tools"]["revision"],
        "executable": executable.name,
        "executable_sha256": hashlib.sha256(b"verified").hexdigest(),
        "runtime_artifacts": artifacts,
        "runtime_bundle_sha256": hashlib.sha256(
            json.dumps(artifacts, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "patch_series_sha256": patch_series_digest(ROOT),
        "patched_sources_sha256": "0" * 64,
        "gn_args_sha256": hashlib.sha256(
            json.dumps(
                manifest["build"]["gn_args"], separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest(),
    }
    (tmp_path / "browser-core-build.json").write_text(json.dumps(attestation), encoding="utf-8")
    assert load_build_attestation(ROOT, executable)["executable_sha256"] == attestation["executable_sha256"]
    attestation["patch_series_sha256"] = "0" * 64
    (tmp_path / "browser-core-build.json").write_text(json.dumps(attestation), encoding="utf-8")
    with pytest.raises(ContractError, match="patch series"):
        load_build_attestation(ROOT, executable)
    attestation["patch_series_sha256"] = patch_series_digest(ROOT)
    (tmp_path / "browser-core-build.json").write_text(json.dumps(attestation), encoding="utf-8")
    executable.write_bytes(b"tampered")
    with pytest.raises(ContractError, match="hash"):
        load_build_attestation(ROOT, executable)


def test_attestation_detects_runtime_dll_tampering(tmp_path: Path) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"verified")
    chrome_dll = tmp_path / "chrome.dll"
    chrome_dll.write_bytes(b"patched-runtime")
    trace_processor = tmp_path / "trace_processor_shell.exe"
    trace_processor.write_bytes(b"trace-processor")
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    artifacts = [
        {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in (executable, chrome_dll, trace_processor)
    ]
    attestation = {
        "schema": "browser-core.build/3",
        "created_at": "2026-08-03T00:00:00Z",
        "chromium_revision": manifest["chromium"]["revision"],
        "depot_tools_revision": manifest["depot_tools"]["revision"],
        "executable": executable.name,
        "executable_sha256": artifacts[0]["sha256"],
        "runtime_artifacts": artifacts,
        "runtime_bundle_sha256": hashlib.sha256(
            json.dumps(artifacts, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "patch_series_sha256": patch_series_digest(ROOT),
        "patched_sources_sha256": "0" * 64,
        "gn_args_sha256": hashlib.sha256(
            json.dumps(manifest["build"]["gn_args"], separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest(),
    }
    (tmp_path / "browser-core-build.json").write_text(json.dumps(attestation), encoding="utf-8")
    assert load_build_attestation(ROOT, executable)["runtime_bundle_sha256"]
    chrome_dll.write_bytes(b"tampered-runtime")
    with pytest.raises(ContractError, match="chrome.dll"):
        load_build_attestation(ROOT, executable)


def test_attested_evidence_names_the_runtime_bundle(tmp_path: Path) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"verified")
    chrome_dll = tmp_path / "chrome.dll"
    chrome_dll.write_bytes(b"patched-runtime")
    trace_processor = tmp_path / "trace_processor_shell.exe"
    trace_processor.write_bytes(b"trace-processor")
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    artifacts = [
        {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in (executable, chrome_dll, trace_processor)
    ]
    bundle_digest = hashlib.sha256(
        json.dumps(artifacts, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    attestation = {
        "schema": "browser-core.build/3",
        "created_at": "2026-08-03T00:00:00Z",
        "chromium_revision": manifest["chromium"]["revision"],
        "depot_tools_revision": manifest["depot_tools"]["revision"],
        "executable": executable.name,
        "executable_sha256": artifacts[0]["sha256"],
        "runtime_artifacts": artifacts,
        "runtime_bundle_sha256": bundle_digest,
        "patch_series_sha256": patch_series_digest(ROOT),
        "patched_sources_sha256": "0" * 64,
        "gn_args_sha256": hashlib.sha256(
            json.dumps(manifest["build"]["gn_args"], separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
        ).hexdigest(),
    }
    (tmp_path / "browser-core-build.json").write_text(json.dumps(attestation), encoding="utf-8")

    evidence = executable_evidence(ROOT, executable, allow_unverified=False)
    assert evidence["runtime_bundle_sha256_16"] == bundle_digest[:16]


@pytest.mark.parametrize("nested", [False, True])
def test_build_attestation_rejects_uninterpreted_fields(
    tmp_path: Path,
    nested: bool,
) -> None:
    executable, path, document = _write_fixture_attestation(tmp_path)
    if nested:
        document["runtime_artifacts"][1]["download_url"] = "https://private.invalid/"
    else:
        document["operator_notes"] = "private-path"
    path.write_bytes(canonical_json_bytes(document))
    with pytest.raises(ContractError, match="fields are invalid|runtime artifact is invalid"):
        load_build_attestation(ROOT, executable)


def test_build_attestation_requires_aware_timestamp_and_bounded_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, path, document = _write_fixture_attestation(tmp_path)
    document["created_at"] = "2026-08-10T00:00:00"
    path.write_bytes(canonical_json_bytes(document))
    with pytest.raises(ContractError, match="created_at is invalid"):
        load_build_attestation(ROOT, executable)

    monkeypatch.setattr(build_module, "MAX_BUILD_ATTESTATION_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        load_build_attestation(ROOT, executable)


def test_runtime_hash_detects_file_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"first-generation")
    real_lstat = build_module.os.lstat
    calls = 0

    def mutate_before_final_lstat(path: Path) -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            Path(path).write_bytes(b"second-generation")
        return real_lstat(path)

    monkeypatch.setattr(build_module.os, "lstat", mutate_before_final_lstat)
    with pytest.raises(ContractError, match="changed while hashing"):
        build_module._hash_regular_file(executable, label="runtime artifact chrome.exe")


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_runtime_hash_rejects_same_size_edit_with_restored_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"AAAA")
    stamp = executable.stat()
    real_fstat = build_module.os.fstat
    calls = 0

    def write_after_first_pass(descriptor: int):
        nonlocal calls
        calls += 1
        if calls == 2:
            with executable.open("r+b") as writer:
                writer.write(b"BBBB")
            os.utime(executable, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return real_fstat(descriptor)

    monkeypatch.setattr(build_module.os, "fstat", write_after_first_pass)
    with pytest.raises(ContractError, match="changed while hashing"):
        build_module._hash_regular_file(executable, label="runtime artifact chrome.exe")
    assert executable.read_bytes() == b"BBBB"


def test_runtime_hash_is_bounded_single_link_and_path_typed(tmp_path: Path) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"runtime")
    with pytest.raises(ContractError, match="exceeds 3 bytes"):
        build_module._hash_regular_file(
            executable,
            label="runtime artifact chrome.exe",
            maximum=3,
        )
    os.link(executable, tmp_path / "runtime-alias.exe")
    with pytest.raises(ContractError, match="hard links"):
        build_module._hash_regular_file(
            executable,
            label="runtime artifact chrome.exe",
        )
    with pytest.raises(ContractError, match="path must be a Path"):
        build_module._hash_regular_file(  # type: ignore[arg-type]
            str(executable),
            label="runtime artifact chrome.exe",
        )


def test_build_attestation_is_strict_single_link_and_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, path, _document = _write_fixture_attestation(tmp_path)
    original_body = path.read_bytes()
    path.write_bytes(
        original_body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    )
    with pytest.raises(ContractError, match="duplicate key"):
        load_build_attestation(ROOT, executable)

    path.write_bytes(original_body)
    os.link(path, tmp_path / "attestation-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        load_build_attestation(ROOT, executable)
    (tmp_path / "attestation-alias.json").unlink()

    real_read = build_module.read_bounded_control_snapshot_result
    observed = 0

    def replace_after_first_attestation(candidate: Path, **kwargs):
        nonlocal observed
        snapshot = real_read(candidate, **kwargs)
        if Path(candidate) == path:
            observed += 1
            if observed == 1:
                replacement = tmp_path / "same-attestation.json"
                replacement.write_bytes(original_body)
                replacement.replace(path)
        return snapshot

    monkeypatch.setattr(
        build_module,
        "read_bounded_control_snapshot_result",
        replace_after_first_attestation,
    )
    with pytest.raises(ContractError, match="changed during verification"):
        load_build_attestation(ROOT, executable)


def test_build_runtime_artifact_rejects_hard_link_alias(tmp_path: Path) -> None:
    executable, _path, _document = _write_fixture_attestation(tmp_path)
    os.link(executable, tmp_path / "chrome-alias.exe")
    with pytest.raises(ContractError, match="hard links"):
        load_build_attestation(ROOT, executable)


def test_build_attestation_update_preserves_a_racing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _executable, path, document = _write_fixture_attestation(tmp_path)
    competitor = canonical_json_bytes({"schema": "competitor/1"})
    real_replace = build_module.replace_json_conditionally_result

    def inject_then_replace(target: Path, new_document: dict, **kwargs: object) -> None:
        injected = tmp_path / "competitor-attestation.json"
        injected.write_bytes(competitor)
        injected.replace(target)
        real_replace(target, new_document, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(build_module, "replace_json_conditionally_result", inject_then_replace)
    with pytest.raises(ContractError, match="changed before transition"):
        build_module._write_json_atomic(path, document)
    assert path.read_bytes() == competitor


def test_build_attestation_writer_does_not_recreate_missing_runtime_directory(
    tmp_path: Path,
) -> None:
    output = tmp_path / 'removed-runtime'
    path = output / 'browser-core-build.json'
    with pytest.raises(ContractError):
        build_module._write_json_atomic(path, {'schema': 'test/1'})
    assert not output.exists()
