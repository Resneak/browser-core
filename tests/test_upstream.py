from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import browser_core.upstream as upstream_module
from browser_core.bounded_process import BoundedProcessResult
from browser_core.contracts import ContractError
from browser_core.git_executable import decode_portable_git_path, git_blob_sha1
from browser_core.upstream import (
    apply_patch_series,
    verify_patch_series,
    verify_patched_checkout,
    verify_upstream,
)


ROOT = Path(__file__).parents[1]
CHROMIUM_REPOSITORY = "https://chromium.googlesource.com/chromium/src.git"
GCLIENT_HBC = (
    f'solutions = [{{"name": "src", "url": "{CHROMIUM_REPOSITORY}", '
    '"custom_deps": {}, "custom_vars": {}}]\n'
)


def _depot_tools_checkout(tmp_path: Path) -> tuple[Path, str]:
    checkout = tmp_path / "depot_tools"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.email", "fixture@example.test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.name", "Fixture"],
        check=True,
    )
    (checkout / "bootstrap").mkdir()
    (checkout / "bootstrap" / "win_tools.bat").write_text("@echo off\n")
    (checkout / "gclient.bat").write_text("@echo off\n")
    (checkout / "autoninja.bat").write_text("@echo off\n")
    (checkout / ".gitignore").write_text(".bleeding_edge\nignored-runtime/\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "fixture"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return checkout, revision


def test_depot_tools_checkout_verifier_accepts_clean_pin_and_ignored_runtime(tmp_path):
    checkout, revision = _depot_tools_checkout(tmp_path)
    (checkout / "ignored-runtime").mkdir()
    (checkout / "ignored-runtime" / "python.exe").write_bytes(b"downloaded")
    assert upstream_module.verify_depot_tools_checkout(checkout, revision) == {
        "status": "verified",
        "revision": revision,
    }


def test_depot_tools_checkout_rejects_local_commit_replacement(tmp_path: Path) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    wrapper = checkout / "gclient.bat"
    original = wrapper.read_bytes()
    wrapper.write_bytes(b"@echo substituted\n")
    subprocess.run(["git", "-C", str(checkout), "add", "gclient.bat"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "alternate"], check=True)
    alternate = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
    ).decode("ascii").strip()
    subprocess.run(["git", "-C", str(checkout), "reset", "--hard", revision], check=True)
    subprocess.run(["git", "-C", str(checkout), "replace", revision, alternate], check=True)
    subprocess.run(["git", "-C", str(checkout), "reset", "--hard", revision], check=True)
    assert wrapper.read_bytes() != original
    assert subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
    ).decode("ascii").strip() == revision

    with pytest.raises(ContractError, match="tracked inventory differs from HEAD"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_verification_does_not_refresh_git_index(
    tmp_path: Path,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    wrapper = checkout / "gclient.bat"
    stamp = wrapper.stat()
    os.utime(wrapper, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 5_000_000_000))
    index = checkout / ".git" / "index"
    before_body = index.read_bytes()
    before_mtime = index.stat().st_mtime_ns
    assert upstream_module.verify_depot_tools_checkout(checkout, revision)["status"] == "verified"
    assert index.read_bytes() == before_body
    assert index.stat().st_mtime_ns == before_mtime
    (checkout / ".gitignore").write_bytes(b"modified\n")
    with pytest.raises(ContractError, match="tracked content differs from HEAD"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_rejects_hidden_nonwrapper_content_change(tmp_path: Path) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path)
    support = checkout / "support.py"
    support.write_bytes(b"safe\n")
    old_time_ns = 1_600_000_000_000_000_000
    os.utime(support, ns=(old_time_ns, old_time_ns))
    subprocess.run(["git", "-C", str(checkout), "add", "support.py"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "support"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    before = support.stat()
    support.write_bytes(b"evil\n")
    os.utime(support, ns=(before.st_atime_ns, before.st_mtime_ns))
    status = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(checkout), "status", "--porcelain"],
        check=True, capture_output=True,
    )
    assert status.stdout == b"", "fixture did not reproduce Git's stale status cache"
    with pytest.raises(ContractError, match="tracked content"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)
    assert support.read_bytes() == b"evil\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable mode is not available on Windows")
def test_depot_tools_checkout_rejects_tracked_executable_mode_change(tmp_path: Path) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    tracked = checkout / ".gitignore"
    assert not tracked.stat().st_mode & 0o111
    os.chmod(tracked, tracked.stat().st_mode | 0o100)
    assert tracked.stat().st_mode & 0o111

    with pytest.raises(ContractError, match="tracked mode differs from HEAD"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_rejects_repository_clean_filter_without_running_it(
    tmp_path: Path,
) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path)
    tracked = checkout / "tracked.txt"
    tracked.write_bytes(b"unchanged\n")
    (checkout / ".gitattributes").write_text("*.txt filter=observed\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "filter fixture"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    marker = tmp_path / "clean-filter-called.txt"
    command = f"sh -c 'echo invoked >> \"{marker.as_posix()}\"; cat'"
    subprocess.run(
        ["git", "-C", str(checkout), "config", "filter.observed.clean", command],
        check=True,
    )
    before = tracked.stat()
    tracked.write_bytes(b"unchanged\n")
    os.utime(tracked, ns=(before.st_atime_ns, before.st_mtime_ns + 5_000_000_000))
    subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain"],
        check=True, capture_output=True,
    )
    assert marker.exists(), "fixture clean filter did not run"
    marker.unlink()
    with pytest.raises(ContractError, match="tracked filter is not allowed"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)
    assert not marker.exists()


def test_depot_tools_checkout_rejects_ambiguous_unset_filter_attribute(
    tmp_path: Path,
) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path)
    tracked = checkout / "tracked.txt"
    tracked.write_bytes(b"unchanged\n")
    (checkout / ".gitattributes").write_text("*.txt filter=unset\n", encoding="ascii")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "filter fixture"], check=True)
    revision = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
    ).decode("ascii").strip()
    marker = tmp_path / "unset-filter-called.txt"
    subprocess.run([
        "git", "-C", str(checkout), "config", "filter.unset.clean",
        f"sh -c 'echo invoked >> \"{marker.as_posix()}\"; cat'",
    ], check=True)
    before = tracked.stat()
    tracked.write_bytes(b"unchanged\n")
    os.utime(tracked, ns=(before.st_atime_ns, before.st_mtime_ns + 5_000_000_000))
    attribute = subprocess.check_output([
        "git", "-C", str(checkout), "check-attr", "--cached", "-z",
        "filter", "--", "tracked.txt",
    ])
    assert attribute == b"tracked.txt\0filter\0unset\0"
    subprocess.run(
        ["git", "-C", str(checkout), "diff", "--name-only", "HEAD", "--"],
        check=True, capture_output=True,
    )
    assert marker.exists(), "fixture named filter did not run"
    marker.unlink()

    with pytest.raises(ContractError, match="tracked filter is not allowed"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)
    assert not marker.exists()


def test_depot_tools_checkout_rejects_crlf_alias_for_binary_attribute(tmp_path: Path) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path)
    (checkout / ".gitattributes").write_bytes(b"*.txt -text\n")
    source = checkout / "tracked.txt"
    source.write_bytes(b"first\nsecond\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "binary attribute"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "core.autocrlf", "true"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    source.write_bytes(b"first\r\nsecond\r\n")
    with pytest.raises(ContractError, match="tracked content differs from HEAD"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_checks_batched_crlf_attributes(tmp_path: Path) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path)
    subprocess.run(["git", "-C", str(checkout), "config", "core.autocrlf", "true"], check=True)
    files = [checkout / f"support-{number:02d}.txt" for number in range(70)]
    for path in files:
        path.write_bytes(b"first\nsecond\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "text files"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    for path in files:
        path.write_bytes(b"first\r\nsecond\r\n")
    assert upstream_module.verify_depot_tools_checkout(checkout, revision)["status"] == "verified"


@pytest.mark.parametrize("raw", [
    b"", b"../source", b"nested//source", b"nested/./source", b"nested/../source",
    b"nested\\source", b"file:stream", b"CON.txt", b"name./file", b"name ",
    b'name"quote', b"name\x1f", b"invalid\xff", b"name\x00tail",
])
def test_portable_git_path_rejects_unsafe_names(raw: bytes) -> None:
    with pytest.raises(ContractError, match="Git path is invalid"):
        decode_portable_git_path(raw)


def test_git_blob_hash_and_portable_path_are_literal() -> None:
    assert git_blob_sha1(b"test\n") == "9daeafb9864cf43055ae93beb0afd6c7d144bfa4"
    assert decode_portable_git_path("docs/caf\u00e9.txt".encode("utf-8")) == (
        "docs", "caf\u00e9.txt",
    )
    with pytest.raises(ContractError, match="blob body"):
        git_blob_sha1("test\n")  # type: ignore[arg-type]


def test_depot_tools_checkout_bounds_total_tracked_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    monkeypatch.setattr(upstream_module, "MAX_DEPOT_TRACKED_BYTES", 1)
    with pytest.raises(ContractError, match="tracked file exceeds 1 bytes"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_rejects_casefold_alias_in_head_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    real_run = upstream_module.run_with_bounded_stdout

    def duplicate_head_name(command, **kwargs):
        result = real_run(command, **kwargs)
        if command[-4:] == ["ls-tree", "-r", "-z", "HEAD"]:
            original = next(
                record for record in result.stdout.split(b"\0")
                if record.endswith(b"\tgclient.bat")
            )
            return BoundedProcessResult(
                returncode=0,
                stdout=result.stdout + original.replace(b"\tgclient.bat", b"\tGCLIENT.BAT") + b"\0",
            )
        return result

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", duplicate_head_name)
    with pytest.raises(ContractError, match="tracked inventory is invalid"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


@pytest.mark.skipif(os.name != "nt", reason="Windows materializes Git symlinks as payload files")
def test_depot_tools_checkout_accepts_nonreparse_git_symlink_payload(tmp_path: Path) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path)
    payload = b"gclient.bat"
    placeholder = checkout / "gerrit"
    placeholder.write_bytes(payload)
    object_id = subprocess.run(
        ["git", "-C", str(checkout), "hash-object", "-w", "--stdin"],
        input=payload, capture_output=True, check=True,
    ).stdout.decode("ascii").strip()
    subprocess.run(
        ["git", "-C", str(checkout), "update-index", "--add", "--cacheinfo",
         f"120000,{object_id},gerrit"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "core.symlinks", "false"], check=True,
    )
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "link payload"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert upstream_module.verify_depot_tools_checkout(checkout, revision)["status"] == "verified"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_depot_tools_checkout_rejects_tracked_parent_junction(tmp_path: Path) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path)
    tracked_directory = checkout / "library"
    tracked_directory.mkdir()
    (tracked_directory / "support.py").write_bytes(b"trusted\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "library"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    tracked_directory.rename(tmp_path / "held-library")
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "support.py").write_bytes(b"trusted\n")
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(tracked_directory), str(foreign)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            upstream_module.verify_depot_tools_checkout(checkout, revision)
        assert (foreign / "support.py").read_bytes() == b"trusted\n"
    finally:
        tracked_directory.rmdir()


def test_depot_tools_checkout_rejects_same_size_wrapper_change_hidden_by_git_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    wrapper = checkout / "gclient.bat"
    before = wrapper.stat()
    original = wrapper.read_bytes()
    changed = original.replace(b"off", b"bad")
    assert changed != original and len(changed) == len(original)
    wrapper.write_bytes(changed)
    os.utime(wrapper, ns=(before.st_atime_ns, before.st_mtime_ns))
    real_run = upstream_module.run_with_bounded_stdout

    def stale_status(command, **kwargs):
        if "status" in command:
            return BoundedProcessResult(returncode=0, stdout=b"")
        return real_run(command, **kwargs)

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", stale_status)
    with pytest.raises(ContractError, match="wrapper"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_accepts_expected_lf_to_crlf_wrapper_conversion(
    tmp_path: Path,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "core.autocrlf", "true"], check=True,
    )
    for relative in ("bootstrap/win_tools.bat", "gclient.bat", "autoninja.bat"):
        wrapper = checkout / relative
        lf = wrapper.read_bytes().replace(b"\r\n", b"\n")
        wrapper.write_bytes(lf.replace(b"\n", b"\r\n"))
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1"],
        capture_output=True, check=True,
    )
    assert status.stdout == b""
    assert upstream_module.verify_depot_tools_checkout(checkout, revision)["status"] == "verified"


def test_depot_tools_checkout_bounds_wrapper_reads_even_if_status_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    (checkout / "gclient.bat").write_bytes(b"x" * (upstream_module.MAX_DEPOT_WRAPPER_BYTES + 1))
    real_run = upstream_module.run_with_bounded_stdout

    def stale_status(command, **kwargs):
        if "status" in command:
            return BoundedProcessResult(returncode=0, stdout=b"")
        return real_run(command, **kwargs)

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", stale_status)
    with pytest.raises(ContractError, match="byte limit"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_rejects_nonregular_wrapper_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    wrapper = checkout / "gclient.bat"
    wrapper.unlink()
    wrapper.mkdir()
    real_run = upstream_module.run_with_bounded_stdout
    real_open = Path.open

    def stale_status(command, **kwargs):
        if "status" in command:
            return BoundedProcessResult(returncode=0, stdout=b"")
        return real_run(command, **kwargs)

    def forbid_nonregular_open(path, *args, **kwargs):
        if path == wrapper:
            raise AssertionError("nonregular wrapper was opened")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", stale_status)
    monkeypatch.setattr(Path, "open", forbid_nonregular_open)
    with pytest.raises(ContractError, match="wrapper is irregular"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_rechecks_wrapper_bytes_after_final_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    wrapper = checkout / "autoninja.bat"
    real_run = upstream_module.run_with_bounded_stdout
    head_checks = 0

    def change_after_final_head(command, **kwargs):
        nonlocal head_checks
        if "status" in command:
            return BoundedProcessResult(returncode=0, stdout=b"")
        result = real_run(command, **kwargs)
        if command[-3:] == ["rev-parse", "--verify", "HEAD"]:
            head_checks += 1
            if head_checks == 2:
                before = wrapper.stat()
                wrapper.write_bytes(wrapper.read_bytes().replace(b"off", b"bad"))
                os.utime(wrapper, ns=(before.st_atime_ns, before.st_mtime_ns))
        return result

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", change_after_final_head)
    with pytest.raises(ContractError, match="wrapper"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)
    assert head_checks == 2
    assert b"bad" in wrapper.read_bytes()


def test_depot_tools_checkout_rechecks_worktree_config_after_final_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    real_run = upstream_module.run_with_bounded_stdout
    head_checks = 0

    def change_config_after_final_head(command, **kwargs):
        nonlocal head_checks
        result = real_run(command, **kwargs)
        if command[-3:] == ["rev-parse", "--verify", "HEAD"]:
            head_checks += 1
            if head_checks == 2:
                subprocess.run(
                    ["git", "-C", str(checkout), "config", "core.worktree", str(foreign)],
                    check=True,
                )
        return result

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", change_config_after_final_head)
    with pytest.raises(ContractError, match="core.worktree"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)
    assert head_checks == 2


def test_depot_tools_checkout_uses_an_absolute_selected_git_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    git_executable = Path(shutil.which("git.exe") or "")
    assert git_executable.is_absolute()
    monkeypatch.setenv("BROWSER_CORE_GIT_EXE", str(git_executable))
    original = upstream_module.run_with_bounded_stdout
    launched: list[str] = []

    def capture_selected_git(command, **kwargs):
        launched.append(command[0])
        return original(command, **kwargs)

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", capture_selected_git)
    upstream_module.verify_depot_tools_checkout(checkout, revision)
    assert launched and set(launched) == {str(git_executable)}


def test_depot_tools_checkout_rejects_invalid_git_environment_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    monkeypatch.setenv("BROWSER_CORE_GIT_EXE", str(checkout / "git.bat"))
    with pytest.raises(ContractError, match="Git executable"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_rejects_selected_git_inside_checkout(
    tmp_path: Path,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    ignored_bin = checkout / "ignored-runtime"
    ignored_bin.mkdir()
    copied_git = ignored_bin / "git.exe"
    shutil.copyfile(shutil.which("git.exe"), copied_git)
    with pytest.raises(ContractError, match="Git executable"):
        upstream_module.verify_depot_tools_checkout(
            checkout, revision, git_executable=copied_git,
        )


def test_git_selector_rejects_hard_linked_executable(tmp_path: Path) -> None:
    source = Path(shutil.which("git.exe") or "")
    copied_git = tmp_path / "git.exe"
    shutil.copyfile(source, copied_git)
    os.link(copied_git, tmp_path / "git-alias.exe")
    with pytest.raises(ContractError, match="single-link"):
        upstream_module.select_git_executable(copied_git)


def test_git_selector_rejects_invalid_leaf_without_raw_filesystem_error(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "invalid\x00parent" / "git.exe"
    with pytest.raises(ContractError, match="Git executable"):
        upstream_module.select_git_executable(malformed)


def test_depot_tools_checkout_rejects_dirty_wrapper_after_detach(tmp_path):
    checkout, revision = _depot_tools_checkout(tmp_path)
    (checkout / "gclient.bat").write_text("@echo modified\n")
    subprocess.run(
        ["git", "-C", str(checkout), "checkout", "--detach", "HEAD"],
        check=True,
        capture_output=True,
    )
    with pytest.raises(ContractError, match="required wrapper differs from HEAD"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_rejects_nonignored_untracked_file(tmp_path):
    checkout, revision = _depot_tools_checkout(tmp_path)
    (checkout / "unexpected.bat").write_text("@echo unexpected\n")
    with pytest.raises(ContractError, match="depot_tools checkout has changes"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_rejects_different_head(tmp_path):
    checkout, _revision = _depot_tools_checkout(tmp_path)
    with pytest.raises(ContractError, match="revision does not match pin"):
        upstream_module.verify_depot_tools_checkout(checkout, "0" * 40)


def test_depot_tools_checkout_rejects_inherited_git_repository_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path / "target")
    clean, clean_revision = _depot_tools_checkout(tmp_path / "foreign")
    (checkout / "gclient.bat").write_text("@echo compromised\n")
    monkeypatch.setenv("GIT_DIR", str(clean / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(clean))
    with pytest.raises(ContractError):
        upstream_module.verify_depot_tools_checkout(checkout, clean_revision)
    assert (checkout / "gclient.bat").read_text() == "@echo compromised\n"


def test_depot_tools_checkout_rejects_conflicting_core_worktree(
    tmp_path: Path,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    foreign = tmp_path / "foreign"
    (foreign / "bootstrap").mkdir(parents=True)
    for name in (
        "bootstrap/win_tools.bat", "gclient.bat", "autoninja.bat", ".gitignore",
    ):
        (foreign / name).write_bytes((checkout / name).read_bytes())
    subprocess.run(
        ["git", "-C", str(checkout), "config", "core.worktree", str(foreign)],
        check=True,
    )
    with pytest.raises(ContractError, match="core.worktree"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_accepts_linked_worktree_without_override(
    tmp_path: Path,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    linked = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(checkout), "worktree", "add", "-q", "--detach", str(linked)],
        check=True,
    )
    assert (linked / ".git").is_file()
    assert upstream_module.verify_depot_tools_checkout(linked, revision) == {
        "status": "verified", "revision": revision,
    }


def test_git_capture_ignores_inherited_repository_selectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, _revision = _depot_tools_checkout(tmp_path / "target")
    clean, _clean_revision = _depot_tools_checkout(tmp_path / "foreign")
    (checkout / "gclient.bat").write_text("@echo compromised\n")
    monkeypatch.setenv("GIT_DIR", str(clean / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(clean))
    code, body = upstream_module._run_git_capture(
        checkout, ["status", "--porcelain=v1"], maximum=1024,
    )
    assert code == 0
    assert b"gclient.bat" in body


def test_depot_tools_checkout_rejects_ancestor_replacement_during_git_check(
    tmp_path, monkeypatch,
):
    checkout, revision = _depot_tools_checkout(tmp_path)
    real_run = upstream_module.run_with_bounded_stdout
    moved = tmp_path / "old-depot_tools"
    calls = 0

    def move_after_first_check(*args, **kwargs):
        nonlocal calls
        result = real_run(*args, **kwargs)
        calls += 1
        if calls == 1:
            checkout.rename(moved)
            checkout.mkdir()
        return result

    monkeypatch.setattr(upstream_module, "run_with_bounded_stdout", move_after_first_check)
    with pytest.raises(ContractError, match="checkout authority changed"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)
    assert (moved / "gclient.bat").read_text() == "@echo off\n"


def test_depot_tools_checkout_rejects_ignored_bleeding_edge_marker(tmp_path):
    checkout, revision = _depot_tools_checkout(tmp_path)
    (checkout / ".bleeding_edge").write_bytes(b"")
    assert subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain"],
        check=True,
        capture_output=True,
    ).stdout == b""
    with pytest.raises(ContractError, match="bleeding-edge marker"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_depot_tools_checkout_rejects_hidden_index_flags(tmp_path, flag):
    checkout, revision = _depot_tools_checkout(tmp_path)
    subprocess.run(
        ["git", "-C", str(checkout), "update-index", flag, "gclient.bat"],
        check=True,
    )
    with pytest.raises(ContractError, match="index flags"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_requires_all_invoked_wrappers_tracked(tmp_path):
    checkout, _revision = _depot_tools_checkout(tmp_path)
    subprocess.run(
        ["git", "-C", str(checkout), "rm", "-q", "--", "autoninja.bat"],
        check=True,
    )
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "omit wrapper"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    with pytest.raises(ContractError, match="required wrapper is not tracked"):
        upstream_module.verify_depot_tools_checkout(checkout, revision)


def test_depot_tools_checkout_cli_binds_manifest_pin(tmp_path, monkeypatch, capsys):
    import browser_core.cli as cli_module

    checkout, revision = _depot_tools_checkout(tmp_path)
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    manifest["depot_tools"]["revision"] = revision
    manifest_body = json.dumps(manifest).encode("utf-8")
    (tmp_path / "upstream.json").write_bytes(manifest_body)
    digest = hashlib.sha256(manifest_body).hexdigest()
    git_executable = Path(shutil.which("git.exe") or "")
    monkeypatch.setattr(cli_module, "ROOT", tmp_path)
    assert cli_module.main([
        "upstream", "verify-depot-tools", "--checkout", str(checkout),
        "--git-executable", str(git_executable),
        "--expected-manifest-sha256", digest,
    ]) == 0
    assert json.loads(capsys.readouterr().out)["revision"] == revision
    assert cli_module.main([
        "upstream", "verify-depot-tools", "--checkout", str(checkout),
        "--expected-manifest-sha256", "0" * 64,
    ]) == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "body",
    [
        "# Existing H:\\bc\\chromium\\.gclient shape.\n" + GCLIENT_HBC,
        """solutions = [
  { 'name': 'src',
    'url': 'https://chromium.googlesource.com/chromium/src.git',
    'deps_file': 'DEPS',
    'managed': False,
    'custom_deps': {},
    'custom_vars': {},
  },
]
""",
    ],
)
def test_gclient_config_accepts_only_pinned_single_solution_shapes(
    tmp_path: Path, body: str,
) -> None:
    config = tmp_path / ".gclient"
    config.write_text(body, encoding="utf-8")
    assert upstream_module.verify_gclient_config(config, CHROMIUM_REPOSITORY) == {
        "status": "verified", "solution": "src",
    }


@pytest.mark.parametrize(
    "body",
    [
        "# " + CHROMIUM_REPOSITORY + "\n"
        + GCLIENT_HBC.replace(CHROMIUM_REPOSITORY, "https://example.test/other.git"),
        GCLIENT_HBC.replace("}]", "}, {'name': 'other', 'url': 'https://example.test/other.git'}]"),
        GCLIENT_HBC.replace('"custom_deps":', '"url": "https://example.test/other.git", "custom_deps":'),
        GCLIENT_HBC.replace('"custom_deps": {}', '"custom_deps": {"src/third_party": None}'),
        GCLIENT_HBC + "target_os = ['android']\n",
        GCLIENT_HBC + "solutions = []\n",
        GCLIENT_HBC.replace(f'"{CHROMIUM_REPOSITORY}"', "__import__('os').getenv('REPO')"),
        GCLIENT_HBC + "__import__('os').system('echo unexpected')\n",
        GCLIENT_HBC.replace('"custom_deps":', '"managed": True, "custom_deps":'),
        f'solutions = [{{"name": "src", "url": "{CHROMIUM_REPOSITORY}"}}]\n',
    ],
)
def test_gclient_config_rejects_ambiguous_or_executable_content(
    tmp_path: Path, body: str,
) -> None:
    config = tmp_path / ".gclient"
    config.write_text(body, encoding="utf-8")
    with pytest.raises(ContractError, match="gclient configuration"):
        upstream_module.verify_gclient_config(config, CHROMIUM_REPOSITORY)


def test_gclient_config_is_bounded_and_finally_rechecked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / ".gclient"
    good = GCLIENT_HBC
    config.write_text(good + "#" * 65_536, encoding="utf-8")
    with pytest.raises(ContractError, match="exceeds"):
        upstream_module.verify_gclient_config(config, CHROMIUM_REPOSITORY)

    config.write_text(good, encoding="utf-8")
    original = upstream_module.read_bounded_control_snapshot_result
    reads = 0

    def replace_after_first_read(*args, **kwargs):
        nonlocal reads
        snapshot = original(*args, **kwargs)
        reads += 1
        if reads == 1:
            config.write_text(good.replace('"src"', '"bad"'), encoding="utf-8")
        return snapshot

    monkeypatch.setattr(upstream_module, "read_bounded_control_snapshot_result", replace_after_first_read)
    with pytest.raises(ContractError, match="changed"):
        upstream_module.verify_gclient_config(config, CHROMIUM_REPOSITORY)
    assert reads == 2


def test_gclient_config_cli_uses_verified_upstream_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from browser_core.cli import main

    config = tmp_path / ".gclient"
    config.write_text(
        GCLIENT_HBC,
        encoding="utf-8",
    )
    assert main(["upstream", "verify-gclient", "--config", str(config)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "status": "verified", "solution": "src",
    }
    digest = hashlib.sha256((ROOT / "upstream.json").read_bytes()).hexdigest()
    assert main([
        "upstream", "verify-gclient", "--config", str(config),
        "--expected-manifest-sha256", digest,
    ]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "verified"
    config.write_text(
        'solutions = [{"name": "src", "url": "https://example.test/other.git"}]\n',
        encoding="utf-8",
    )
    assert main(["upstream", "verify-gclient", "--config", str(config)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "gclient configuration" in captured.err


def test_gclient_cli_can_bind_bootstrap_manifest_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import browser_core.cli as cli_module

    original_body = (ROOT / "upstream.json").read_bytes()
    expected_digest = hashlib.sha256(original_body).hexdigest()
    manifest = json.loads(original_body)
    changed_repository = "https://example.test/other.git"
    manifest["chromium"]["repository"] = changed_repository
    (tmp_path / "upstream.json").write_text(json.dumps(manifest), encoding="utf-8")
    config = tmp_path / ".gclient"
    config.write_text(
        GCLIENT_HBC.replace(CHROMIUM_REPOSITORY, changed_repository),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli_module, "ROOT", tmp_path)
    assert cli_module.main([
        "upstream", "verify-gclient", "--config", str(config),
        "--expected-manifest-sha256", expected_digest,
    ]) == 2
    assert capsys.readouterr().out == ""


def test_upstream_verify_binds_expected_manifest_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = ROOT / "upstream.json"
    path = tmp_path / "upstream.json"
    original_body = source.read_bytes()
    path.write_bytes(original_body)
    expected = hashlib.sha256(original_body).hexdigest()
    assert verify_upstream(tmp_path, expected_manifest_sha256=expected)["chromium"]["repository"] == CHROMIUM_REPOSITORY
    with pytest.raises(ContractError, match="manifest digest"):
        verify_upstream(tmp_path, expected_manifest_sha256="0" * 64)
    with pytest.raises(ContractError, match="manifest digest"):
        verify_upstream(tmp_path, expected_manifest_sha256=[])

    original_read = upstream_module._load_json_with_body
    reads = 0

    def rewrite_after_initial_snapshot(*args, **kwargs):
        nonlocal reads
        result = original_read(*args, **kwargs)
        reads += 1
        if reads == 1:
            path.write_bytes(original_body.replace(b'"captured_at": "', b'"captured_at":"  ', 1))
        return result

    monkeypatch.setattr(upstream_module, "_load_json_with_body", rewrite_after_initial_snapshot)
    with pytest.raises(ContractError, match="manifest changed"):
        verify_upstream(tmp_path, expected_manifest_sha256=expected)


def test_upstream_verify_without_expected_digest_rechecks_manifest_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "upstream.json"
    original_body = (ROOT / "upstream.json").read_bytes()
    changed_body = original_body.replace(b"2026-08-02", b"2026-08-03")
    assert changed_body != original_body and len(changed_body) == len(original_body)
    path.write_bytes(original_body)
    initial_stat = path.stat()
    original_validate = upstream_module._validate_https_repository
    changed = False

    def rewrite_during_validation(value: str, label: str) -> str:
        nonlocal changed
        if not changed:
            changed = True
            path.write_bytes(changed_body)
            os.utime(path, ns=(initial_stat.st_atime_ns, initial_stat.st_mtime_ns))
        return original_validate(value, label)

    monkeypatch.setattr(upstream_module, "_validate_https_repository", rewrite_during_validation)
    with pytest.raises(ContractError, match="manifest changed"):
        verify_upstream(tmp_path)
    assert changed


def test_upstream_verify_cli_expected_manifest_digest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from browser_core.cli import main

    expected = hashlib.sha256((ROOT / "upstream.json").read_bytes()).hexdigest()
    assert main(["upstream", "verify", "--expected-manifest-sha256", expected]) == 0
    assert json.loads(capsys.readouterr().out)["chromium"]["repository"] == CHROMIUM_REPOSITORY
    assert main(["upstream", "verify", "--expected-manifest-sha256", "0" * 64]) == 2
    assert capsys.readouterr().out == ""


def _copy_upstream_controls(destination: Path) -> Path:
    destination.mkdir()
    shutil.copy2(ROOT / "upstream.json", destination / "upstream.json")
    shutil.copytree(ROOT / "patches", destination / "patches")
    # These legacy fixtures model one Git worktree. Dependency behavior has
    # separate real-Git fixtures in test_dependency_patches.py.
    manifest_path = destination / 'patches' / 'series.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    scopes = [item['path'] for item in manifest.pop('dependencies', [])]
    for item in manifest['patches']:
        if item.get('checkout') in scopes:
            (destination / 'patches' / item['file']).unlink()
    manifest['patches'] = [item for item in manifest['patches'] if 'checkout' not in item]
    retained_patches = {item['file'] for item in manifest['patches']}
    manifest['postimages'] = [item for item in manifest['postimages']
                             if not any(item['path'].startswith(scope+'/') for scope in scopes)]
    routes = manifest.get('native_event_routes')
    if isinstance(routes, dict):
        routes['routes'] = [item for item in routes.get('routes', [])
                            if item.get('patch') in retained_patches]
        if routes.get('schema') == 'browser-core.native-event-routes/8':
            routes['schema'] = 'browser-core.native-event-routes/7'
    manifest_path.write_text(json.dumps(manifest, indent=2)+'\n',encoding='utf-8')
    return destination


def test_checked_in_upstream_and_series_verify() -> None:
    upstream = verify_upstream(ROOT)
    assert upstream["chromium"]["revision"]
    assert upstream["build"]["support_targets"] == ["trace_processor_shell"]
    verified = verify_patch_series(ROOT)
    assert verified["patches"] == 53
    assert verified["postimages"] == 62


@pytest.mark.parametrize("new_assignment", ["is_debug=true", "is_debug = true"])
def test_upstream_rejects_duplicate_gn_assignment_names(
    tmp_path: Path, new_assignment: str,
) -> None:
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    manifest["build"]["gn_args"].append(new_assignment)
    (tmp_path / "upstream.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    with pytest.raises(ContractError, match="GN arguments"):
        verify_upstream(tmp_path)


@pytest.mark.parametrize("support_target", ["--help", "-t", "-j0"])
def test_upstream_rejects_option_shaped_support_targets(
    tmp_path: Path, support_target: str,
) -> None:
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    manifest["build"]["support_targets"] = [support_target]
    (tmp_path / "upstream.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ContractError, match="support_targets"):
        verify_upstream(tmp_path)


@pytest.mark.parametrize(
    "output_directory", ["C:/outside", "C:outside", "out/BrowserCore:alternate",
                         "out//BrowserCore", "out/./BrowserCore", "out/BrowserCore/",
                         "out/BrowserCore.", "out/BrowserCore ", "out/CON",
                         "out/CON.txt", "out/Browser*Core", "out/Browser?Core",
                         "out/Browser|Core", 'out/Browser"Core', "out/Browser<Core",
                         "out/Browser>Core", "out/Browser\nCore", "--help", "-h", ".git",
                         "out/.git", "out/.GIT"]
)
def test_upstream_output_directory_rejects_noncanonical_or_windows_unsafe_paths(
    tmp_path: Path, output_directory: str,
) -> None:
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    manifest["build"]["output_directory"] = output_directory
    (tmp_path / "upstream.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    with pytest.raises(ContractError, match="output directory"):
        verify_upstream(tmp_path)


@pytest.mark.parametrize(
    ("component", "accepted"),
    [
        pytest.param("A" * 255, True, id="ascii-255"),
        pytest.param("A" * 256, False, id="ascii-256"),
        pytest.param("\U0001f600" * 127 + "A", True, id="utf16-255"),
        pytest.param("\U0001f600" * 128, False, id="utf16-256"),
    ],
)
def test_upstream_output_directory_bounds_utf16_component_length(
    tmp_path: Path, component: str, accepted: bool,
) -> None:
    manifest = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    output_directory = f"out/{component}"
    manifest["build"]["output_directory"] = output_directory
    (tmp_path / "upstream.json").write_text(json.dumps(manifest), encoding="utf-8")
    if accepted:
        assert verify_upstream(tmp_path)["build"]["output_directory"] == output_directory
    else:
        with pytest.raises(ContractError, match="output directory"):
            verify_upstream(tmp_path)


@pytest.mark.parametrize(
    "postimage_path",
    ["D:/outside", "out/file:stream", "out//file.cc", "out/./file.cc",
     "out/file.", "out/CON", "out/CON.txt", "out/file*.cc", "out/file?.cc",
     "out/file|.cc", 'out/file".cc', "out/file<.cc", "out/file>.cc",
     ".git/config", "out/.Git/config"],
)
def test_patch_series_rejects_nonportable_postimage_paths(
    tmp_path: Path, postimage_path: str,
) -> None:
    upstream = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    (tmp_path / "upstream.json").write_text(
        json.dumps(upstream), encoding="utf-8"
    )
    patches = tmp_path / "patches"
    patches.mkdir()
    series = {
        "schema": "browser-core.patch-series/1",
        "chromium_revision": upstream["chromium"]["revision"],
        "patches": [],
        "postimages": [{"path": postimage_path, "sha256": "0" * 64}],
    }
    (patches / "series.json").write_text(json.dumps(series), encoding="utf-8")
    with pytest.raises(ContractError, match="postimage entry.*invalid path"):
        verify_patch_series(tmp_path)


@pytest.mark.parametrize(
    "component",
    [pytest.param("A" * 256, id="ascii-256"),
     pytest.param("\U0001f600" * 128, id="utf16-256")],
)
def test_patch_series_rejects_overlength_utf16_postimage_component(
    tmp_path: Path, component: str,
) -> None:
    upstream = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    (tmp_path / "upstream.json").write_text(json.dumps(upstream), encoding="utf-8")
    patches = tmp_path / "patches"
    patches.mkdir()
    series = {
        "schema": "browser-core.patch-series/1",
        "chromium_revision": upstream["chromium"]["revision"],
        "patches": [],
        "postimages": [{"path": f"out/{component}", "sha256": "0" * 64}],
    }
    (patches / "series.json").write_text(json.dumps(series), encoding="utf-8")
    with pytest.raises(ContractError, match="postimage entry.*invalid path"):
        verify_patch_series(tmp_path)


def test_patch_series_rejects_casefold_duplicate_postimages(tmp_path: Path) -> None:
    upstream = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    (tmp_path / "upstream.json").write_text(
        json.dumps(upstream), encoding="utf-8"
    )
    patches = tmp_path / "patches"
    patches.mkdir()
    series = {
        "schema": "browser-core.patch-series/1",
        "chromium_revision": upstream["chromium"]["revision"],
        "patches": [],
        "postimages": [
            {"path": name, "sha256": "0" * 64}
            for name in ("out/File.cc", "out/file.cc")
        ],
    }
    (patches / "series.json").write_text(json.dumps(series), encoding="utf-8")
    with pytest.raises(ContractError, match="duplicate postimage path"):
        verify_patch_series(tmp_path)


@pytest.mark.parametrize("schema", [[], {}])
def test_patch_series_rejects_non_string_schema(
    tmp_path: Path, schema,
) -> None:
    upstream = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    (tmp_path / "upstream.json").write_text(
        json.dumps(upstream), encoding="utf-8"
    )
    patches = tmp_path / "patches"
    patches.mkdir()
    series = {
        "schema": schema,
        "chromium_revision": upstream["chromium"]["revision"],
        "patches": [],
        "postimages": [],
    }
    (patches / "series.json").write_text(json.dumps(series), encoding="utf-8")
    with pytest.raises(ContractError, match="unsupported patch series schema"):
        verify_patch_series(tmp_path)


@pytest.mark.parametrize('cached', [False, True])
def test_patch_series_rejects_relocated_source_ancestor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cached: bool) -> None:
    outer = tmp_path / 'outer'
    outer.mkdir()
    root = _copy_upstream_controls(outer / 'root')
    if cached:
        verify_patch_series(root)
    hook = 'read_bounded_control_snapshot_result' if cached else '_load_json_with_body'
    original = getattr(upstream_module, hook)
    relocated = False

    def read_then_relocate(*args, **kwargs):
        nonlocal relocated
        result = original(*args, **kwargs)
        if not relocated:
            retained = tmp_path / 'retained-outer'
            outer.rename(retained)
            outer.mkdir()
            (retained / 'root').rename(root)
            relocated = True
        return result

    monkeypatch.setattr(upstream_module, hook, read_then_relocate)
    expected_error = (
        'patch series root authority changed' if cached
        else 'upstream manifest changed during verification'
    )
    with pytest.raises(ContractError, match=expected_error):
        verify_patch_series(root)
    assert relocated
    assert (root / 'upstream.json').exists()


@pytest.mark.parametrize("cached", [False, True])
def test_patch_series_rejects_replaced_patch_directory_after_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cached: bool,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    upstream = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    (root / "upstream.json").write_text(json.dumps(upstream), encoding="utf-8")
    series = {
        "schema": upstream_module.LEGACY_PATCH_SCHEMA,
        "chromium_revision": upstream["chromium"]["revision"],
        "patches": [],
        "postimages": [],
    }
    patch_dir = root / "patches"
    patch_dir.mkdir()
    (patch_dir / "series.json").write_text(json.dumps(series), encoding="utf-8")
    if cached:
        assert verify_patch_series(root)["postimages"] == 0
    replacement = root / "replacement-patches"
    replacement.mkdir()
    changed_series = {
        **series,
        "postimages": [{"path": "changed.cc", "sha256": "0" * 64}],
    }
    (replacement / "series.json").write_text(
        json.dumps(changed_series), encoding="utf-8"
    )

    hook = (
        "_cached_verified_patch_bundle" if cached else "_verified_patch_bundle_uncached"
    )
    original = getattr(upstream_module, hook)
    swapped = False

    def replace_after_verification(*args, **kwargs):
        nonlocal swapped
        result = original(*args, **kwargs)
        if result is not None and not swapped:
            patch_dir.rename(root / "retained-patches")
            replacement.rename(patch_dir)
            swapped = True
        return result

    monkeypatch.setattr(upstream_module, hook, replace_after_verification)
    with pytest.raises(ContractError, match="patch series directory authority changed"):
        verify_patch_series(root)
    assert swapped
    assert json.loads((patch_dir / "series.json").read_text(encoding="utf-8")) == changed_series
    assert json.loads(
        (root / "retained-patches" / "series.json").read_text(encoding="utf-8")
    ) == series


@pytest.mark.parametrize("url", [
    "https://@example.com/repository.git",
    "https://example.com/repository.git\n",
    "https://example.com/repository.git\t",
    "https://example.com/repository.git?",
    "https://example.com/repository.git#",
])
def test_upstream_repository_rejects_ambiguous_authority(url: str) -> None:
    with pytest.raises(ContractError, match="repository"):
        upstream_module._validate_https_repository(url, "Chromium")


@pytest.mark.parametrize(
    ("patch_name", "old", "new"),
    [
        (
            "0002-browser-core-canvas-track-event.patch",
            b'"api",\n+                      "HTMLCanvasElement.toDataURL"',
            b'"canvas",\n+                      "HTMLCanvasElement.toDataURL"',
        ),
        (
            "0003-browser-core-context-and-causality-track-events.patch",
            b'"event_category", "crypto", "event_name"',
            b'"event_category", "network", "event_name"',
        ),
        (
            "0003-browser-core-context-and-causality-track-events.patch",
            b'"SubtleCrypto.digest"',
            b'"SubtleCrypto.encrypt"',
        ),
        (
            "0003-browser-core-context-and-causality-track-events.patch",
            b'"BrowserCore.CryptoDigest"',
            b'"BrowserCore.CryptoDigext"',
        ),
    ],
    ids=("legacy-category", "category", "event-name", "native-name"),
)
def test_patch_series_rejects_rehashed_native_event_route_drift(
    tmp_path: Path, patch_name: str, old: bytes, new: bytes
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = root / "patches" / patch_name
    patch = patch_path.read_bytes()
    assert patch.count(old) == 1
    patch_path.write_bytes(patch.replace(old, new, 1))

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(patch_path.read_bytes()).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_rehashed_removal_of_every_native_route(
    tmp_path: Path,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    changed = 0
    for item in series["patches"]:
        patch_path = root / "patches" / item["file"]
        body = patch_path.read_bytes()
        replacement = body.replace(b"BrowserCore.", b"BrowserDrift.")
        if replacement != body:
            patch_path.write_bytes(replacement)
            item["sha256"] = hashlib.sha256(replacement).hexdigest()
            changed += 1
    assert changed == 8
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_route_decoy_outside_trace_call(tmp_path: Path) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    old = b'"BrowserCore.CryptoDigest"'
    assert body.count(old) == 1
    body = body.replace(old, b'"BrowserDrift.CryptoDigest"', 1)
    body += (
        b'\n+// "BrowserCore.CryptoDigest" "event_category", "crypto", '
        b'"event_name", "SubtleCrypto.digest"\n'
    )
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_trace_call_decoy_inside_block_comment(
    tmp_path: Path,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    old = b'"BrowserCore.CryptoDigest"'
    assert body.count(old) == 1
    body = body.replace(old, b'"BrowserDrift.CryptoDigest"', 1)
    body += (
        b'\n+/*\n+TRACE_EVENT_INSTANT("browser_core.debug", '
        b'"BrowserCore.CryptoDigest", "schema", "browser-core.native/1", '
        b'"event_category", "crypto", "event_name", "SubtleCrypto.digest", '
        b'"component", "blink.webcrypto");\n+*/\n'
    )
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_trace_decoy_after_spliced_line_comment(
    tmp_path: Path,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    old = b'"BrowserCore.CryptoDigest"'
    assert body.count(old) == 1
    body = body.replace(old, b'"BrowserDrift.CryptoDigest"', 1)
    body += (
        b"\n+// continued comment \\\n"
        b'+TRACE_EVENT_INSTANT("browser_core.debug", '
        b'"BrowserCore.CryptoDigest", "schema", "browser-core.native/1", '
        b'"event_category", "crypto", "event_name", "SubtleCrypto.digest", '
        b'"component", "blink.webcrypto");\n'
    )
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_trace_call_decoy_inside_raw_string(
    tmp_path: Path,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    old = b'"BrowserCore.CryptoDigest"'
    assert body.count(old) == 1
    body = body.replace(old, b'"BrowserDrift.CryptoDigest"', 1)
    body += (
        b'\n+constexpr char kDecoy[] = R"route(\n'
        b'+TRACE_EVENT_INSTANT("browser_core.debug", '
        b'"BrowserCore.CryptoDigest", "schema", "browser-core.native/1", '
        b'"event_category", "crypto", "event_name", "SubtleCrypto.digest", '
        b'"component", "blink.webcrypto");\n'
        b'+)route";\n'
    )
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_trace_call_decoy_inside_if_zero(
    tmp_path: Path,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    old = b'"BrowserCore.CryptoDigest"'
    assert body.count(old) == 1
    body = body.replace(old, b'"BrowserDrift.CryptoDigest"', 1)
    body += (
        b'\n+#if 0\n+TRACE_EVENT_INSTANT("browser_core.debug", '
        b'"BrowserCore.CryptoDigest", "schema", "browser-core.native/1", '
        b'"event_category", "crypto", "event_name", "SubtleCrypto.digest", '
        b'"component", "blink.webcrypto");\n+#endif\n'
    )
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_cpp_noncode_mask_is_conservative_across_conditional_branches() -> None:
    cases = (
        (
            "#if 0\nDEAD\n#else\nLIVE\n#endif\n",
            ("LIVE",),
            ("DEAD",),
        ),
        (
            "#if 0\n#if FLAG\nINNER_A\n#else\nINNER_B\n#endif\n"
            "#else\nOUTER_LIVE\n#endif\n",
            ("OUTER_LIVE",),
            ("INNER_A", "INNER_B"),
        ),
        (
            "#if FLAG\nMAYBE_A\n#else\nMAYBE_B\n#endif\n",
            ("MAYBE_A", "MAYBE_B"),
            (),
        ),
    )

    for source, visible, hidden in cases:
        masked = upstream_module._mask_cpp_noncode(source)
        assert all(item in masked for item in visible)
        assert all(item not in masked for item in hidden)


def test_patch_series_rejects_rehashed_duplicate_native_emitter(tmp_path: Path) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    body += (
        b'\n+TRACE_EVENT_INSTANT("browser_core.debug", '
        b'"BrowserCore.CryptoDigest", "schema", "browser-core.native/1", '
        b'"event_category", "crypto", "event_name", "SubtleCrypto.digest");\n'
    )
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_rehashed_missing_repeated_emitter(tmp_path: Path) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = root / "patches" / "0004-browser-core-readable-stream-track-events.patch"
    body = patch_path.read_bytes()
    old = b'"BrowserCore.StreamReadRequest"'
    assert body.count(old) == 2
    body = body.replace(old, b'"BrowserDrift.StreamReadRequest"', 1)
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_rehashed_trace_category_drift(tmp_path: Path) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    old = (
        b'"browser_core.debug", "BrowserCore.CryptoDigest", "schema"'
    )
    new = (
        b'"browser_core.stream", "BrowserCore.CryptoDigest", "schema"'
    )
    assert body.count(old) == 1
    body = body.replace(old, new, 1)
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (b'"browser-core.native/1"', b'"browser-core.native/2"'),
        (b'"component", "blink.webcrypto"', b'"component", "blink.crypto"'),
    ],
    ids=("schema", "component"),
)
def test_patch_series_rejects_rehashed_native_call_identity_drift(
    tmp_path: Path, old: bytes, new: bytes
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    if old == b'"browser-core.native/1"':
        anchor = body.index(b'"BrowserCore.CryptoDigest"')
        occurrence = body.index(old, anchor)
        body = body[:occurrence] + new + body[occurrence + len(old) :]
    else:
        assert body.count(old) == 1
        body = body.replace(old, new, 1)
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_rehashed_native_emitter_patch_migration(
    tmp_path: Path,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    original_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    destination_path = (
        root / "patches" / "0004-browser-core-readable-stream-track-events.patch"
    )
    original = original_path.read_bytes()
    name = b'"BrowserCore.CryptoDigest"'
    assert original.count(name) == 1
    original = original.replace(name, b'"BrowserDrift.CryptoDigest"', 1)
    destination = destination_path.read_bytes() + (
        b'\n+TRACE_EVENT_INSTANT("browser_core.debug", '
        b'"BrowserCore.CryptoDigest", "schema", "browser-core.native/1", '
        b'"event_category", "crypto", "event_name", "SubtleCrypto.digest", '
        b'"component", "blink.webcrypto");\n'
    )
    original_path.write_bytes(original)
    destination_path.write_bytes(destination)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    replacements = {
        original_path.name: hashlib.sha256(original).hexdigest(),
        destination_path.name: hashlib.sha256(destination).hexdigest(),
    }
    for item in series["patches"]:
        if item["file"] in replacements:
            item["sha256"] = replacements.pop(item["file"])
    assert not replacements
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_rehashed_native_emitter_source_migration(
    tmp_path: Path,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = (
        root / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    )
    body = patch_path.read_bytes()
    name = b'"BrowserCore.CryptoDigest"'
    assert body.count(name) == 1
    body = body.replace(name, b'"BrowserDrift.CryptoDigest"', 1)
    body += (
        b"\ndiff --git a/third_party/blink/renderer/core/fetch/fetch_manager.cc "
        b"b/third_party/blink/renderer/core/fetch/fetch_manager.cc\n"
        b"--- a/third_party/blink/renderer/core/fetch/fetch_manager.cc\n"
        b"+++ b/third_party/blink/renderer/core/fetch/fetch_manager.cc\n"
        b"@@ -1,0 +1,1 @@\n"
        b'+TRACE_EVENT_INSTANT("browser_core.debug", '
        b'"BrowserCore.CryptoDigest", "schema", "browser-core.native/1", '
        b'"event_category", "crypto", "event_name", "SubtleCrypto.digest", '
        b'"component", "blink.webcrypto");\n'
    )
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route"):
        verify_patch_series(root)


def test_patch_series_rejects_route_contract_downgrade_and_all_name_removal(
    tmp_path: Path,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    series["schema"] = "browser-core.patch-series/1"
    series.pop("native_event_routes")
    for item in series["patches"]:
        patch_path = root / "patches" / item["file"]
        replacement = patch_path.read_bytes().replace(
            b"BrowserCore.", b"BrowserDrift."
        )
        patch_path.write_bytes(replacement)
        item["sha256"] = hashlib.sha256(replacement).hexdigest()
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route declaration"):
        verify_patch_series(root)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda series: series.pop("native_event_routes"),
        lambda series: series["native_event_routes"].__setitem__("extra", True),
        lambda series: series["native_event_routes"].__setitem__("schema", "wrong"),
        lambda series: series["native_event_routes"].__setitem__("schema", []),
        lambda series: series["native_event_routes"].__setitem__("schema", {}),
        lambda series: series["native_event_routes"].__setitem__("routes", {}),
        lambda series: series["native_event_routes"]["routes"].append(
            dict(series["native_event_routes"]["routes"][0])
        ),
        lambda series: series["native_event_routes"]["routes"][0].__setitem__(
            "category", "wrong"
        ),
        lambda series: series["native_event_routes"]["routes"][0].__setitem__(
            "sources", []
        ),
        lambda series: series["native_event_routes"]["routes"][0].__setitem__(
            "sources", [[]]
        ),
        lambda series: series["native_event_routes"]["routes"][0].__setitem__(
            "sources", ["../v8_script_runner.cc"]
        ),
        lambda series: series["native_event_routes"]["routes"][0].__setitem__(
            "sources", ["third_party\\blink\\v8_script_runner.cc"]
        ),
        lambda series: series["native_event_routes"]["routes"][0].__setitem__(
            "sources", 2
            * series["native_event_routes"]["routes"][0]["sources"]
        ),
    ],
)
def test_native_event_route_declaration_is_closed(
    tmp_path: Path, mutation
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    mutation(series)
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="native event route|patch series fields"):
        verify_patch_series(root)


def test_patch_series_rejects_mismatched_diff_target_header(tmp_path: Path) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    patch_path = root / "patches" / "0002-browser-core-canvas-track-event.patch"
    body = patch_path.read_bytes()
    old = (
        b"diff --git a/base/trace_event/builtin_categories.h "
        b"b/base/trace_event/builtin_categories.h"
    )
    new = (
        b"diff --git a/base/trace_event/builtin_categories.h "
        b"b/base/trace_event/other_categories.h"
    )
    assert body.count(old) == 1
    body = body.replace(old, new, 1)
    patch_path.write_bytes(body)

    series_path = root / "patches" / "series.json"
    series = json.loads(series_path.read_text(encoding="utf-8"))
    for item in series["patches"]:
        if item["file"] == patch_path.name:
            item["sha256"] = hashlib.sha256(body).hexdigest()
            break
    else:
        pytest.fail("fixture patch is absent from the series manifest")
    series_path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="patch diff target"):
        verify_patch_series(root)


def test_message_dispatch_patch_reuses_upstream_mojo_trace_id_without_delta() -> None:
    context_patch = (
        ROOT / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    ).read_text(encoding="utf-8")
    dispatch_patch = (
        ROOT / "patches" / "0010-browser-core-messageport-delivery-correlation.patch"
    ).read_text(encoding="utf-8")
    changed_paths = [
        line for line in dispatch_patch.splitlines() if line.startswith("diff --git ")
    ]

    assert changed_paths == [
        "diff --git a/third_party/blink/renderer/core/messaging/message_port.cc "
        "b/third_party/blink/renderer/core/messaging/message_port.cc"
    ]
    assert "mojo_message.GetTraceId()" in context_patch
    assert "message.trace_id = browser_core_trace_id" in context_patch
    assert "BrowserCoreMessageId(message.trace_id)" in dispatch_patch
    assert "browser_core_message_id" not in context_patch + dispatch_patch
    assert "transferable_message.mojom" not in dispatch_patch


def test_fetch_url_class_excludes_authority_while_target_scope_discards_it() -> None:
    patch = (
        ROOT / "patches" / "0003-browser-core-context-and-causality-track-events.patch"
    ).read_text(encoding="utf-8")
    assert "request->Url().Protocol().Utf8()" in patch
    assert "request->Url().GetPath()" in patch
    assert '{scheme, ":", same_origin ? "same-origin:" : "cross-origin:", path}' in patch
    assert 'scheme == "http" || scheme == "https" || scheme == "chrome-extension"' in patch
    assert 'retain_path ? path_view.ToString().Utf8() : "<redacted>"' in patch
    assert "const std::string host = request->Url().Host().Utf8();" in patch
    assert "net::HostStringIsLocalhost(host)" in patch
    assert '"target_scope", target_scope' in patch
    assert '"host", host' not in patch
    assert "request->Url().Query()" not in patch
    assert "request->Url().FragmentIdentifier()" not in patch


def test_hashed_patch_bytes_are_forced_to_lf_in_windows_worktrees() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "patches/*.patch text eol=lf" in attributes
    assert "patches/series.json text eol=lf" in attributes
    for patch in (ROOT / "patches").glob("*.patch"):
        assert b"\r\n" not in patch.read_bytes()
    manifest = (ROOT / "patches" / "series.json").read_bytes()
    assert b"\r\n" not in manifest
    assert b"\n" in manifest


def test_patch_hash_drift_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "patches").mkdir()
    upstream = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    (tmp_path / "upstream.json").write_text(json.dumps(upstream), encoding="utf-8")
    patch = tmp_path / "patches" / "0001.patch"
    patch.write_text("fixture", encoding="utf-8")
    series = {
        "schema": "browser-core.patch-series/1",
        "chromium_revision": upstream["chromium"]["revision"],
        "patches": [
            {
                "file": "0001.patch",
                "sha256": "0" * 64,
                "purpose": "fixture",
                "component": "fixture",
                "classification": "fixture",
            }
        ],
        "postimages": [],
    }
    (tmp_path / "patches" / "series.json").write_text(json.dumps(series), encoding="utf-8")
    with pytest.raises(ContractError, match="hash mismatch"):
        verify_patch_series(tmp_path)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda manifest: manifest.__setitem__("uninterpreted", True),
        lambda manifest: manifest["chromium"].__setitem__("uninterpreted", True),
        lambda manifest: manifest["build"].__setitem__("uninterpreted", True),
    ],
)
def test_upstream_manifest_is_closed_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    path = root / "upstream.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutation(manifest)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ContractError, match="fields|entry|target"):
        verify_upstream(root)

    path.write_text(json.dumps(json.loads((ROOT / "upstream.json").read_text())), encoding="utf-8")
    monkeypatch.setattr(upstream_module, "MAX_UPSTREAM_MANIFEST_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        verify_upstream(root)


def test_patch_series_rejects_rehashed_unknown_fields(tmp_path: Path) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    path = root / "patches" / "series.json"
    series = json.loads(path.read_text(encoding="utf-8"))
    series["patches"][0]["uninterpreted"] = "private"
    path.write_text(json.dumps(series), encoding="utf-8")

    with pytest.raises(ContractError, match="patch entry 0"):
        verify_patch_series(root)


def test_upstream_and_patch_manifests_reject_ambiguous_json(tmp_path: Path) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    upstream_path = root / "upstream.json"
    upstream_body = upstream_path.read_bytes()
    upstream_path.write_bytes(
        upstream_body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    )
    with pytest.raises(ContractError, match="duplicate key"):
        verify_upstream(root)

    upstream_path.write_bytes(upstream_body)
    series_path = root / "patches" / "series.json"
    series_body = series_path.read_bytes()
    series_path.write_bytes(
        series_body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    )
    with pytest.raises(ContractError, match="duplicate key"):
        verify_patch_series(root)


def test_upstream_controls_and_patch_sources_require_single_links(tmp_path: Path) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    upstream_path = root / "upstream.json"
    os.link(upstream_path, tmp_path / "upstream-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        verify_upstream(root)

    (tmp_path / "upstream-alias.json").unlink()
    patch = root / "patches" / "0001-browser-core-evaluation-automation-surface.patch"
    os.link(patch, tmp_path / "patch-alias.patch")
    with pytest.raises(ContractError, match="hard links"):
        verify_patch_series(root)


def test_same_byte_patch_replacement_is_detected_by_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    first_patch = root / "patches" / "0001-browser-core-evaluation-automation-surface.patch"
    real_read = upstream_module.read_bounded_control_snapshot_result
    replaced = False

    def replace_after_snapshot(path, **kwargs):  # noqa: ANN001
        nonlocal replaced
        snapshot = real_read(path, **kwargs)
        if Path(path) == first_patch and not replaced:
            replaced = True
            replacement = tmp_path / "same-patch"
            replacement.write_bytes(first_patch.read_bytes())
            replacement.replace(first_patch)
        return snapshot

    monkeypatch.setattr(
        upstream_module,
        "read_bounded_control_snapshot_result",
        replace_after_snapshot,
    )
    with pytest.raises(ContractError, match="changed during verification"):
        verify_patch_series(root)


def test_postimage_hashing_rejects_hard_link_aliases(tmp_path: Path) -> None:
    target = tmp_path / "postimage.cc"
    target.write_text("owned\n", encoding="utf-8")
    os.link(target, tmp_path / "postimage-alias.cc")
    with pytest.raises(ContractError, match="hard links"):
        upstream_module._stable_file_sha256(
            target,
            label="patched source postimage",
            maximum=1024,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows filename executable bits")
def test_stable_postimage_hash_accepts_unchanged_batch_file(tmp_path: Path) -> None:
    target = tmp_path / "postimage.bat"
    body = b"@echo off\r\n"
    target.write_bytes(body)
    assert upstream_module._stable_file_sha256(
        target, label="patched source postimage", maximum=1024,
    ) == hashlib.sha256(body).hexdigest()


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_patched_checkout_rejects_restored_mtime_change_during_final_postimage_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    target = checkout / "postimage.cc"
    target.write_bytes(b"BEFORE")
    subprocess.run(["git", "-C", str(checkout), "add", "postimage.cc"], check=True)
    subprocess.run([
        "git", "-C", str(checkout),
        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "baseline",
    ], check=True)
    revision = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
    ).decode("ascii").strip()
    target.write_bytes(b"AFTER1")
    series = {
        "chromium_revision": revision,
        "patches": [],
        "postimages": [{
            "path": "postimage.cc", "sha256": hashlib.sha256(b"AFTER1").hexdigest(),
        }],
    }
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"", series=series, series_body=b"",
        patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)
    real_fstat = upstream_module.os.fstat
    target_identity = target.stat()
    postimage_stats = 0

    def mutate_after_final_hash(descriptor: int):
        nonlocal postimage_stats
        metadata = real_fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            target_identity.st_dev, target_identity.st_ino,
        ):
            postimage_stats += 1
            if postimage_stats == 4:
                stamp = target.stat()
                target.write_bytes(b"OTHER1")
                os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
                return real_fstat(descriptor)
        return metadata

    monkeypatch.setattr(upstream_module.os, "fstat", mutate_after_final_hash)
    with pytest.raises(ContractError, match="postimage changed"):
        verify_patched_checkout(tmp_path / "root", checkout)
    assert postimage_stats >= 4
    assert target.read_bytes() == b"OTHER1"


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_patched_checkout_rejects_hidden_extra_tracked_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    declared = checkout / "declared.txt"
    extra = checkout / "extra.txt"
    declared.write_bytes(b"before")
    extra.write_bytes(b"baseline")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run([
        "git", "-C", str(checkout),
        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "baseline",
    ], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True,
    ).stdout.decode("ascii").strip()
    declared.write_bytes(b"after")
    extra.write_bytes(b"modified")
    subprocess.run(
        ["git", "-C", str(checkout), "update-index", flag, extra.name],
        check=True,
    )
    assert subprocess.run(
        ["git", "-C", str(checkout), "diff", "--name-only", "HEAD", "--"],
        check=True, capture_output=True,
    ).stdout == b"declared.txt\n"
    series = {
        "chromium_revision": revision,
        "patches": [],
        "postimages": [{
            "path": declared.name,
            "sha256": hashlib.sha256(b"after").hexdigest(),
        }],
    }
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"", series=series, series_body=b"",
        patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)

    with pytest.raises(ContractError, match="index flags"):
        verify_patched_checkout(tmp_path / "root", checkout)
    assert extra.read_bytes() == b"modified"
    with monkeypatch.context() as capped:
        capped.setattr(upstream_module, "MAX_PATCHED_INDEX_BYTES", 1)
        with pytest.raises(ContractError, match="exceeds 1 bytes"):
            verify_patched_checkout(tmp_path / "root", checkout)


def test_patched_checkout_does_not_run_repository_fsmonitor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    target = checkout / "target.txt"
    target.write_bytes(b"before")
    subprocess.run(["git", "-C", str(checkout), "add", target.name], check=True)
    subprocess.run([
        "git", "-C", str(checkout),
        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "baseline",
    ], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True,
    ).stdout.decode("ascii").strip()
    target.write_bytes(b"after")
    marker = tmp_path / "fsmonitor-called.txt"
    hook = f"sh -c 'echo invoked >> \"{marker.as_posix()}\"; exit 1'"
    subprocess.run(
        ["git", "-C", str(checkout), "config", "core.fsmonitor", hook],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain"],
        check=True, capture_output=True,
    )
    assert marker.exists(), "fixture fsmonitor command did not run"
    marker.unlink()
    series = {
        "chromium_revision": revision,
        "patches": [],
        "postimages": [{
            "path": target.name, "sha256": hashlib.sha256(b"after").hexdigest(),
        }],
    }
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"", series=series, series_body=b"",
        patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)

    assert verify_patched_checkout(tmp_path / "root", checkout)["status"] == "declared-postimages-verified"
    assert not marker.exists()


def test_patched_checkout_rejects_aggregate_postimage_bytes_before_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    first = checkout / "gclient.bat"
    second = checkout / "autoninja.bat"
    first.write_bytes(b"@echo changed\n")
    second.write_bytes(b"@echo updated\n")
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"",
        series={
            "chromium_revision": revision,
            "patches": [],
            "postimages": [
                {"path": first.name, "sha256": hashlib.sha256(first.read_bytes()).hexdigest()},
                {"path": second.name, "sha256": hashlib.sha256(second.read_bytes()).hexdigest()},
            ],
        },
        series_body=b"", patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)
    monkeypatch.setattr(
        upstream_module, "MAX_TOTAL_POSTIMAGE_BYTES",
        first.stat().st_size + second.stat().st_size - 1,
        raising=False,
    )
    original_hash = upstream_module._stable_file_sha256
    hashed: list[Path] = []

    def record_hash(path: Path, *, label: str, maximum: int) -> str:
        hashed.append(path)
        return original_hash(path, label=label, maximum=maximum)

    monkeypatch.setattr(upstream_module, "_stable_file_sha256", record_hash)
    with pytest.raises(ContractError, match="aggregate postimage"):
        verify_patched_checkout(tmp_path / "package", checkout)
    assert hashed == []


def test_patched_checkout_rechecks_postimage_after_final_git_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, revision = _depot_tools_checkout(tmp_path)
    target = checkout / "gclient.bat"
    expected_body = b"@echo present\n"
    changed_body = b"@echo altered\n"
    assert len(changed_body) == len(expected_body)
    target.write_bytes(expected_body)
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"",
        series={
            "chromium_revision": revision, "patches": [],
            "postimages": [{
                "path": target.name,
                "sha256": hashlib.sha256(expected_body).hexdigest(),
            }],
        },
        series_body=b"", patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)
    assert verify_patched_checkout(tmp_path / "package", checkout)["status"] == (
        "declared-postimages-verified"
    )
    original_capture = upstream_module._run_git_capture
    inventory_reads = 0

    def change_after_inventory(path: Path, arguments: list[str], *, maximum: int):
        nonlocal inventory_reads
        result = original_capture(path, arguments, maximum=maximum)
        if arguments[:3] == ["diff", "--name-only", "-z"]:
            inventory_reads += 1
            if inventory_reads == 2:
                prior = target.stat()
                target.write_bytes(changed_body)
                os.utime(target, ns=(prior.st_atime_ns, prior.st_mtime_ns))
        return result

    monkeypatch.setattr(upstream_module, "_run_git_capture", change_after_inventory)
    with pytest.raises(ContractError, match="postimage changed"):
        verify_patched_checkout(tmp_path / "package", checkout)
    assert inventory_reads == 2
    assert target.read_bytes() == changed_body


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_patched_checkout_rejects_junction_in_selected_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    physical_parent = tmp_path / "physical"
    physical_parent.mkdir()
    checkout, revision = _depot_tools_checkout(physical_parent)
    original_wrapper = (checkout / "gclient.bat").read_bytes()
    selected_parent = tmp_path / "selected"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_parent), str(physical_parent)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"",
        series={"chromium_revision": revision, "patches": [], "postimages": []},
        series_body=b"", patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)
    try:
        with pytest.raises(ContractError, match="patched checkout"):
            verify_patched_checkout(tmp_path / "package", selected_parent / checkout.name)
        assert (checkout / "gclient.bat").read_bytes() == original_wrapper
    finally:
        selected_parent.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("command", (("patches", "apply", "--check"), ("patches", "state")))
def test_patch_cli_preserves_selected_checkout_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    command: tuple[str, ...],
) -> None:
    from browser_core.cli import main

    physical_parent = tmp_path / "physical"
    physical_parent.mkdir()
    checkout, revision = _depot_tools_checkout(physical_parent)
    selected_parent = tmp_path / "selected"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_parent), str(physical_parent)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"",
        series={"chromium_revision": revision, "patches": [], "postimages": []},
        series_body=b"", patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)
    try:
        assert main([*command, "--checkout", str(selected_parent / checkout.name)]) == 2
        output = capsys.readouterr()
        assert output.out == ""
        assert "checkout" in output.err
    finally:
        selected_parent.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_patched_checkout_rejects_postimage_parent_relinked_after_first_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    parent = checkout / "source"
    parent.mkdir()
    target = parent / "postimage.cc"
    target.write_bytes(b"before")
    subprocess.run(["git", "-C", str(checkout), "add", "source/postimage.cc"], check=True)
    subprocess.run([
        "git", "-C", str(checkout),
        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "baseline",
    ], check=True)
    revision = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
    ).decode("ascii").strip()
    target.write_bytes(b"after!")
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / target.name).write_bytes(b"after!")
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"", series={
            "chromium_revision": revision, "patches": [], "postimages": [{
                "path": "source/postimage.cc",
                "sha256": hashlib.sha256(b"after!").hexdigest(),
            }],
        }, series_body=b"", patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)
    hash_file = upstream_module._stable_file_sha256
    swapped = False

    def hash_then_relink(path: Path, *, label: str, maximum: int) -> str:
        nonlocal swapped
        digest = hash_file(path, label=label, maximum=maximum)
        if path == target and not swapped:
            parent.rename(checkout / "retained-source")
            linked = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(parent), str(foreign)],
                capture_output=True,
            )
            if linked.returncode:
                pytest.skip("host could not create an unprivileged directory junction")
            swapped = True
        return digest

    monkeypatch.setattr(upstream_module, "_stable_file_sha256", hash_then_relink)
    try:
        with pytest.raises(ContractError, match="postimage.*(parent|authority)|patched checkout authority"):
            verify_patched_checkout(tmp_path / "package", checkout)
        assert swapped
        assert (foreign / target.name).read_bytes() == b"after!"
    finally:
        if swapped:
            parent.rmdir()


def test_patched_checkout_accepts_linked_git_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, revision = _depot_tools_checkout(tmp_path)
    checkout = tmp_path / "linked-worktree"
    subprocess.run(
        ["git", "-C", str(source), "worktree", "add", "-q", "--detach", str(checkout), revision],
        check=True,
    )
    assert checkout.joinpath(".git").is_file()
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"",
        series={"chromium_revision": revision, "patches": [], "postimages": []},
        series_body=b"", patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)

    assert verify_patched_checkout(tmp_path / "package", checkout)["status"] == (
        "declared-postimages-verified"
    )


def test_patched_checkout_does_not_run_repository_clean_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    target = checkout / "target.txt"
    target.write_bytes(b"before\n")
    subprocess.run(["git", "-C", str(checkout), "add", target.name], check=True)
    subprocess.run([
        "git", "-C", str(checkout),
        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "baseline",
    ], check=True)
    revision = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
    ).decode("ascii").strip()
    target.write_bytes(b"after\n")
    old = target.stat()
    os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns + 5_000_000_000))
    (checkout / ".git" / "info" / "attributes").write_text(
        "target.txt filter=observed\n", encoding="ascii",
    )
    marker = tmp_path / "clean-filter-called.txt"
    subprocess.run([
        "git", "-C", str(checkout), "config", "filter.observed.clean",
        f"sh -c 'echo invoked >> \"{marker.as_posix()}\"; cat'",
    ], check=True)
    series = {
        "chromium_revision": revision,
        "patches": [],
        "postimages": [{
            "path": target.name, "sha256": hashlib.sha256(b"after\n").hexdigest(),
        }],
    }
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"", series=series, series_body=b"",
        patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)

    assert verify_patched_checkout(tmp_path / "root", checkout)["status"] == "declared-postimages-verified"
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Git for Windows stat-cache fixture")
def test_patched_checkout_labels_hidden_undeclared_tracked_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    declared = checkout / "declared.txt"
    extra = checkout / "extra.txt"
    declared.write_bytes(b"before")
    extra.write_bytes(b"first")
    old_time_ns = 1_600_000_000_000_000_000
    os.utime(extra, ns=(old_time_ns, old_time_ns))
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run([
        "git", "-C", str(checkout),
        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "baseline",
    ], check=True)
    revision = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
    ).decode("ascii").strip()
    declared.write_bytes(b"after!")
    extra.write_bytes(b"other")
    os.utime(extra, ns=(old_time_ns, old_time_ns))
    observed = subprocess.check_output([
        "git", "--no-optional-locks", "-C", str(checkout),
        "diff", "--name-only", "HEAD", "--",
    ])
    assert observed == b"declared.txt\n", "fixture did not reproduce hidden tracked edit"
    series = {
        "chromium_revision": revision,
        "patches": [],
        "postimages": [{
            "path": declared.name, "sha256": hashlib.sha256(b"after!").hexdigest(),
        }],
    }
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"", series=series, series_body=b"",
        patch_bodies=(), report={"status": "verified"},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)

    result = verify_patched_checkout(tmp_path / "root", checkout)
    assert result["status"] == "declared-postimages-verified"
    assert result["changed_path_inventory"] == "git-observed"
    assert result["undeclared_tracked_content"] == "unverified"
    assert extra.read_bytes() == b"other"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda manifest: manifest.__setitem__("captured_at", "2026-99-99"),
        lambda manifest: manifest["chromium"].__setitem__("repository", "https://["),
        lambda manifest: manifest["build"].__setitem__("output_directory", ""),
    ],
)
def test_upstream_manifest_normalizes_malformed_semantic_values(
    tmp_path: Path, mutation
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    path = root / "upstream.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutation(manifest)
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ContractError, match="invalid|HTTPS"):
        verify_upstream(root)


def test_patch_series_manifest_is_bounded_before_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    monkeypatch.setattr(upstream_module, "MAX_PATCH_SERIES_BYTES", 1)

    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        verify_patch_series(root)


def test_patch_sources_are_bounded_before_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    monkeypatch.setattr(upstream_module, "MAX_PATCH_BYTES", 1)

    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        verify_patch_series(root)


def test_patch_mutation_during_verification_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    first_patch = root / "patches" / "0001-browser-core-evaluation-automation-surface.patch"
    real_read = upstream_module.read_bounded_control_snapshot_result
    injected = False

    def mutate_after_snapshot(path, **kwargs):  # noqa: ANN001
        nonlocal injected
        snapshot = real_read(path, **kwargs)
        if Path(path) == first_patch and not injected:
            injected = True
            first_patch.write_bytes(first_patch.read_bytes() + b"\nforeign mutation\n")
        return snapshot

    monkeypatch.setattr(
        upstream_module,
        "read_bounded_control_snapshot_result",
        mutate_after_snapshot,
    )
    with pytest.raises(ContractError, match="changed during verification"):
        verify_patch_series(root)


def test_patch_application_consumes_the_verified_bytes_not_the_source_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    first_patch = root / "patches" / "0001-browser-core-evaluation-automation-surface.patch"
    expected = first_patch.read_bytes()
    observed: list[bytes] = []

    def fake_apply(_checkout, _arguments, patches):  # noqa: ANN001
        first_patch.write_bytes(b"replacement after verification")
        observed.extend(patches)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(upstream_module, "_run_apply", fake_apply)
    result = apply_patch_series(root, checkout, check_only=True)

    assert result["checked"] == 40
    assert observed[0] == expected


def _single_target_patch_bundle() -> upstream_module.VerifiedPatchBundle:
    patch = (
        b"diff --git a/source/target.txt b/source/target.txt\n"
        b"--- a/source/target.txt\n"
        b"+++ b/source/target.txt\n"
        b"@@ -1 +1 @@\n"
        b"-before\n"
        b"+after\n"
    )
    return upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"", series={"dependencies": []},
        series_body=b"", patch_bodies=(("target.patch", patch),),
        report={"patches": 1},
    )


def test_patch_application_accepts_ordinary_nested_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "core.autocrlf", "false"], check=True)
    parent = checkout / "source"
    parent.mkdir()
    target = parent / "target.txt"
    target.write_bytes(b"before\n")
    monkeypatch.setattr(
        upstream_module, "_verified_patch_bundle", lambda _root: _single_target_patch_bundle(),
    )

    assert apply_patch_series(tmp_path / "package", checkout, check_only=False) == {
        "applied": 1, "already_applied": 0, "checked": 1,
    }
    assert target.read_bytes() == b"after\n"


def test_patch_application_allows_new_ordinary_target_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    patch = (
        b"diff --git a/newdir/new.txt b/newdir/new.txt\n"
        b"new file mode 100644\n"
        b"--- /dev/null\n"
        b"+++ b/newdir/new.txt\n"
        b"@@ -0,0 +1 @@\n"
        b"+created\n"
    )
    bundle = upstream_module.VerifiedPatchBundle(
        upstream={}, upstream_body=b"", series={"dependencies": []},
        series_body=b"", patch_bodies=(("new.patch", patch),),
        report={"patches": 1},
    )
    monkeypatch.setattr(upstream_module, "_verified_patch_bundle", lambda _root: bundle)

    assert apply_patch_series(tmp_path / "package", checkout, check_only=False)["applied"] == 1
    assert (checkout / "newdir" / "new.txt").read_bytes().replace(b"\r\n", b"\n") == b"created\n"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_patch_application_rejects_junction_target_before_foreign_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    target = foreign / "target.txt"
    target.write_bytes(b"before\n")
    linked_parent = checkout / "source"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(linked_parent), str(foreign)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    monkeypatch.setattr(
        upstream_module, "_verified_patch_bundle", lambda _root: _single_target_patch_bundle(),
    )
    try:
        with pytest.raises(ContractError, match="patch target"):
            apply_patch_series(tmp_path / "package", checkout, check_only=False)
        assert target.read_bytes() == b"before\n"
    finally:
        linked_parent.rmdir()


def test_patch_application_preflights_and_applies_one_pending_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    mutation_calls: list[list[bytes]] = []
    reverse_calls = 0

    def fake_apply(_checkout, arguments, patches):  # noqa: ANN001
        nonlocal reverse_calls
        if arguments == ["--reverse", "--check"]:
            reverse_calls += 1
            # Model one already-applied patch and thirty-nine pending patches.
            return subprocess.CompletedProcess([], 0 if reverse_calls == 1 else 1)
        if arguments == ["--check"]:
            assert len(patches) == 39
            return subprocess.CompletedProcess([], 0)
        assert arguments == []
        mutation_calls.append(list(patches))
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(upstream_module, "_run_apply", fake_apply)
    result = apply_patch_series(root, checkout, check_only=False)
    assert result == {"applied": 39, "already_applied": 1, "checked": 40}
    assert len(mutation_calls) == 1
    assert len(mutation_calls[0]) == 39


def test_patch_application_never_mutates_after_population_preflight_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_upstream_controls(tmp_path / "root")
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    mutation_called = False

    def fake_apply(_checkout, arguments, _patches):  # noqa: ANN001
        nonlocal mutation_called
        if arguments == ["--reverse", "--check"]:
            return subprocess.CompletedProcess([], 1)
        if arguments == ["--check"]:
            return subprocess.CompletedProcess([], 1)
        mutation_called = True
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(upstream_module, "_run_apply", fake_apply)
    with pytest.raises(ContractError, match="does not apply cleanly"):
        apply_patch_series(root, checkout, check_only=False)
    assert mutation_called is False


def test_patch_application_rejects_untyped_process_status() -> None:
    with pytest.raises(ContractError, match="status is invalid"):
        upstream_module._apply_succeeded(
            subprocess.CompletedProcess([], True)  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("runner", "message"),
    [
        (lambda root: upstream_module._run_apply(root, ["--check"], [b"patch"]), "Git patch operation"),
        (lambda root: upstream_module._run_git_no_output(root, ["status"]), "Git operation"),
    ],
)
def test_git_helpers_normalize_private_spawn_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner,
    message: str,
) -> None:
    private_marker = str(tmp_path / "private-checkout")

    def fail(*_args, **_kwargs):
        raise OSError(f"cannot execute in {private_marker}")

    monkeypatch.setattr(upstream_module.subprocess, "run", fail)

    with pytest.raises(ContractError) as captured:
        runner(tmp_path)

    assert str(captured.value) == f"{message} could not start (OSError)"
    assert private_marker not in str(captured.value)


@pytest.mark.parametrize("returncode", [True, None, "0"])
def test_git_no_output_rejects_untyped_process_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode,
) -> None:
    monkeypatch.setattr(
        upstream_module.subprocess,
        "run",
        lambda *_args, **_kwargs: type("Completed", (), {"returncode": returncode})(),
    )

    with pytest.raises(ContractError, match="status is invalid"):
        upstream_module._run_git_no_output(tmp_path, ["status"])


def test_git_worktree_shape_rejects_hard_linked_gitfile(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    metadata = checkout / ".git"
    metadata.write_text("gitdir: ../git-data\n", encoding="utf-8")
    os.link(metadata, tmp_path / "gitfile-alias")
    with pytest.raises(ContractError, match="metadata file is invalid"):
        upstream_module._require_git_worktree_shape(checkout)


def test_git_capture_enforces_its_byte_ceiling(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.email", "fixture@example.test"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.name", "Fixture"], check=True)
    target = checkout / "long-target-name.txt"
    target.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", target.name], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "fixture"], check=True)
    target.write_text("after\n", encoding="utf-8")

    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        upstream_module._run_git_capture(
            checkout,
            ["diff", "--name-only", "-z", "HEAD", "--"],
            maximum=1,
        )


def test_patch_apply_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "core"
    checkout = tmp_path / "checkout"
    (root / "patches").mkdir(parents=True)
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.email", "fixture@example.test"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.name", "Fixture"], check=True)
    target = checkout / "target.txt"
    target.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "target.txt"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "fixture"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    target.write_text("after\n", encoding="utf-8")
    postimage_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
    diff = subprocess.run(
        ["git", "-C", str(checkout), "diff", "--binary"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    subprocess.run(["git", "-C", str(checkout), "restore", "target.txt"], check=True)
    patch = root / "patches" / "0001.patch"
    patch.write_text(diff, encoding="utf-8")
    upstream = json.loads((ROOT / "upstream.json").read_text(encoding="utf-8"))
    upstream["chromium"]["revision"] = revision
    (root / "upstream.json").write_text(json.dumps(upstream), encoding="utf-8")
    series = {
        "schema": "browser-core.patch-series/1",
        "chromium_revision": upstream["chromium"]["revision"],
        "patches": [
            {
                "file": patch.name,
                "sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                "purpose": "fixture",
                "component": "fixture",
                "classification": "fixture",
            }
        ],
        "postimages": [
            {"path": "target.txt", "sha256": postimage_sha256}
        ],
    }
    (root / "patches" / "series.json").write_text(json.dumps(series), encoding="utf-8")

    assert apply_patch_series(root, checkout, check_only=True)["checked"] == 1
    assert apply_patch_series(root, checkout, check_only=False)["applied"] == 1
    repeated = apply_patch_series(root, checkout, check_only=False)
    assert repeated["applied"] == 0
    assert repeated["already_applied"] == 1
    assert target.read_text(encoding="utf-8") == "after\n"
    state = verify_patched_checkout(root, checkout)
    assert state["chromium_revision"] == revision
    assert state["postimages"] == 1
    assert state["status"] == "declared-postimages-verified"
    assert state["changed_path_inventory"] == "git-observed"
    assert state["undeclared_tracked_content"] == "unverified"

    real_capture = upstream_module._run_git_capture
    inventory_reads = 0

    def stage_after_final_inventory(checkout_arg, arguments, *, maximum):
        nonlocal inventory_reads
        result = real_capture(checkout_arg, arguments, maximum=maximum)
        if arguments[:3] == ["diff", "--name-only", "-z"]:
            inventory_reads += 1
            if inventory_reads == 2:
                late = checkout / "late.txt"
                late.write_text("late\n", encoding="utf-8")
                subprocess.run(
                    ["git", "-C", str(checkout), "add", late.name], check=True,
                )
        return result

    with monkeypatch.context() as changed_index:
        changed_index.setattr(upstream_module, "_run_git_capture", stage_after_final_inventory)
        with pytest.raises(ContractError, match="tracked index changed"):
            verify_patched_checkout(root, checkout)
    assert inventory_reads == 2
    subprocess.run(
        ["git", "-C", str(checkout), "rm", "--cached", "-q", "--", "late.txt"],
        check=True,
    )
    (checkout / "late.txt").unlink()

    with monkeypatch.context() as limited:
        limited.setattr(upstream_module, "MAX_POSTIMAGE_BYTES", 1)
        with pytest.raises(ContractError, match="exceeds 1 bytes"):
            verify_patched_checkout(root, checkout)

    (checkout / "extra.txt").write_text("extra\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "extra.txt"], check=True)
    with pytest.raises(ContractError, match="delta mismatch"):
        verify_patched_checkout(root, checkout)


def test_verified_patch_bundle_cache_invalidates_on_input_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Skip parsing on equal bytes; restored mtime cannot conceal changed bytes."""

    from browser_core.upstream import _BUNDLE_CACHE, _verified_patch_bundle

    root = _copy_upstream_controls(tmp_path / "root")
    first = _verified_patch_bundle(root)
    with monkeypatch.context() as cached:
        cached.setattr(upstream_module, "_verified_patch_bundle_uncached", lambda _root: pytest.fail("cache hit unexpectedly reparsed"))
        second = _verified_patch_bundle(root)
    assert second.report == first.report
    assert tmp_path / "root" in _BUNDLE_CACHE
    # This used to pass the Windows metadata cache after restoring mtime.
    patch = next((root / "patches").glob("*.patch"))
    stat_before = patch.stat()
    body = patch.read_bytes()
    patch.write_bytes(body.replace(b"diff --git", b"daff --git", 1))
    os.utime(patch, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
    with pytest.raises(ContractError):
        _verified_patch_bundle(root)
