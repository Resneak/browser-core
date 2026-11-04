from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
from pathlib import Path

import pytest

import browser_core.control_files as control_files_module
import browser_core.platform_cli as cli_module
from browser_core.contracts import ContractError
from browser_core.control import ControlStore
from browser_core.platform_cli import main
from test_personas import fixture_persona


@pytest.mark.skipif(os.name != "nt", reason="Win32 output component aliases")
@pytest.mark.parametrize("leaf", ["CON", "result."])
@pytest.mark.parametrize(
    "kind", ["json", "transport", "secret", "secret-checked", "remote-artifact"],
)
def test_cli_output_rejects_invalid_leaf_before_parent_creation(
    tmp_path: Path, kind: str, leaf: str,
) -> None:
    parent = tmp_path / "new-parent"
    destination = parent / leaf
    with pytest.raises(ContractError):
        if kind == "json":
            cli_module._write_json(destination, {"schema": "fixture/1"})
        elif kind == "transport":
            cli_module._write_transport_json_checked(
                destination, {"schema": "fixture/1"},
            )
        elif kind == "secret":
            cli_module._write_secret(destination, "secret")
        elif kind == "secret-checked":
            cli_module._publish_secret_checked(destination, "secret")
        else:
            cli_module._publish_remote_artifact_checked(destination, b"artifact")
    assert not parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="Win32 output component aliases")
@pytest.mark.parametrize("leaf", ["CON", "bundle."])
def test_persona_export_rejects_invalid_leaf_before_parent_creation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], leaf: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "new-parent" / leaf
    assert main(["--workspace", str(workspace), "persona", "export", str(output)]) == 2
    emitted = capsys.readouterr()
    assert emitted.out == ""
    assert "invalid component" in emitted.err
    assert not output.parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="Win32 parent component aliases")
@pytest.mark.parametrize("kind", ["json", "secret", "remote-artifact", "persona-export"])
def test_cli_output_rejects_trailing_dot_parent_before_creation(
    tmp_path: Path, kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    destination = tmp_path / "new-parent." / "output.json"
    if kind == "persona-export":
        assert main([
            "--workspace", str(workspace), "persona", "export", str(destination),
        ]) == 2
    else:
        with pytest.raises(ContractError):
            if kind == "json":
                cli_module._write_json(destination, {"schema": "fixture/1"})
            elif kind == "secret":
                cli_module._write_secret(destination, "secret")
            else:
                cli_module._publish_remote_artifact_checked(destination, b"artifact")
    assert not (tmp_path / "new-parent").exists()


@pytest.mark.parametrize(
    "leaf",
    [
        pytest.param("bad\x00name", id="nul"),
        pytest.param("bad\ud800name", id="unpaired-surrogate"),
    ],
)
@pytest.mark.parametrize(
    "kind", ["json", "transport", "secret", "secret-checked", "remote-artifact", "persona-export"],
)
def test_cli_output_rejects_invalid_text_before_parent_creation(
    tmp_path: Path, kind: str, leaf: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    parent = tmp_path / "new-parent"
    destination = parent / leaf
    if kind == "persona-export":
        assert main([
            "--workspace", str(workspace), "persona", "export", str(destination),
        ]) == 2
    else:
        with pytest.raises(ContractError):
            if kind == "json":
                cli_module._write_json(destination, {"schema": "fixture/1"})
            elif kind == "transport":
                cli_module._write_transport_json_checked(
                    destination, {"schema": "fixture/1"},
                )
            elif kind == "secret":
                cli_module._write_secret(destination, "secret")
            elif kind == "secret-checked":
                cli_module._publish_secret_checked(destination, "secret")
            else:
                cli_module._publish_remote_artifact_checked(destination, b"artifact")
    assert not parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("kind", ["json", "secret", "remote-artifact"])
def test_cli_output_rejects_parent_junction_before_creating_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    target = tmp_path / "unrelated"
    target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    destination = junction / "new-parent" / "result.bin"
    try:
        if kind == "json":
            with pytest.raises(ContractError):
                cli_module._write_json(destination, {"value": 1})
        elif kind == "secret":
            with pytest.raises(ContractError):
                cli_module._write_secret(destination, "opaque-secret")
        else:
            class Client:
                def __init__(self, *_args):
                    pass

                def get_artifact(self, *_args):
                    return b"downloaded"

            monkeypatch.setattr(cli_module, "ControlClient", Client)
            monkeypatch.setenv("BROWSER_PLATFORM_TOKEN", "opaque-token")
            assert main([
                "control", "remote-artifact-get", "http://127.0.0.1:1",
                "workspace", "a" * 64, str(destination),
            ]) == 2
        assert list(target.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.parametrize("relocate_parent", [False, True])
def test_remote_artifact_download_rechecks_published_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], relocate_parent: bool,
) -> None:
    class Client:
        def __init__(self, *_args):
            pass

        def get_artifact(self, *_args):
            return b"downloaded artifact"

    monkeypatch.setattr(cli_module, "ControlClient", Client)
    monkeypatch.setenv("BROWSER_PLATFORM_TOKEN", "opaque-token")
    selected = tmp_path / "selected"
    selected.mkdir()
    output = selected / "artifact.bin"
    if relocate_parent:
        original_publish = control_files_module.publish_bytes_exclusive_result

        def relocate_after_publication(*args, **kwargs):
            published = original_publish(*args, **kwargs)
            selected.rename(tmp_path / "retained")
            selected.mkdir()
            output.write_bytes(b"competitor")
            return published

        monkeypatch.setattr(
            control_files_module, "publish_bytes_exclusive_result",
            relocate_after_publication,
        )
    status = main([
        "control", "remote-artifact-get", "http://127.0.0.1:1",
        "workspace", "a" * 64, str(output),
    ])
    assert status == (2 if relocate_parent else 0)
    if relocate_parent:
        assert output.read_bytes() == b"competitor"
        assert (tmp_path / "retained" / output.name).read_bytes() == b"downloaded artifact"
    else:
        assert output.read_bytes() == b"downloaded artifact"
        assert json.loads(capsys.readouterr().out) == {
            "output": str(output.absolute()), "bytes": len(b"downloaded artifact"),
        }


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_persona_cli_rejects_selected_workspace_junction(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    physical_workspace = tmp_path / "physical-workspace"
    physical_workspace.mkdir()
    selected_workspace = tmp_path / "selected-workspace"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected_workspace), str(physical_workspace)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        assert main(["--workspace", str(physical_workspace), "persona", "list"]) == 0
        assert json.loads(capsys.readouterr().out) == {"personas": []}
        assert main(["--workspace", str(selected_workspace), "persona", "list"]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "persona workspace" in captured.err
        assert list(physical_workspace.iterdir()) == []
    finally:
        selected_workspace.rmdir()


def test_platform_cli_parse_errors_do_not_echo_caller_values(capsys) -> None:
    private = 'private-synthetic-parser-value'
    assert main(['persona', 'list', f'--unknown={private}']) == 2
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == 'browser-platform: invalid options\n'
    assert private not in captured.err


def test_platform_cli_does_not_accept_abbreviated_options() -> None:
    with pytest.raises(ContractError, match='invalid options'):
        cli_module.parser().parse_args(
            ['transport', 'fingerprint', 'chrome.exe', '--timeout-s', '3'])


@pytest.mark.parametrize('failure', [OSError, ValueError])
def test_platform_cli_does_not_echo_private_infrastructure_errors(
    monkeypatch, capsys, failure,
) -> None:
    private = 'private-synthetic-infrastructure-value'

    def fail(_args):
        raise failure(private)

    monkeypatch.setattr(cli_module, '_workspace', fail)
    assert main(['persona', 'list']) == 2
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == f'browser-platform: operation failed ({failure.__name__})\n'
    assert private not in captured.err


def test_cli_json_loader_is_stable_bounded_and_strict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "input.json"
    source.write_text('{\n  "value": 1\n}\n', encoding="utf-8")
    assert cli_module._load(source) == {"value": 1}

    for malformed, message in (
        (b'{"value":1,"value":2}', "duplicate key"),
        (b'{"value":NaN}', "non-finite"),
        (b'{"value":1e400}', "non-finite"),
        (b"\xff", "valid UTF-8 JSON"),
    ):
        source.write_bytes(malformed)
        with pytest.raises(ContractError, match=message):
            cli_module._load(source)

    source.write_bytes(b"{}")
    monkeypatch.setattr(cli_module, "MAX_CLI_JSON_INPUT_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds"):
        cli_module._load(source)


def test_cli_json_loader_refuses_symlink_input(tmp_path: Path) -> None:
    source = tmp_path / "input.json"
    source.write_bytes(b"{}")
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {type(exc).__name__}")

    with pytest.raises(ContractError, match="not a regular file"):
        cli_module._load(alias)


def test_cli_json_and_secret_outputs_are_exclusive_and_bounded(
    tmp_path: Path,
) -> None:
    output = tmp_path / "result.json"
    cli_module._write_json(output, {"schema": "owned/1", "value": 1})
    assert output.read_bytes() == b'{"schema":"owned/1","value":1}\n'
    with pytest.raises(ContractError, match="publication failed"):
        cli_module._write_json(output, {"competitor": False})
    assert output.read_bytes() == b'{"schema":"owned/1","value":1}\n'

    secret = tmp_path / "owner.token"
    cli_module._write_secret(secret, "bc1.header.secret")
    assert secret.read_bytes() == b"bc1.header.secret\n"
    if os.name != "nt":
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    with pytest.raises(ContractError, match="publication failed"):
        cli_module._write_secret(secret, "replacement")
    assert secret.read_bytes() == b"bc1.header.secret\n"


def test_persona_export_rejects_output_parent_replacement_after_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    selected_parent = tmp_path / "selected"
    selected_parent.mkdir()
    retained_parent = tmp_path / "retained"
    output = selected_parent / "bundle.json"
    foreign_body = b'{"foreign":true}\n'
    original_write = cli_module._write_json

    def replace_parent_after_write(path: Path, value: dict):
        published = original_write(path, value)
        selected_parent.rename(retained_parent)
        selected_parent.mkdir()
        output.write_bytes(foreign_body)
        return published

    monkeypatch.setattr(cli_module, "_write_json", replace_parent_after_write)
    assert main(["--workspace", str(workspace), "persona", "export", str(output)]) == 2
    emitted = capsys.readouterr()
    assert emitted.out == ""
    assert "output" in emitted.err
    assert (retained_parent / output.name).is_file()
    assert output.read_bytes() == foreign_body


def test_persona_export_receipt_binds_published_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "bundle.json"
    assert main(["--workspace", str(workspace), "persona", "export", str(output)]) == 0
    receipt = json.loads(capsys.readouterr().out)
    bundle = json.loads(output.read_bytes())
    assert receipt == {
        "output": str(output.absolute()),
        "personas": 0,
        "bundle_sha256": bundle["bundle_sha256"],
    }

    original_write = cli_module._write_json

    def replace_after_write(path: Path, value: dict):
        published = original_write(path, value)
        path.write_bytes(b'{"foreign":true}\n')
        return published

    replacement = tmp_path / "replacement.json"
    monkeypatch.setattr(cli_module, "_write_json", replace_after_write)
    assert main(["--workspace", str(workspace), "persona", "export", str(replacement)]) == 2
    emitted = capsys.readouterr()
    assert emitted.out == ""
    assert "output changed after publication" in emitted.err


def test_persona_export_uses_selected_relative_destination_after_cwd_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    selected = tmp_path / "selected"
    selected.mkdir()
    shifted = tmp_path / "shifted"
    shifted.mkdir()
    monkeypatch.chdir(tmp_path)
    original_write = cli_module._write_json

    def change_cwd_before_write(path: Path, value: dict):
        monkeypatch.chdir(shifted)
        return original_write(path, value)

    monkeypatch.setattr(cli_module, "_write_json", change_cwd_before_write)
    assert main([
        "--workspace", str(workspace), "persona", "export", "selected/bundle.json",
    ]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["output"] == str(selected / "bundle.json")
    assert (selected / "bundle.json").is_file()
    assert not (shifted / "selected").exists()


def test_persona_export_rechecks_parent_after_final_output_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    selected_parent = tmp_path / "selected"
    selected_parent.mkdir()
    retained_parent = tmp_path / "retained"
    output = selected_parent / "bundle.json"
    original_read = cli_module.read_bounded_control_snapshot_result
    changed = False

    def relocate_after_read(path: Path, **kwargs):
        nonlocal changed
        snapshot = original_read(path, **kwargs)
        if path == output and not changed:
            selected_parent.rename(retained_parent)
            selected_parent.mkdir()
            output.write_bytes(b'{"foreign":true}\n')
            changed = True
        return snapshot

    monkeypatch.setattr(
        cli_module, "read_bounded_control_snapshot_result", relocate_after_read,
    )
    assert main(["--workspace", str(workspace), "persona", "export", str(output)]) == 2
    emitted = capsys.readouterr()
    assert emitted.out == ""
    assert "output parent changed" in emitted.err
    assert (retained_parent / output.name).is_file()
    assert output.read_bytes() == b'{"foreign":true}\n'


def test_cli_outputs_reject_invalid_values_before_parent_creation(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "missing"
    with pytest.raises(ContractError, match="JSON output contract"):
        cli_module._write_json(parent / "value.json", [1, 2])
    with pytest.raises(ContractError, match="secret output contract"):
        cli_module._write_secret(parent / "token", "secret\nsecond")
    assert not parent.exists()


def test_cli_token_environment_contract_is_bounded_and_value_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ContractError, match="name"):
        cli_module._token("BAD-NAME")

    monkeypatch.setenv("CLI_TOKEN", "private\nsecond")
    with pytest.raises(ContractError, match="unset") as raised:
        cli_module._token("CLI_TOKEN")
    assert "private" not in str(raised.value)

    monkeypatch.setenv("CLI_TOKEN", "\ud800")
    with pytest.raises(ContractError, match="unset") as raised:
        cli_module._token("CLI_TOKEN")
    assert "\\ud800" not in str(raised.value)

    monkeypatch.setenv("CLI_TOKEN", "opaque-token")
    assert cli_module._token("CLI_TOKEN") == "opaque-token"


def test_cli_console_json_rejects_nonfinite_values(capsys) -> None:
    with pytest.raises(ContractError, match="strict JSON"):
        cli_module._json({"value": float("nan")})
    assert capsys.readouterr().out == ""


def test_cli_console_json_normalizes_encoder_recursion(capsys) -> None:
    value: object = 0
    for _ in range(2_000):
        value = [value]

    with pytest.raises(ContractError, match="strict JSON"):
        cli_module._json(value)

    assert capsys.readouterr().out == ""


def test_cli_console_json_limit_includes_windows_line_endings(
    capsys, monkeypatch
) -> None:
    value = {"values": ["first", "second"]}
    rendered = json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
    )
    emitted = len(rendered.encode("ascii")) + rendered.count("\n") + 2
    monkeypatch.setattr(cli_module, "MAX_CLI_JSON_OUTPUT_BYTES", emitted - 1)

    with pytest.raises(ContractError, match="exceeds output limit"):
        cli_module._json(value)

    assert capsys.readouterr().out == ""


def test_cli_requires_explicit_external_workspace(capsys, monkeypatch) -> None:
    # The assertion is about a *missing* workspace, so the variable has to be
    # removed explicitly. Inheriting it from the caller's shell silently turned
    # this into a "workspace is set" test that passed for the wrong reason.
    monkeypatch.delenv("BROWSER_CORE_WORKSPACE", raising=False)
    assert main(["persona", "list"]) == 2
    assert "set BROWSER_CORE_WORKSPACE" in capsys.readouterr().err


def test_cli_rejects_explicit_empty_workspace_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BROWSER_CORE_WORKSPACE", raising=False)
    assert main(["--workspace", "", "persona", "list"]) == 2
    emitted = capsys.readouterr()
    assert emitted.out == ""
    assert "invalid options" in emitted.err
    assert main(["--workspace", ".", "persona", "list"]) == 0
    assert json.loads(capsys.readouterr().out) == {"personas": []}


@pytest.mark.skipif(os.name != "nt", reason="Win32 directory-name normalization")
@pytest.mark.parametrize("suffix", [".", " "])
def test_cli_rejects_normalized_workspace_alias(
    tmp_path: Path, suffix: str, capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    selected = tmp_path / f"workspace{suffix}"
    assert selected.is_dir() and os.path.samefile(selected, workspace)

    assert main(["--workspace", str(selected), "persona", "list"]) == 2
    assert not (workspace / "personas").exists()
    assert main(["--workspace", str(workspace), "persona", "list"]) == 0
    assert json.loads(capsys.readouterr().out) == {"personas": []}


@pytest.mark.skipif(os.name != "nt", reason="Win32 directory-name normalization")
@pytest.mark.parametrize("suffix", [".", " "])
def test_cli_rejects_environment_workspace_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    selected = tmp_path / f"workspace{suffix}"
    assert selected.is_dir() and os.path.samefile(selected, workspace)
    monkeypatch.setenv("BROWSER_CORE_WORKSPACE", str(selected))

    assert main(["persona", "list"]) == 2
    assert capsys.readouterr().out == ""
    assert main(["--workspace", str(workspace), "persona", "list"]) == 0
    assert json.loads(capsys.readouterr().out) == {"personas": []}

    monkeypatch.setenv("BROWSER_CORE_WORKSPACE", str(workspace))
    assert main(["persona", "list"]) == 0
    assert json.loads(capsys.readouterr().out) == {"personas": []}


@pytest.mark.skipif(os.name != "nt", reason="Win32 selected-input aliases")
@pytest.mark.parametrize("suffix", [".", " "])
def test_persona_add_rejects_normalized_input_alias_before_publication(
    tmp_path: Path, suffix: str, capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = tmp_path / "source.json"
    source.write_text(json.dumps(fixture_persona("alias-input")), encoding="utf-8")
    selected = tmp_path / f"source.json{suffix}"
    assert selected.is_file() and os.path.samefile(selected, source)

    assert main(["--workspace", str(workspace), "persona", "add", str(selected)]) == 2
    assert capsys.readouterr().out == ""
    assert not (workspace / "personas" / "catalog" / "alias-input.json").exists()

    assert main(["--workspace", str(workspace), "persona", "add", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["id"] == "alias-input"
    assert (workspace / "personas" / "catalog" / "alias-input.json").is_file()


@pytest.mark.parametrize("area", ["control", "fleet"])
def test_cli_rejects_empty_control_root_before_store_initialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, area: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BROWSER_PLATFORM_TOKEN", raising=False)
    token_path = tmp_path / "owner.token"
    command = (
        ["bootstrap", "lab", "Lab", "alice", "Alice", "--token-out", str(token_path)]
        if area == "control"
        else ["status", "lab"]
    )
    assert main([area, "--control-root", "", *command]) == 2
    assert not (tmp_path / "control.sqlite3").exists()
    assert not token_path.exists()

    if area == "control":
        assert main([area, "--control-root", ".", *command]) == 0
        assert (tmp_path / "control.sqlite3").is_file()
        assert token_path.is_file()


def test_transport_fingerprint_cli_uses_attested_local_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository_root = tmp_path / "repo"
    executable = tmp_path / "out" / "chrome.exe"
    receipt = {
        "schema": "browser-core.transport-fingerprint/1",
        "digest_sha256": "a" * 64,
        "core_build": {
            "chromium_revision": "b" * 40,
            "executable_sha256_16": "c" * 16,
            "runtime_bundle_sha256_16": "d" * 16,
        },
    }
    calls: list[tuple[Path, Path, float]] = []

    def capture(root: Path, binary: Path, *, timeout_seconds: float):
        calls.append((root, binary, timeout_seconds))
        return receipt

    monkeypatch.setattr(cli_module, "capture_attested_client_hello", capture)

    assert (
        main(
            [
                "transport",
                "fingerprint",
                str(executable),
                "--repository-root",
                str(repository_root),
                "--timeout-seconds",
                "7.5",
            ]
        )
        == 0
    )
    assert calls == [(repository_root.resolve(), executable.resolve(), 7.5)]
    assert json.loads(capsys.readouterr().out) == receipt


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize(
    "command,capture_name,schema",
    [
        ("fingerprint", "capture_attested_client_hello", "browser-core.transport-fingerprint/1"),
        ("http2-fingerprint", "capture_attested_http2_fingerprint", "browser-core.http2-fingerprint/1"),
        ("http2-evidence", "capture_attested_http2_evidence", "browser-core.http2-capture-evidence/1"),
    ],
)
def test_transport_cli_preserves_selected_attestation_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    command: str, capture_name: str, schema: str,
) -> None:
    physical_repo = tmp_path / "physical-repo"
    physical_runtime = tmp_path / "physical-runtime"
    physical_repo.mkdir()
    physical_runtime.mkdir()
    (physical_runtime / "chrome.exe").write_bytes(b"fixture")
    selected_repo = tmp_path / "selected-repo"
    selected_runtime = tmp_path / "selected-runtime"
    for alias, target in (
        (selected_repo, physical_repo),
        (selected_runtime, physical_runtime),
    ):
        linked = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(target)],
            capture_output=True,
        )
        if linked.returncode:
            if selected_repo.exists():
                selected_repo.rmdir()
            pytest.skip("host could not create an unprivileged directory junction")
    calls: list[tuple[Path, Path]] = []

    def capture(root: Path, executable: Path, *_args, **_kwargs) -> dict:
        calls.append((root, executable))
        return {"schema": schema}

    monkeypatch.setattr(cli_module, capture_name, capture)
    try:
        arguments = [
            "transport", command, str(selected_runtime / "chrome.exe"),
            "--repository-root", str(selected_repo),
        ]
        if command != "fingerprint":
            arguments.extend(
                ["--certificate", str(tmp_path / "cert.pem"),
                 "--private-key", str(tmp_path / "key.pem")]
            )
        assert main(
            arguments
        ) == 0
        assert calls == [(selected_repo, selected_runtime / "chrome.exe")]
        assert json.loads(capsys.readouterr().out)["schema"] == schema
    finally:
        selected_runtime.rmdir()
        selected_repo.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_batched_persona_cli_preserves_selected_kernel_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    physical_repo = tmp_path / "physical-repo"
    physical_runtime = tmp_path / "physical-runtime"
    physical_repo.mkdir()
    physical_runtime.mkdir()
    (physical_runtime / "chrome.exe").write_bytes(b"fixture")
    selected_repo = tmp_path / "selected-repo"
    selected_runtime = tmp_path / "selected-runtime"
    for alias, target in (
        (selected_repo, physical_repo),
        (selected_runtime, physical_runtime),
    ):
        linked = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(target)],
            capture_output=True,
        )
        if linked.returncode:
            if selected_repo.exists():
                selected_repo.rmdir()
            pytest.skip("host could not create an unprivileged directory junction")
    calls: list[tuple[Path, str | None]] = []

    def capture(_workspace: Path, root: Path, **kwargs) -> dict:
        calls.append((root, kwargs.get("device_memory_executable")))
        return {"schema": "test-kernel-path-forwarding/1"}

    monkeypatch.setattr(cli_module, "bulk_capture_personas_batched", capture)
    try:
        assert main([
            "--workspace", str(tmp_path), "persona", "bulk-capture", "--batched",
            "--repository-root", str(selected_repo),
            "--device-memory-executable", str(selected_runtime / "chrome.exe"),
        ]) == 0
        assert calls == [(selected_repo, str(selected_runtime / "chrome.exe"))]
        assert json.loads(capsys.readouterr().out)["schema"] == "test-kernel-path-forwarding/1"
    finally:
        selected_runtime.rmdir()
        selected_repo.rmdir()


def test_transport_fingerprint_cli_publishes_a_strict_exclusive_golden(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "golden.json"
    receipt = {
        "schema": "browser-core.transport-fingerprint/1",
        "digest_sha256": "a" * 64,
        "core_build": {
            "chromium_revision": "b" * 40,
            "executable_sha256_16": "c" * 16,
            "runtime_bundle_sha256_16": "d" * 16,
        },
    }
    monkeypatch.setattr(
        cli_module,
        "capture_attested_client_hello",
        lambda *_args, **_kwargs: receipt,
    )

    assert (
        main(
            [
                "transport",
                "fingerprint",
                str(tmp_path / "chrome.exe"),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text(encoding="utf-8")) == receipt
    publication = json.loads(capsys.readouterr().out)
    assert publication == {
        "schema": "browser-core.transport-fingerprint-publication/1",
        "output": str(output.resolve()),
        "digest_sha256": "a" * 64,
        "core_build": receipt["core_build"],
    }

    with pytest.raises(ContractError, match="publication failed"):
        cli_module._write_json(output, {"replacement": True})
    assert json.loads(output.read_text(encoding="utf-8")) == receipt


@pytest.mark.parametrize(
    "command,capture_name",
    [
        ("fingerprint", "capture_attested_client_hello"),
        ("http2-fingerprint", "capture_attested_http2_fingerprint"),
        ("http2-evidence", "capture_attested_http2_evidence"),
    ],
)
@pytest.mark.parametrize("relocate_parent", [False, True])
def test_transport_publication_rechecks_selected_output_after_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], command: str, capture_name: str,
    relocate_parent: bool,
) -> None:
    selected = tmp_path / "selected"
    selected.mkdir()
    output = selected / "capture.json"
    core_build = {"chromium_revision": "b" * 40}
    record = {
        "schema": "fixture/1",
        "digest_sha256": "a" * 64,
        "core_build": core_build,
        "fingerprint": {"digest_sha256": "a" * 64, "core_build": core_build},
        "header_order": {"digest_sha256": "c" * 64},
    }
    monkeypatch.setattr(cli_module, capture_name, lambda *_args, **_kwargs: record)
    if relocate_parent:
        original_write = cli_module._write_json

        def relocate_after_publication(path: Path, value: dict):
            published = original_write(path, value)
            selected.rename(tmp_path / "retained")
            selected.mkdir()
            output.write_text("competitor", encoding="ascii")
            return published

        monkeypatch.setattr(cli_module, "_write_json", relocate_after_publication)

    arguments = [
        "transport", command, str(tmp_path / "chrome.exe"), "--output", str(output),
    ]
    if command != "fingerprint":
        arguments.extend([
            "--certificate", str(tmp_path / "cert.pem"),
            "--private-key", str(tmp_path / "key.pem"),
        ])
    assert main(arguments) == (2 if relocate_parent else 0)
    if relocate_parent:
        assert output.read_text(encoding="ascii") == "competitor"
        assert json.loads((tmp_path / "retained" / output.name).read_text()) == record
    else:
        assert json.loads(output.read_text(encoding="utf-8")) == record
        assert json.loads(capsys.readouterr().out)["output"] == str(output.absolute())


def test_transport_publication_uses_selected_relative_destination_after_cwd_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "selected"
    selected.mkdir()
    shifted = tmp_path / "shifted"
    shifted.mkdir()
    monkeypatch.chdir(tmp_path)
    original_write = cli_module._write_json

    def change_cwd_before_write(path: Path, value: dict):
        monkeypatch.chdir(shifted)
        return original_write(path, value)

    monkeypatch.setattr(cli_module, "_write_json", change_cwd_before_write)
    destination = cli_module._write_transport_json_checked(
        Path("selected/capture.json"), {"schema": "fixture/1"},
    )
    assert destination == selected / "capture.json"
    assert json.loads(destination.read_text(encoding="utf-8")) == {"schema": "fixture/1"}
    assert not (shifted / "selected").exists()


@pytest.mark.parametrize(("passed", "status"), [(True, 0), (False, 1)])
def test_transport_check_cli_surfaces_the_offline_golden_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    passed: bool,
    status: int,
) -> None:
    current = tmp_path / "current.json"
    baseline = tmp_path / "baseline.json"
    current.write_text('{"kind":"current"}', encoding="utf-8")
    baseline.write_text('{"kind":"baseline"}', encoding="utf-8")
    report = {
        "schema": "browser-core.transport-fingerprint-comparison/1",
        "passed": passed,
        "same_digest": passed,
        "changed_fields": [] if passed else ["ciphers"],
    }
    calls: list[tuple[object, object]] = []

    def compare(left: object, right: object):
        calls.append((left, right))
        return report

    monkeypatch.setattr(
        cli_module,
        "load_transport_fingerprint",
        lambda path: {"kind": path.stem},
    )
    monkeypatch.setattr(cli_module, "compare_transport_fingerprints", compare)

    assert main(["transport", "check", str(current), str(baseline)]) == status
    assert calls == [({"kind": "current"}, {"kind": "baseline"})]
    assert json.loads(capsys.readouterr().out) == report


def test_transport_baseline_approval_cli_requires_explicit_digest_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt = {
        "schema": "browser-core.transport-baseline-approval/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden-1",
        "digest_sha256": "a" * 64,
    }
    calls: list[tuple[Path, str, str, str]] = []

    def approve(
        workspace: Path,
        *,
        current_id: str,
        baseline_id: str,
        expected_digest: str,
    ) -> dict:
        calls.append((workspace, current_id, baseline_id, expected_digest))
        return receipt

    monkeypatch.setattr(cli_module, "approve_transport_baseline", approve)
    assert (
        main(
            [
                "--workspace",
                str(tmp_path),
                "transport",
                "approve-baseline",
                "candidate",
                "golden-1",
                "--expected-digest",
                "a" * 64,
            ]
        )
        == 0
    )
    assert calls == [(tmp_path.resolve(), "candidate", "golden-1", "a" * 64)]
    assert json.loads(capsys.readouterr().out) == receipt


def test_http2_fingerprint_cli_uses_attested_loopback_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    executable = tmp_path / "chrome.exe"
    certificate = tmp_path / "cert.pem"
    private_key = tmp_path / "key.pem"
    repository_root = tmp_path / "repo"
    receipt = {
        "schema": "browser-core.http2-fingerprint/1",
        "digest_sha256": "a" * 64,
        "core_build": {
            "chromium_revision": "b" * 40,
            "executable_sha256_16": "c" * 16,
            "runtime_bundle_sha256_16": "d" * 16,
        },
    }
    calls: list[tuple[Path, Path, Path, Path, float]] = []

    def capture(
        root: Path,
        binary: Path,
        cert: Path,
        key: Path,
        *,
        timeout_seconds: float,
    ) -> dict:
        calls.append((root, binary, cert, key, timeout_seconds))
        return receipt

    monkeypatch.setattr(cli_module, "capture_attested_http2_fingerprint", capture)
    assert (
        main(
            [
                "transport",
                "http2-fingerprint",
                str(executable),
                "--certificate",
                str(certificate),
                "--private-key",
                str(private_key),
                "--repository-root",
                str(repository_root),
                "--timeout-seconds",
                "13",
            ]
        )
        == 0
    )
    assert calls == [
        (
            repository_root.resolve(),
            executable.resolve(),
            certificate.resolve(),
            private_key.resolve(),
            13.0,
        )
    ]
    assert json.loads(capsys.readouterr().out) == receipt


def test_http2_evidence_cli_uses_attested_same_connection_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    executable = tmp_path / "chrome.exe"
    certificate = tmp_path / "cert.pem"
    private_key = tmp_path / "key.pem"
    repository_root = tmp_path / "repo"
    receipt = {
        "schema": "browser-core.http2-capture-evidence/1",
        "fingerprint": {"digest_sha256": "a" * 64},
        "header_order": {"digest_sha256": "b" * 64},
        "same_connection": True,
    }
    calls: list[tuple[Path, Path, Path, Path, float]] = []

    def capture(
        root: Path,
        binary: Path,
        cert: Path,
        key: Path,
        *,
        timeout_seconds: float,
    ) -> dict:
        calls.append((root, binary, cert, key, timeout_seconds))
        return receipt

    monkeypatch.setattr(cli_module, "capture_attested_http2_evidence", capture)
    assert (
        main(
            [
                "transport",
                "http2-evidence",
                str(executable),
                "--certificate",
                str(certificate),
                "--private-key",
                str(private_key),
                "--repository-root",
                str(repository_root),
                "--timeout-seconds",
                "13",
            ]
        )
        == 0
    )
    assert calls == [
        (
            repository_root.resolve(),
            executable.resolve(),
            certificate.resolve(),
            private_key.resolve(),
            13.0,
        )
    ]
    assert json.loads(capsys.readouterr().out) == receipt


def test_http2_evidence_baseline_cli_requires_reviewed_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt = {
        "schema": "browser-core.http2-evidence-baseline-approval/1",
        "digest_sha256": "a" * 64,
    }
    calls: list[tuple[Path, str, str, str]] = []

    def approve(
        workspace: Path,
        *,
        current_id: str,
        baseline_id: str,
        expected_digest: str,
    ) -> dict:
        calls.append((workspace, current_id, baseline_id, expected_digest))
        return receipt

    monkeypatch.setattr(cli_module, "approve_http2_evidence_baseline", approve)
    assert (
        main(
            [
                "--workspace",
                str(tmp_path),
                "transport",
                "approve-http2-evidence-baseline",
                "candidate",
                "golden",
                "--expected-digest",
                "a" * 64,
            ]
        )
        == 0
    )
    assert calls == [(tmp_path.resolve(), "candidate", "golden", "a" * 64)]
    assert json.loads(capsys.readouterr().out) == receipt


@pytest.mark.parametrize("status", [0, 1])
def test_http2_evidence_check_cli_surfaces_comparison_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: int,
) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    current = {"kind": "current"}
    baseline = {"evidence": {"kind": "baseline"}}
    report = {
        "schema": "browser-core.http2-capture-evidence-comparison/1",
        "passed": status == 0,
    }
    monkeypatch.setattr(
        cli_module,
        "load_http2_capture_evidence",
        lambda path: current if path == current_path else pytest.fail("wrong current"),
    )
    monkeypatch.setattr(
        cli_module,
        "load_http2_evidence_baseline",
        lambda path: baseline
        if path == baseline_path
        else pytest.fail("wrong baseline"),
    )
    monkeypatch.setattr(
        cli_module,
        "compare_http2_capture_evidence",
        lambda actual, golden: report
        if (actual, golden) == (current, baseline["evidence"])
        else pytest.fail("wrong comparison inputs"),
    )

    assert (
        main(
            [
                "transport",
                "http2-evidence-check",
                str(current_path),
                str(baseline_path),
            ]
        )
        == status
    )
    assert json.loads(capsys.readouterr().out) == report


def test_http2_baseline_approval_cli_requires_explicit_digest_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt = {
        "schema": "browser-core.http2-baseline-approval/1",
        "source_fingerprint_id": "candidate",
        "baseline_fingerprint_id": "golden-1",
        "digest_sha256": "a" * 64,
    }
    calls: list[tuple[Path, str, str, str]] = []

    def approve(
        workspace: Path,
        *,
        current_id: str,
        baseline_id: str,
        expected_digest: str,
    ) -> dict:
        calls.append((workspace, current_id, baseline_id, expected_digest))
        return receipt

    monkeypatch.setattr(cli_module, "approve_http2_baseline", approve)
    assert (
        main(
            [
                "--workspace",
                str(tmp_path),
                "transport",
                "approve-http2-baseline",
                "candidate",
                "golden-1",
                "--expected-digest",
                "a" * 64,
            ]
        )
        == 0
    )
    assert calls == [(tmp_path.resolve(), "candidate", "golden-1", "a" * 64)]
    assert json.loads(capsys.readouterr().out) == receipt


@pytest.mark.parametrize(("passed", "status"), [(True, 0), (False, 1)])
def test_http2_check_cli_surfaces_the_offline_golden_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    passed: bool,
    status: int,
) -> None:
    current = tmp_path / "current.json"
    baseline = tmp_path / "baseline.json"
    report = {
        "schema": "browser-core.http2-fingerprint-comparison/1",
        "passed": passed,
        "same_digest": passed,
        "changed_fields": [] if passed else ["settings"],
    }
    calls: list[tuple[object, object]] = []
    monkeypatch.setattr(
        cli_module,
        "load_http2_fingerprint",
        lambda path: {"kind": "current"},
    )
    monkeypatch.setattr(
        cli_module,
        "load_http2_baseline",
        lambda path: {"fingerprint": {"kind": "baseline"}},
    )

    def compare(left: object, right: object):
        calls.append((left, right))
        return report

    monkeypatch.setattr(cli_module, "compare_http2_fingerprints", compare)
    assert main(["transport", "http2-check", str(current), str(baseline)]) == status
    assert calls == [({"kind": "current"}, {"kind": "baseline"})]
    assert json.loads(capsys.readouterr().out) == report


@pytest.mark.parametrize(("passed", "status"), [(True, 0), (False, 1)])
def test_transport_suite_check_cli_enforces_cross_protocol_build_coherence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    passed: bool,
    status: int,
) -> None:
    paths = [
        tmp_path / name
        for name in ("tls.json", "tls-base.json", "h2.json", "h2-base.json")
    ]
    report = {
        "schema": "browser-core.transport-suite-comparison/1",
        "passed": passed,
        "current_build_coherent": passed,
        "baseline_build_coherent": True,
    }
    calls: list[tuple[object, object, object, object]] = []
    monkeypatch.setattr(
        cli_module,
        "load_transport_fingerprint",
        lambda path: {"kind": "tls-current", "path": path},
    )
    monkeypatch.setattr(
        cli_module,
        "load_transport_baseline",
        lambda path: {"kind": "tls-baseline", "path": path},
    )
    monkeypatch.setattr(
        cli_module,
        "load_http2_fingerprint",
        lambda path: {"kind": "h2-current", "path": path},
    )
    monkeypatch.setattr(
        cli_module,
        "load_http2_baseline",
        lambda path: {"kind": "h2-baseline", "path": path},
    )

    def compare(left: object, left_base: object, right: object, right_base: object):
        calls.append((left, left_base, right, right_base))
        return report

    monkeypatch.setattr(cli_module, "compare_transport_suite", compare)
    assert main(["transport", "suite-check", *(str(path) for path in paths)]) == status
    assert calls == [
        (
            {"kind": "tls-current", "path": paths[0]},
            {"kind": "tls-baseline", "path": paths[1]},
            {"kind": "h2-current", "path": paths[2]},
            {"kind": "h2-baseline", "path": paths[3]},
        )
    ]
    assert json.loads(capsys.readouterr().out) == report


@pytest.mark.parametrize(("passed", "status"), [(True, 0), (False, 1)])
def test_transport_evidence_suite_cli_gates_same_connection_header_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    passed: bool,
    status: int,
) -> None:
    paths = [
        tmp_path / name
        for name in ("tls.json", "tls-base.json", "h2e.json", "h2e-base.json")
    ]
    report = {
        "schema": "browser-core.transport-evidence-suite-comparison/1",
        "passed": passed,
    }
    monkeypatch.setattr(
        cli_module,
        "load_transport_fingerprint",
        lambda path: {"kind": "tls-current", "path": path},
    )
    monkeypatch.setattr(
        cli_module,
        "load_transport_baseline",
        lambda path: {"kind": "tls-baseline", "path": path},
    )
    monkeypatch.setattr(
        cli_module,
        "load_http2_capture_evidence",
        lambda path: {"kind": "h2e-current", "path": path},
    )
    monkeypatch.setattr(
        cli_module,
        "load_http2_evidence_baseline",
        lambda path: {"kind": "h2e-baseline", "path": path},
    )
    calls: list[tuple[object, object, object, object]] = []

    def compare(left: object, left_base: object, right: object, right_base: object):
        calls.append((left, left_base, right, right_base))
        return report

    monkeypatch.setattr(cli_module, "compare_transport_evidence_suite", compare)
    assert (
        main(["transport", "evidence-suite-check", *(str(path) for path in paths)])
        == status
    )
    assert calls == [
        (
            {"kind": "tls-current", "path": paths[0]},
            {"kind": "tls-baseline", "path": paths[1]},
            {"kind": "h2e-current", "path": paths[2]},
            {"kind": "h2e-baseline", "path": paths[3]},
        )
    ]
    assert json.loads(capsys.readouterr().out) == report


@pytest.mark.parametrize(
    ("warning_count", "failed_count", "expected_status"),
    [(0, 0, 0), (1, 0, 1), (0, 1, 1), (1, 1, 1)],
)
def test_retirement_cli_emits_its_receipt_and_surfaces_attention_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    warning_count: int,
    failed_count: int,
    expected_status: int,
) -> None:
    report = {
        "schema": "browser-core.persona-retirement/3",
        "warning_count": warning_count,
        "failed_count": failed_count,
    }
    calls = []

    def retire(workspace, *, dry_run, minimum_claims):
        calls.append((workspace, dry_run, minimum_claims))
        return report

    monkeypatch.setattr(cli_module, "retire_incoherent_personas", retire)
    status = main(
        [
            "--workspace",
            str(tmp_path),
            "persona",
            "retire-incoherent",
            "--apply",
            "--minimum-claims",
            "7",
        ]
    )

    assert status == expected_status
    assert json.loads(capsys.readouterr().out) == report
    assert calls == [(tmp_path.resolve(), False, 7)]


@pytest.mark.parametrize("command", ["uniqueness", "quality"])
@pytest.mark.parametrize(("passed", "expected_status"), [(True, 0), (False, 1)])
def test_persona_quality_gates_return_their_verdict_as_process_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    passed: bool,
    expected_status: int,
) -> None:
    report = {"schema": f"test.{command}/1", "passed": passed}
    function_name = (
        "catalog_uniqueness" if command == "uniqueness" else "catalog_quality_report"
    )
    monkeypatch.setattr(cli_module, function_name, lambda *_args, **_kwargs: report)

    extra = ["--json"] if command == "uniqueness" else []
    status = main(["--workspace", str(tmp_path), "persona", command, *extra])

    assert status == expected_status
    assert json.loads(capsys.readouterr().out) == report


def test_control_bootstrap_secret_collision_rolls_back(tmp_path: Path) -> None:
    control_root = tmp_path / "control"
    owner_token = tmp_path / "owner.token"
    owner_token.write_text("occupied", encoding="ascii")
    command = [
        "control", "--control-root", str(control_root), "bootstrap",
        "lab", "Lab", "alice", "Alice", "--token-out", str(owner_token),
    ]

    assert main(command) == 2
    with sqlite3.connect(control_root / "control.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0
    owner_token.unlink()
    assert main(command) == 0
    assert ControlStore(control_root).authenticate(owner_token.read_text().strip()).user_id == "alice"


@pytest.mark.parametrize("operation", ["bootstrap", "token-issue", "worker-register"])
def test_control_secret_callback_rejects_relocated_output_parent_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    control_root = tmp_path / "control"
    if operation != "bootstrap":
        owner_token = tmp_path / "owner.token"
        assert main([
            "control", "--control-root", str(control_root), "bootstrap",
            "lab", "Lab", "alice", "Alice", "--token-out", str(owner_token),
        ]) == 0
        store = ControlStore(control_root)
        monkeypatch.setenv("BROWSER_PLATFORM_TOKEN", owner_token.read_text().strip())
        if operation == "token-issue":
            store.add_member(
                store.authenticate(owner_token.read_text().strip()), "lab",
                user_id="bob", display_name="Bob", role="viewer",
            )

    selected = tmp_path / "selected"
    selected.mkdir()
    destination = selected / "new.token"
    if operation == "bootstrap":
        command = [
            "control", "--control-root", str(control_root), "bootstrap",
            "lab", "Lab", "alice", "Alice", "--token-out", str(destination),
        ]
        table = "workspaces"
    elif operation == "token-issue":
        command = [
            "control", "--control-root", str(control_root), "token-issue",
            "lab", "bob", "--token-out", str(destination),
        ]
        table = "tokens"
    else:
        command = [
            "fleet", "--control-root", str(control_root), "worker-register",
            "lab", "worker-one", "Worker", "--capability", "chromium",
            "--worker-token-out", str(destination),
        ]
        table = "workers"
    if operation == "bootstrap":
        before = 0
    else:
        with sqlite3.connect(control_root / "control.sqlite3") as db:
            before = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    original_write = cli_module._write_secret

    def relocate_after_publication(path: Path, token: str):
        published = original_write(path, token)
        selected.rename(tmp_path / "retained")
        selected.mkdir()
        destination.write_text("competitor", encoding="ascii")
        return published

    monkeypatch.setattr(cli_module, "_write_secret", relocate_after_publication)
    assert main(command) == 2
    assert destination.read_text(encoding="ascii") == "competitor"
    assert (tmp_path / "retained" / "new.token").is_file()
    with sqlite3.connect(control_root / "control.sqlite3") as db:
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == before


def test_control_secret_receipts_report_selected_absolute_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    control_root = tmp_path / "control"
    owner_token = tmp_path / "owner.token"
    assert main([
        "control", "--control-root", str(control_root), "bootstrap",
        "lab", "Lab", "alice", "Alice", "--token-out", str(owner_token),
    ]) == 0
    assert json.loads(capsys.readouterr().out)["token_file"] == str(owner_token.absolute())

    store = ControlStore(control_root)
    owner = owner_token.read_text(encoding="ascii").strip()
    monkeypatch.setenv("BROWSER_PLATFORM_TOKEN", owner)
    store.add_member(
        store.authenticate(owner), "lab", user_id="bob", display_name="Bob", role="viewer",
    )
    issued_token = tmp_path / "issued.token"
    assert main([
        "control", "--control-root", str(control_root), "token-issue",
        "lab", "bob", "--token-out", str(issued_token),
    ]) == 0
    assert json.loads(capsys.readouterr().out)["token_file"] == str(issued_token.absolute())

    worker_token = tmp_path / "worker.token"
    assert main([
        "fleet", "--control-root", str(control_root), "worker-register",
        "lab", "worker-one", "Worker", "--capability", "chromium",
        "--worker-token-out", str(worker_token),
    ]) == 0
    assert json.loads(capsys.readouterr().out)["worker_token_file"] == str(worker_token.absolute())


@pytest.mark.parametrize("operation", ["bootstrap", "token-issue", "worker-register"])
def test_control_secret_receipt_keeps_callback_selected_relative_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    operation: str,
) -> None:
    control_root = tmp_path / "control"
    if operation != "bootstrap":
        owner_token = tmp_path / "owner.token"
        assert main([
            "control", "--control-root", str(control_root), "bootstrap",
            "lab", "Lab", "alice", "Alice", "--token-out", str(owner_token),
        ]) == 0
        capsys.readouterr()
        owner = owner_token.read_text(encoding="ascii").strip()
        monkeypatch.setenv("BROWSER_PLATFORM_TOKEN", owner)
        if operation == "token-issue":
            store = ControlStore(control_root)
            store.add_member(
                store.authenticate(owner), "lab", user_id="bob",
                display_name="Bob", role="viewer",
            )

    selected = tmp_path / "selected"
    selected.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(selected)
    original_publish = cli_module._publish_secret_checked

    def publish_then_change_cwd(path: Path, token: str) -> None:
        original_publish(path, token)
        monkeypatch.chdir(other)

    monkeypatch.setattr(cli_module, "_publish_secret_checked", publish_then_change_cwd)
    if operation == "bootstrap":
        command = [
            "control", "--control-root", str(control_root), "bootstrap",
            "lab", "Lab", "alice", "Alice", "--token-out", "new.token",
        ]
        receipt_field = "token_file"
    elif operation == "token-issue":
        command = [
            "control", "--control-root", str(control_root), "token-issue",
            "lab", "bob", "--token-out", "new.token",
        ]
        receipt_field = "token_file"
    else:
        command = [
            "fleet", "--control-root", str(control_root), "worker-register",
            "lab", "worker-one", "Worker", "--capability", "chromium",
            "--worker-token-out", "new.token",
        ]
        receipt_field = "worker_token_file"
    assert main(command) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert (selected / "new.token").is_file()
    assert not (other / "new.token").exists()
    assert receipt[receipt_field] == str(selected / "new.token")


def test_control_token_issue_secret_collision_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_root = tmp_path / "control"
    owner_token = tmp_path / "owner.token"
    assert main([
        "control", "--control-root", str(control_root), "bootstrap",
        "lab", "Lab", "alice", "Alice", "--token-out", str(owner_token),
    ]) == 0
    store = ControlStore(control_root)
    store.add_member(
        store.authenticate(owner_token.read_text().strip()), "lab",
        user_id="bob", display_name="Bob", role="viewer",
    )
    monkeypatch.setenv("BROWSER_PLATFORM_TOKEN", owner_token.read_text().strip())
    target = tmp_path / "bob.token"
    target.write_text("occupied", encoding="ascii")
    with sqlite3.connect(store.database_path) as db:
        before = db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]

    assert main([
        "control", "--control-root", str(control_root), "token-issue",
        "lab", "bob", "--token-out", str(target),
    ]) == 2
    with sqlite3.connect(store.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == before


def test_worker_rotation_secret_collision_preserves_previous_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_root = tmp_path / "control"
    owner_token = tmp_path / "owner.token"
    assert main([
        "control", "--control-root", str(control_root), "bootstrap",
        "lab", "Lab", "alice", "Alice", "--token-out", str(owner_token),
    ]) == 0
    monkeypatch.setenv("BROWSER_PLATFORM_TOKEN", owner_token.read_text().strip())
    worker_token = tmp_path / "worker.token"
    register = [
        "fleet", "--control-root", str(control_root), "worker-register",
        "lab", "worker-one", "Worker", "--capability", "chromium",
        "--worker-token-out", str(worker_token),
    ]
    assert main(register) == 0
    previous = worker_token.read_text().strip()
    collision = tmp_path / "occupied.token"
    collision.write_text("occupied", encoding="ascii")

    assert main([*register[:-1], str(collision)]) == 2
    store = ControlStore(control_root)
    assert store.authenticate_worker(previous).worker_id == "worker-one"
    with sqlite3.connect(store.database_path) as db:
        assert db.execute("SELECT revision FROM workers WHERE id='worker-one'").fetchone()[0] == 1


def test_control_and_typed_worker_cli_roundtrip(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    control_root = tmp_path / "control"
    owner_token = tmp_path / "owner.token"
    worker_token = tmp_path / "worker.token"
    runtime = tmp_path / "runtime"
    assert (
        main(
            [
                "control",
                "--control-root",
                str(control_root),
                "bootstrap",
                "lab",
                "Lab",
                "alice",
                "Alice",
                "--token-out",
                str(owner_token),
            ]
        )
        == 0
    )
    bootstrap_output = capsys.readouterr().out
    assert "bc1." not in bootstrap_output and owner_token.is_file()
    monkeypatch.setenv(
        "BROWSER_PLATFORM_TOKEN", owner_token.read_text(encoding="utf-8").strip()
    )
    assert (
        main(
            [
                "fleet",
                "--control-root",
                str(control_root),
                "worker-register",
                "lab",
                "wk",
                "Worker",
                "--capability",
                "webkit",
                "--worker-token-out",
                str(worker_token),
            ]
        )
        == 0
    )
    assert "bcw1." not in capsys.readouterr().out and worker_token.is_file()
    payload = tmp_path / "payload.json"
    payload.write_text(
        json.dumps(
            {
                "kernel_id": "playwright-webkit",
                "device_preset": "iPhone 13",
                "locale": "en-US",
                "timezone": "America/Chicago",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("JOB_KEY", "cli-live-job")
    assert (
        main(
            [
                "fleet",
                "--control-root",
                str(control_root),
                "enqueue",
                "lab",
                "kernel-probe",
                str(payload),
                "JOB_KEY",
                "--requirement",
                "webkit",
            ]
        )
        == 0
    )
    capsys.readouterr()
    monkeypatch.setenv(
        "BROWSER_PLATFORM_WORKER_TOKEN",
        worker_token.read_text(encoding="utf-8").strip(),
    )
    assert (
        main(
            [
                "--workspace",
                str(runtime),
                "fleet",
                "--control-root",
                str(control_root),
                "worker-once",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["leased"] is True and output["job"]["state"] == "succeeded"


def test_every_reviewed_job_kind_is_enqueueable_from_both_cli_surfaces() -> None:
    from browser_core.control import JOB_KINDS

    command_parser = cli_module.parser()
    for kind in sorted(JOB_KINDS):
        local = command_parser.parse_args(
            ["fleet", "enqueue", "lab", kind, "payload.json", "JOB_KEY"]
        )
        remote = command_parser.parse_args(
            [
                "fleet",
                "remote-enqueue",
                "https://control.invalid",
                "lab",
                kind,
                "payload.json",
                "JOB_KEY",
            ]
        )
        assert local.kind == kind
        assert remote.kind == kind
