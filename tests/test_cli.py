from __future__ import annotations

import json
import io
import importlib
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.cli as cli
from browser_core.argument_capture import HOOK_TARGETS, parse_harvest
from browser_core.contracts import ContractError, load_session
from browser_core.cli import build_parser, command_stream_scope_smoke
from browser_core.profiles import create_profile
from browser_core.proxy_import import load_proxy_secret, parse_proxy_line, store_proxy_secret


def test_profile_create_rejects_empty_workspace_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BROWSER_CORE_WORKSPACE", raising=False)
    with pytest.raises(SystemExit) as failure:
        cli.main(["profile", "create", "accidental", "--workspace", ""])
    assert failure.value.code == 2
    assert not (tmp_path / "profiles").exists()

    assert cli.main(["profile", "create", "intentional", "--workspace", "."]) == 0
    assert (tmp_path / "profiles" / "registry" / "intentional.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Win32 directory-name normalization")
@pytest.mark.parametrize("suffix", [".", " "])
def test_profile_create_rejects_normalized_workspace_alias_before_publication(
    tmp_path: Path, suffix: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    selected = tmp_path / f"workspace{suffix}"
    assert selected.is_dir() and os.path.samefile(selected, workspace)

    with pytest.raises(SystemExit) as failure:
        cli.main(["profile", "create", "aliased", "--workspace", str(selected)])
    assert failure.value.code == 2
    assert not (workspace / "profiles").exists()

    assert cli.main(["profile", "create", "direct", "--workspace", str(workspace)]) == 0
    assert (workspace / "profiles" / "registry" / "direct.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Win32 directory-name normalization")
@pytest.mark.parametrize("suffix", [".", " "])
def test_profile_create_rejects_environment_workspace_alias_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    selected = tmp_path / f"workspace{suffix}"
    assert selected.is_dir() and os.path.samefile(selected, workspace)
    monkeypatch.setenv("BROWSER_CORE_WORKSPACE", str(selected))

    assert cli.main(["profile", "create", "aliased"]) == 2
    assert not (workspace / "profiles").exists()

    assert cli.main(["profile", "create", "direct", "--workspace", str(workspace)]) == 0
    assert (workspace / "profiles" / "registry" / "direct.json").is_file()

    monkeypatch.setenv("BROWSER_CORE_WORKSPACE", str(workspace))
    assert cli.main(["profile", "create", "ambient-direct"]) == 0
    assert (workspace / "profiles" / "registry" / "ambient-direct.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Win32 selected-input aliases")
@pytest.mark.parametrize("suffix", [".", " "])
def test_script_identity_rejects_normalized_input_alias(
    tmp_path: Path, suffix: str, capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "source.js"
    source.write_bytes(b"const fixture = 1;")
    selected = tmp_path / f"source.js{suffix}"
    assert selected.is_file() and os.path.samefile(selected, source)

    assert cli.main(["observe", "script-identity", str(selected)]) == 2
    assert capsys.readouterr().out == ""

    assert cli.main(["observe", "script-identity", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["signals"]["bytes"] == len(source.read_bytes())


@pytest.mark.skipif(os.name != "nt", reason="Win32 selected-session aliases")
@pytest.mark.parametrize("part", ["parent", "leaf"])
@pytest.mark.parametrize(
    "route,module_name,function_name,extra",
    [
        ("session-query", "browser_core.session_query", "session_query", []),
        ("session-inventory", "browser_core.metadata_inventory_query", "session_inventory", []),
        ("session-rows", "browser_core.metadata_rows", "session_rows", []),
        ("session-compare", "browser_core.metadata_compare", "session_compare", ["--anchor-api", "fetch.request.start"]),
    ],
)
def test_trace_session_commands_preserve_selected_path_for_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    part: str, route: str, module_name: str, function_name: str, extra: list[str],
) -> None:
    from test_contracts import session

    parent = tmp_path / "sessions"
    parent.mkdir()
    ordinary = parent / "run.json"
    ordinary.write_text(json.dumps(session()), encoding="utf-8")
    selected = (
        tmp_path / "sessions." / "run.json"
        if part == "parent"
        else parent / "run.json."
    )
    assert selected.is_file() and os.path.samefile(selected, ordinary)

    seen: list[Path] = []

    def read(path: Path, *args: object, **kwargs: object) -> dict:
        seen.append(path)
        load_session(path)
        raise ContractError("fixture reader stopped")

    monkeypatch.setattr(importlib.import_module(module_name), function_name, read)
    command = ["trace", route, "--session", str(selected), "--expected-run-id", "test-run", *extra]
    assert cli.main(command) == 2
    capsys.readouterr()
    assert seen == [selected.absolute()]

    seen.clear()
    command[3] = str(ordinary)
    assert cli.main(command) == 2
    capsys.readouterr()
    assert seen == [ordinary.absolute()]


def test_session_validate_does_not_publish_stale_session_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from test_contracts import session

    contracts_module = importlib.import_module("browser_core.contracts")
    path = tmp_path / "session.json"
    original = session()
    changed = {**original, "run_id": "next-run"}
    original_body = json.dumps(original, sort_keys=True).encode("utf-8")
    changed_body = json.dumps(changed, sort_keys=True).encode("utf-8")
    assert len(original_body) == len(changed_body)
    path.write_bytes(original_body)
    before = path.stat()
    real_validate = contracts_module.validate_session

    def change_during_validation(document: dict) -> dict:
        validated = real_validate(document)
        path.write_bytes(changed_body)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return validated

    monkeypatch.setattr(contracts_module, "validate_session", change_during_validation)
    assert cli.main(["session", "validate", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "changed during load" in output.err
    assert str(path) not in output.err
    assert path.read_bytes() == changed_body


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize(
    "route,module_name,function_name,extra",
    [
        ("evidence-inventory", "browser_core.metadata_inventory_query", "evidence_inventory", []),
        ("evidence-rows", "browser_core.metadata_rows", "evidence_rows", []),
        ("evidence-compare", "browser_core.metadata_compare", "evidence_compare", ["--anchor-api", "fetch.request.start"]),
    ],
)
def test_trace_evidence_commands_preserve_selected_reader_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    route: str, module_name: str, function_name: str, extra: list[str],
) -> None:
    physical = tmp_path / "physical-runtime"
    physical.mkdir()
    (physical / "chrome.exe").write_bytes(b"fixture")
    selected = tmp_path / "selected-runtime"
    linked = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(selected), str(physical)],
        capture_output=True,
    )
    if linked.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    calls: list[Path] = []
    module = importlib.import_module(module_name)

    def capture(_bundle: Path, _root: Path, reader: Path, **_kwargs) -> dict:
        calls.append(reader)
        return {"schema": "test-reader-forwarding/1"}

    monkeypatch.setattr(module, function_name, capture)
    try:
        assert cli.main([
            "trace", route, "--bundle", str(tmp_path / "bundle"),
            "--reader-executable", str(selected / "chrome.exe"), *extra,
        ]) == 0
        assert calls == [selected / "chrome.exe"]
    finally:
        selected.rmdir()


@pytest.mark.parametrize(
    ("stored", "sticky"), [(False, False), (True, False), (True, True)]
)
def test_network_session_preview_does_not_echo_identity_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stored: bool, sticky: bool
) -> None:
    key = "private-identity-key"
    monkeypatch.setattr(cli, "describe_route", lambda *_args: {"sticky_capable": sticky})
    monkeypatch.setattr(cli, "has_proxy_secret", lambda *_args: stored)
    monkeypatch.setattr(
        cli,
        "load_proxy_secret",
        lambda *_args: {"session": {
            "grammar": "dash-token", "session_key": "sessid",
            "session_id_length": 10, "session_minutes": 10,
        }},
    )
    args = SimpleNamespace(workspace=tmp_path, route_id="route-1", session_key=key)

    result = cli._session_preview(args)
    assert key not in json.dumps(result)
    assert result["session_key_supplied"] is True
    assert result["sticky_capable"] is sticky


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_cli_workspace_keeps_junction_visible_to_secret_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    external = tmp_path / "external"
    store_proxy_secret(
        external,
        "route-1",
        parse_proxy_line("user:pass@proxy.example:8080"),
    )
    junction = tmp_path / "workspace"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
        capture_output=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        monkeypatch.setenv("BROWSER_CORE_WORKSPACE", str(junction))
        for workspace in (cli._required_workspace(junction), cli._required_workspace()):
            with pytest.raises(ContractError, match="proxy secret directory"):
                load_proxy_secret(workspace, "route-1")
    finally:
        junction.rmdir()


def _empty_argument_capture() -> dict:
    return parse_harvest(
        json.dumps(
            {
                "records": [],
                "total_samples": 0,
                "dropped": 0,
                "record_failures": 0,
                "installed": {target.name: "ok" for target in HOOK_TARGETS},
                "self_suppressed": 0,
            }
        )
    )


def test_cli_document_loader_is_bounded_strict_and_no_follow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "document.json"
    source.write_bytes(b'{"value":1}')
    assert cli._load_cli_json(source) == {"value": 1}

    for body, message in (
        (b'{"value":1,"value":2}', "duplicate key"),
        (b'{"value":NaN}', "non-finite"),
        (b'{"value":1e400}', "non-finite"),
        (b"\xff", "not valid UTF-8 JSON"),
    ):
        source.write_bytes(body)
        with pytest.raises(ContractError, match=message):
            cli._load_cli_json(source)

    source.write_bytes(b"{}")
    monkeypatch.setattr(cli, "MAX_CLI_DOCUMENT_BYTES", 1)
    with pytest.raises(ContractError, match="exceeds"):
        cli._load_cli_json(source)


@pytest.mark.parametrize(
    ("claim_ready", "coherent", "expected"),
    [(True, True, 0), (False, True, 1), (False, False, 1)],
)
def test_worker_coherence_cli_requires_collector_equivalent_claim(
    monkeypatch: pytest.MonkeyPatch,
    claim_ready: bool,
    coherent: bool,
    expected: int,
) -> None:
    monkeypatch.setattr(
        cli,
        "check_worker_realm_coherence",
        lambda *_args, **_kwargs: {
            "coherent": coherent,
            "worker_coherence_claim_ready": claim_ready,
        },
    )
    monkeypatch.setattr(cli, "_json", lambda _value: None)
    args = build_parser().parse_args(
        ["browser-fact", "worker-coherence", "--session", "session.json"]
    )

    assert args.func(args) == expected


def test_trace_summary_cli_exposes_all_bounded_edge_limits() -> None:
    defaults = build_parser().parse_args(["trace", "summary", "trace.jsonl"])
    configured = build_parser().parse_args(
        [
            "trace",
            "summary",
            "trace.jsonl",
            "--callback-edge-limit",
            "1",
            "--promise-edge-limit",
            "2",
            "--dynamic-code-edge-limit",
            "3",
        ]
    )

    assert (
        defaults.callback_edge_limit,
        defaults.promise_edge_limit,
        defaults.dynamic_code_edge_limit,
    ) == (64, 64, 64)
    assert (
        configured.callback_edge_limit,
        configured.promise_edge_limit,
        configured.dynamic_code_edge_limit,
    ) == (1, 2, 3)


def test_evidence_pack_cli_passes_the_transport_fingerprint_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def build(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"schema": "browser-core.evidence-pack/1"}

    monkeypatch.setattr(cli, "build_evidence_pack", build)
    monkeypatch.setattr(cli, "_json", lambda _value: None)
    args = build_parser().parse_args(
        [
            "evidence",
            "pack",
            "--session",
            str(tmp_path / "session.json"),
            "--out",
            str(tmp_path / "pack"),
            "--transport-fingerprint",
            str(tmp_path / "transport.json"),
        ]
    )

    assert args.func(args) == 0
    assert captured["transport_fingerprint_path"] == tmp_path / "transport.json"


def test_evidence_pack_cli_passes_the_http2_fingerprint_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def build(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"schema": "browser-core.evidence-pack/1"}

    monkeypatch.setattr(cli, "build_evidence_pack", build)
    monkeypatch.setattr(cli, "_json", lambda _value: None)
    args = build_parser().parse_args(
        [
            "evidence",
            "pack",
            "--session",
            str(tmp_path / "session.json"),
            "--out",
            str(tmp_path / "pack"),
            "--http2-fingerprint",
            str(tmp_path / "http2.json"),
        ]
    )

    assert args.func(args) == 0
    assert captured["http2_fingerprint_path"] == tmp_path / "http2.json"


def test_evidence_pack_cli_passes_the_http2_evidence_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def build(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"schema": "browser-core.evidence-pack/1"}

    monkeypatch.setattr(cli, "build_evidence_pack", build)
    monkeypatch.setattr(cli, "_json", lambda _value: None)
    args = build_parser().parse_args(
        [
            "evidence",
            "pack",
            "--session",
            str(tmp_path / "session.json"),
            "--out",
            str(tmp_path / "pack"),
            "--http2-evidence",
            str(tmp_path / "http2-evidence.json"),
        ]
    )

    assert args.func(args) == 0
    assert captured["http2_evidence_path"] == tmp_path / "http2-evidence.json"


def test_cli_population_overflow_is_not_silently_treated_as_junk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "one.json").write_bytes(b"{}")
    (tmp_path / "two.json").write_bytes(b"{}")
    monkeypatch.setattr(cli, "MAX_CLI_POPULATION_FILES", 1)

    with pytest.raises(ContractError, match="population exceeds"):
        cli._failed_arm_labels(tmp_path)


def test_cli_population_refuses_linked_candidate(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"{}")
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {type(exc).__name__}")

    with pytest.raises(ContractError, match="non-regular"):
        cli._failed_arm_labels(tmp_path)


def test_cli_population_detects_root_inventory_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "one.json").write_bytes(b"{}")
    real_lstat = cli.os.lstat
    root_calls = 0

    def mutate_before_final_root_stat(path: Path):  # type: ignore[no-untyped-def]
        nonlocal root_calls
        if Path(path) == tmp_path:
            root_calls += 1
            if root_calls == 2:
                (tmp_path / "appeared.json").write_bytes(b"{}")
        return real_lstat(path)

    monkeypatch.setattr(cli.os, "lstat", mutate_before_final_root_stat)

    with pytest.raises(ContractError, match="changed during inventory"):
        cli._bounded_population_paths(
            tmp_path,
            "*.json",
            per_file_maximum=1024,
            label="test population",
        )


def test_profile_state_cli_captures_and_lists_redacted_receipts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    create_profile(tmp_path, "research-main", "Research Main")
    private_state = (
        tmp_path / "profiles" / "data" / "research-main" / "Default" / "Cookies"
    )
    private_state.parent.mkdir()
    private_state.write_bytes(b"private-cookie-value")

    assert (
        cli.main(
            [
                "profile",
                "state-digest",
                "research-main",
                "after-stop-1",
                "--workspace",
                str(tmp_path),
            ]
        )
        == 0
    )
    captured = json.loads(capsys.readouterr().out)
    assert captured["snapshot_id"] == "after-stop-1"
    assert captured["state"]["files"] == 1
    assert "private-cookie-value" not in json.dumps(captured)

    assert (
        cli.main(
            [
                "profile",
                "state-list",
                "research-main",
                "--workspace",
                str(tmp_path),
            ]
        )
        == 0
    )
    listed = json.loads(capsys.readouterr().out)
    assert listed == {"profile_id": "research-main", "receipts": [captured]}


def test_cli_secret_stdin_and_console_output_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    monkeypatch.setattr(cli, "MAX_PROXY_STDIN_BYTES", 4)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("12345\nprivate"))
    with pytest.raises(ContractError, match="exceeds") as raised:
        cli._read_secret_line()
    assert "private" not in str(raised.value)

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("\ud800\n"))
    with pytest.raises(ContractError, match="encoding") as raised:
        cli._read_secret_line()
    assert "\\ud800" not in str(raised.value)

    with pytest.raises(ContractError, match="strict JSON"):
        cli._json({"value": float("nan")})
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("padding", ["\u00a0", "\u2028"])
def test_cli_secret_stdin_does_not_strip_non_ascii_whitespace(
    monkeypatch: pytest.MonkeyPatch, padding: str
) -> None:
    line = f"{padding}http://user:pass@proxy.example:8080\n"
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(line))
    with pytest.raises(ContractError, match="whitespace"):
        parse_proxy_line(cli._read_secret_line())


@pytest.mark.parametrize("kind", ["choice", "unknown"])
def test_network_cli_parse_errors_do_not_echo_a_supplied_credential(
    capsys, kind: str
) -> None:
    sensitive = "http://user:CredentialMarker@proxy.example:8080"
    tail = (["--protocol", sensitive] if kind == "choice" else ["--unexpected", sensitive])
    try:
        result = cli.main(["network", "import", "route-1", *tail])
    except SystemExit as exc:
        result = exc.code
    assert result == 2
    assert sensitive not in capsys.readouterr().err


def test_cli_console_json_normalizes_encoder_recursion(capsys) -> None:
    value: object = 0
    for _ in range(2_000):
        value = [value]

    with pytest.raises(ContractError, match="strict JSON"):
        cli._json(value)

    assert capsys.readouterr().out == ""


def test_cli_console_json_cap_includes_windows_newline_translation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = {"a": 1}
    rendered = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)
    expected = (rendered + "\n").replace("\n", "\r\n").encode("ascii")
    sink = io.StringIO(newline="\r\n")
    monkeypatch.setattr(cli.sys, "stdout", sink)

    monkeypatch.setattr(cli, "MAX_CLI_STDOUT_BYTES", len(expected) - 1)
    with pytest.raises(ContractError, match="CLI output exceeds byte limit"):
        cli._json(value)
    assert sink.getvalue() == ""

    monkeypatch.setattr(cli, "MAX_CLI_STDOUT_BYTES", len(expected))
    cli._json(value)
    assert sink.getvalue().encode("ascii") == expected


def test_stream_scope_smoke_cli_contract() -> None:
    args = build_parser().parse_args([
        "smoke",
        "stream-scope-isolation",
        "--executable",
        "C:/browser/chrome.exe",
        "--trace-processor",
        "C:/browser/trace_processor_shell.exe",
        "--workspace",
        "C:/browser-core-workspace",
    ])

    assert args.func is command_stream_scope_smoke
    assert args.reads == 128
    assert args.warmup_reads == 8


def test_doctor_finds_workspace_local_depot_tools(
    monkeypatch, tmp_path, capsys
) -> None:
    workspace = tmp_path / "workspace"
    depot_tools = workspace / "depot_tools"
    depot_tools.mkdir(parents=True)
    (workspace / "chromium" / "src").mkdir(parents=True)

    def which(name: str, path: str | None = None) -> str | None:
        if path is None:
            return f"C:/tools/{name}.exe" if name in {"git", "python"} else None
        if path == str(depot_tools) and name in {"gclient", "gn", "autoninja"}:
            return str(depot_tools / f"{name}.bat")
        return None

    monkeypatch.setattr(cli, "_workspace", lambda: workspace)
    monkeypatch.setattr(cli.shutil, "which", which)

    assert cli.command_doctor(SimpleNamespace()) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ready_for_checkout"] is True
    assert report["ready_for_build"] is True
    assert report["workspace_exists"] is True
    assert report["chromium_source_exists"] is True
    assert report["depot_tools_exists"] is True
    assert report["commands"]["gn"] == str(depot_tools / "gn.bat")


@pytest.mark.parametrize(
    ("missing_command", "source_exists"),
    [
        ("git", True),
        ("python", True),
        ("gclient", True),
        ("gn", True),
        ("autoninja", True),
        (None, False),
    ],
)
def test_doctor_build_readiness_requires_checkout_and_all_core_commands(
    monkeypatch,
    tmp_path,
    capsys,
    missing_command: str | None,
    source_exists: bool,
) -> None:
    workspace = tmp_path / "workspace"
    depot_tools = workspace / "depot_tools"
    depot_tools.mkdir(parents=True)
    if source_exists:
        (workspace / "chromium" / "src").mkdir(parents=True)

    def which(name: str, path: str | None = None) -> str | None:
        if name == missing_command:
            return None
        if path is None:
            return f"C:/tools/{name}.exe" if name in {"git", "python"} else None
        if path == str(depot_tools) and name in {"gclient", "gn", "autoninja"}:
            return str(depot_tools / f"{name}.bat")
        return None

    monkeypatch.setattr(cli, "_workspace", lambda: workspace)
    monkeypatch.setattr(cli.shutil, "which", which)

    assert cli.command_doctor(SimpleNamespace()) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["ready_for_build"] is False
    assert report["chromium_source_exists"] is source_exists
    if missing_command in {"git", "python"}:
        assert report["ready_for_checkout"] is False


def _walk_commands(parser, path: str = "") -> list[tuple[str, str]]:
    """Yield (dotted-command-path, help-text) for every subcommand in the tree."""
    import argparse

    rows: list[tuple[str, str]] = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                help_text = next(
                    (c.help or "" for c in action._choices_actions if c.dest == name), ""
                )
                full = f"{path} {name}".strip()
                rows.append((full, help_text))
                rows.extend(_walk_commands(sub, full))
    return rows


def test_every_command_has_help_text() -> None:
    """Discoverability is the whole interface for an operator with no memory.

    This tool's intended user is an agent that arrives cold every session and
    pays a round trip plus context for each `--help`. Measured 2026-08-06 before
    this guard: the author of the `observe` module could not recall its own
    subcommand names 18 hours after writing it, and guessed three wrong. An
    undocumented command is effectively an undiscoverable one, so a missing
    help string is a defect rather than a cosmetic gap.
    """
    undocumented = [name for name, help_text in _walk_commands(build_parser()) if not help_text.strip()]
    assert not undocumented, f"commands without help text: {undocumented}"


def test_command_tree_is_non_trivial() -> None:
    """Guard the guard: an empty walk would make the help check vacuously pass."""
    assert len(_walk_commands(build_parser())) > 40


def test_every_help_page_is_strict_windows_console_encodable() -> None:
    """A cold agent must be able to discover every command on stock Windows.

    The Windows launcher inherited a cp1252 stream on the qualification host.
    One Unicode arrow in a nested option made the entire `ops --help` page
    raise before argparse could print it. Render every parser, not just the root,
    so an unreachable nested help page cannot silently return.
    """
    import argparse

    pending = [build_parser()]
    rendered = 0
    while pending:
        parser = pending.pop()
        parser.format_help().encode("cp1252", errors="strict")
        rendered += 1
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                pending.extend(action.choices.values())
    assert rendered > 40


def test_dead_arms_are_announced_wherever_a_directory_is_aggregated(tmp_path, capsys):
    """A guard you must remember to run is a guard that gets skipped.

    A bisection reported clean negatives from two runs that had produced no data at
    all, so the warning is emitted by the aggregating commands themselves rather
    than only by `observe batch-audit`.
    """
    import json

    from browser_core.cli import _warn_failed_arms

    (tmp_path / "good.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-observation/1",
                "label": "good",
                "analysis": {"events_by_name": {"api.A.b": 1}},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "dead.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-observation/1",
                "label": "dead",
                "error": "trace export failed",
            }
        ),
        encoding="utf-8",
    )
    _warn_failed_arms(tmp_path)
    out = capsys.readouterr().out
    assert "1 arm(s) in this directory produced NO data" in out
    assert "dead" in out
    assert "not evidence of absence" in out


def test_no_warning_when_every_arm_produced_data(tmp_path, capsys):
    import json

    from browser_core.cli import _warn_failed_arms

    (tmp_path / "a.json").write_text(
        json.dumps({"schema": "x", "label": "a", "analysis": {}}), encoding="utf-8"
    )
    _warn_failed_arms(tmp_path)
    assert capsys.readouterr().out == ""


def test_warning_survives_unparseable_files_in_the_directory(tmp_path, capsys):
    """Run directories accumulate stray files; one must not break the guard."""
    import json

    from browser_core.cli import _warn_failed_arms

    (tmp_path / "junk.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "dead.json").write_text(
        json.dumps({
            "schema": "browser-core.product-script-observation/1",
            "label": "dead", "error": "boom",
        }),
        encoding="utf-8",
    )
    _warn_failed_arms(tmp_path)
    assert "1 arm(s)" in capsys.readouterr().out


def test_batch_audit_does_not_overwrite_duplicate_document_labels(tmp_path, capsys):
    import json
    from types import SimpleNamespace

    from browser_core.cli import _emit_batch_audit

    for filename, headed in (("a.json", True), ("b.json", False)):
        (tmp_path / filename).write_text(
            json.dumps(
                {
                    "schema": "browser-core.product-script-observation/1",
                    "label": "duplicate",
                    "headed": headed,
                    "analysis": {"events_by_name": {"api.A.b": 1}},
                }
            ),
            encoding="utf-8",
        )
    assert _emit_batch_audit(SimpleNamespace(directory=tmp_path, json=True)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["total"] == 2
    assert report["usable_labels"] == ["a.json", "b.json"]


def test_batch_audit_prefers_subtractions_over_raw_intermediates(tmp_path, capsys):
    import json
    from types import SimpleNamespace

    from browser_core.cli import _emit_batch_audit

    raw = {
        "schema": "browser-core.product-script-observation/1",
        "analysis": {"events_by_name": {"api.A.b": 1}},
    }
    subtraction = {
        "schema": "browser-core.product-script-subtraction/1",
        "only_in_arm": {"api.A.b": 1},
        "clean_subtraction": True,
    }
    for filename, document in (
        ("arm-sample.json", raw),
        ("arm-control.json", raw),
        ("subtraction-r1.json", subtraction),
        ("subtraction-r2.json", subtraction),
    ):
        (tmp_path / filename).write_text(json.dumps(document), encoding="utf-8")
    assert _emit_batch_audit(SimpleNamespace(directory=tmp_path, json=True)) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["total"] == 2
    assert report["population_selection"] == {
        "kind": "attributed_subtractions",
        "selected": 2,
        "ignored_successful_intermediates": 2,
        "ignored_labels": ["arm-control.json", "arm-sample.json"],
    }


def test_batch_audit_keeps_failed_raw_arm_with_subtractions(tmp_path, capsys):
    import json
    from types import SimpleNamespace

    from browser_core.cli import _emit_batch_audit

    (tmp_path / "subtraction.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-subtraction/1",
                "only_in_arm": {"api.A.b": 1},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "dead-arm.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-observation/1",
                "error": "trace export failed",
            }
        ),
        encoding="utf-8",
    )
    assert _emit_batch_audit(SimpleNamespace(directory=tmp_path, json=True)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["total"] == 2
    assert report["failed"] == 1
    assert report["failed_labels"] == ["dead-arm.json"]


def test_argument_corpus_does_not_overwrite_duplicate_document_labels(tmp_path, capsys):
    import json
    from types import SimpleNamespace

    from browser_core.cli import _emit_argument_corpus

    for filename, input_profile in (("a.json", "none"), ("b.json", "mouse-line")):
        (tmp_path / filename).write_text(
            json.dumps(
                {
                    "schema": "browser-core.product-script-observation/1",
                    "label": "duplicate",
                    "hook_mode": "on",
                    "input_profile": input_profile,
                    "analysis": {"events_by_name": {"api.A.b": 1}},
                    "argument_capture": _empty_argument_capture(),
                }
            ),
            encoding="utf-8",
        )
    args = SimpleNamespace(directory=tmp_path, json=True, name=None, limit=8)
    assert _emit_argument_corpus(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["arm_count"] == 2
    assert report["arms"] == ["a.json", "b.json"]
    assert report["method_population"]["mixed_axes"] == ["input_profile"]


def test_corpus_json_is_pure_and_structures_failed_and_raw_arms(tmp_path, capsys):
    import json

    from browser_core.cli import _emit_corpus

    (tmp_path / "subtraction.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-subtraction/1",
                "only_in_arm": {"api.Navigator.a": 1},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "raw.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-observation/1",
                "analysis": {"events_by_name": {"api.Navigator.a": 1}},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "dead.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-observation/1",
                "error": "trace export failed",
            }
        ),
        encoding="utf-8",
    )
    _emit_corpus(
        tmp_path,
        group_by=None,
        technique=None,
        as_json=True,
        include_raw=False,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["failed_arms"] == ["dead.json"]
    assert sorted(report["raw_observations_excluded"]) == ["dead.json", "raw.json"]
    assert report["trustworthy_population"] is False


def test_corpus_json_does_not_certify_unready_subtractions(tmp_path, capsys):
    import json

    from browser_core.cli import _emit_corpus

    for name, ready in (("ready", True), ("unready", False)):
        (tmp_path / f"{name}.json").write_text(
            json.dumps(
                {
                    "schema": "browser-core.product-script-subtraction/1",
                    "only_in_arm": {"api.Navigator.a": 1},
                    "clean_subtraction": True,
                    "surface_claim_ready": ready,
                }
            ),
            encoding="utf-8",
        )
    _emit_corpus(
        tmp_path,
        group_by=None,
        technique=None,
        as_json=True,
        include_raw=False,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["unready_arms"] == ["unready.json"]
    assert report["trustworthy_population"] is False


def test_corpus_uses_file_identities_when_human_labels_repeat(tmp_path, capsys):
    from browser_core.cli import _emit_corpus

    for filename in ("arm-a.json", "arm-b.json"):
        (tmp_path / filename).write_text(
            json.dumps({
                "schema": "browser-core.product-script-subtraction/1",
                "arm_label": "reused",
                "only_in_arm": {"api.Navigator.a": 1},
                "clean_subtraction": True,
            }),
            encoding="utf-8",
        )
    _emit_corpus(
        tmp_path, group_by=r"^(reused)$", technique="webrtc",
        as_json=True, include_raw=False,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["arms"] == 2
    assert report["groups"]["reused"]["arms"] == 2
    assert [row["label"] for row in report["technique_detail"]["per_arm"]] == [
        "arm-a.json", "arm-b.json",
    ]
    (tmp_path / "raw.json").write_text(
        json.dumps({
            "schema": "browser-core.product-script-observation/1",
            "label": "reused",
            "analysis": {"events_by_name": {"api.Navigator.a": 1}},
        }),
        encoding="utf-8",
    )
    _emit_corpus(
        tmp_path, group_by=r"^(RAW:reused|reused)$", technique=None,
        as_json=True, include_raw=True,
    )
    mixed = json.loads(capsys.readouterr().out)
    assert mixed["arms"] == 3
    assert mixed["groups"]["reused"]["arms"] == 2
    assert mixed["groups"]["RAW:reused"]["arms"] == 1
    assert mixed["raw_surfaces_included"] == ["raw.json"]


def test_corpus_invalid_group_pattern_has_a_bounded_cli_error(tmp_path):
    from browser_core.cli import _emit_corpus

    (tmp_path / "arm.json").write_text(
        json.dumps({
            "schema": "browser-core.product-script-subtraction/1",
            "only_in_arm": {"api.Navigator.a": 1},
            "clean_subtraction": True,
        }),
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="corpus group pattern is invalid"):
        _emit_corpus(
            tmp_path, group_by="[", technique=None,
            as_json=True, include_raw=False,
        )


def test_directory_readers_ignore_foreign_json_error_receipts(tmp_path, capsys):
    from browser_core.cli import (
        _emit_batch_audit, _emit_claim, _emit_corpus, _warn_failed_arms,
    )

    for index in range(3):
        (tmp_path / f"arm-{index}.json").write_text(
            json.dumps({
                "schema": "browser-core.product-script-subtraction/1",
                "only_in_arm": {"api.Navigator.a": 1},
                "clean_subtraction": True,
            }),
            encoding="utf-8",
        )
    (tmp_path / "foreign.json").write_text(
        json.dumps({
            "schema": "foreign.subtraction/1",
            "error": "foreign application error",
        }),
        encoding="utf-8",
    )
    assert _warn_failed_arms(tmp_path) == []
    assert _emit_claim(tmp_path, "webrtc", as_json=True) == 0
    claim = json.loads(capsys.readouterr().out)
    assert claim["failed_arms"] == []
    _emit_corpus(
        tmp_path, group_by=None, technique=None, as_json=True, include_raw=False,
    )
    corpus = json.loads(capsys.readouterr().out)
    assert corpus["arms"] == 3
    assert corpus["failed_arms"] == []
    assert _emit_batch_audit(SimpleNamespace(directory=tmp_path, json=True)) == 0
    audit = json.loads(capsys.readouterr().out)
    assert audit["total"] == 3
    assert audit["failed_labels"] == []


def test_claim_directory_marks_malformed_json_as_unparseable(tmp_path, capsys):
    import json

    from browser_core.cli import _emit_claim

    for index in range(3):
        (tmp_path / f"arm-{index}.json").write_text(
            json.dumps(
                {
                    "schema": "browser-core.product-script-subtraction/1",
                    "only_in_arm": {"api.Navigator.a": 1},
                    "clean_subtraction": True,
                }
            ),
            encoding="utf-8",
        )
    (tmp_path / "broken.json").write_bytes(b"{")
    assert _emit_claim(tmp_path, "webrtc", as_json=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "UNVERIFIABLE"
    assert report["failed_arms"] == []
    assert report["unparseable_files"] == ["broken.json"]
    assert _emit_claim(tmp_path, "webrtc", as_json=False) == 1
    assert "UNPARSEABLE" in capsys.readouterr().out


def test_corpus_directory_marks_malformed_json_as_unparseable(tmp_path, capsys):
    import json

    from browser_core.cli import _emit_corpus

    (tmp_path / "arm.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-subtraction/1",
                "only_in_arm": {"api.Navigator.a": 1},
                "clean_subtraction": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "broken.json").write_bytes(b"{")
    _emit_corpus(
        tmp_path,
        group_by=None,
        technique=None,
        as_json=True,
        include_raw=False,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["failed_arms"] == []
    assert report["unparseable_files"] == ["broken.json"]
    assert report["trustworthy_population"] is False
    _emit_corpus(
        tmp_path, group_by=None, technique=None, as_json=False, include_raw=False
    )
    assert "UNPARSEABLE FILES" in capsys.readouterr().out


def test_batch_audit_directory_marks_malformed_json_as_unparseable(tmp_path, capsys):
    import json
    from types import SimpleNamespace

    from browser_core.cli import _emit_batch_audit

    (tmp_path / "arm.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-subtraction/1",
                "only_in_arm": {"api.Navigator.a": 1},
                "clean_subtraction": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "broken.json").write_bytes(b"{")
    assert _emit_batch_audit(SimpleNamespace(directory=tmp_path, json=True)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["failed_labels"] == []
    assert report["unparseable_labels"] == ["broken.json"]
    assert report["trustworthy"] is False
    assert _emit_batch_audit(SimpleNamespace(directory=tmp_path, json=False)) == 1
    assert "unreadable file" in capsys.readouterr().out


def test_batch_audit_directory_with_only_unreadable_json_has_no_arm_failure(
    tmp_path, capsys,
):
    from browser_core.cli import _emit_batch_audit

    (tmp_path / "broken.json").write_bytes(b"{")
    assert _emit_batch_audit(SimpleNamespace(directory=tmp_path, json=True)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["total"] == 1
    assert report["usable"] == report["failed"] == 0
    assert report["unparseable_labels"] == ["broken.json"]
    assert report["population_selection"]["kind"] == "unparseable_files"


def test_argument_corpus_json_structures_failed_arms_without_prefix_text(tmp_path, capsys):
    import json
    from types import SimpleNamespace

    from browser_core.cli import _emit_argument_corpus

    (tmp_path / "hooked.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-observation/1",
                "hook_mode": "on",
                "analysis": {"events_by_name": {"api.A.b": 1}},
                "argument_capture": _empty_argument_capture(),
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "dead.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-observation/1",
                "error": "trace export failed",
                "argument_capture": _empty_argument_capture(),
            }
        ),
        encoding="utf-8",
    )
    args = SimpleNamespace(directory=tmp_path, json=True, name=None, limit=8)
    assert _emit_argument_corpus(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["failed_arms"] == ["dead.json"]
    assert report["arms"] == ["hooked.json"]
    assert report["trustworthy_population"] is False


def test_argument_corpus_marks_malformed_json_as_unparseable(tmp_path, capsys):
    import json
    from types import SimpleNamespace

    from browser_core.argument_capture import render_argument_corpus
    from browser_core.cli import _emit_argument_corpus

    (tmp_path / "hooked.json").write_text(
        json.dumps(
            {
                "schema": "browser-core.product-script-observation/1",
                "hook_mode": "on",
                "analysis": {"events_by_name": {"api.A.b": 1}},
                "argument_capture": _empty_argument_capture(),
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "broken.json").write_bytes(b"{")
    args = SimpleNamespace(directory=tmp_path, json=True, name=None, limit=8)
    assert _emit_argument_corpus(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["failed_arms"] == []
    assert report["unparseable_files"] == ["broken.json"]
    assert report["trustworthy_population"] is False
    args.json = False
    assert _emit_argument_corpus(args) == 1
    assert "unparseable JSON file" in capsys.readouterr().out
    report["unparseable_files"] = ["broken.json", "broken.json"]
    with pytest.raises(ContractError, match="argument corpus structure"):
        render_argument_corpus(report)


def test_argument_corpus_ignores_foreign_json_with_error_or_capture(tmp_path, capsys):
    from browser_core.cli import _emit_argument_corpus

    (tmp_path / "hooked.json").write_text(
        json.dumps({
            "schema": "browser-core.product-script-observation/1",
            "argument_capture": _empty_argument_capture(),
        }),
        encoding="utf-8",
    )
    (tmp_path / "foreign-error.json").write_text(
        json.dumps({"schema": "foreign.observation/1", "error": "foreign failure"}),
        encoding="utf-8",
    )
    (tmp_path / "foreign-capture.json").write_text(
        json.dumps({
            "schema": "foreign.observation/1",
            "argument_capture": _empty_argument_capture(),
        }),
        encoding="utf-8",
    )
    args = SimpleNamespace(directory=tmp_path, json=True, name=None, limit=8)
    _emit_argument_corpus(args)
    report = json.loads(capsys.readouterr().out)
    assert report["arms"] == ["hooked.json"]
    assert report["failed_arms"] == []
