from __future__ import annotations

import json
import os
import subprocess
import traceback
from pathlib import Path

import pytest

import browser_core.control_files as control_files_module
import browser_core.contracts as contracts_module
from browser_core.contracts import (
    EXACT_NATIVE_EVENT_COMPONENTS,
    EXACT_NATIVE_EVENT_ROUTES,
    EXACT_NATIVE_TRACE_CATEGORIES,
    ContractError,
    load_session,
    validate_session,
    validate_trace_event,
)
from browser_core.control_files import MAX_SESSION_DOCUMENT_BYTES


REVISION = "a" * 40
ROOT = Path(__file__).parents[1]


def test_exact_native_component_map_covers_the_route_map() -> None:
    assert set(EXACT_NATIVE_EVENT_COMPONENTS) == set(EXACT_NATIVE_EVENT_ROUTES)
    assert set(EXACT_NATIVE_TRACE_CATEGORIES) == set(EXACT_NATIVE_EVENT_ROUTES)


def session() -> dict:
    return {
        "schema": "browser-core.session/1",
        "run_id": "test-run",
        "chromium_revision": REVISION,
        "pid": 123,
        "automation": {"transport": "cdp", "cdp_endpoint": "http://127.0.0.1:9222"},
    }


def proxy_session(endpoint: str) -> dict:
    value = session()
    preflight = {
        "schema": "browser-core.network-preflight/1",
        "route_id": "route",
        "route_sha256_16": "a" * 16,
        "passed": True,
        "protocol": "http",
    }
    value["network"] = {
        "route_id": "route",
        "route_sha256_16": "a" * 16,
        "mode": "proxy",
        "policies": {"dns": "route", "webrtc": "default", "require_alignment": False},
        "preflight": preflight,
        "runtime_identity": {
            "schema": "browser-core.runtime-identity-observation/1",
            "locale": "en-US",
            "languages": ["en-US"],
            "timezone": "America/Chicago",
            "cdp_domains_enabled": [],
        },
        "realization": {
            "schema": "browser-core.geo-realization/1",
            "route_id": "route",
            "route_sha256_16": "a" * 16,
            "passed": True,
            "observed": {"ip_sha256_16": "b" * 16},
        },
        "gateway": {
            "process_identity": {
                "pid": 321,
                "executable": "C:/python.exe",
                "start_marker": "fixture:gateway",
            },
            "endpoint": endpoint,
            "lease_path": "C:/lease",
            "ready_path": "C:/ready",
            "preflight": preflight,
        },
    }
    return value


@pytest.mark.parametrize(
    "invalid_language", ["en-US\nprivate", "en-US\rprivate", "en-US\x00private"]
)
def test_session_rejects_invalid_runtime_identity_language(
    invalid_language: str,
) -> None:
    value = proxy_session("http://127.0.0.1:8123")
    assert validate_session(value)["network"]["runtime_identity"]["languages"] == ["en-US"]
    value["network"]["runtime_identity"]["languages"] = [invalid_language]

    with pytest.raises(ContractError, match="runtime identity language is invalid"):
        validate_session(value)


def test_session_accepts_loopback() -> None:
    assert validate_session(session())["run_id"] == "test-run"


def test_unsupported_schema_diagnostics_do_not_echo_untrusted_text() -> None:
    private_schema = "private-schema-location-marker"
    value = session()
    value["schema"] = private_schema
    with pytest.raises(ContractError) as session_failure:
        validate_session(value)
    assert private_schema not in str(session_failure.value)

    event = {
        "schema": private_schema,
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "api", "name": "fixture"},
        "provenance": {},
        "detail": {},
    }
    with pytest.raises(ContractError) as trace_failure:
        validate_trace_event(event)
    assert private_schema not in str(trace_failure.value)


@pytest.mark.parametrize("field", ["state", "trace_mode", "trace_category_contract"])
def test_session_rejects_unhashable_top_level_enums(field: str) -> None:
    value = session()
    value[field] = []
    with pytest.raises(ContractError):
        validate_session(value)


def test_session_rejects_unhashable_nested_enums() -> None:
    value = session()
    value["build"] = {"provenance": [], "executable_sha256_16": "a" * 16}
    with pytest.raises(ContractError, match="provenance"):
        validate_session(value)

    value = session()
    value["profile"] = {
        "id": None, "persistence": {}, "path": "C:/profile", "lock_path": None,
    }
    with pytest.raises(ContractError, match="persistence"):
        validate_session(value)


def test_session_rejects_unhashable_trace_scope_or_categories() -> None:
    value = session()
    value.update(trace_mode="on", trace_path="C:/trace.perfetto-trace",
                 trace_scope=[], trace_categories=["browser_core.debug"])
    with pytest.raises(ContractError, match="trace scope"):
        validate_session(value)
    value["trace_scope"] = "broad"
    value["trace_categories"] = [[]]
    with pytest.raises(ContractError, match="trace categories"):
        validate_session(value)


@pytest.mark.parametrize("field", ["mode", "policies.dns", "policies.webrtc", "preflight.protocol"])
def test_session_rejects_unhashable_network_enums(field: str) -> None:
    value = session()
    value["network"] = {
        "route_id": "route",
        "route_sha256_16": "a" * 16,
        "mode": "direct",
        "policies": {"dns": "route", "webrtc": "default", "require_alignment": False},
        "preflight": {
            "schema": "browser-core.network-preflight/1", "route_id": "route",
            "route_sha256_16": "a" * 16, "passed": True, "protocol": "direct",
        },
        "runtime_identity": {
            "schema": "browser-core.runtime-identity-observation/1",
            "locale": "en-US", "languages": ["en-US"],
            "timezone": "America/Chicago", "cdp_domains_enabled": [],
        },
        "realization": {
            "schema": "browser-core.geo-realization/1", "route_id": "route",
            "route_sha256_16": "a" * 16, "passed": True,
            "observed": {"ip_sha256_16": "b" * 16},
        },
    }
    assert validate_session(value)["network"]["mode"] == "direct"
    target = value["network"]
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = []
    with pytest.raises(ContractError):
        validate_session(value)


@pytest.mark.parametrize("endpoint", [
    "https://example.com:9222",
    "http://user:pass@127.0.0.1:9222",
    "http://@127.0.0.1:9222",
    "http://[broken",
    "http://127.0.0.1:0",
    "http://127.0.0.1:9222\n",
    "http://127.0.0.1:9222?",
    "http://127.0.0.1:9222#",
    "http://127.0.0.1:9222?token=x",
])
def test_session_rejects_remote_or_secret_endpoint(endpoint: str) -> None:
    value = session()
    value["automation"]["cdp_endpoint"] = endpoint
    with pytest.raises(ContractError):
        validate_session(value)


@pytest.mark.parametrize("endpoint", [
    "http://[broken",
    "http://127.0.0.1:99999",
    "http://@127.0.0.1:8123",
    "http://127.0.0.1:8123/path",
    "http://127.0.0.1:8123?token=x",
    "http://127.0.0.1:8123#fragment",
])
def test_session_rejects_invalid_gateway_endpoint(endpoint: str) -> None:
    with pytest.raises(ContractError):
        validate_session(proxy_session(endpoint))


def test_session_file_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    path.write_text(json.dumps(session()), encoding="utf-8")
    assert load_session(path)["pid"] == 123


@pytest.mark.skipif(os.name != "nt", reason="Win32 selected-session aliases")
@pytest.mark.parametrize("part", ["parent", "leaf"])
def test_session_loader_rejects_normalized_selected_path_alias(
    tmp_path: Path, part: str,
) -> None:
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

    with pytest.raises(ContractError, match="path is invalid"):
        load_session(selected)
    assert load_session(ordinary)["run_id"] == "test-run"


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data stream path syntax")
def test_session_loader_rejects_alternate_stream_selection(tmp_path: Path) -> None:
    holder = tmp_path / "holder.txt"
    holder.write_bytes(b"unrelated")
    selected = Path(str(holder) + ":receipt")
    try:
        selected.write_text(json.dumps(session()), encoding="utf-8")
    except OSError:
        pytest.skip("host filesystem does not support alternate data streams")
    ordinary = tmp_path / "session.json"
    ordinary.write_text(json.dumps(session()), encoding="utf-8")

    with pytest.raises(ContractError, match="path is invalid"):
        load_session(selected)
    assert load_session(ordinary)["run_id"] == "test-run"
    assert holder.read_bytes() == b"unrelated"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_session_loader_rejects_selected_parent_junction(tmp_path: Path) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    ordinary = foreign / "session.json"
    ordinary.write_text(json.dumps(session()), encoding="utf-8")
    junction = tmp_path / "linked"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="owned regular directory"):
            load_session(junction / "session.json")
        assert load_session(ordinary)["run_id"] == "test-run"
    finally:
        if junction.exists():
            junction.rmdir()


def test_load_session_rebinds_bytes_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    with pytest.raises(ContractError, match="changed during load"):
        load_session(path)
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert path.read_bytes() == changed_body


def test_session_loader_accepts_exact_limit_and_rejects_valid_prefix_overflow(
    tmp_path: Path,
) -> None:
    path = tmp_path / "session.json"
    source = json.dumps(session(), sort_keys=True, separators=(",", ":")).encode("ascii")
    exact = source + b" " * (MAX_SESSION_DOCUMENT_BYTES - len(source))
    path.write_bytes(exact)
    assert load_session(path)["run_id"] == "test-run"

    path.write_bytes(exact + b" ")
    with pytest.raises(ContractError, match="exceeds 1048576 bytes") as raised:
        load_session(path)
    assert str(path) not in str(raised.value)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b'{"schema":"browser-core.session/1","value":"\xff"}', "encoding is invalid"),
        (b'{"schema":"browser-core.session/1"', "JSON is invalid"),
    ],
)
def test_session_loader_redacts_encoding_and_json_failures(
    tmp_path: Path,
    body: bytes,
    message: str,
) -> None:
    path = tmp_path / "private-session.json"
    path.write_bytes(body)
    with pytest.raises(ContractError, match=message) as raised:
        load_session(path)
    rendered = "".join(
        traceback.format_exception(
            type(raised.value), raised.value, raised.value.__traceback__
        )
    )
    assert str(path) not in str(raised.value)
    assert str(path) not in rendered
    assert raised.value.__cause__ is None


def test_session_loader_classifies_missing_locked_and_nonregular_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "private-session.json"
    with pytest.raises(ContractError, match="is missing") as raised:
        load_session(path)
    assert str(path) not in str(raised.value)

    path.write_bytes(json.dumps(session()).encode("utf-8"))
    monkeypatch.setattr(
        Path,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PermissionError(13, "private locked path")
        ),
    )
    with pytest.raises(ContractError, match="is locked") as raised:
        load_session(path)
    assert str(path) not in str(raised.value)

    monkeypatch.undo()
    path.unlink()
    path.mkdir()
    with pytest.raises(ContractError, match="not a regular file") as raised:
        load_session(path)
    assert str(path) not in str(raised.value)


def test_session_loader_rejects_a_changed_same_handle_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "private-session.json"
    path.write_bytes(json.dumps(session()).encode("utf-8"))
    identities = iter(
        [
            (1, 1, 1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (1, 1, 1, 2, 1, 1),
        ]
    )
    monkeypatch.setattr(
        control_files_module,
        "_identity",
        lambda _metadata: next(identities),
    )
    with pytest.raises(ContractError, match="is changed") as raised:
        load_session(path)
    assert str(path) not in str(raised.value)


def test_session_loader_requires_strict_single_link_path_typed_json(
    tmp_path: Path,
) -> None:
    path = tmp_path / "session.json"
    body = json.dumps(session(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(body.replace(b'"schema":', b'"schema":"duplicate","schema":', 1))
    with pytest.raises(ContractError, match="duplicate key"):
        load_session(path)

    path.write_bytes(body)
    os.link(path, tmp_path / "session-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        load_session(path)
    with pytest.raises(ContractError, match="path must be a Path"):
        load_session(str(path))  # type: ignore[arg-type]


def test_session_rejects_mismatched_process_identity_pid() -> None:
    value = session()
    value["process_identity"] = {
        "pid": 456,
        "executable": "C:/chrome.exe",
        "start_marker": "fixture:1",
    }
    with pytest.raises(ContractError, match="PID does not match"):
        validate_session(value)


def test_session_rejects_invalid_build_digest() -> None:
    value = session()
    value["build"] = {
        "provenance": "unverified-external",
        "executable_sha256_16": "not-a-digest",
    }
    with pytest.raises(ContractError, match="digest"):
        validate_session(value)


def test_session_accepts_redaction_safe_identity_metadata() -> None:
    value = session()
    value["identity_contract"] = {
        "file": "identity-contract.json",
        "path": "C:/profile/identity-contract.json",
        "sha256_16": "a" * 16,
        "fields": ["window.platform"],
    }
    assert validate_session(value)["identity_contract"]["fields"] == ["window.platform"]


@pytest.mark.parametrize(
    "location",
    ["session", "automation", "build", "process", "profile", "identity"],
)
def test_session_rejects_uninterpreted_nested_fields(location: str) -> None:
    value = session()
    if location == "session":
        value["operator_notes"] = "private"
    elif location == "automation":
        value["automation"]["operator_notes"] = "private"
    elif location == "build":
        value["build"] = {
            "provenance": "unverified-external",
            "executable_sha256_16": "a" * 16,
            "operator_notes": "private",
        }
    elif location == "process":
        value["process_identity"] = {
            "pid": value["pid"],
            "executable": "chrome.exe",
            "start_marker": "fixture:1",
            "operator_notes": "private",
        }
    elif location == "profile":
        value["profile"] = {
            "id": None,
            "persistence": "ephemeral",
            "path": "C:/profiles/ephemeral/test-run",
            "lock_path": None,
            "operator_notes": "private",
        }
    else:
        value["identity_contract"] = {
            "file": "identity-contract.json",
            "path": "C:/profile/identity-contract.json",
            "sha256_16": "a" * 16,
            "fields": ["window.platform"],
            "operator_notes": "private",
        }
    with pytest.raises(ContractError, match="fields are invalid"):
        validate_session(value)


def test_session_requires_aware_timestamps_and_valid_endpoint_port() -> None:
    value = session()
    value["created_at"] = "2026-08-10T00:00:00"
    with pytest.raises(ContractError, match="created_at is invalid"):
        validate_session(value)

    value = session()
    value["automation"]["cdp_endpoint"] = "http://127.0.0.1:99999"
    with pytest.raises(ContractError, match="port is invalid"):
        validate_session(value)


def test_session_rejects_uninterpreted_network_receipt_fields() -> None:
    value = session()
    preflight = {
        "schema": "browser-core.network-preflight/1",
        "route_id": "route",
        "route_sha256_16": "a" * 16,
        "passed": True,
    }
    value["network"] = {
        "route_id": "route",
        "route_sha256_16": "a" * 16,
        "mode": "direct",
        "policies": {"dns": "route", "webrtc": "default", "require_alignment": False},
        "preflight": {**preflight, "operator_notes": "private"},
        "runtime_identity": {
            "schema": "browser-core.runtime-identity-observation/1",
            "locale": "en-US",
            "languages": ["en-US"],
            "timezone": "America/Chicago",
            "cdp_domains_enabled": [],
        },
        "realization": {
            "schema": "browser-core.geo-realization/1",
            "route_id": "route",
            "route_sha256_16": "a" * 16,
            "passed": True,
            "observed": {"ip_sha256_16": "b" * 16},
        },
    }
    with pytest.raises(ContractError, match="preflight fields are invalid"):
        validate_session(value)


def test_session_rejects_unhashable_network_check_values_cleanly() -> None:
    value = session()
    value["network"] = {
        "route_id": "route",
        "route_sha256_16": "a" * 16,
        "mode": "direct",
        "policies": {"dns": "route", "webrtc": "default", "require_alignment": False},
        "preflight": {
            "schema": "browser-core.network-preflight/1",
            "route_id": "route",
            "route_sha256_16": "a" * 16,
            "passed": True,
        },
        "runtime_identity": {
            "schema": "browser-core.runtime-identity-observation/1",
            "locale": "en-US",
            "languages": ["en-US"],
            "timezone": "America/Chicago",
            "cdp_domains_enabled": [],
        },
        "realization": {
            "schema": "browser-core.geo-realization/1",
            "route_id": "route",
            "route_sha256_16": "a" * 16,
            "passed": True,
            "checks": {"country": []},
            "observed": {"ip_sha256_16": "b" * 16},
        },
    }
    with pytest.raises(ContractError, match="checks are invalid"):
        validate_session(value)


@pytest.mark.parametrize("field", ["latitude", "longitude", "distance_km"])
def test_session_geography_rejects_huge_json_integers_without_overflow(field: str) -> None:
    value = session()
    realization = {
        "schema": "browser-core.geo-realization/1",
        "route_id": "route",
        "route_sha256_16": "a" * 16,
        "passed": True,
        "observed": {"ip_sha256_16": "b" * 16},
    }
    if field == "distance_km":
        realization[field] = 10**1_000
    else:
        realization["observed"][field] = 10**1_000
    value["network"] = {
        "route_id": "route",
        "route_sha256_16": "a" * 16,
        "mode": "direct",
        "policies": {"dns": "route", "webrtc": "default", "require_alignment": False},
        "preflight": {
            "schema": "browser-core.network-preflight/1",
            "route_id": "route",
            "route_sha256_16": "a" * 16,
            "passed": True,
        },
        "runtime_identity": {
            "schema": "browser-core.runtime-identity-observation/1",
            "locale": "en-US",
            "languages": ["en-US"],
            "timezone": "America/Chicago",
            "cdp_domains_enabled": [],
        },
        "realization": realization,
    }

    with pytest.raises(ContractError, match="(observation|distance).*invalid"):
        validate_session(value)


@pytest.mark.parametrize(
    ("mode", "path"),
    [("on", None), ("off", "C:/trace.perfetto-trace"), ("invalid", None)],
)
def test_session_rejects_inconsistent_trace_mode(mode: str, path: str | None) -> None:
    value = session()
    value["trace_mode"] = mode
    value["trace_path"] = path
    with pytest.raises(ContractError, match="trace mode"):
        validate_session(value)


@pytest.mark.parametrize(
    ("mode", "path"),
    [("on", "C:/trace.perfetto-trace"), ("off", None)],
)
def test_session_accepts_explicit_trace_mode(mode: str, path: str | None) -> None:
    value = session()
    value["trace_mode"] = mode
    value["trace_path"] = path
    assert validate_session(value)["trace_mode"] == mode


@pytest.mark.parametrize(
    ("mode", "scope", "categories"),
    [
        ("on", "causal", ["browser_core.debug"]),
        ("on", "causal-stream", ["browser_core.debug", "browser_core.stream"]),
        (
            "on",
            "encoding",
            ["browser_core.debug", "blink.bindings.encoding"],
        ),
        (
            "on",
            "broad",
            [
                "browser_core.debug",
                "browser_core.stream",
                "blink.bindings",
                "blink.bindings.encoding",
            ],
        ),
        (
            "on",
            "source-identity",
            [
                "browser_core.debug",
                "browser_core.stream",
                "blink.bindings",
                "blink.bindings.encoding",
                "browser_core.source_identity",
            ],
        ),
        (
            "on",
            "source-context",
            [
                "browser_core.debug",
                "browser_core.stream",
                "blink.bindings",
                "blink.bindings.encoding",
                "browser_core.source_identity",
                "disabled-by-default-browser_core.source_context",
            ],
        ),
        ("off", None, []),
    ],
)
def test_session_accepts_consistent_trace_scope(
    mode: str, scope: str | None, categories: list[str]
) -> None:
    value = session()
    value["trace_mode"] = mode
    value["trace_category_contract"] = "browser-core.trace-categories/8"
    value["trace_path"] = "C:/trace.perfetto-trace" if mode == "on" else None
    value["trace_scope"] = scope
    value["trace_categories"] = categories
    assert validate_session(value)["trace_categories"] == categories


@pytest.mark.parametrize(
    "categories",
    [
        ["browser_core.debug", "blink.bindings"],
        ["browser_core.debug", "browser_core.stream", "blink.bindings"],
    ],
)
def test_current_trace_category_contract_rejects_legacy_broad_scope(
    categories: list[str],
) -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_category_contract": "browser-core.trace-categories/8",
        "trace_scope": "broad",
        "trace_categories": categories,
    })
    with pytest.raises(ContractError, match="categories"):
        validate_session(value)


def test_previous_trace_category_contract_retains_broad_scope() -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_category_contract": "browser-core.trace-categories/3",
        "trace_scope": "broad",
        "trace_categories": [
            "browser_core.debug", "browser_core.stream", "blink.bindings",
            "blink.bindings.encoding",
        ],
    })
    assert validate_session(value)["trace_category_contract"] == (
        "browser-core.trace-categories/3"
    )


def test_previous_source_identity_contract_retains_v8_compile_scope() -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_category_contract": "browser-core.trace-categories/4",
        "trace_scope": "source-identity",
        "trace_categories": [
            "browser_core.debug", "browser_core.stream", "blink.bindings",
            "blink.bindings.encoding", "disabled-by-default-v8.compile",
        ],
    })
    assert validate_session(value)["trace_category_contract"] == (
        "browser-core.trace-categories/4"
    )


def test_previous_tagged_source_identity_scope_remains_readable() -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_category_contract": "browser-core.trace-categories/5",
        "trace_scope": "source-identity",
        "trace_categories": [
            "browser_core.debug", "browser_core.stream", "blink.bindings",
            "blink.bindings.encoding", "browser_core.source_identity",
        ],
    })
    assert validate_session(value)["trace_category_contract"] == (
        "browser-core.trace-categories/5"
    )


def test_previous_experimental_context_scope_remains_readable() -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_category_contract": "browser-core.trace-categories/6",
        "trace_scope": "source-identity",
        "trace_categories": [
            "browser_core.debug", "browser_core.stream", "blink.bindings",
            "blink.bindings.encoding", "browser_core.source_identity",
            "disabled-by-default-blink.debug",
        ],
    })
    assert validate_session(value)["trace_category_contract"] == (
        "browser-core.trace-categories/6"
    )


def test_previous_blink_debug_context_scope_remains_readable() -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_category_contract": "browser-core.trace-categories/7",
        "trace_scope": "source-context",
        "trace_categories": [
            "browser_core.debug", "browser_core.stream", "blink.bindings",
            "blink.bindings.encoding", "browser_core.source_identity",
            "disabled-by-default-blink.debug",
        ],
    })
    assert validate_session(value)["trace_category_contract"] == (
        "browser-core.trace-categories/7"
    )


def test_dynamic_context_contract_rejects_previous_blink_debug_gate() -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_category_contract": "browser-core.trace-categories/8",
        "trace_scope": "source-context",
        "trace_categories": [
            "browser_core.debug", "browser_core.stream", "blink.bindings",
            "blink.bindings.encoding", "browser_core.source_identity",
            "disabled-by-default-blink.debug",
        ],
    })
    with pytest.raises(ContractError, match="categories"):
        validate_session(value)


def test_previous_context_contract_rejects_new_dynamic_gate() -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_category_contract": "browser-core.trace-categories/7",
        "trace_scope": "source-context",
        "trace_categories": [
            "browser_core.debug", "browser_core.stream", "blink.bindings",
            "blink.bindings.encoding", "browser_core.source_identity",
            "disabled-by-default-browser_core.source_context",
        ],
    })
    with pytest.raises(ContractError, match="categories"):
        validate_session(value)


def test_session_rejects_unknown_trace_category_contract() -> None:
    value = session()
    value["trace_category_contract"] = "browser-core.trace-categories/999"
    with pytest.raises(ContractError, match="category contract"):
        validate_session(value)


def test_session_rejects_trace_scope_category_disagreement() -> None:
    value = session()
    value.update({
        "trace_mode": "on",
        "trace_path": "C:/trace.perfetto-trace",
        "trace_scope": "causal",
        "trace_categories": ["browser_core.debug", "blink.bindings"],
    })
    with pytest.raises(ContractError, match="categories"):
        validate_session(value)


def test_session_json_schema_exposes_all_runtime_trace_scopes() -> None:
    schema = json.loads((ROOT / "schemas" / "session-v1.schema.json").read_text(
        encoding="utf-8"
    ))
    properties = schema["properties"]
    assert properties["trace_category_contract"] == {
        "const": "browser-core.trace-categories/8"
    }
    assert properties["trace_scope"]["enum"] == [
        "causal", "causal-stream", "encoding", "broad", "source-identity",
        "source-context", None
    ]
    assert properties["trace_categories"]["items"]["enum"] == [
        "browser_core.debug",
        "browser_core.stream",
        "blink.bindings",
        "blink.bindings.encoding",
        "browser_core.source_identity",
        "disabled-by-default-browser_core.source_context",
    ]


def test_trace_rejects_sensitive_detail() -> None:
    event = {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "api", "name": "fixture"},
        "provenance": {},
        "detail": {"authorization": "Bearer no"},
    }
    with pytest.raises(ContractError, match="sensitive field"):
        validate_trace_event(event)


@pytest.mark.parametrize("field", ["access_token", "refresh-token", "private_key"])
def test_trace_rejects_normalized_sensitive_fields(field: str) -> None:
    event = {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "api", "name": "fixture"},
        "provenance": {},
        "detail": {field: "forbidden"},
    }
    with pytest.raises(ContractError, match="sensitive field"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    "detail",
    [
        {"nested": {"authorization-private-location-marker": "value"}},
        {"private-location-marker": {"note": "\ud800"}},
    ],
)
def test_trace_rejection_does_not_echo_untrusted_field_names(detail: dict) -> None:
    event = {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "api", "name": "fixture"},
        "provenance": {},
        "detail": detail,
    }

    with pytest.raises(ContractError) as failure:
        validate_trace_event(event)
    assert "private-location-marker" not in str(failure.value)


@pytest.mark.parametrize(
    "detail",
    [
        {"note": "\ud800"},
        {"\ud800": "value"},
    ],
)
def test_trace_direct_validator_rejects_non_utf8_detail(detail: dict) -> None:
    event = {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "api", "name": "fixture"},
        "provenance": {},
        "detail": detail,
    }

    with pytest.raises(ContractError, match="UTF-8|field name"):
        validate_trace_event(event)


@pytest.mark.parametrize("field", ["context_id", "frame_id", "worker_id", "script_id"])
def test_generic_trace_execution_identity_requires_text(field: str) -> None:
    event = {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {field: []},
        "event": {"category": "api", "name": "fixture"},
        "provenance": {},
    }
    with pytest.raises(ContractError, match="trace execution"):
        validate_trace_event(event)


def test_generic_trace_execution_keeps_nullable_legacy_identity_fields() -> None:
    event = {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a", "frame_id": "frame-a",
            "worker_id": None, "script_id": None,
        },
        "event": {"category": "api", "name": "fixture"},
        "provenance": {},
    }
    assert validate_trace_event(event) is event


def test_session_direct_validator_rejects_non_utf8_bounded_text() -> None:
    value = session()
    value["executable"] = "\ud800"

    with pytest.raises(ContractError, match="session.executable is invalid"):
        validate_session(value)


def network_trace_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 2,
        "ts_monotonic_ns": 3,
        "causal_parent_seq": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        "event": {"category": "network", "name": "fetch.request.start"},
        "request": {
            "id": "fetch-request:frame-a:1",
            "method": "GET",
            "url_class": "https:same-origin:/probe",
            "target_scope": "loopback",
            "body_bytes": 0,
        },
        "provenance": {"source": "native", "component": "blink.fetch"},
        "detail": {
            "native_name": "BrowserCore.FetchRequestStart",
            "thread_id": 1,
        },
    }


def test_trace_accepts_closed_scheme_safe_network_request() -> None:
    event = network_trace_event()
    assert validate_trace_event(event)["request"] == event["request"]


@pytest.mark.parametrize("field", [
    "process.type", "event.category", "value.redaction",
    "request.target_scope", "detail.native_name",
])
def test_trace_rejects_unhashable_event_enums(field: str) -> None:
    event = network_trace_event()
    event["value"] = {"redaction": "none"}
    target = event
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = []
    with pytest.raises(ContractError):
        validate_trace_event(event)


def test_trace_rejects_request_body_bytes_above_safe_integer_domain() -> None:
    event = network_trace_event()
    event["request"]["body_bytes"] = 9_007_199_254_740_992

    with pytest.raises(ContractError, match="body_bytes.*safe integer"):
        validate_trace_event(event)


@pytest.mark.parametrize("operation", ["01", "١"])
def test_trace_rejects_noncanonical_fetch_request_operation_id(
    operation: str,
) -> None:
    event = network_trace_event()
    event["request"]["id"] = f"fetch-request:frame-a:{operation}"

    with pytest.raises(ContractError, match="fetch request id"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    "url_class",
    [
        "https://private.example/path",
        "https:cross-origin://private.example/path",
        "https:same-origin:/path?private=query",
        "data:cross-origin:text/plain,private",
    ],
)
def test_trace_rejects_unsafe_network_url_class(url_class: str) -> None:
    event = network_trace_event()
    event["request"]["url_class"] = url_class
    with pytest.raises(ContractError, match="scheme-safe"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda request: request.update(extra="private"), "fields"),
        (lambda request: request.pop("id"), "fields"),
        (lambda request: request.update(id="bad\nid"), "request id"),
        (lambda request: request.update(method="BAD METHOD"), "method"),
        (lambda request: request.update(target_scope="private-host"), "target_scope"),
        (lambda request: request.update(body_bytes=True), "body_bytes"),
        (lambda request: request.update(body_sha256_16="A" * 16), "digest"),
    ],
)
def test_trace_rejects_malformed_network_request(mutation, message: str) -> None:
    event = network_trace_event()
    mutation(event["request"])
    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


def test_trace_accepts_legacy_network_request_without_target_scope() -> None:
    event = network_trace_event()
    event["event"] = {"category": "network", "name": "request.start"}
    event["detail"]["native_name"] = "fixture.request.start"
    event["request"].pop("target_scope")
    assert "target_scope" not in validate_trace_event(event)["request"]


def test_trace_requires_request_only_for_network_events() -> None:
    event = network_trace_event()
    event.pop("request")
    with pytest.raises(ContractError, match="must be an object"):
        validate_trace_event(event)

    event = network_trace_event()
    event["event"] = {"category": "api", "name": "fetch"}
    with pytest.raises(ContractError, match="cannot carry"):
        validate_trace_event(event)


def fetch_api_event() -> dict[str, object]:
    event = network_trace_event()
    event["seq"] = 1
    event["ts_monotonic_ns"] = 2
    event["causal_parent_seq"] = 0
    event["event"] = {"category": "api", "name": "fetch"}
    event.pop("request")
    event["detail"] = {"native_name": "BrowserCore.FetchCall", "thread_id": 1}
    return event


def test_trace_accepts_exact_value_free_fetch_api_and_request() -> None:
    assert validate_trace_event(fetch_api_event())["detail"]["native_name"] == (
        "BrowserCore.FetchCall"
    )
    assert validate_trace_event(network_trace_event())["request"]["method"] == "GET"


@pytest.mark.parametrize(
    ("event_factory", "mutation", "message"),
    [
        (
            fetch_api_event,
            lambda event: event["detail"].update(native_name="BrowserCore.Fetch"),
            "fetch API metadata",
        ),
        (
            fetch_api_event,
            lambda event: event["provenance"].update(component="blink.network"),
            "fetch API metadata",
        ),
        (
            fetch_api_event,
            lambda event: event.update(
                value={"type": "string", "redaction": "dropped"}
            ),
            "fetch API metadata",
        ),
        (
            fetch_api_event,
            lambda event: event["execution"].pop("script_id"),
            "fetch API parent",
        ),
        (
            fetch_api_event,
            lambda event: event["execution"].update(world_id="isolated"),
            "fetch API execution",
        ),
        (
            network_trace_event,
            lambda event: event["detail"].update(payload_bytes=1),
            "fetch request metadata",
        ),
        (
            network_trace_event,
            lambda event: event["provenance"].update(source="probe"),
            "fetch request metadata",
        ),
        (
            network_trace_event,
            lambda event: event.pop("causal_parent_seq"),
            "fetch request parent",
        ),
        (
            network_trace_event,
            lambda event: event["execution"].update(world_id="isolated"),
            "fetch request execution",
        ),
    ],
)
def test_trace_rejects_forged_fetch_chain_event(
    event_factory,
    mutation,
    message: str,
) -> None:
    event = event_factory()
    mutation(event)

    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


def canvas_readback_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "canvas-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "event": {"category": "api", "name": "HTMLCanvasElement.toDataURL"},
        "provenance": {"source": "native", "component": "blink.canvas"},
        "detail": {
            "native_name": "BrowserCore.CanvasReadback",
            "thread_id": 11,
            "width": 300,
            "height": 150,
            "origin_clean": True,
        },
    }


def test_trace_accepts_exact_canvas_readback_call_metadata() -> None:
    event = validate_trace_event(canvas_readback_event())

    assert event["detail"]["width"] == 300
    assert event["detail"]["origin_clean"] is True


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda event: event["detail"].update(
                native_name="BrowserCore.CanvasExport"
            ),
            "canvas readback metadata",
        ),
        (
            lambda event: event["detail"].update(mime_type="image/png"),
            "canvas readback metadata",
        ),
        (
            lambda event: event["provenance"].update(component="blink.graphics"),
            "canvas readback metadata",
        ),
        (
            lambda event: event["detail"].update(width=True),
            "canvas readback width",
        ),
        (
            lambda event: event["detail"].update(height=2_147_483_648),
            "canvas readback height",
        ),
        (
            lambda event: event["detail"].update(origin_clean=1),
            "canvas readback origin-clean",
        ),
        (
            lambda event: event["process"].update(type="browser"),
            "canvas readback process",
        ),
        (
            lambda event: event["event"].update(category="diagnostic"),
            "canvas readback event identity",
        ),
        (
            lambda event: event["event"].update(name="HTMLCanvasElement.toBlob"),
            "canvas readback event identity",
        ),
        (
            lambda event: event.update(execution={"context_id": "frame-a"}),
            "canvas readback execution",
        ),
        (
            lambda event: event.update(
                value={"type": "bytes", "length": 1, "redaction": "metadata"}
            ),
            "canvas readback metadata",
        ),
        (
            lambda event: event.update(causal_parent_seq=0),
            "canvas readback parent",
        ),
    ],
)
def test_trace_rejects_forged_canvas_readback_call_metadata(
    mutation,
    message: str,
) -> None:
    event = canvas_readback_event()
    mutation(event)

    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


def generated_binding_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "binding-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "bindings:1:11",
            "frame_id": "bindings:1:11",
        },
        "event": {"category": "api", "name": "Navigator.userAgent.get"},
        "provenance": {
            "source": "native",
            "component": "blink.bindings.generated",
            "trace_category": "blink.bindings",
        },
        "detail": {
            "native_name": "Navigator.userAgent.get",
            "thread_id": 11,
            "completion": "complete",
            "duration_ns": 7,
        },
    }


def test_trace_accepts_exact_generated_binding_scope() -> None:
    event = validate_trace_event(generated_binding_event())

    assert event["detail"]["duration_ns"] == 7
    assert event["execution"]["context_id"] == "bindings:1:11"


def test_trace_accepts_generated_binding_without_observed_script_parent() -> None:
    event = generated_binding_event()
    event["execution"]["script_id"] = "v8:1:bindings:11:7"
    event["detail"]["script_attribution"] = "script-run-not-in-trace"

    assert validate_trace_event(event)["detail"]["script_attribution"] == (
        "script-run-not-in-trace"
    )


def test_trace_accepts_generated_binding_attributed_to_host_callback() -> None:
    event = generated_binding_event()
    event["seq"] = 2
    event["callback_parent_seq"] = 1
    event["execution"] = {
        "context_id": "frame-a",
        "frame_id": "frame-a",
        "script_id": "v8:1:frame-a:7",
    }
    event["detail"].update(
        script_attribution="callback-contained",
        context_attribution="host-callback",
    )

    assert validate_trace_event(event)["detail"]["context_attribution"] == (
        "host-callback"
    )


@pytest.mark.parametrize("mutation", ["parent", "context", "attribution"])
def test_trace_rejects_forged_generated_binding_callback_attribution(
    mutation: str,
) -> None:
    event = generated_binding_event()
    event["seq"] = 2
    event["callback_parent_seq"] = 1
    event["execution"] = {
        "context_id": "frame-a",
        "frame_id": "frame-a",
        "script_id": "v8:1:frame-a:7",
    }
    event["detail"].update(
        script_attribution="callback-contained",
        context_attribution="host-callback",
    )
    if mutation == "parent":
        event.pop("callback_parent_seq")
    elif mutation == "context":
        event["execution"] = {
            "context_id": "bindings:1:11",
            "frame_id": "bindings:1:11",
            "script_id": "v8:1:bindings:1:11:7",
        }
    else:
        event["detail"]["script_attribution"] = "matched-script-run"

    with pytest.raises(ContractError, match="binding callback attribution"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda event: event["detail"].update(native_name="Navigator.platform.get"),
            "generated binding metadata",
        ),
        (
            lambda event: event["detail"].update(width=1),
            "generated binding metadata",
        ),
        (
            lambda event: event["provenance"].update(source="probe"),
            "generated binding metadata",
        ),
        (
            lambda event: event["provenance"].pop("trace_category"),
            "generated binding metadata",
        ),
        (
            lambda event: event["provenance"].update(
                trace_category="blink.bindings.encoding"
            ),
            "generated binding category",
        ),
        (
            lambda event: event["event"].update(name="Navigator userAgent"),
            "generated binding name",
        ),
        (
            lambda event: event["detail"].update(duration_ns=True),
            "generated binding duration",
        ),
        (
            lambda event: event["detail"].update(
                duration_ns=7 * 24 * 60 * 60 * 1_000_000_000 + 1
            ),
            "generated binding duration",
        ),
        (
            lambda event: event["detail"].update(completion="open"),
            "generated binding completion",
        ),
        (
            lambda event: event["process"].update(type="browser"),
            "generated binding process",
        ),
        (
            lambda event: event.pop("execution"),
            "generated binding execution",
        ),
        (
            lambda event: event["execution"].update(context_id="frame-a"),
            "generated binding execution",
        ),
        (
            lambda event: event.update(
                value={"type": "string", "redaction": "dropped"}
            ),
            "generated binding metadata",
        ),
        (
            lambda event: event.update(causal_parent_seq=0),
            "generated binding parent",
        ),
    ],
)
def test_trace_rejects_forged_generated_binding_scope(
    mutation,
    message: str,
) -> None:
    event = generated_binding_event()
    mutation(event)

    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


def crypto_digest_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "crypto-run",
        "seq": 1,
        "ts_monotonic_ns": 2,
        "causal_parent_seq": 0,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "worker-a",
            "worker_id": "worker-a",
            "script_id": "v8:1:worker-a:7",
        },
        "event": {"category": "crypto", "name": "SubtleCrypto.digest"},
        "provenance": {"source": "native", "component": "blink.webcrypto"},
        "detail": {
            "native_name": "BrowserCore.CryptoDigest",
            "thread_id": 11,
            "algorithm": "SHA-256",
            "data_bytes": 32,
        },
        "value": {"type": "bytes", "length": 32, "redaction": "metadata"},
    }


def test_trace_accepts_exact_crypto_digest_metadata() -> None:
    event = validate_trace_event(crypto_digest_event())

    assert event["detail"]["algorithm"] == "SHA-256"
    assert event["value"]["length"] == 32


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda event: event["detail"].update(
                native_name="BrowserCore.CryptoDigestResult"
            ),
            "crypto digest metadata",
        ),
        (
            lambda event: event["detail"].update(result_bytes=32),
            "crypto digest metadata",
        ),
        (
            lambda event: event["provenance"].update(component="blink.crypto"),
            "crypto digest metadata",
        ),
        (
            lambda event: event["detail"].update(algorithm="SHA-999"),
            "crypto digest algorithm",
        ),
        (
            lambda event: event["detail"].update(data_bytes=2**40 + 1),
            "crypto digest data_bytes",
        ),
        (
            lambda event: event["value"].update(length=31),
            "crypto digest value",
        ),
        (
            lambda event: event["value"].update(redaction="digest"),
            "crypto digest value",
        ),
        (
            lambda event: event["process"].update(type="browser"),
            "crypto digest process",
        ),
        (
            lambda event: event["event"].update(category="api"),
            "crypto digest event identity",
        ),
        (
            lambda event: event["event"].update(name="SubtleCrypto.encrypt"),
            "crypto digest event identity",
        ),
        (
            lambda event: event["execution"].update(world_id="isolated"),
            "crypto digest execution",
        ),
        (
            lambda event: event.pop("causal_parent_seq"),
            "crypto digest parent",
        ),
    ],
)
def test_trace_rejects_forged_crypto_digest_metadata(
    mutation,
    message: str,
) -> None:
    event = crypto_digest_event()
    mutation(event)

    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


def wasm_compile_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "wasm-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "event": {"category": "wasm", "name": "WebAssembly.compile.completed"},
        "provenance": {"source": "native", "component": "v8.wasm"},
        "detail": {
            "native_name": "BrowserCore.WasmCompiled",
            "thread_id": 11,
            "success": True,
            "async": True,
            "cached": False,
            "code_bytes": 8,
        },
    }


def test_trace_accepts_exact_wasm_compile_completion() -> None:
    event = validate_trace_event(wasm_compile_event())

    assert event["detail"]["success"] is True
    assert event["detail"]["code_bytes"] == 8


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda event: event["detail"].update(
                native_name="BrowserCore.WasmCompile"
            ),
            "WASM compile metadata",
        ),
        (
            lambda event: event["detail"].update(module_count=1),
            "WASM compile metadata",
        ),
        (
            lambda event: event["provenance"].update(component="blink.wasm"),
            "WASM compile metadata",
        ),
        (
            lambda event: event["detail"].update(success=1),
            "WASM compile flags",
        ),
        (
            lambda event: event["detail"].update(code_bytes=1024**3 + 1),
            "WASM compile code_bytes",
        ),
        (
            lambda event: event.update(
                value={"type": "bytes", "length": 8, "redaction": "metadata"}
            ),
            "WASM compile metadata",
        ),
        (
            lambda event: event["process"].update(type="browser"),
            "WASM compile process",
        ),
        (
            lambda event: event["event"].update(category="api"),
            "WASM compile event identity",
        ),
        (
            lambda event: event["event"].update(name="WebAssembly.instantiate"),
            "WASM compile event identity",
        ),
        (
            lambda event: event["execution"].update(world_id="isolated"),
            "WASM compile execution",
        ),
        (
            lambda event: event["execution"].update(script_id="v8:1:frame-a:7"),
            "WASM compile script",
        ),
        (
            lambda event: event.update(causal_parent_seq=0),
            "WASM compile parent",
        ),
    ],
)
def test_trace_rejects_forged_wasm_compile_completion(
    mutation,
    message: str,
) -> None:
    event = wasm_compile_event()
    mutation(event)

    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


def stream_result_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 1,
        "ts_monotonic_ns": 2,
        "causal_parent_seq": 0,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "event": {"category": "stream", "name": "stream.read.result"},
        "provenance": {"source": "native", "component": "blink.streams"},
        "detail": {
            "native_name": "BrowserCore.StreamReadResult",
            "thread_id": 1,
            "reader_mode": "default",
            "result_kind": "chunk",
            "chunk_value_type": "bytes",
            "chunk_bytes": 2,
        },
        "value": {"type": "bytes", "length": 2, "redaction": "metadata"},
    }


def stream_request_event(*, script: bool = True) -> dict[str, object]:
    event: dict[str, object] = {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 1 if script else 0,
        "ts_monotonic_ns": 2 if script else 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "event": {"category": "stream", "name": "stream.read.request"},
        "provenance": {"source": "native", "component": "blink.streams"},
        "detail": {
            "native_name": "BrowserCore.StreamReadRequest",
            "thread_id": 1,
            "reader_mode": "default",
        },
    }
    if script:
        event["causal_parent_seq"] = 0
        event["execution"]["script_id"] = "v8:1:frame-a:7"
    return event


def body_consumer_event() -> dict[str, object]:
    event = stream_result_event()
    event["seq"] = 0
    event.pop("causal_parent_seq")
    event.pop("value")
    event["event"] = {"category": "stream", "name": "body.consume"}
    event["provenance"]["component"] = "blink.fetch-body"
    event["detail"] = {
        "native_name": "BrowserCore.BodyConsume",
        "thread_id": 1,
        "consumer_mode": "array-buffer",
    }
    return event


def test_trace_accepts_redacted_native_stream_result() -> None:
    assert validate_trace_event(stream_result_event())["detail"]["chunk_bytes"] == 2


def test_trace_accepts_exact_native_stream_request() -> None:
    assert validate_trace_event(stream_request_event())["detail"]["reader_mode"] == (
        "default"
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda event: event["detail"].update(
                native_name="BrowserCore.StreamReadResult"
            ),
            "stream result event identity",
        ),
        (
            lambda event: event["detail"].update(payload_bytes=1),
            "stream request metadata",
        ),
        (
            lambda event: event["provenance"].update(source="probe"),
            "stream request metadata",
        ),
        (
            lambda event: event["provenance"].update(component="blink.fetch"),
            "stream request metadata",
        ),
        (
            lambda event: event["process"].update(type="browser"),
            "stream request process",
        ),
        (
            lambda event: event["execution"].update(frame_id="frame-b"),
            "stream request execution",
        ),
        (
            lambda event: event["execution"].update(script_id="forged"),
            "stream request script identity",
        ),
        (
            lambda event: event.update(
                value={"type": "bytes", "length": 1, "redaction": "metadata"}
            ),
            "stream request metadata",
        ),
    ],
)
def test_trace_rejects_forged_native_stream_request(mutation, message: str) -> None:
    event = stream_request_event()
    mutation(event)

    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda event: event["detail"].update(
                native_name="BrowserCore.StreamReadRequest"
            ),
            "stream request event identity",
        ),
        (
            lambda event: event["detail"].update(payload_bytes=1),
            "stream result metadata",
        ),
        (
            lambda event: event["provenance"].update(source="probe"),
            "stream result metadata",
        ),
        (
            lambda event: event["process"].update(type="browser"),
            "stream result process",
        ),
        (
            lambda event: event["execution"].update(frame_id="frame-b"),
            "stream result execution",
        ),
        (
            lambda event: event["detail"].update(
                chunk_bytes=32 * 1024 * 1024 * 1024
            ),
            "stream chunk_bytes exceeds limit",
        ),
    ],
)
def test_trace_rejects_forged_native_stream_result(mutation, message: str) -> None:
    event = stream_result_event()
    mutation(event)

    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


def test_trace_accepts_value_free_high_level_body_consumer() -> None:
    event = body_consumer_event()

    assert validate_trace_event(event)["detail"]["consumer_mode"] == "array-buffer"


@pytest.mark.parametrize(
    "consumer_mode",
    ["array-buffer", "blob", "bytes", "form-data", "json", "text"],
)
def test_trace_accepts_each_declared_high_level_body_consumer(
    consumer_mode: str,
) -> None:
    event = body_consumer_event()
    event["detail"]["consumer_mode"] = consumer_mode

    assert validate_trace_event(event)["detail"]["consumer_mode"] == consumer_mode


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.StreamReadRequest"),
        ("consumer_mode", "TEXT"),
        ("reader_mode", "default"),
        ("result_kind", "chunk"),
        ("chunk_value_type", "bytes"),
        ("chunk_bytes", 1),
    ],
)
def test_trace_rejects_forged_high_level_body_consumer_detail(
    field: str,
    value: object,
) -> None:
    event = body_consumer_event()
    event["detail"][field] = value

    error_match = (
        "stream request event identity"
        if field == "native_name"
        else "body consumer metadata"
    )
    with pytest.raises(ContractError, match=error_match):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("field", "value"),
    [("source", "probe"), ("component", "blink.streams")],
)
def test_trace_rejects_forged_high_level_body_consumer_provenance(
    field: str,
    value: str,
) -> None:
    event = body_consumer_event()
    event["provenance"][field] = value

    with pytest.raises(ContractError, match="body consumer metadata"):
        validate_trace_event(event)


def test_trace_rejects_body_consumer_values() -> None:
    event = body_consumer_event()
    event["value"] = {"type": "bytes", "length": 1, "redaction": "metadata"}

    with pytest.raises(ContractError, match="body consumer metadata"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        (
            lambda event: event["process"].update(type="browser"),
            "body consumer process",
        ),
        (
            lambda event: event["execution"].update(frame_id="frame-b"),
            "body consumer execution",
        ),
        (
            lambda event: event["execution"].update(world_id="isolated"),
            "body consumer execution",
        ),
    ],
)
def test_trace_rejects_forged_body_consumer_execution_scope(
    mutation,
    error_match: str,
) -> None:
    event = body_consumer_event()
    mutation(event)

    with pytest.raises(ContractError, match=error_match):
        validate_trace_event(event)


def script_run_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        "event": {"category": "execution", "name": "script.run"},
        "provenance": {"source": "native", "component": "blink.v8"},
        "detail": {"native_name": "BrowserCore.ScriptRun", "thread_id": 1},
    }


def test_trace_accepts_exact_value_free_script_run_anchor() -> None:
    event = script_run_event()

    assert validate_trace_event(event)["detail"]["native_name"] == (
        "BrowserCore.ScriptRun"
    )


@pytest.mark.parametrize("script_number", ["07", "٧"])
def test_trace_rejects_noncanonical_v8_script_identity(
    script_number: str,
) -> None:
    event = script_run_event()
    event["execution"]["script_id"] = f"v8:1:frame-a:{script_number}"

    with pytest.raises(ContractError, match="script run script identity"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda event: event["detail"].update(native_name="BrowserCore.Script"), "metadata"),
        (lambda event: event["detail"].update(duration_ns=1), "metadata"),
        (lambda event: event["provenance"].update(source="probe"), "metadata"),
        (lambda event: event["provenance"].update(component="v8"), "metadata"),
        (
            lambda event: event.update(
                value={"type": "string", "redaction": "dropped"}
            ),
            "metadata",
        ),
        (lambda event: event.update(causal_parent_seq=0), "parent"),
        (lambda event: event["execution"].pop("script_id"), "script"),
        (lambda event: event["execution"].update(context_id=""), "context"),
        (lambda event: event["process"].update(type="browser"), "process"),
        (lambda event: event["event"].update(category="api"), "event identity"),
        (
            lambda event: event["event"].update(name="script.execution"),
            "event identity",
        ),
    ],
)
def test_trace_rejects_forged_script_run_anchor(mutation, message: str) -> None:
    event = script_run_event()
    mutation(event)

    with pytest.raises(ContractError, match=f"script run {message}"):
        validate_trace_event(event)


def script_execution_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        "event": {"category": "execution", "name": "script.execution"},
        "provenance": {"source": "native", "component": "blink.v8"},
        "detail": {
            "native_name": "BrowserCore.ScriptExecution",
            "thread_id": 1,
            "completion": "complete",
            "duration_ns": 7,
        },
    }


def test_trace_accepts_exact_value_free_script_execution_scope() -> None:
    event = script_execution_event()

    assert validate_trace_event(event)["detail"]["completion"] == "complete"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda event: event["provenance"].update(source="probe"), "metadata"),
        (lambda event: event["provenance"].update(component="v8"), "metadata"),
        (
            lambda event: event.update(
                value={"type": "string", "redaction": "dropped"}
            ),
            "metadata",
        ),
        (lambda event: event["process"].update(type="browser"), "process"),
        (lambda event: event["execution"].update(context_id=""), "context"),
        (lambda event: event["execution"].pop("script_id"), "script"),
        (lambda event: event.update(causal_parent_seq=0), "parent"),
        (lambda event: event["event"].update(category="api"), "event identity"),
        (
            lambda event: event["event"].update(name="script.run"),
            "event identity",
        ),
    ],
)
def test_trace_rejects_forged_script_execution_scope(
    mutation,
    message: str,
) -> None:
    event = script_execution_event()
    mutation(event)

    with pytest.raises(ContractError, match=f"script execution {message}"):
        validate_trace_event(event)


def promise_microtask_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 1,
        "ts_monotonic_ns": 2,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "event": {
            "category": "execution",
            "name": "promise.microtask.execution",
        },
        "provenance": {
            "source": "native",
            "component": "blink.scheduler.promise",
        },
        "detail": {
            "native_name": "BrowserCore.PromiseMicrotaskExecution",
            "thread_id": 1,
            "completion": "complete",
            "duration_ns": 7,
            "boundary": "v8-isolate-promise-hook-before-after",
            "job_kind": "unclassified",
        },
    }


def test_trace_accepts_exact_value_free_promise_microtask_scope() -> None:
    event = promise_microtask_event()

    assert validate_trace_event(event)["detail"]["job_kind"] == "unclassified"


def test_trace_accepts_open_promise_microtask_scope() -> None:
    event = promise_microtask_event()
    event["detail"].update(completion="open")
    event["detail"].pop("duration_ns")

    assert validate_trace_event(event)["detail"]["completion"] == "open"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda event: event["provenance"].update(source="probe"), "metadata"),
        (
            lambda event: event["provenance"].update(component="v8.promise"),
            "metadata",
        ),
        (lambda event: event["process"].update(type="browser"), "process"),
        (lambda event: event["execution"].update(context_id=""), "context"),
        (lambda event: event["execution"].update(script_id="v8:1:frame-a:7"), "execution"),
        (lambda event: event["detail"].update(job_kind="fulfilled"), "metadata"),
        (lambda event: event["detail"].update(boundary="reaction-job"), "metadata"),
        (lambda event: event.update(causal_parent_seq=0), "metadata"),
        (
            lambda event: event.update(
                value={"type": "promise", "redaction": "metadata"}
            ),
            "metadata",
        ),
        (
            lambda event: event["event"].update(name="promise.reaction"),
            "execution event identity",
        ),
    ],
)
def test_trace_rejects_forged_promise_microtask_scope(
    mutation,
    message: str,
) -> None:
    event = promise_microtask_event()
    mutation(event)

    with pytest.raises(ContractError, match=f"promise microtask {message}"):
        validate_trace_event(event)


@pytest.mark.parametrize("parent", [1, 2])
def test_trace_promise_parent_must_be_earlier(parent: int) -> None:
    event = promise_microtask_event()
    event["promise_parent_seq"] = parent

    with pytest.raises(ContractError, match="promise parent is not earlier"):
        validate_trace_event(event)


def dynamic_code_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 2,
        "ts_monotonic_ns": 3,
        "causal_parent_seq": 1,
        "process": {"pid": 7, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:7:frame-a:11",
        },
        "event": {
            "category": "execution",
            "name": "dynamic.code.materialized",
        },
        "provenance": {
            "source": "native",
            "component": "v8.compiler",
        },
        "detail": {
            "native_name": "BrowserCore.DynamicCodeMaterialized",
            "thread_id": 9,
            "dynamic_kind": "eval",
            "cache_status": "compiled",
            "generated_script_id": 12,
            "caller_script_id": 11,
            "caller_status": "observed",
            "source_length": 31,
            "source_length_unit": "utf16-code-units",
        },
    }


def test_trace_accepts_exact_value_free_dynamic_code_materialization() -> None:
    event = dynamic_code_event()

    assert validate_trace_event(event)["detail"]["generated_script_id"] == 12


def test_trace_accepts_bounded_compiler_input_digest() -> None:
    event = dynamic_code_event()
    event["detail"].update(
        compiler_input_hash_status="observed",
        compiler_input_utf16le_sha256="a" * 64,
    )
    assert validate_trace_event(event)["detail"]["compiler_input_utf16le_sha256"] == "a" * 64


def test_trace_accepts_over_limit_compiler_input_without_digest() -> None:
    event = dynamic_code_event()
    event["detail"].update(
        source_length=262_145,
        compiler_input_hash_status="over-limit",
        compiler_input_utf16le_sha256=None,
    )
    assert validate_trace_event(event)["detail"]["compiler_input_hash_status"] == "over-limit"


@pytest.mark.parametrize(
    ("status", "digest", "length"),
    [
        ({}, "a" * 64, 31),
        ("observed", None, 31),
        ("observed", "A" * 64, 31),
        ("over-limit", "a" * 64, 262_145),
        ("over-limit", None, 31),
        ("observed", "a" * 64, 262_145),
    ],
)
def test_trace_rejects_inconsistent_compiler_input_digest(
    status: object, digest: object, length: int,
) -> None:
    event = dynamic_code_event()
    event["detail"].update(
        source_length=length,
        compiler_input_hash_status=status,
        compiler_input_utf16le_sha256=digest,
    )
    with pytest.raises(ContractError, match="compiler input hash"):
        validate_trace_event(event)


def test_trace_accepts_dynamic_code_when_caller_parent_is_not_retained() -> None:
    event = dynamic_code_event()
    event.pop("causal_parent_seq")
    event.pop("execution")
    event["detail"]["caller_parent_status"] = "script_parent_not_in_trace"

    assert validate_trace_event(event)["detail"]["caller_parent_status"] == (
        "script_parent_not_in_trace"
    )


def test_trace_rejects_dynamic_code_context_when_caller_parent_is_not_retained() -> None:
    event = dynamic_code_event()
    event.pop("causal_parent_seq")
    event["detail"]["caller_parent_status"] = "script_parent_not_in_trace"

    with pytest.raises(ContractError, match="caller parent"):
        validate_trace_event(event)


def test_trace_accepts_dynamic_code_with_unavailable_caller() -> None:
    event = dynamic_code_event()
    event.pop("causal_parent_seq")
    event.pop("execution")
    event["detail"].update(caller_script_id=-1, caller_status="unavailable")

    assert validate_trace_event(event)["detail"]["caller_status"] == "unavailable"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda event: event["provenance"].update(source="probe"), "metadata"),
        (
            lambda event: event["provenance"].update(component="blink.v8"),
            "metadata",
        ),
        (lambda event: event["process"].update(type="browser"), "process"),
        (lambda event: event["detail"].update(dynamic_kind="module"), "metadata"),
        (lambda event: event["detail"].update(cache_status="hit"), "metadata"),
        (
            lambda event: event["detail"].update(generated_script_id=-1),
            "generated_script_id",
        ),
        (
            lambda event: event["detail"].update(caller_script_id=12),
            "caller script",
        ),
        (lambda event: event["detail"].update(source_length=-1), "source_length"),
        (
            lambda event: event["detail"].update(source_length_unit="bytes"),
            "metadata",
        ),
        (
            lambda event: event.update(
                value={"type": "string", "redaction": "metadata"}
            ),
            "metadata",
        ),
        (
            lambda event: event["event"].update(name="dynamic.code.executed"),
            "materialization event identity",
        ),
    ],
)
def test_trace_rejects_forged_dynamic_code_materialization(
    mutation,
    message: str,
) -> None:
    event = dynamic_code_event()
    mutation(event)

    with pytest.raises(ContractError, match=f"dynamic code {message}"):
        validate_trace_event(event)


@pytest.mark.parametrize("parent", [2, 3])
def test_trace_dynamic_code_parent_must_be_earlier(parent: int) -> None:
    event = dynamic_code_event()
    event["dynamic_code_parent_seq"] = parent

    with pytest.raises(ContractError, match="dynamic code parent is not earlier"):
        validate_trace_event(event)


def host_callback_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 1,
        "ts_monotonic_ns": 2,
        "causal_parent_seq": 0,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        "event": {
            "category": "execution",
            "name": "host.callback.execution",
        },
        "provenance": {
            "source": "native",
            "component": "blink.bindings.callback",
        },
        "detail": {
            "native_name": "BrowserCore.HostCallbackExecution",
            "thread_id": 1,
            "completion": "complete",
            "duration_ns": 7,
            "callback_interface": "EventListener",
            "callback_operation": "handleEvent",
            "callback_kind": "function",
        },
    }


def test_trace_accepts_exact_value_free_host_callback_scope() -> None:
    event = host_callback_event()

    assert validate_trace_event(event)["detail"]["callback_operation"] == (
        "handleEvent"
    )


def test_trace_accepts_host_callback_without_observed_script_parent() -> None:
    event = host_callback_event()
    event.pop("causal_parent_seq")
    event["detail"]["causal_parent_status"] = "script_parent_not_in_trace"

    assert validate_trace_event(event)["detail"]["causal_parent_status"] == (
        "script_parent_not_in_trace"
    )


def test_trace_accepts_exact_message_dispatch_to_callback_link() -> None:
    event = host_callback_event()
    event["seq"] = 2
    event["message_dispatch_parent_seq"] = 1

    assert validate_trace_event(event)["message_dispatch_parent_seq"] == 1


def test_trace_accepts_message_callback_when_dispatch_is_not_in_trace() -> None:
    event = host_callback_event()
    event["detail"]["message_dispatch_parent_status"] = (
        "message_dispatch_parent_not_in_trace"
    )

    assert validate_trace_event(event)["detail"][
        "message_dispatch_parent_status"
    ] == "message_dispatch_parent_not_in_trace"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda event: event.update(message_dispatch_parent_seq=event["seq"]),
            "message dispatch parent is not earlier",
        ),
        (
            lambda event: event["detail"].update(
                callback_interface="MutationCallback"
            ),
            "message dispatch link",
        ),
        (
            lambda event: event["detail"].update(
                message_dispatch_parent_status="dispatch_missing"
            ),
            "message dispatch parent",
        ),
        (
            lambda event: event["detail"].update(
                message_dispatch_parent_status=(
                    "message_dispatch_parent_not_in_trace"
                )
            ),
            "message dispatch parent",
        ),
    ],
)
def test_trace_rejects_forged_message_dispatch_callback_link(
    mutation,
    message: str,
) -> None:
    event = host_callback_event()
    event["seq"] = 2
    event["message_dispatch_parent_seq"] = 1
    mutation(event)

    with pytest.raises(ContractError, match=message):
        validate_trace_event(event)


def test_trace_rejects_message_dispatch_parent_on_unrelated_event() -> None:
    event = message_dispatch_event()
    event["seq"] = 2
    event["message_dispatch_parent_seq"] = 1

    with pytest.raises(ContractError, match="on an unrelated event"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda event: event["provenance"].update(source="probe"), "metadata"),
        (
            lambda event: event["provenance"].update(component="blink.events"),
            "metadata",
        ),
        (lambda event: event["process"].update(type="browser"), "process"),
        (lambda event: event["execution"].update(context_id=""), "context"),
        (lambda event: event["execution"].pop("script_id"), "script parent"),
        (lambda event: event["detail"].update(callback_interface="Event.Listener"), "descriptor"),
        (lambda event: event["detail"].update(callback_operation=""), "descriptor"),
        (lambda event: event["detail"].update(callback_kind="method"), "kind"),
        (lambda event: event["detail"].update(completion="pending"), "completion"),
        (
            lambda event: event["event"].update(category="api"),
            "execution event identity",
        ),
        (
            lambda event: event["event"].update(name="script.execution"),
            "execution event identity",
        ),
    ],
)
def test_trace_rejects_forged_host_callback_scope(mutation, message: str) -> None:
    event = host_callback_event()
    mutation(event)

    with pytest.raises(ContractError, match=f"host callback {message}"):
        validate_trace_event(event)


@pytest.mark.parametrize("parent", [1, 2])
def test_trace_callback_parent_must_be_earlier(parent: int) -> None:
    event = host_callback_event()
    event["callback_parent_seq"] = parent

    with pytest.raises(ContractError, match="callback parent is not earlier"):
        validate_trace_event(event)


def message_post_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 1,
        "ts_monotonic_ns": 2,
        "causal_parent_seq": 0,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {
            "context_id": "frame-a",
            "frame_id": "frame-a",
            "script_id": "v8:1:frame-a:7",
        },
        "event": {"category": "message", "name": "MessagePort.postMessage"},
        "provenance": {"source": "native", "component": "blink.messaging"},
        "detail": {"native_name": "BrowserCore.MessagePost", "thread_id": 1},
    }


def test_trace_accepts_value_free_message_post_with_script_parent() -> None:
    event = message_post_event()

    assert validate_trace_event(event)["detail"]["native_name"] == (
        "BrowserCore.MessagePost"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.MessageDispatch"),
        ("causal_parent_status", "message_parent_not_in_trace"),
        ("payload_bytes", 1),
    ],
)
def test_trace_rejects_forged_message_post_detail(
    field: str,
    value: object,
) -> None:
    event = message_post_event()
    event["detail"][field] = value

    error_match = (
        "message dispatch event identity"
        if field == "native_name"
        else "message post metadata"
    )
    with pytest.raises(ContractError, match=error_match):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("parent", "status", "script_id"),
    [
        (None, None, "v8:1:frame-a:7"),
        (0, "script_parent_not_in_trace", "v8:1:frame-a:7"),
        (0, None, None),
        (None, "script_parent_not_in_trace", None),
    ],
)
def test_trace_rejects_incoherent_message_post_script_parent_state(
    parent: int | None,
    status: str | None,
    script_id: str | None,
) -> None:
    event = message_post_event()
    event.pop("causal_parent_seq", None)
    event["detail"].pop("causal_parent_status", None)
    event["execution"].pop("script_id", None)
    if parent is not None:
        event["causal_parent_seq"] = parent
    if status is not None:
        event["detail"]["causal_parent_status"] = status
    if script_id is not None:
        event["execution"]["script_id"] = script_id

    with pytest.raises(ContractError, match="message post parent"):
        validate_trace_event(event)


def test_trace_rejects_message_post_values_and_forged_provenance() -> None:
    event = message_post_event()
    event["value"] = {"type": "bytes", "length": 1, "redaction": "metadata"}
    with pytest.raises(ContractError, match="message post metadata"):
        validate_trace_event(event)

    event = message_post_event()
    event["provenance"]["component"] = "blink.messaging.listener"
    with pytest.raises(ContractError, match="message post metadata"):
        validate_trace_event(event)


def message_dispatch_event() -> dict[str, object]:
    return {
        "schema": "browser-core.trace-event/1",
        "run_id": "test-run",
        "seq": 0,
        "ts_monotonic_ns": 1,
        "process": {"pid": 1, "type": "renderer"},
        "execution": {"context_id": "frame-a", "frame_id": "frame-a"},
        "event": {"category": "message", "name": "MessagePort.message.dispatch"},
        "provenance": {"source": "native", "component": "blink.messaging"},
        "detail": {
            "native_name": "BrowserCore.MessageDispatch",
            "thread_id": 1,
            "dispatch_kind": "message",
            "causal_parent_status": "message_parent_unavailable",
        },
    }


def test_trace_accepts_value_free_message_dispatch_attempt() -> None:
    event = message_dispatch_event()

    assert validate_trace_event(event)["detail"]["dispatch_kind"] == "message"


@pytest.mark.parametrize(
    ("event_factory", "wrong_name", "label"),
    [
        (fetch_api_event, "XMLHttpRequest.open", "fetch API"),
        (network_trace_event, "fetch.request.end", "fetch request"),
        (message_post_event, "Window.postMessage", "message post"),
        (message_dispatch_event, "MessagePort.message", "message dispatch"),
        (stream_request_event, "stream.read.start", "stream request"),
        (stream_result_event, "stream.read.end", "stream result"),
        (body_consumer_event, "body.used", "body consumer"),
    ],
)
def test_exact_native_name_rejects_relabelled_event_route(
    event_factory,
    wrong_name: str,
    label: str,
) -> None:
    event = event_factory()
    event["event"]["name"] = wrong_name

    with pytest.raises(ContractError, match=rf"{label} event identity"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.MessagePost"),
        ("dispatch_kind", "listener-complete"),
        ("causal_parent_status", "script_parent_not_in_trace"),
        ("payload_bytes", 1),
    ],
)
def test_trace_rejects_forged_message_dispatch_detail(
    field: str,
    value: object,
) -> None:
    event = message_dispatch_event()
    event["detail"][field] = value

    error_match = (
        "message post event identity"
        if field == "native_name"
        else "message dispatch metadata"
    )
    with pytest.raises(ContractError, match=error_match):
        validate_trace_event(event)


def test_trace_rejects_message_dispatch_values_and_script_attribution() -> None:
    event = message_dispatch_event()
    event["value"] = {"type": "bytes", "length": 1, "redaction": "metadata"}
    with pytest.raises(ContractError, match="message dispatch metadata"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("event_factory", "mutation", "error_match"),
    [
        (
            message_post_event,
            lambda event: event["process"].update(type="browser"),
            "message post process",
        ),
        (
            message_post_event,
            lambda event: event["execution"].update(frame_id="frame-b"),
            "message post execution",
        ),
        (
            message_post_event,
            lambda event: event["execution"].update(world_id="isolated"),
            "message post execution",
        ),
        (
            message_dispatch_event,
            lambda event: event["process"].update(type="browser"),
            "message dispatch process",
        ),
        (
            message_dispatch_event,
            lambda event: event["execution"].update(frame_id="frame-b"),
            "message dispatch execution",
        ),
        (
            message_dispatch_event,
            lambda event: event["execution"].update(world_id="isolated"),
            "message dispatch execution",
        ),
    ],
)
def test_trace_rejects_forged_message_execution_scope(
    event_factory,
    mutation,
    error_match: str,
) -> None:
    event = event_factory()
    mutation(event)

    with pytest.raises(ContractError, match=error_match):
        validate_trace_event(event)

    event = message_dispatch_event()
    event["execution"]["script_id"] = "v8:1:frame-a:7"
    with pytest.raises(ContractError, match="message dispatch metadata"):
        validate_trace_event(event)


@pytest.mark.parametrize(
    ("parent", "status", "script_id"),
    [
        (None, None, "v8:1:frame-a:7"),
        (0, "script_parent_not_in_trace", "v8:1:frame-a:7"),
        (0, None, None),
        (None, "script_parent_not_in_trace", None),
    ],
)
def test_trace_rejects_incoherent_body_consumer_script_parent_state(
    parent: int | None,
    status: str | None,
    script_id: str | None,
) -> None:
    event = body_consumer_event()
    if parent is not None:
        event["causal_parent_seq"] = parent
    if status is not None:
        event["detail"]["causal_parent_status"] = status
    if script_id is not None:
        event["execution"]["script_id"] = script_id

    with pytest.raises(ContractError, match="body consumer parent"):
        validate_trace_event(event)


@pytest.mark.parametrize("with_parent", [False, True])
def test_trace_accepts_one_body_consumer_script_parent_state(
    with_parent: bool,
) -> None:
    event = body_consumer_event()
    event["execution"]["script_id"] = "v8:1:frame-a:7"
    if with_parent:
        event["causal_parent_seq"] = 0
    else:
        event["detail"]["causal_parent_status"] = "script_parent_not_in_trace"

    assert validate_trace_event(event)["execution"]["script_id"] == (
        "v8:1:frame-a:7"
    )


def generated_binding_with_matched_script() -> dict[str, object]:
    event = generated_binding_event()
    event["execution"] = {
        "context_id": "frame-a",
        "frame_id": "frame-a",
        "script_id": "v8:1:frame-a:7",
    }
    event["detail"]["script_attribution"] = "matched-script-run"
    return event


@pytest.mark.parametrize(
    "event_factory",
    [
        script_run_event,
        script_execution_event,
        fetch_api_event,
        network_trace_event,
        crypto_digest_event,
        message_post_event,
        generated_binding_with_matched_script,
    ],
)
def test_exact_native_events_reject_forged_v8_script_identity(event_factory) -> None:
    event = event_factory()
    event["execution"]["script_id"] = "forged-script-label"

    with pytest.raises(ContractError, match="script identity"):
        validate_trace_event(event)


def test_body_consumer_rejects_forged_v8_script_identity() -> None:
    event = body_consumer_event()
    event["execution"]["script_id"] = "forged-script-label"
    event["causal_parent_seq"] = 0

    with pytest.raises(ContractError, match="script identity"):
        validate_trace_event(event)


def test_trace_validates_optional_native_trace_category_provenance() -> None:
    event = stream_result_event()
    event["provenance"]["trace_category"] = "browser_core.stream"
    assert validate_trace_event(event)["provenance"]["trace_category"] == (
        "browser_core.stream"
    )
    event["provenance"]["trace_category"] = "browser_core.debug"
    with pytest.raises(ContractError, match="exact native.*category"):
        validate_trace_event(event)
    event["provenance"]["trace_category"] = "blink.bindings"
    with pytest.raises(ContractError, match="exact native.*category"):
        validate_trace_event(event)


def test_trace_accepts_encoding_binding_category_only_for_api_events() -> None:
    event = stream_result_event()
    event["event"] = {"category": "api", "name": "TextEncoder.encode"}
    event["detail"]["native_name"] = "fixture.TextEncoder.encode"
    event["provenance"]["trace_category"] = "blink.bindings.encoding"
    assert validate_trace_event(event)["provenance"]["trace_category"] == (
        "blink.bindings.encoding"
    )
    event["event"] = {"category": "diagnostic", "name": "fixture.event"}
    with pytest.raises(ContractError, match="non-API"):
        validate_trace_event(event)


def test_trace_rejects_stream_byte_value_length_mismatch() -> None:
    event = stream_result_event()
    event["value"]["length"] = 3

    with pytest.raises(ContractError, match="byte value is inconsistent"):
        validate_trace_event(event)


@pytest.mark.parametrize("factory,field", [
    (generated_binding_event, "provenance.trace_category"),
    (generated_binding_event, "detail.context_attribution"),
    (generated_binding_event, "detail.script_attribution"),
    (crypto_digest_event, "detail.algorithm"),
    (body_consumer_event, "detail.consumer_mode"),
    (stream_request_event, "detail.reader_mode"),
    (stream_result_event, "detail.result_kind"),
    (stream_result_event, "detail.chunk_value_type"),
    (message_dispatch_event, "detail.dispatch_kind"),
    (dynamic_code_event, "detail.dynamic_kind"),
    (dynamic_code_event, "detail.cache_status"),
    (host_callback_event, "detail.callback_kind"),
])
def test_trace_rejects_unhashable_native_route_enums(factory, field: str) -> None:
    event = factory()
    target = event
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = []
    with pytest.raises(ContractError):
        validate_trace_event(event)
