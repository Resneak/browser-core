"""Machine-readable static capability inventory for research agents."""
import copy
import json
import os
import shutil
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core import agent_capabilities as capabilities
from browser_core.contracts import ContractError


ROOT = Path(__file__).resolve().parents[1]


@lru_cache
def inventory():
    return capabilities.agent_capabilities(ROOT)


def validator():
    import jsonschema

    schema = json.loads(
        (ROOT / "schemas" / "agent-capabilities-v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def validator_v2():
    import jsonschema

    schema = json.loads(
        (ROOT / "schemas" / "agent-capabilities-v2.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_inventory_separates_declared_support_from_observation():
    result = inventory()
    validator().validate(result)
    assert result["status"] == "ok"
    assert result["runtime_check"] == {
        "requested": False,
        "runtime_verified": None,
        "code": None,
        "runtime_bundle_sha256": None,
    }
    assert len(result["native_observation"]["routes"]) == 15
    assert result["native_observation"]["generated_bindings"]["available"]
    assert result["native_observation"]["compiler_input_identity"] == {
        "native_recording_available": False,
        "availability_basis": "not-in-native-series",
        "required_scope": "source-identity",
        "algorithm": "sha256-utf16le-compiler-input-v1",
        "maximum_code_units": 262144,
        "unsalted": True,
    }
    assert result["native_observation"]["compiler_input_context_identity"] == {
        "native_recording_available": False,
        "availability_basis": "not-in-native-series",
        "required_scope": "source-context",
        "native_event": "BrowserCore.ScriptSourceContext",
        "algorithm": "sha256-utf16le-compiler-input-v1",
        "maximum_code_units": 262144,
        "unsalted": True,
        "known_candidate_gap": "inspector-injected-isolated-world-scripts",
    }
    assert result["native_observation"]["compiler_input_realm_identity"] == {
        "native_recording_available": False,
        "availability_basis": "not-in-native-series",
        "required_scope": "source-context",
        "native_events": ["BrowserCore.ScriptSourceContext", "BrowserCore.ScriptRun"],
        "match_command": "script-source-realm-match",
        "api_link_basis": "same-v8-context-world-root-script-and-thread",
        "module_run_coverage": "module-root-evaluation-attempt;static-dependencies-not-individual",
        "known_candidate_gap": "inspector-injected-isolated-world-scripts",
    }
    assert result["semantics"] == {
        "capability_basis": "verified-package-resources",
        "native_route_is_runtime_observation": False,
        "reader_known_api_is_runtime_observation": False,
        "zero_observations_mean_unsupported": False,
        "client_side_coverage_complete": False,
        "server_side_architecture_observed": False,
        "browser_launched": False,
        "trace_read": False,
        "active_probe": False,
        "private_values_included": False,
    }


def test_capture_availability_is_bound_to_verified_patch_names():
    captures = {
        row["allowlist"]: row for row in inventory()["value_observation"]["captures"]
    }
    assert captures["fingerprint-v1"]["native_recording_available"]
    assert captures["fingerprint-v2"]["native_recording_available"]
    assert not captures["research-v3"]["native_recording_available"]
    for row in captures.values():
        assert row["api_count"] == len(row["apis"])
        assert row["apis"] == sorted(set(row["apis"]))


def test_contracts_are_bounded_content_digests_without_paths():
    result = inventory()
    assert len(result["contracts"]) == 11
    assert len({row["name"] for row in result["contracts"]}) == 11
    assert result["interfaces"]["saved_evidence_query"] == {
        "available": True,
        "input_schema": None,
        "output_schema": "browser-core.evidence-query/1",
        "browser_effect": "none",
    }
    assert result["interfaces"]["session_evidence_query"] == {
        "available": True,
        "input_schema": None,
        "output_schema": "browser-core.evidence-query/1",
        "browser_effect": "none",
    }
    assert result["interfaces"]["saved_evidence_research_plan"] == {
        "available": True,
        "input_schema": None,
        "output_schema": "browser-core.agent-research-plan/1",
        "browser_effect": "none",
    }
    rendered = json.dumps(result)
    assert str(ROOT) not in rendered
    assert "fixture-secret-must-not-escape" not in rendered


def test_contract_digest_rebinds_schema_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    path = schemas / "fixture.json"
    original_body = (
        b'{"$schema":"https://json-schema.org/draft/2020-12/schema",'
        b'"$id":"urn:fixture","note":"A"}'
    )
    path.write_bytes(original_body)
    decoded = capabilities.decode_strict_json_bytes

    def change_after_decode(body: bytes, *, label: str):
        document = decoded(body, label=label)
        previous = path.stat()
        path.write_bytes(original_body.replace(b'"A"', b'"B"'))
        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        return document

    monkeypatch.setattr(capabilities, "decode_strict_json_bytes", change_after_decode)
    with pytest.raises(ContractError, match="schema changed during read"):
        capabilities._contract(
            tmp_path, "fixture", "fixture.json", "urn:fixture"
        )


def test_contract_rejects_schema_with_external_hard_link(tmp_path: Path) -> None:
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    path = schemas / "fixture.json"
    path.write_bytes(
        b'{"$schema":"https://json-schema.org/draft/2020-12/schema",'
        b'"$id":"urn:fixture"}'
    )
    os.link(path, tmp_path / "external-alias.json")
    with pytest.raises(ContractError, match="hard links"):
        capabilities._contract(tmp_path, "fixture", "fixture.json", "urn:fixture")


def test_capability_inventory_rebinds_earlier_schema_after_later_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_snapshot = capabilities.read_bounded_control_snapshot_result
    read_contract = capabilities._contract
    later_contract_seen = False

    def snapshot(path: Path, **kwargs):
        value = read_snapshot(path, **kwargs)
        if later_contract_seen and path.name == "metadata-query-v1.schema.json":
            return SimpleNamespace(
                state=value.state, body=value.body + b" ", identity=value.identity
            )
        return value

    def contract(root, name, filename, identifier, **kwargs):
        nonlocal later_contract_seen
        value = read_contract(root, name, filename, identifier, **kwargs)
        if name == "agent-capabilities":
            later_contract_seen = True
        return value

    monkeypatch.setattr(capabilities, "read_bounded_control_snapshot_result", snapshot)
    monkeypatch.setattr(capabilities, "_contract", contract)
    with pytest.raises(ContractError, match="schema inventory changed"):
        capabilities.agent_capabilities(ROOT)


def test_capability_inventory_rejects_schema_hard_link_added_after_first_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    shutil.copy2(ROOT / "upstream.json", package / "upstream.json")
    shutil.copytree(ROOT / "patches", package / "patches")
    shutil.copytree(ROOT / "schemas", package / "schemas")
    schema = package / "schemas" / "metadata-query-v1.schema.json"
    read_contract = capabilities._contract

    def link_after_contract(root, name, filename, identifier, **kwargs):
        value = read_contract(root, name, filename, identifier, **kwargs)
        if name == "metadata-query":
            os.link(schema, tmp_path / "external-alias.json")
        return value

    monkeypatch.setattr(capabilities, "_contract", link_after_contract)
    with pytest.raises(ContractError, match="hard links"):
        capabilities.agent_capabilities(package)


def test_capability_inventory_rebinds_package_after_schema_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    shutil.copy2(ROOT / "upstream.json", package / "upstream.json")
    shutil.copytree(ROOT / "patches", package / "patches")
    shutil.copytree(ROOT / "schemas", package / "schemas")
    manifest = package / "upstream.json"
    initial = manifest.read_bytes()
    read_contract = capabilities._contract

    def change_manifest(root, name, filename, identifier, **kwargs):
        value = read_contract(root, name, filename, identifier, **kwargs)
        if name == "metadata-query":
            previous = manifest.stat()
            changed = initial.replace(b'"version": "153.0.7988.0"',
                                      b'"version": "154.0.7988.0"')
            assert changed != initial and len(changed) == len(initial)
            manifest.write_bytes(changed)
            os.utime(manifest, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        return value

    monkeypatch.setattr(capabilities, "_contract", change_manifest)
    with pytest.raises(ContractError, match="package changed"):
        capabilities.agent_capabilities(package)


def test_capability_inventory_rebinds_same_meaning_manifest_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    shutil.copy2(ROOT / "upstream.json", package / "upstream.json")
    shutil.copytree(ROOT / "patches", package / "patches")
    shutil.copytree(ROOT / "schemas", package / "schemas")
    manifest = package / "upstream.json"
    initial = manifest.read_bytes()
    changed = initial.replace(b'"captured_at": ', b'"captured_at" :', 1)
    assert changed != initial and len(changed) == len(initial)
    assert json.loads(changed) == json.loads(initial)
    read_contract = capabilities._contract

    def rewrite_manifest(root, name, filename, identifier, **kwargs):
        value = read_contract(root, name, filename, identifier, **kwargs)
        if name == "metadata-query":
            previous = manifest.stat()
            manifest.write_bytes(changed)
            os.utime(manifest, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        return value

    monkeypatch.setattr(capabilities, "_contract", rewrite_manifest)
    with pytest.raises(ContractError, match="package changed"):
        capabilities.agent_capabilities(package)


def test_extended_v1_schema_still_accepts_the_nine_contract_agent11_shape():
    prior = copy.deepcopy(inventory())
    prior["contracts"] = [
        row for row in prior["contracts"] if row["name"] != "agent-research-plan"
    ]
    del prior["interfaces"]["saved_evidence_research_plan"]
    validator().validate(prior)


def test_v2_compact_discovery_is_closed_and_value_free():
    result = capabilities.agent_capabilities(ROOT, schema_version=2)
    validator_v2().validate(result)
    assert result["schema"] == capabilities.SCHEMA_V2
    assert result["projection"] == "metadata"
    assert result["omitted_from_projection"] == [
        "native_observation", "value_observation"
    ]
    assert len(result["contracts"]) == 16
    assert {row["name"] for row in result["contracts"]} >= {
        "agent-capabilities-v2", "metadata-query-v2",
        "metadata-inventory-query", "metadata-rows", "evidence-stop-timeouts",
    }
    interfaces = result["interfaces"]
    expected = {
        "metadata_session_inventory": ("session-inventory", "session", False),
        "metadata_evidence_inventory": (
            "evidence-inventory", "immutable-evidence-bundle", False
        ),
        "metadata_session_rows": ("session-rows", "session", True),
        "metadata_evidence_rows": (
            "evidence-rows", "immutable-evidence-bundle", True
        ),
    }
    for name, (route, source, rows) in expected.items():
        interface = interfaces[name]
        assert interface["cli_argv_prefix"] == ["trace", route]
        assert interface["source_kind"] == source
        assert interface["event_rows"] is rows
        assert interface["row_policy"] == (
            "complete-only" if rows else "no-event-rows"
        )
        assert interface["capture_requirement"] == "metadata-only-zero-private-values"
        assert interface["portable_context_pair_required"] is True
        assert interface["private_values_included"] is False
        assert interface["full_population_validated"] is True
        assert interface["identity_and_health_retained"] is True
        assert interface["outer_delivery_verified"] is False
        assert interface["max_emitted_json_bytes"] == 16_384
        assert interface["cursor_flag"] == (
            "--cursor" if rows and source == "immutable-evidence-bundle" else None
        )
        assert interface["cursor_binding"] == (
            "same-verified-bundle-digest-selectors-limit-and-snapshot"
            if rows and source == "immutable-evidence-bundle" else None
        )
    assert interfaces["metadata_session_rows"]["required_flags"] == [
        "--session", "--expected-run-id"
    ]
    assert interfaces["metadata_evidence_rows"]["required_flags"] == [
        "--bundle", "--reader-executable"
    ]
    assert interfaces["metadata_evidence_rows"]["recommended_binding_flags"] == [
        "--expected-sha256"
    ]
    assert interfaces["saved_evidence_research_plan"]["capture_requirement"] == (
        "supported-private-value-capture"
    )
    assert result["semantics"]["browser_launched"] is False
    assert result["semantics"]["trace_read"] is False
    assert result["semantics"]["server_side_architecture_observed"] is False


def test_v2_full_scope_retains_native_and_value_catalogs():
    result = capabilities.agent_capabilities(ROOT, schema_version=2, scope="full")
    validator_v2().validate(result)
    assert result["projection"] == "full"
    assert "native_observation" in result
    assert "value_observation" in result
    assert "omitted_from_projection" not in result


def test_full_capability_byte_limit_covers_pretty_printed_windows_output(monkeypatch):
    result = inventory()
    compact = len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii"))
    rendered = json.dumps(
        result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
    )
    emitted = len(rendered.encode("ascii")) + rendered.count("\n") + 2
    assert compact < emitted - 1
    monkeypatch.setattr(capabilities, "MAX_OUTPUT_BYTES", emitted - 1)

    with pytest.raises(ContractError, match="output exceeds byte limit"):
        capabilities.agent_capabilities(ROOT)


def test_v2_schema_rejects_false_delivery_and_swapped_routes():
    result = capabilities.agent_capabilities(ROOT, schema_version=2)
    result["interfaces"]["metadata_evidence_rows"]["outer_delivery_verified"] = True
    with pytest.raises(Exception):
        validator_v2().validate(result)


def test_v2_schema_requires_each_named_contract_exactly_once():
    result = capabilities.agent_capabilities(ROOT, schema_version=2)
    result["contracts"][-1] = dict(result["contracts"][0])
    result["contracts"][-1]["sha256"] = "0" * 64
    with pytest.raises(Exception):
        validator_v2().validate(result)
    result = capabilities.agent_capabilities(ROOT, schema_version=2)
    result["contracts"] = result["contracts"][:-1]
    with pytest.raises(Exception):
        validator_v2().validate(result)
    result = capabilities.agent_capabilities(ROOT, schema_version=2)
    result["interfaces"]["metadata_evidence_rows"]["cli_argv_prefix"] = [
        "trace", "session-rows"
    ]
    with pytest.raises(Exception):
        validator_v2().validate(result)


@pytest.mark.parametrize("version,scope", [(True, None), (3, None), (1, "metadata")])
def test_capability_version_and_scope_fail_closed(version, scope):
    with pytest.raises(ContractError):
        capabilities.agent_capabilities(ROOT, schema_version=version, scope=scope)


def test_v2_requires_verified_new_contract_resources(monkeypatch):
    original = capabilities._contract

    def unavailable(root, name, filename, identifier, **kwargs):
        if name == "metadata-rows":
            raise ContractError("schema unavailable")
        return original(root, name, filename, identifier, **kwargs)

    monkeypatch.setattr(capabilities, "_contract", unavailable)
    validator().validate(capabilities.agent_capabilities(ROOT))
    with pytest.raises(ContractError, match="schema unavailable"):
        capabilities.agent_capabilities(ROOT, schema_version=2)


def test_v2_rejects_invalid_json_schema_resource_before_advertising(monkeypatch):
    original = capabilities.read_bounded_control_snapshot_result

    def invalid_rows(path, **kwargs):
        if path.name == "metadata-rows-v1.schema.json":
            return SimpleNamespace(
                state="complete",
                body=(
                    b'{"$schema":"https://json-schema.org/draft/2020-12/schema",'
                    b'"$id":"urn:browser-core:metadata-rows:1","type":42}'
                ),
            )
        return original(path, **kwargs)

    monkeypatch.setattr(capabilities, "read_bounded_control_snapshot_result", invalid_rows)
    validator().validate(capabilities.agent_capabilities(ROOT))
    with pytest.raises(ContractError, match="schema is invalid"):
        capabilities.agent_capabilities(ROOT, schema_version=2)


def test_verified_runtime_must_bind_the_same_package(monkeypatch):
    base = inventory()["package"]
    monkeypatch.setattr(
        capabilities,
        "check_runtime",
        lambda root, executable: {
            "code": "verified",
            "runtime_verified": True,
            "package": {
                "chromium_revision": base["chromium_revision"],
                "patch_series_sha256": base["patch_series_sha256"],
                "patches": base["native_patches"],
            },
            "runtime": {"runtime_bundle_sha256": "a" * 64},
        },
    )
    result = capabilities.agent_capabilities(ROOT, Path("C:/browser/chrome.exe"))
    assert result["runtime_check"] == {
        "requested": True,
        "runtime_verified": True,
        "code": "verified",
        "runtime_bundle_sha256": "a" * 64,
    }
    validator().validate(result)


@pytest.mark.parametrize("mutation", ["revision", "digest", "count", "runtime-digest"])
def test_inconsistent_verified_runtime_is_rejected(monkeypatch, mutation):
    base = inventory()["package"]
    package = {
        "chromium_revision": base["chromium_revision"],
        "patch_series_sha256": base["patch_series_sha256"],
        "patches": base["native_patches"],
    }
    runtime_digest = "a" * 64
    if mutation == "revision":
        package["chromium_revision"] = "b" * 40
    elif mutation == "digest":
        package["patch_series_sha256"] = "b" * 64
    elif mutation == "count":
        package["patches"] += 1
    else:
        runtime_digest = "bad"
    monkeypatch.setattr(
        capabilities,
        "check_runtime",
        lambda root, executable: {
            "code": "verified",
            "runtime_verified": True,
            "package": package,
            "runtime": {"runtime_bundle_sha256": runtime_digest},
        },
    )
    with pytest.raises(ContractError, match="binding"):
        capabilities.agent_capabilities(ROOT, Path("C:/browser/chrome.exe"))


def test_unverified_runtime_stays_a_successful_inventory_but_not_a_match(monkeypatch):
    monkeypatch.setattr(
        capabilities,
        "check_runtime",
        lambda root, executable: {
            "code": "artifact-mismatch",
            "runtime_verified": False,
        },
    )
    result = capabilities.agent_capabilities(ROOT, Path("C:/browser/chrome.exe"))
    assert result["status"] == "ok"
    assert result["runtime_check"] == {
        "requested": True,
        "runtime_verified": False,
        "code": "artifact-mismatch",
        "runtime_bundle_sha256": None,
    }
    validator().validate(result)


def test_runtime_code_and_boolean_cannot_disagree(monkeypatch):
    monkeypatch.setattr(
        capabilities,
        "check_runtime",
        lambda root, executable: {"code": "verified", "runtime_verified": False},
    )
    with pytest.raises(ContractError, match="capability check"):
        capabilities.agent_capabilities(ROOT, Path("C:/browser/chrome.exe"))


def test_schema_rejects_promoted_claims_and_extra_payloads():
    result = copy.deepcopy(inventory())
    result["semantics"]["client_side_coverage_complete"] = True
    with pytest.raises(Exception):
        validator().validate(result)
    result = copy.deepcopy(inventory())
    result["private_value"] = "must-not-be-admitted"
    with pytest.raises(Exception):
        validator().validate(result)


@pytest.mark.parametrize(
    "failure,code,exit_code",
    [
        (ContractError("private detail"), "capabilities-unavailable", 2),
        (OSError("private path"), "capabilities-unavailable", 2),
        (KeyboardInterrupt(), "interrupted", 130),
    ],
)
def test_cli_failures_are_fixed_json(monkeypatch, capsys, failure, code, exit_code):
    from browser_core import cli

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(capabilities, "agent_capabilities", fail)
    assert cli.main(["agent", "capabilities"]) == exit_code
    output = capsys.readouterr()
    assert json.loads(output.out) == {
        "schema": capabilities.SCHEMA,
        "status": "error",
        "code": code,
    }
    assert output.err == ""


def test_cli_exit_distinguishes_package_only_and_runtime_mismatch(monkeypatch, capsys):
    from browser_core import cli

    result = copy.deepcopy(inventory())
    monkeypatch.setattr(capabilities, "agent_capabilities", lambda *args: result)
    assert cli.main(["agent", "capabilities"]) == 0
    capsys.readouterr()
    result["runtime_check"] = {
        "requested": True,
        "runtime_verified": False,
        "code": "package-mismatch",
        "runtime_bundle_sha256": None,
    }
    assert cli.main(["agent", "capabilities", "--executable", "missing.exe"]) == 2
    assert json.loads(capsys.readouterr().out)["runtime_check"]["code"] == "package-mismatch"


def test_cli_v1_default_and_explicit_version_are_identical(capsys):
    from browser_core import cli

    assert cli.main(["agent", "capabilities"]) == 0
    default = capsys.readouterr()
    assert cli.main(["agent", "capabilities", "--schema-version", "1"]) == 0
    explicit = capsys.readouterr()
    assert default == explicit
    validator().validate(json.loads(default.out))


def test_cli_v2_metadata_projection_is_bounded_and_schema_valid(capsys):
    from browser_core import cli

    assert cli.main(["agent", "capabilities", "--schema-version", "2"]) == 0
    output = capsys.readouterr()
    document = json.loads(output.out)
    validator_v2().validate(document)
    assert document["projection"] == "metadata"
    assert len(output.out.replace("\n", "\r\n").encode("ascii")) <= 16_384
    assert output.err == ""


def test_cli_v2_failure_uses_v2_error_schema(monkeypatch, capsys):
    from browser_core import cli

    def fail(*args):
        raise ContractError("private detail")

    monkeypatch.setattr(capabilities, "agent_capabilities", fail)
    assert cli.main(["agent", "capabilities", "--schema-version", "2"]) == 2
    output = capsys.readouterr()
    assert json.loads(output.out) == {
        "schema": capabilities.SCHEMA_V2,
        "status": "error",
        "code": "capabilities-unavailable",
    }
    assert output.err == ""


@pytest.mark.parametrize(
    "arguments,expected_schema",
    [
        (["--schema-version", "2", "--scope", "AUDIT_PRIVATE_SENTINEL" + "x" * 17_000], capabilities.SCHEMA_V2),
        (["--schema-version=2", "--scope=invalid"], capabilities.SCHEMA_V2),
        (["--scope", "invalid", "--schema-version", "2"], capabilities.SCHEMA_V2),
        (["--schema-version", "2", "--scope"], capabilities.SCHEMA_V2),
        (["--schema-version", "2", "--unknown", "AUDIT_PRIVATE_SENTINEL"], capabilities.SCHEMA_V2),
        (["--schema-version", "2", "--schema-version", "1"], capabilities.SCHEMA_V2),
        (["--schema-version", "2", "--", "--scope", "AUDIT_PRIVATE_SENTINEL"], capabilities.SCHEMA_V2),
        (["--schema-version", "3"], capabilities.SCHEMA),
        (["--schema-v", "2"], capabilities.SCHEMA_V2),
        (["--schema-v=2", "--scop=AUDIT_PRIVATE_SENTINEL" + "x" * 17_000], capabilities.SCHEMA_V2),
        (["--s", "2", "--scope", "metadata"], capabilities.SCHEMA_V2),
        (["--sc", "AUDIT_PRIVATE_SENTINEL"], capabilities.SCHEMA),
        (["--schema-version", "2", "--schema-v", "1"], capabilities.SCHEMA_V2),
        (["--schema-v", "1", "--schema-version", "2"], capabilities.SCHEMA_V2),
        (["--schema-v=2", "--schema-v=1"], capabilities.SCHEMA_V2),
        (["--schema-version", "2", "--scope", "metadata", "--scop", "full"], capabilities.SCHEMA_V2),
        (["--schema-version=02", "--unknown", "AUDIT_PRIVATE_SENTINEL"], capabilities.SCHEMA_V2),
        (["--schema-version=+2", "--unknown", "AUDIT_PRIVATE_SENTINEL"], capabilities.SCHEMA_V2),
        (["--schema-version=" + "0" * 32 + "2", "--unknown", "AUDIT_PRIVATE_SENTINEL"], capabilities.SCHEMA_V2),
    ],
)
def test_explicit_capability_parse_failures_are_bounded_json(
    capsys, arguments, expected_schema
):
    from browser_core import cli

    assert cli.main(["agent", "capabilities", *arguments]) == 2
    output = capsys.readouterr()
    assert json.loads(output.out) == {
        "schema": expected_schema,
        "status": "error",
        "code": "capabilities-unavailable",
    }
    assert len(output.out.encode("ascii")) <= 16_384
    assert "AUDIT_PRIVATE_SENTINEL" not in output.out
    assert output.err == ""
