from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

from browser_core.errors import ContractError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_device_memory_override as gate  # noqa: E402


def _attestation() -> dict[str, object]:
    return {
        "chromium_revision": "1" * 40,
        "executable_sha256": "2" * 64,
        "runtime_bundle_sha256": "3" * 64,
    }


def test_override_argument_contract_keeps_deliberate_malformed_cases_bounded() -> None:
    assert gate._args_for(None) == []
    assert gate._args_for(2048) == ["--browser-core-device-memory-mb=2048"]
    assert gate._args_for("banana") == ["--browser-core-device-memory-mb=banana"]
    assert gate._args_for("") == ["--browser-core-device-memory-mb="]
    for value in (True, 1.5, "x\n--remote-debugging-port=1", "x" * 33):
        with pytest.raises(ContractError):
            gate._args_for(value)  # type: ignore[arg-type]


def test_observation_projection_is_closed_and_finite() -> None:
    assert gate._validate_observation({"header": "8", "main": 8, "worker": 8}) == {
        "header": "8",
        "main": 8,
        "worker": 8,
    }
    assert gate._validate_observation(
        {"header": None, "main": 4, "worker": "worker-timeout"}
    )["worker"] == "worker-timeout"
    for value in (
        {"header": "8", "main": 8, "worker": 8, "private": "secret"},
        {"header": "private", "main": 8, "worker": 8},
        {"header": "8", "main": math.inf, "worker": 8},
        {"header": "8", "main": 10**10_000, "worker": 8},
        {"header": "8", "main": 8, "worker": {"private": "secret"}},
    ):
        with pytest.raises(ContractError):
            gate._validate_observation(value)


def test_case_population_rejects_duplicates_and_coercive_entries() -> None:
    with pytest.raises(ContractError, match="population"):
        gate._validate_cases(())
    with pytest.raises(ContractError, match="duplicated"):
        gate._validate_cases([("same", None, 8), ("same", 2048, 2)])
    with pytest.raises(ContractError, match="entry"):
        gate._validate_cases([["list", None, 8]])
    with pytest.raises(ContractError, match="label"):
        gate._validate_cases([("bad\ud800", None, 8)])
    with pytest.raises(ContractError, match="expected"):
        gate._validate_cases([("bad", None, math.nan)])
    with pytest.raises(ContractError, match="expected"):
        gate._validate_cases([("huge", None, 10**10_000)])


def test_observe_rejects_string_executable_before_attestation_contact() -> None:
    with pytest.raises(ContractError, match="must be a Path"):
        gate.observe("chrome.exe", None, expected_attestation={})  # type: ignore[arg-type]


def test_main_emits_a_path_free_refusal_for_attestation_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private = r"C:\private\tenant\chrome.exe"

    def refuse(_root: Path, _executable: Path):
        raise ContractError(f"invalid build at {private}")

    monkeypatch.setattr(gate, "load_build_attestation", refuse)
    monkeypatch.setattr(sys, "argv", ["gate", "--executable", private])
    assert gate.main() == 2
    output = capsys.readouterr().err
    assert "contract-failure" in output
    assert "private" not in output
    assert "tenant" not in output


def test_main_binds_a_closed_build_receipt_and_all_cases(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    attestation = _attestation()
    expected = {megabytes: want for _label, megabytes, want in gate.CASES}
    monkeypatch.setattr(gate, "load_build_attestation", lambda *_args: attestation)

    def fake_observe(
        executable: Path,
        megabytes: int | str | None,
        *,
        expected_attestation: dict[str, object],
    ) -> dict[str, object]:
        assert isinstance(executable, Path)
        assert expected_attestation is attestation
        want = expected[megabytes]
        return {"header": f"{want:g}", "main": want, "worker": want}

    monkeypatch.setattr(gate, "observe", fake_observe)
    monkeypatch.setattr(sys, "argv", ["gate", "--executable", "chrome.exe"])
    assert gate.main() == 0
    output = capsys.readouterr().out
    assert gate.DEVICE_MEMORY_GATE_SCHEMA in output
    assert '"failures": 0' in output
    assert "2" * 16 in output
    assert "3" * 16 in output
