"""B11 / residual R04 — honest speech-voice availability in browser facts.

The observed Akamai BM web SBSD collector calls `SpeechSynthesis.getVoices()` and
reads `lang`, `localService`, and `voiceURI` per voice, so the voice list is a real
constructor input. These tests pin two properties:

* an empty list is recorded as *observed* empty, with how hard we looked; and
* a snapshot can never claim voices it did not enumerate.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

import browser_core.browser_facts as browser_facts
from browser_core.browser_facts import (
    SPEECH_POLL_ATTEMPTS,
    _SPEECH_JS,
    _validate_speech_facts,
    browser_fact_from_observed,
    browserless_ordinary_facts_from_snapshot,
    poll_speech_observation,
    validate_browser_fact_snapshot,
)
from browser_core.contracts import ContractError


def _speech(**overrides):
    base = {
        "api_present": True,
        "voice_count": 0,
        "languages": [],
        "local_service_count": 0,
        "default_count": 0,
    }
    base.update(overrides)
    return base


def _observed(speech=None):
    observed = {
        "ua": "Mozilla/5.0 Test",
        "platform": "Win32",
        "language": "en-US",
        "languages": ["en-US"],
        "timezone": "America/Chicago",
        "locale": "en-US",
        "hardware_concurrency": 8,
        "screen": {
            "width": 1920,
            "height": 1080,
            "avail_width": 1920,
            "avail_height": 1040,
            "color_depth": 24,
            "pixel_depth": 24,
        },
        "window": {
            "inner_width": 1200,
            "inner_height": 800,
            "outer_width": 1200,
            "outer_height": 900,
            "device_pixel_ratio": 1.0,
        },
        "webgl": {
            "webgl1": {"vendor": "V", "renderer": "R", "version": "1"},
            "webgl2": {"vendor": "V", "renderer": "R", "version": "2"},
        },
        "automation": {"webdriver": False, "chrome_object": True},
    }
    if speech is not None:
        observed["speech"] = speech
    return observed


# ---------------------------------------------------------------- polling


def test_speech_probe_does_not_report_an_exception_as_empty_voices() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    harness = """
const vm = require('node:vm');
const source = process.argv[1];
const run = (getVoices) => vm.runInNewContext(`(${source})()`, {
  window: {speechSynthesis: {getVoices}},
});
const failed = run(() => {throw new Error('unreadable voice list')});
const missing = run(() => null);
const invalid = run(() => [null]);
const invalidObject = run(() => ({}));
const invalidNumber = run(() => 42);
const sparse = run(() => new Array(1));
const empty = run(() => []);
process.stdout.write(JSON.stringify([failed, missing, invalid, invalidObject, invalidNumber, sparse, empty]));
"""
    result = subprocess.run(
        [node, "-e", harness, _SPEECH_JS], capture_output=True, check=True,
        text=True, timeout=10,
    )
    failed, missing, invalid, invalid_object, invalid_number, sparse, empty = (
        json.loads(result.stdout)
    )
    assert failed is None
    assert missing is None
    assert invalid is None
    assert invalid_object is None
    assert invalid_number is None
    assert sparse is None
    assert empty["api_present"] is True and empty["voice_count"] == 0


def test_poll_stops_immediately_when_voices_are_present() -> None:
    calls = []
    result = poll_speech_observation(
        lambda: (calls.append(1), _speech(voice_count=3, languages=["en-US"]))[1],
        sleep=lambda _s: None,
    )
    assert len(calls) == 1
    assert result["voice_count"] == 3
    assert result["poll_attempts"] == 1
    assert result["voices_observed_empty"] is False


def test_poll_exhausts_budget_then_records_observed_empty() -> None:
    """An empty list after a bounded wait is a finding, not an absence of one."""
    slept = []
    result = poll_speech_observation(lambda: _speech(), sleep=slept.append)
    assert result["poll_attempts"] == SPEECH_POLL_ATTEMPTS
    assert len(slept) == SPEECH_POLL_ATTEMPTS - 1
    assert result["voice_count"] == 0
    assert result["voices_observed_empty"] is True
    assert result["poll_budget_ms"] > 0


def test_poll_returns_voices_that_arrive_late() -> None:
    """Windows/Chromium populates voices asynchronously."""
    responses = [_speech(), _speech(), _speech(voice_count=2, languages=["en-GB"])]
    result = poll_speech_observation(lambda: responses.pop(0), sleep=lambda _s: None)
    assert result["voice_count"] == 2
    assert result["poll_attempts"] == 3
    assert result["voices_observed_empty"] is False


def test_poll_does_not_retry_when_the_api_is_absent() -> None:
    calls = []
    result = poll_speech_observation(
        lambda: (calls.append(1), _speech(api_present=False))[1],
        sleep=lambda _s: None,
    )
    assert len(calls) == 1
    assert result["api_present"] is False
    # API absent is NOT "observed empty" -- there was nothing to observe.
    assert result["voices_observed_empty"] is False


def test_poll_returns_none_when_the_probe_is_unreadable() -> None:
    """ "Could not look" must not be recorded as "looked and found none"."""

    def boom():
        raise RuntimeError("target closed")

    assert poll_speech_observation(boom, sleep=lambda _s: None) is None


def test_poll_does_not_claim_empty_voices_after_a_later_probe_failure() -> None:
    calls = 0

    def once_then_fail():
        nonlocal calls
        calls += 1
        if calls == 1:
            return _speech()
        raise RuntimeError("speech probe disconnected")

    assert poll_speech_observation(once_then_fail, sleep=lambda _s: None) is None
    assert calls == 2


def test_poll_does_not_claim_api_absence_after_it_was_observed_present() -> None:
    responses = [_speech(), _speech(api_present=False)]
    assert poll_speech_observation(
        lambda: responses.pop(0), sleep=lambda _s: None
    ) is None


def test_poll_returns_none_for_a_response_that_is_not_speech_shaped() -> None:
    assert (
        poll_speech_observation(
            lambda: {"ua": "something else entirely"}, sleep=lambda _s: None
        )
        is None
    )


def test_poll_rejects_open_or_inconsistent_speech_receipts() -> None:
    assert (
        poll_speech_observation(
            lambda: {**_speech(), "private_token": "tenant-secret"},
            sleep=lambda _s: None,
        )
        is None
    )
    assert (
        poll_speech_observation(
            lambda: _speech(voice_count=-1),
            sleep=lambda _s: None,
        )
        is None
    )


def test_poll_rejects_oversized_language_before_serializing(monkeypatch) -> None:
    candidate = _speech(voice_count=1, languages=["a" * 10_000])
    serialized = []
    original_canonical = browser_facts._canonical

    def track_canonical(value):
        serialized.append(value)
        return original_canonical(value)

    monkeypatch.setattr(browser_facts, "_canonical", track_canonical)
    assert poll_speech_observation(lambda: candidate, sleep=lambda _s: None) is None
    assert serialized == []


def test_poll_retains_a_detached_speech_receipt() -> None:
    candidate = _speech(voice_count=1, languages=["en-US"])
    result = poll_speech_observation(lambda: candidate, sleep=lambda _s: None)
    candidate["languages"].append("private")
    candidate["voice_count"] = 2
    assert result["languages"] == ["en-US"]
    assert result["voice_count"] == 1


@pytest.mark.parametrize("attempts", [0, True, 1.5, 101])
def test_poll_rejects_invalid_attempt_budgets_without_evaluating(attempts) -> None:
    calls = []
    with pytest.raises(ContractError, match="attempts must be an integer"):
        poll_speech_observation(lambda: calls.append(1), attempts=attempts)
    assert calls == []


@pytest.mark.parametrize(
    "interval", [float("nan"), float("inf"), -1, 5.1, True, 10**400]
)
def test_poll_rejects_invalid_intervals_without_evaluating(interval) -> None:
    calls = []
    with pytest.raises(ContractError, match="interval must be a finite number"):
        poll_speech_observation(
            lambda: calls.append(1), interval_seconds=interval, sleep=lambda _s: None
        )
    assert calls == []


def test_poll_rejects_noncallable_hooks_before_evaluating() -> None:
    calls = []
    with pytest.raises(ContractError, match="hooks must be callable"):
        poll_speech_observation(lambda: calls.append(1), sleep=object())
    assert calls == []


# ---------------------------------------------------------------- validation


def test_speech_block_validates() -> None:
    assert _validate_speech_facts(
        _speech(voice_count=2, languages=["en-US", "fr-FR"], local_service_count=1)
    )


def test_languages_without_voices_is_rejected() -> None:
    """The core anti-fabrication rule."""
    with pytest.raises(ContractError, match="languages present with zero voices"):
        _validate_speech_facts(_speech(voice_count=0, languages=["en-US"]))


def test_voices_without_the_api_is_rejected() -> None:
    with pytest.raises(ContractError, match="without the API present"):
        _validate_speech_facts(_speech(api_present=False, voice_count=3))


def test_local_service_count_cannot_exceed_voice_count() -> None:
    with pytest.raises(ContractError, match="local_service_count exceeds"):
        _validate_speech_facts(
            _speech(voice_count=1, languages=["en-US"], local_service_count=5)
        )


def test_default_count_cannot_exceed_voice_count() -> None:
    with pytest.raises(ContractError, match="default_count exceeds"):
        _validate_speech_facts(
            _speech(voice_count=1, languages=["en-US"], default_count=2)
        )


def test_malformed_language_tag_is_rejected() -> None:
    with pytest.raises(ContractError, match="not a language tag"):
        _validate_speech_facts(_speech(voice_count=1, languages=["not a tag!"]))


def test_duplicate_languages_are_rejected() -> None:
    with pytest.raises(ContractError, match="must be unique"):
        _validate_speech_facts(_speech(voice_count=2, languages=["en-US", "en-US"]))


def test_inconsistent_observed_empty_flag_is_rejected() -> None:
    with pytest.raises(ContractError, match="voices_observed_empty is inconsistent"):
        _validate_speech_facts(
            _speech(voice_count=2, languages=["en-US"], voices_observed_empty=True)
        )


def test_unknown_speech_field_is_rejected() -> None:
    with pytest.raises(ContractError, match="speech fields are invalid"):
        _validate_speech_facts(dict(_speech(), synthesized=True))


# ---------------------------------------------------------------- snapshot wiring


def test_snapshot_carries_observed_empty_speech() -> None:
    snapshot = browser_fact_from_observed(
        _observed(
            _speech(voices_observed_empty=True, poll_attempts=6, poll_budget_ms=1250)
        ),
        snapshot_id="b11-empty",
        source_kind="fixture",
        source_label="unit",
    )
    speech = snapshot["browser"]["speech"]
    assert speech["voices_observed_empty"] is True
    assert speech["poll_attempts"] == 6
    validate_browser_fact_snapshot(snapshot)


def test_snapshot_cannot_claim_observed_empty_after_zero_polls() -> None:
    with pytest.raises(ContractError, match="browser.speech.poll_attempts"):
        browser_fact_from_observed(
            _observed(
                _speech(
                    voices_observed_empty=True,
                    poll_attempts=0,
                    poll_budget_ms=1250,
                )
            ),
            snapshot_id="zero-polls",
            source_kind="fixture",
            source_label="unit",
        )


def test_snapshot_without_speech_still_validates() -> None:
    """Snapshots captured before B11 must not become invalid."""
    snapshot = browser_fact_from_observed(
        _observed(), snapshot_id="pre-b11", source_kind="fixture", source_label="unit"
    )
    assert "speech" not in snapshot["browser"]
    validate_browser_fact_snapshot(snapshot)


def test_snapshot_rejects_fabricated_voice_list() -> None:
    with pytest.raises(ContractError, match="languages present with zero voices"):
        browser_fact_from_observed(
            _observed(_speech(voice_count=0, languages=["en-US", "de-DE"])),
            snapshot_id="fake",
            source_kind="fixture",
            source_label="unit",
        )


def test_ordinary_facts_forward_speech_and_distinguish_absence() -> None:
    with_speech = browser_fact_from_observed(
        _observed(
            _speech(voice_count=1, languages=["en-US"], voices_observed_empty=False)
        ),
        snapshot_id="with-speech",
        source_kind="fixture",
        source_label="unit",
    )
    without = browser_fact_from_observed(
        _observed(),
        snapshot_id="without-speech",
        source_kind="fixture",
        source_label="unit",
    )
    assert (
        browserless_ordinary_facts_from_snapshot(with_speech)["speech"]["voice_count"]
        == 1
    )
    # Absent is not zero: a pre-B11 snapshot says nothing about voices.
    assert browserless_ordinary_facts_from_snapshot(without)["speech"] is None


def test_ordinary_speech_projection_does_not_mutate_its_snapshot() -> None:
    snapshot = browser_fact_from_observed(
        _observed(_speech(voice_count=1, languages=["en-US"])),
        snapshot_id="speech-detached", source_kind="fixture", source_label="unit",
    )
    ordinary = browserless_ordinary_facts_from_snapshot(snapshot)
    ordinary["speech"]["languages"].append("fr-FR")
    assert snapshot["browser"]["speech"]["languages"] == ["en-US"]
    validate_browser_fact_snapshot(snapshot)
