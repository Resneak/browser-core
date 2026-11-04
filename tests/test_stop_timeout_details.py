"""Fail-closed saved stop-timeout diagnostic contract tests."""

from pathlib import Path
from types import SimpleNamespace
import csv
import io
import json
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator

from browser_core.contracts import ContractError
from browser_core import stop_timeout_details as details


COUNT = "traced_data_source_stop_timeouts"
INSTANCES = "traced_data_source_stop_timeout_pending_instances"
PRODUCERS = "traced_data_source_stop_timeout_pending_producers"
TRUNCATED = "traced_data_source_stop_timeout_details_truncated"
FIELDS = (
    "traced_data_source_stop_timeout_producer_id",
    "traced_data_source_stop_timeout_instance_id",
    "traced_data_source_stop_timeout_producer_name_hash",
    "traced_data_source_stop_timeout_data_source_name_hash",
    "traced_data_source_stop_timeout_state",
)


def encoded(rows):
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("name", "idx", "value"))
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def aggregate(count=1, pending=1, producers=1, truncated=0):
    return [
        (COUNT, "[NULL]", count),
        (INSTANCES, "[NULL]", pending),
        (PRODUCERS, "[NULL]", producers),
        (TRUNCATED, "[NULL]", truncated),
    ]


def row(index, producer=6, instance=7, state=3):
    values = (producer, instance, 101, 202, state)
    return [(name, index, value) for name, value in zip(FIELDS, values)]


def test_actual_s5_shape_is_bounded_and_not_health_success():
    result = details.decode_stop_timeout_stats(encoded(aggregate() + row(0)))
    assert result["details_status"] == "complete-last-timeout"
    assert result["recorded_stop_timeouts"] == "1"
    assert result["last_timeout_pending_instances"] == "1"
    assert result["last_timeout_pending_producers"] == "1"
    assert result["last_timeout_details_truncated"] is False
    assert result["details"] == [{
        "index": 0,
        "producer_id": "6",
        "instance_id": "7",
        "state": "stopping",
        "producer_name_fnv1a_63": "101",
        "data_source_name_fnv1a_63": "202",
    }]


def test_no_timeout_and_older_trace_are_distinct():
    no_timeout = details.decode_stop_timeout_stats(encoded(aggregate(0, 0, 0)))
    assert no_timeout["details_status"] == "unknown"
    assert no_timeout["recorded_stop_timeouts"] is None
    assert no_timeout["last_timeout_pending_instances"] is None
    assert no_timeout["last_timeout_details_truncated"] is None
    assert no_timeout["details"] == []
    older = details.decode_stop_timeout_stats(encoded([(COUNT, "[NULL]", 2)]))
    assert older["details_status"] == "unavailable"
    assert older["recorded_stop_timeouts"] == "2"
    reader_default = details.decode_stop_timeout_stats(encoded(aggregate(2, 0, 0)))
    assert reader_default["details_status"] == "unavailable"
    assert reader_default["recorded_stop_timeouts"] == "2"
    assert reader_default["last_timeout_pending_instances"] is None
    assert reader_default["last_timeout_pending_producers"] is None
    assert reader_default["last_timeout_details_truncated"] is None
    unknown = details.decode_stop_timeout_stats(encoded([]))
    assert unknown["details_status"] == "unknown"
    assert unknown["recorded_stop_timeouts"] is None


def test_multiple_timeouts_are_not_misreported_as_whole_lifetime_details():
    result = details.decode_stop_timeout_stats(encoded(aggregate(count=3) + row(0)))
    assert result["details_status"] == "complete-last-timeout"
    assert result["recorded_stop_timeouts"] == "3"
    assert len(result["details"]) == 1


def test_exact_native_detail_cap_and_truncation():
    rows = aggregate(count=1, pending=33, producers=1, truncated=1)
    for index in range(32):
        rows += row(index, instance=index + 1)
    result = details.decode_stop_timeout_stats(encoded(rows))
    assert result["details_status"] == "truncated-last-timeout"
    assert len(result["details"]) == 32


@pytest.mark.parametrize("mutation", (
    lambda rows: rows + [rows[-1]],
    lambda rows: [item for item in rows if item[0] != FIELDS[4]],
    lambda rows: [(*item[:1], "2", item[2]) if item[0] in FIELDS else item for item in rows],
    lambda rows: [("unexpected_stop_timeout_field", "[NULL]", 1)] + rows,
    lambda rows: [(item[0], item[1], "-1") if item[0] == COUNT else item for item in rows],
    lambda rows: [(item[0], item[1], "9223372036854775808") if item[0] == COUNT else item for item in rows],
    lambda rows: [(item[0], item[1], 9) if item[0] == FIELDS[4] else item for item in rows],
    lambda rows: [(item[0], "[NULL]", item[2]) if item[0] == FIELDS[0] else item for item in rows],
    lambda rows: [(item[0], "0", item[2]) if item[0] == COUNT else item for item in rows],
    lambda rows: [(item[0], item[1], 2) if item[0] == INSTANCES else item for item in rows],
    lambda rows: [(item[0], item[1], 2) if item[0] == PRODUCERS else item for item in rows],
    lambda rows: [(item[0], item[1], 1) if item[0] == TRUNCATED else item for item in rows],
    lambda rows: [(item[0], item[1], 0) if item[0] == INSTANCES else item for item in rows],
    lambda rows: [(item[0], item[1], 0) if item[0] == PRODUCERS else item for item in rows],
))
def test_malformed_populations_fail_closed(mutation):
    with pytest.raises(ContractError, match="stop-timeout statistics are malformed"):
        details.decode_stop_timeout_stats(encoded(mutation(aggregate() + row(0))))


def test_unterminated_quoted_timeout_count_is_not_a_valid_native_stat():
    body = encoded([(COUNT, "[NULL]", 2)]).rstrip(b"\n").rsplit(b",", 1)[0] + b',"2'
    with pytest.raises(ContractError, match="stop-timeout statistics are malformed"):
        details.decode_stop_timeout_stats(body)


def test_truncated_claim_requires_thirty_two_actual_rows():
    with pytest.raises(ContractError):
        details.decode_stop_timeout_stats(encoded(aggregate(1, 33, 1, 1) + row(0)))


def test_truncated_producer_totals_require_possible_omitted_instances():
    listed = []
    for index in range(32):
        listed += row(index, instance=index + 1)
    for pending, producers in ((33, 3), (70000, 65536)):
        with pytest.raises(ContractError, match="stop-timeout statistics are malformed"):
            details.decode_stop_timeout_stats(
                encoded(aggregate(1, pending, producers, 1) + listed)
            )
    boundary = details.decode_stop_timeout_stats(
        encoded(aggregate(1, 33, 2, 1) + listed)
    )
    assert boundary["details_status"] == "truncated-last-timeout"
    assert boundary["last_timeout_pending_producers"] == "2"


@pytest.mark.parametrize("rows", (
    aggregate() + row(0, state=4),
    aggregate() + row(0, producer=65536),
    aggregate(1, 2, 1) + row(0) + row(1),
    aggregate(1, 2, 2) + row(0) + row(1, producer=8),
    aggregate(1, 2, 1) + row(0) + [
        (name, index, 102 if name == FIELDS[2] else value)
        for name, index, value in row(1, instance=8)
    ],
))
def test_native_impossible_pending_populations_fail_closed(rows):
    with pytest.raises(ContractError, match="stop-timeout statistics are malformed"):
        details.decode_stop_timeout_stats(encoded(rows))


def test_response_schema_and_fixed_semantics(monkeypatch):
    class FakeEvidence:
        sha256 = "a" * 64
        path = Path("synthetic.trace")
        metadata = {"recording": {"sha256": "b" * 64}}
        closed = False

        @property
        def source(self):
            return SimpleNamespace(resolve=lambda: SimpleNamespace(
                executable=Path("reader/chrome.exe")))

        def close(self):
            self.closed = True

    opened = FakeEvidence()
    monkeypatch.setattr(details, "OpenEvidence", lambda *args, **kwargs: opened)
    monkeypatch.setattr(details, "run_with_bounded_stdout", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=encoded(aggregate() + row(0))))
    result = details.evidence_stop_timeouts(
        Path("bundle"), Path("root"), Path("reader"), expected_sha256="a" * 64)
    assert opened.closed
    assert result["source"] == {
        "bundle_sha256": "a" * 64,
        "recording_sha256": "b" * 64,
        "expected_digest_matched": True,
    }
    assert result["semantics"]["cause_identified"] is False
    assert result["semantics"]["recording_health_qualified"] is False
    schema_path = Path(__file__).resolve().parents[1] / "schemas/evidence-stop-timeouts-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(result)


def test_failed_decoder_still_closes_evidence(monkeypatch):
    class FakeEvidence:
        sha256 = "a" * 64
        path = Path("synthetic.trace")
        metadata = {"recording": {"sha256": "b" * 64}}
        closed = False

        @property
        def source(self):
            return SimpleNamespace(resolve=lambda: SimpleNamespace(
                executable=Path("reader/chrome.exe")))

        def close(self):
            self.closed = True

    opened = FakeEvidence()
    monkeypatch.setattr(details, "OpenEvidence", lambda *args, **kwargs: opened)
    monkeypatch.setattr(details, "run_with_bounded_stdout", lambda *args, **kwargs:
                        SimpleNamespace(returncode=1, stdout=b""))
    with pytest.raises(ContractError, match="stop-timeout decoder failed"):
        details.evidence_stop_timeouts(Path("bundle"), Path("root"), Path("reader"))
    assert opened.closed


@pytest.mark.parametrize("suffix", (
    ["--audit-unknown", "AUDIT_SECRET_" + "x" * 17000],
    ["--expected-sha256"],
    ["AUDIT_SECRET_EXTRA"],
))
def test_canonical_cli_parse_error_is_fixed_private_json(suffix):
    process = subprocess.run(
        [sys.executable, "-B", "-m", "browser_core", "trace",
         "evidence-stop-timeouts", "--bundle", "AUDIT_MISSING_BUNDLE",
         "--reader-executable", "AUDIT_MISSING_READER", *suffix],
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        check=False,
    )
    assert process.returncode == 2
    assert process.stderr == b""
    assert len(process.stdout) <= 16384
    assert b"AUDIT_SECRET_" not in process.stdout
    assert json.loads(process.stdout) == {
        "schema": details.SCHEMA,
        "status": "error",
        "code": "stop-timeout-details-unavailable",
    }
