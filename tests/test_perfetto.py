from __future__ import annotations

import csv
import copy
import io
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
from browser_core.perfetto import (
    EXPORT_COLUMNS,
    NULL_VALUE,
    bind_perfetto_source_trace,
    build_trace_export_report,
    count_exportable_events,
    export_perfetto,
    parse_export_csv,
    validate_trace_processor,
    validate_trace_export_report,
)


REVISION = "a" * 40


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("role", ["normalized", "report"])
def test_perfetto_export_rejects_parent_junction_before_creating_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    import browser_core.perfetto as perfetto

    target = tmp_path / "unrelated"
    target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    output = (junction / "new-parent" / "trace.jsonl"
              if role == "normalized" else tmp_path / "trace.jsonl")
    report = (junction / "new-parent" / "report.json"
              if role == "report" else None)
    reached: list[bool] = []

    def popen(*args, **kwargs):
        reached.append(True)
        raise OSError("processor should not start")

    monkeypatch.setattr(perfetto.subprocess, "Popen", popen)
    try:
        with pytest.raises(ContractError):
            export_perfetto(processor, trace, output, "fixture-run", REVISION, report)
        assert reached == []
        assert list(target.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("role", ["normalized", "report"])
def test_perfetto_export_rejects_parent_redirected_during_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output_parent = tmp_path / "output-parent"
    output_parent.mkdir()
    output = output_parent / "trace.jsonl"
    report_parent = tmp_path / "report-parent"
    report_parent.mkdir()
    redirected_parent = output_parent if role == "normalized" else report_parent
    moved = tmp_path / f"moved-{role}-parent"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    report = report_parent / "report.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    probe = tmp_path / "junction-probe"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(probe), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    probe.rmdir()

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    original_popen = subprocess.Popen

    def popen(*_args, **_kwargs):
        redirected_parent.rename(moved)
        monkeypatch.setattr(perfetto.subprocess, "Popen", original_popen)
        try:
            redirect = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(redirected_parent), str(foreign)],
                capture_output=True, check=False,
            )
        finally:
            monkeypatch.setattr(perfetto.subprocess, "Popen", popen)
        assert redirect.returncode == 0, redirect.stderr
        return Process()

    monkeypatch.setattr(perfetto.subprocess, "Popen", popen)
    try:
        with pytest.raises(ContractError):
            export_perfetto(processor, trace, output, "fixture-run", REVISION, report)
        assert list(foreign.iterdir()) == []
    finally:
        if redirected_parent.exists():
            redirected_parent.rmdir()


def test_trace_processor_preflight_requires_nonempty_single_link_file(
    tmp_path: Path,
) -> None:
    processor = tmp_path / "trace_processor.exe"
    processor.write_bytes(b"")
    with pytest.raises(ContractError, match="empty"):
        validate_trace_processor(processor)
    processor.write_bytes(b"processor")
    binding = validate_trace_processor(processor)
    assert binding["bytes"] == len(b"processor")
    assert len(binding["sha256"]) == 64


def csv_fixture(**overrides: str) -> str:
    row = {field: NULL_VALUE for field in EXPORT_COLUMNS}
    row.update(
        {
            "ts_monotonic_ns": "1234",
            "trace_category": "browser_core.debug",
            "native_name": "BrowserCore.CanvasReadback",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "api": "HTMLCanvasElement.toDataURL",
            "width": "300",
            "height": "150",
            "origin_clean": "true",
        }
    )
    row.update(overrides)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerow(row)
    return output.getvalue()


def csv_rows_fixture(rows: list[dict[str, str]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for overrides in rows:
        row = {field: NULL_VALUE for field in EXPORT_COLUMNS}
        row.update(
            {
                "ts_monotonic_ns": "1234",
                "trace_category": "browser_core.debug",
                "pid": "42",
                "process_name": "Renderer",
                "tid": "43",
                "thread_name": "CrRendererMain",
                "native_schema": "browser-core.native/1",
            }
        )
        row.update(overrides)
        writer.writerow(row)
    return output.getvalue()


@pytest.mark.parametrize("field", ["native_schema", "event_category"])
def test_native_event_diagnostic_does_not_echo_untrusted_fields(field: str) -> None:
    private_value = "private-native-field-marker"
    with pytest.raises(ContractError) as failure:
        parse_export_csv(csv_fixture(**{field: private_value}), "fixture-run", REVISION)
    assert private_value not in str(failure.value)


def test_perfetto_csv_requires_non_decreasing_timestamp_order() -> None:
    row = {
        "native_name": "BrowserCore.CanvasReadback",
        "api": "HTMLCanvasElement.toDataURL",
        "width": "300",
        "height": "150",
        "origin_clean": "true",
    }
    with pytest.raises(ContractError, match="timestamp order"):
        parse_export_csv(
            csv_rows_fixture([
                {**row, "ts_monotonic_ns": "200"},
                {**row, "ts_monotonic_ns": "100"},
            ]),
            "fixture-run",
            REVISION,
        )
    assert len(
        parse_export_csv(
            csv_rows_fixture([
                {**row, "ts_monotonic_ns": "200"},
                {**row, "ts_monotonic_ns": "200"},
            ]),
            "fixture-run",
            REVISION,
        )
    ) == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [("pid", "042"), ("tid", "+43"), ("ts_monotonic_ns", "١٢٣٤")],
)
def test_perfetto_csv_rejects_noncanonical_numeric_cells(field: str, value: str) -> None:
    with pytest.raises(ContractError, match="not an integer"):
        parse_export_csv(csv_fixture(**{field: value}), "fixture-run", REVISION)


def test_perfetto_csv_normalizes_to_trace_contract() -> None:
    events = parse_export_csv(csv_fixture(), "fixture-run", REVISION)
    assert len(events) == 1
    event = events[0]
    assert event["event"] == {"category": "api", "name": "HTMLCanvasElement.toDataURL"}
    assert event["process"] == {"pid": 42, "type": "renderer"}
    assert event["detail"]["origin_clean"] is True
    assert event["provenance"]["source"] == "native"


def test_perfetto_canvas_readback_accepts_zero_duration_instant_slice() -> None:
    event = parse_export_csv(
        csv_fixture(duration_ns="0"),
        "fixture-run",
        REVISION,
    )[0]

    assert event["event"] == {
        "category": "api",
        "name": "HTMLCanvasElement.toDataURL",
    }
    assert "duration_ns" not in event["detail"]


@pytest.mark.parametrize("duration_ns", ["", "-0", "+0", "00", " 0", "0 "])
def test_perfetto_canvas_readback_rejects_noncanonical_zero_duration(
    duration_ns: str,
) -> None:
    with pytest.raises(ContractError, match="canvas readback"):
        parse_export_csv(
            csv_fixture(duration_ns=duration_ns),
            "fixture-run",
            REVISION,
        )


def test_perfetto_canvas_readback_retains_only_call_time_metadata() -> None:
    event = parse_export_csv(
        csv_fixture(width=str(2_147_483_647), origin_clean="false"),
        "fixture-run",
        REVISION,
    )[0]

    assert event["detail"] == {
        "native_name": "BrowserCore.CanvasReadback",
        "thread_id": 43,
        "width": 2_147_483_647,
        "height": 150,
        "origin_clean": False,
    }
    assert "execution" not in event
    assert "causal_parent_seq" not in event
    assert "value" not in event


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.CanvasExport"),
        ("component", "blink.canvas"),
        ("context_id", "frame-token"),
        ("native_id", "canvas:frame-token:1"),
        ("duration_ns", "1"),
        ("width", str(2_147_483_648)),
        ("origin_clean", NULL_VALUE),
        ("data_bytes", "1"),
    ],
)
def test_perfetto_rejects_forged_canvas_readback_event(
    field: str,
    value: str,
) -> None:
    overrides = {field: value}

    with pytest.raises(ContractError, match="canvas readback"):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


def test_perfetto_rejects_relabelled_legacy_canvas_readback_event() -> None:
    with pytest.raises(ContractError, match="canvas readback"):
        parse_export_csv(
            csv_fixture(api="HTMLCanvasElement.toBlob"),
            "fixture-run",
            REVISION,
        )


def test_perfetto_rejects_relabelled_modern_canvas_readback_event() -> None:
    with pytest.raises(ContractError, match="canvas readback"):
        parse_export_csv(
            csv_fixture(
                event_category="api",
                event_name="HTMLCanvasElement.toBlob",
                api=NULL_VALUE,
            ),
            "fixture-run",
            REVISION,
        )


@pytest.mark.parametrize(
    ("native_name", "category", "wrong_name", "label"),
    [
        ("BrowserCore.FetchCall", "api", "XMLHttpRequest.open", "fetch API"),
        (
            "BrowserCore.FetchRequestStart",
            "network",
            "fetch.request.end",
            "fetch request",
        ),
        (
            "BrowserCore.MessagePost",
            "message",
            "Window.postMessage",
            "message post",
        ),
        (
            "BrowserCore.MessageDispatch",
            "message",
            "MessagePort.message",
            "message dispatch",
        ),
        (
            "BrowserCore.StreamReadRequest",
            "stream",
            "stream.read.start",
            "stream request",
        ),
        (
            "BrowserCore.StreamReadResult",
            "stream",
            "stream.read.end",
            "stream result",
        ),
        ("BrowserCore.BodyConsume", "stream", "body.used", "body consumer"),
    ],
)
def test_perfetto_exact_native_name_rejects_relabelled_event_route(
    native_name: str,
    category: str,
    wrong_name: str,
    label: str,
) -> None:
    with pytest.raises(ContractError, match=rf"{label} event identity"):
        parse_export_csv(
            csv_fixture(
                trace_category=(
                    "browser_core.stream"
                    if category == "stream"
                    else "browser_core.debug"
                ),
                native_name=native_name,
                event_category=category,
                event_name=wrong_name,
                api=NULL_VALUE,
                width=NULL_VALUE,
                height=NULL_VALUE,
                origin_clean=NULL_VALUE,
            ),
            "fixture-run",
            REVISION,
        )


def test_perfetto_rejects_canvas_readback_from_browser_process() -> None:
    with pytest.raises(ContractError, match="canvas readback"):
        parse_export_csv(
            csv_fixture(process_name="Browser", thread_name="CrBrowserMain"),
            "fixture-run",
            REVISION,
        )


def test_perfetto_rejects_modern_shape_forged_as_legacy_canvas_readback() -> None:
    with pytest.raises(ContractError, match="canvas readback"):
        parse_export_csv(
            csv_fixture(
                event_category="api",
                event_name="HTMLCanvasElement.toDataURL",
                component="blink.canvas",
            ),
            "fixture-run",
            REVISION,
        )


def _network_csv(url_class: str) -> str:
    return csv_fixture(
        native_name="fixture.request.start",
        event_category="network",
        event_name="request.start",
        component="blink.network",
        api=NULL_VALUE,
        native_id="request:frame-token:1",
        request_id="request:frame-token:1",
        method="GET",
        url_class=url_class,
        target_scope="loopback",
        body_bytes="0",
        width=NULL_VALUE,
        height=NULL_VALUE,
        origin_clean=NULL_VALUE,
    )


@pytest.mark.parametrize(
    "url_class",
    [
        "same-origin:/probe",
        "https:same-origin:/probe",
        "chrome-extension:cross-origin:/popup.html",
        "data:cross-origin:<redacted>",
    ],
)
def test_perfetto_accepts_only_safe_legacy_or_scheme_url_classes(
    url_class: str,
) -> None:
    event = parse_export_csv(_network_csv(url_class), "fixture-run", REVISION)[0]
    assert event["request"]["url_class"] == url_class


@pytest.mark.parametrize(
    "url_class",
    [
        "https://secret.example/path",
        "https:cross-origin://secret.example/path",
        "https:cross-origin:/path?token=secret",
        "https:cross-origin:/path#fragment",
        "https:cross-origin:/path\nforged",
        "HTTPS:cross-origin:/probe",
        "data:cross-origin:text/plain,secret",
        "https:same-origin:/" + "x" * 4_192,
    ],
)
def test_perfetto_rejects_unsafe_url_class_metadata(url_class: str) -> None:
    with pytest.raises(ContractError, match="scheme-safe"):
        parse_export_csv(_network_csv(url_class), "fixture-run", REVISION)


def test_perfetto_rejects_unknown_network_target_scope() -> None:
    csv_text = _network_csv("https:same-origin:/probe").replace(
        '"loopback"', '"private-host"'
    )
    with pytest.raises(ContractError, match="target scope"):
        parse_export_csv(csv_text, "fixture-run", REVISION)


def test_trace_export_report_exactly_binds_input_and_output(tmp_path: Path) -> None:
    events = parse_export_csv(csv_fixture(), "fixture-run", REVISION)
    source = tmp_path / "fixture.perfetto-trace"
    output = tmp_path / "fixture.jsonl"
    source.write_bytes(b"owned perfetto fixture")
    output.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )

    report = build_trace_export_report(source, output, events, "fixture-run", REVISION)

    assert report["schema"] == "browser-core.trace-export/1"
    assert report["source_trace"]["bytes"] == len(b"owned perfetto fixture")
    assert report["normalized_trace"]["events"] == 1
    assert report["normalized_trace"]["trace_categories"] == {"browser_core.debug": 1}
    assert len(report["source_trace"]["sha256"]) == 64
    assert len(report["normalized_trace"]["sha256"]) == 64

    forged = copy.deepcopy(report)
    forged["normalized_trace"]["trace_categories"]["browser_core.debug"] = 2
    with pytest.raises(ContractError, match="category counts"):
        validate_trace_export_report(forged)


def test_trace_export_report_rejects_invalid_event_with_complete_category_fields(
    tmp_path: Path,
) -> None:
    event = parse_export_csv(csv_fixture(), "fixture-run", REVISION)[0]
    del event["process"]
    source = tmp_path / "fixture.perfetto-trace"
    output = tmp_path / "fixture.jsonl"
    source.write_bytes(b"trace")
    output.write_bytes(b"event")

    with pytest.raises(ContractError, match="trace process"):
        build_trace_export_report(source, output, [event], "fixture-run", REVISION)


def test_trace_export_report_rejects_mismatched_normalized_event_bytes(
    tmp_path: Path,
) -> None:
    event = parse_export_csv(csv_fixture(), "fixture-run", REVISION)[0]
    other = copy.deepcopy(event)
    other["seq"] = event["seq"] + 1
    source = tmp_path / "fixture.perfetto-trace"
    output = tmp_path / "fixture.jsonl"
    source.write_bytes(b"trace")
    output.write_text(json.dumps(other, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="events disagree with normalized output"):
        build_trace_export_report(source, output, [event], "fixture-run", REVISION)


def test_trace_export_report_rejects_nontext_revision_as_contract_error(
    tmp_path: Path,
) -> None:
    events = parse_export_csv(csv_fixture(), "fixture-run", REVISION)
    source = tmp_path / "fixture.perfetto-trace"
    output = tmp_path / "fixture.jsonl"
    source.write_bytes(b"trace")
    output.write_bytes(b"event")

    with pytest.raises(ContractError, match="Chromium revision is invalid"):
        build_trace_export_report(source, output, events, "fixture-run", [])


def test_trace_export_report_rejects_claimed_population_and_size_over_limits(
    tmp_path: Path,
) -> None:
    import browser_core.perfetto as perfetto

    events = parse_export_csv(csv_fixture(), "fixture-run", REVISION)
    source = tmp_path / "fixture.perfetto-trace"
    output = tmp_path / "fixture.jsonl"
    source.write_bytes(b"trace")
    output.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )
    report = build_trace_export_report(source, output, events, "fixture-run", REVISION)
    oversized_events = copy.deepcopy(report)
    oversized_events["normalized_trace"]["events"] = perfetto.MAX_EXPORT_EVENTS + 1
    oversized_events["normalized_trace"]["trace_categories"] = {
        "browser_core.debug": perfetto.MAX_EXPORT_EVENTS + 1
    }
    with pytest.raises(ContractError, match="category counts"):
        validate_trace_export_report(oversized_events)
    for key, maximum in (
        ("source_trace", perfetto.MAX_PERFETTO_ARTIFACT_BYTES),
        ("normalized_trace", perfetto.MAX_NORMALIZED_TRACE_BYTES),
    ):
        oversized_file = copy.deepcopy(report)
        oversized_file[key]["bytes"] = maximum + 1
        with pytest.raises(ContractError, match="digest binding"):
            validate_trace_export_report(oversized_file)


def test_perfetto_event_count_preflights_without_requesting_the_full_csv(
    tmp_path: Path, monkeypatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    seen = {}

    class Result:
        returncode = 0
        stdout = b'"events"\n"267569"\n'

    def run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return Result()

    monkeypatch.setattr(perfetto, "run_with_bounded_stdout", run)
    assert count_exportable_events(processor, trace) == 267569
    assert seen["command"][-1] == perfetto.EXPORT_COUNT_SQL
    assert "EXTRACT_ARG" not in perfetto.EXPORT_COUNT_SQL
    assert seen["kwargs"] == {
        "maximum_stdout": perfetto.MAX_COUNT_QUERY_BYTES,
        "timeout_seconds": perfetto.COUNT_QUERY_TIMEOUT_SECONDS,
        "label": "Perfetto count query",
    }


def test_perfetto_count_rejects_unterminated_quoted_native_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    monkeypatch.setattr(
        perfetto, "run_with_bounded_stdout",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b'"events"\n"1'),
    )
    with pytest.raises(ContractError, match="count CSV"):
        count_exportable_events(processor, trace)


def test_perfetto_count_rejects_duplicate_native_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    monkeypatch.setattr(
        perfetto, "run_with_bounded_stdout",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=b'"events","events"\n"1","2"\n'),
    )
    with pytest.raises(ContractError, match="invalid result"):
        count_exportable_events(processor, trace)


@pytest.mark.parametrize("value", ["01", "+1", "١"])
def test_perfetto_count_rejects_noncanonical_numeric_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    body = (f'"events"\n"{value}"\n').encode("utf-8")
    monkeypatch.setattr(
        perfetto, "run_with_bounded_stdout",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=body),
    )
    with pytest.raises(ContractError, match="not an integer"):
        count_exportable_events(processor, trace)


def test_perfetto_count_rejects_a_source_other_than_the_settled_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"first")
    expected = bind_perfetto_source_trace(trace)
    trace.write_bytes(b"other")
    monkeypatch.setattr(
        perfetto,
        "run_with_bounded_stdout",
        lambda *_args, **_kwargs: pytest.fail("mismatched trace reached processor"),
    )

    with pytest.raises(ContractError, match="does not match expected binding"):
        count_exportable_events(
            processor,
            trace,
            expected_source_binding=expected,
        )


def test_perfetto_export_rejects_a_source_other_than_the_preflight_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"first")
    expected = bind_perfetto_source_trace(trace)
    trace.write_bytes(b"other")
    monkeypatch.setattr(
        perfetto.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("mismatched trace reached processor"),
    )

    with pytest.raises(ContractError, match="does not match expected binding"):
        export_perfetto(
            processor,
            trace,
            output,
            "fixture-run",
            REVISION,
            expected_source_binding=expected,
        )


def test_perfetto_event_count_rejects_input_mutation_during_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace-a")

    class Result:
        returncode = 0
        stdout = b'"events"\n"1"\n'

    def run(*_args, **_kwargs):
        trace.write_bytes(b"trace-b-different-size")
        return Result()

    monkeypatch.setattr(perfetto, "run_with_bounded_stdout", run)

    with pytest.raises(ContractError, match="inputs changed"):
        count_exportable_events(processor, trace)


def test_perfetto_event_count_rejects_invalid_utf8_without_diagnostic_echo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Result:
        returncode = 0
        stdout = b"\xffprivate-marker"

    monkeypatch.setattr(
        perfetto,
        "run_with_bounded_stdout",
        lambda *_args, **_kwargs: Result(),
    )

    with pytest.raises(ContractError, match="invalid UTF-8") as failure:
        count_exportable_events(processor, trace)
    assert "private-marker" not in str(failure.value)


def test_perfetto_stable_binding_rejects_symlink_inputs(tmp_path: Path) -> None:
    import browser_core.perfetto as perfetto

    target = tmp_path / "target"
    link = tmp_path / "link"
    target.write_bytes(b"target")
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("host does not permit symlink creation")

    with pytest.raises(ContractError, match="regular file"):
        perfetto._stable_file_binding(link, label="fixture")


@pytest.mark.parametrize("invalid", ["bad\x00trace", "bad\ud800trace"])
def test_perfetto_source_binding_rejects_invalid_path_text(invalid: str) -> None:
    with pytest.raises(ContractError, match="Perfetto source trace path is invalid") as raised:
        bind_perfetto_source_trace(Path(invalid))
    assert invalid not in str(raised.value)


@pytest.mark.parametrize("invalid", ["bad\x00output", "bad\ud800output"])
@pytest.mark.parametrize("role", ["normalized", "report"])
def test_perfetto_export_rejects_invalid_destination_path_text(
    tmp_path: Path, invalid: str, role: str,
) -> None:
    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    invalid_path = tmp_path / invalid
    output = invalid_path if role == "normalized" else tmp_path / "trace.jsonl"
    report = invalid_path if role == "report" else None
    with pytest.raises(ContractError, match="path is invalid") as raised:
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report)
    assert invalid not in str(raised.value)
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "trace.perfetto-trace", "trace_processor"
    ]


@pytest.mark.parametrize("role", ["normalized", "report"])
def test_perfetto_export_rejects_destination_without_a_filename(
    tmp_path: Path, role: str,
) -> None:
    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    output = Path(".") if role == "normalized" else tmp_path / "trace.jsonl"
    report = Path(".") if role == "report" else None

    with pytest.raises(ContractError, match="path is invalid"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report)

    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "trace.perfetto-trace", "trace_processor"
    ]


def test_perfetto_stable_binding_detects_in_read_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    source = tmp_path / "source.trace"
    source.write_bytes(b"first-population")
    real_fstat = perfetto.os.fstat
    calls = 0

    def mutate_after_open(descriptor: int):
        nonlocal calls
        metadata = real_fstat(descriptor)
        calls += 1
        if calls == 1:
            source.write_bytes(b"second-population-with-different-size")
        return metadata

    monkeypatch.setattr(perfetto.os, "fstat", mutate_after_open)

    with pytest.raises(ContractError, match="changed while its digest"):
        perfetto._stable_file_binding(source, label="fixture")


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_perfetto_stable_binding_rejects_same_size_edit_with_restored_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    source = tmp_path / "source.trace"
    source.write_bytes(b"before")
    stamp = source.stat()
    real_fstat = perfetto.os.fstat
    calls = 0

    def mutate_after_digest(descriptor: int):
        nonlocal calls
        calls += 1
        if calls == 2:
            with source.open("r+b") as writer:
                writer.write(b"after!")
            os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return real_fstat(descriptor)

    monkeypatch.setattr(perfetto.os, "fstat", mutate_after_digest)
    # Native change times may have the same tick for two fast writes.
    monkeypatch.setattr(perfetto, "windows_change_time", lambda _handle: 0, raising=False)

    with pytest.raises(ContractError, match="changed while its digest"):
        perfetto._stable_file_binding(source, label="fixture")
    assert source.read_bytes() == b"after!"


def test_perfetto_binding_is_bounded_and_single_link(tmp_path: Path) -> None:
    import browser_core.perfetto as perfetto

    source = tmp_path / "source.trace"
    source.write_bytes(b"trace")
    with pytest.raises(ContractError, match="exceeds 4 bytes"):
        perfetto._stable_file_binding(source, label="fixture", maximum=4)
    os.link(source, tmp_path / "source-alias.trace")
    with pytest.raises(ContractError, match="hard links"):
        perfetto._stable_file_binding(source, label="fixture")


def test_perfetto_csv_reader_caps_a_physical_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.perfetto as perfetto

    monkeypatch.setattr(perfetto, "MAX_EXPORT_CSV_LINE_CHARS", 8)
    with pytest.raises(ContractError, match="CSV line exceeds"):
        parse_export_csv(csv_fixture(), "fixture-run", REVISION)


def test_perfetto_export_streams_processor_rows_to_atomic_jsonl(
    tmp_path: Path, monkeypatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    report_path = tmp_path / "trace.export.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    seen = {}

    class Process:
        def __init__(self):
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None
            self.killed = False

        def wait(self, timeout=None):
            self.returncode = 0
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -1

    def popen(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        seen["process"] = Process()
        return seen["process"]

    monkeypatch.setattr(perfetto.subprocess, "Popen", popen)
    result = export_perfetto(
        processor, trace, output, "fixture-run", REVISION, report_path
    )

    assert result["events"] == 1
    assert result["report"]["normalized_trace"]["events"] == 1
    assert result["report"]["normalized_trace"]["trace_categories"] == {
        "browser_core.debug": 1
    }
    assert json.loads(output.read_text(encoding="utf-8"))["run_id"] == "fixture-run"
    assert json.loads(report_path.read_text(encoding="utf-8")) == result["report"]
    assert seen["command"][-1] == perfetto.EXPORT_SQL
    assert seen["kwargs"]["stdout"] is perfetto.subprocess.PIPE
    assert not seen["process"].killed
    assert not output.with_suffix(".jsonl.tmp").exists()


def test_perfetto_export_rejects_normalized_output_changed_during_report_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    report_path = tmp_path / "trace.export.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    original_publish = perfetto._publish_export_report

    def mutate_after_report(report, temporary, destination):
        original_publish(report, temporary, destination)
        body = output.read_bytes()
        output.write_bytes(b"X" + body[1:])

    monkeypatch.setattr(perfetto, "_publish_export_report", mutate_after_report)
    with pytest.raises(ContractError, match="normalized trace changed after publication"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report_path)


def test_perfetto_export_rejects_relocated_output_ancestor_after_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    private = tmp_path / "private"
    parent = private / "leaf"
    parent.mkdir(parents=True)
    output = parent / "trace.jsonl"
    report_path = parent / "trace.export.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    original_publish = perfetto._publish_export_report
    retained = tmp_path / "retained"

    def relocate_after_report(report, temporary, destination):
        binding = original_publish(report, temporary, destination)
        private.rename(retained)
        private.mkdir()
        (retained / "leaf").rename(parent)
        return binding

    monkeypatch.setattr(perfetto, "_publish_export_report", relocate_after_report)
    with pytest.raises(ContractError, match="trace export .* parent changed during export"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report_path)

    assert output.exists()
    assert report_path.exists()


def test_perfetto_export_failure_preserves_temporary_after_ancestor_relocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    private = tmp_path / "private"
    parent = private / "leaf"
    parent.mkdir(parents=True)
    output = parent / "trace.jsonl"
    temporary = output.with_suffix(".jsonl.tmp")
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    retained = tmp_path / "retained"

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            private.rename(retained)
            private.mkdir()
            (retained / "leaf").rename(parent)
            self.returncode = 1
            return 1

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    with pytest.raises(ContractError, match="temporary-remove"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert temporary.exists()
    assert not output.exists()


def test_perfetto_export_preserves_output_when_report_failure_moves_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    private = tmp_path / "private"
    parent = private / "leaf"
    parent.mkdir(parents=True)
    output = parent / "trace.jsonl"
    report_path = parent / "trace.export.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    retained = tmp_path / "retained"

    def relocate_and_fail(_report, _temporary, _destination):
        private.rename(retained)
        private.mkdir()
        (retained / "leaf").rename(parent)
        raise ContractError("injected report failure")

    monkeypatch.setattr(perfetto, "_publish_export_report", relocate_and_fail)
    with pytest.raises(ContractError, match="normalized trace rollback failed"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report_path)

    assert output.exists()
    assert not report_path.exists()


def test_perfetto_export_rejects_report_changed_after_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    report_path = tmp_path / "trace.export.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    original_publish = perfetto._publish_export_report

    def mutate_report(report, temporary, destination):
        binding = original_publish(report, temporary, destination)
        body = report_path.read_bytes()
        assert b'"events": 1' in body
        report_path.write_bytes(body.replace(b'"events": 1', b'"events": 0', 1))
        return binding

    monkeypatch.setattr(perfetto, "_publish_export_report", mutate_report)
    with pytest.raises(ContractError, match="trace export report changed after publication"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report_path)


def test_perfetto_export_rejects_source_trace_changed_during_report_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    report_path = tmp_path / "trace.export.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    original_publish = perfetto._publish_export_report

    def mutate_source(report, temporary, destination):
        binding = original_publish(report, temporary, destination)
        trace.write_bytes(b"Trace")
        return binding

    monkeypatch.setattr(perfetto, "_publish_export_report", mutate_source)
    with pytest.raises(ContractError, match="source trace changed after publication"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report_path)


@pytest.mark.parametrize("mutation", ["truncate", "same-length-replace"])
def test_perfetto_export_rejects_changed_staged_normalized_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    original = perfetto._build_trace_export_report_from_counts

    def altered_report(trace_path, output_path, *args):
        body = output_path.read_bytes()
        if mutation == "truncate":
            output_path.write_bytes(body[:-1])
        else:
            output_path.write_bytes(b"X" + body[1:])
        return original(trace_path, output_path, *args)

    monkeypatch.setattr(perfetto, "_build_trace_export_report_from_counts", altered_report)
    with pytest.raises(ContractError, match="normalized trace .*changed"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)
    assert not output.exists()
    assert not output.with_suffix(".jsonl.tmp").exists()


@pytest.mark.parametrize("mutation", ["truncate", "same-length-replace"])
def test_perfetto_export_rejects_changed_staged_report_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    report_path = tmp_path / "trace.export.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    original = perfetto._stable_file_binding
    altered_once = False

    def altered_binding(path, *, label, maximum=None):
        nonlocal altered_once
        if label == "trace export report temporary" and not altered_once:
            altered_once = True
            body = path.read_bytes()
            if mutation == "truncate":
                path.write_bytes(body[:-1])
            else:
                path.write_bytes(b"X" + body[1:])
        return original(path, label=label, maximum=maximum)

    monkeypatch.setattr(perfetto, "_stable_file_binding", altered_binding)
    with pytest.raises(ContractError, match="trace export report bytes changed"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report_path)
    assert not output.exists()
    assert not report_path.exists()
    assert not report_path.with_suffix(".json.tmp").exists()


def test_perfetto_export_rolls_back_normalized_output_when_report_destination_races(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    report_path = tmp_path / "trace.export.json"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.returncode = -1

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    original_publish = perfetto._publish_temporary_exclusive

    def race_report(
        temporary, destination, *, expected_binding, expected_parent_ancestry, label
    ):
        if label == "trace export report":
            report_path.write_bytes(b"competitor report")
        return original_publish(
            temporary,
            destination,
            expected_binding=expected_binding,
            expected_parent_ancestry=expected_parent_ancestry,
            label=label,
        )

    monkeypatch.setattr(perfetto, "_publish_temporary_exclusive", race_report)
    with pytest.raises(ContractError, match="report destination became occupied"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report_path)
    assert not output.exists()
    assert report_path.read_bytes() == b"competitor report"
    assert not report_path.with_suffix(".json.tmp").exists()


@pytest.mark.parametrize("maximum", [0, True, "1"])
def test_perfetto_export_rejects_invalid_event_limits_before_process_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, maximum
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    monkeypatch.setattr(
        perfetto.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("processor must not start"),
    )

    with pytest.raises(ContractError, match="event limit"):
        export_perfetto(
            processor,
            trace,
            output,
            "fixture-run",
            REVISION,
            maximum_events=maximum,
        )

    assert not output.exists()


@pytest.mark.parametrize("blocked_parent", ["normalized", "report"])
def test_perfetto_export_prepares_both_destination_parents_before_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked_parent: str
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    blocker = tmp_path / "blocked"
    blocker.write_bytes(b"not a directory")
    output = (blocker if blocked_parent == "normalized" else tmp_path) / "trace.jsonl"
    report = (blocker if blocked_parent == "report" else tmp_path) / "trace.report.json"
    monkeypatch.setattr(
        perfetto.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("processor started before destination preflight"),
    )
    with pytest.raises(ContractError, match="destination directory"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION, report)
    assert not output.exists()


def test_perfetto_export_kills_event_population_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    lines = csv_fixture().splitlines()

    class Process:
        def __init__(self):
            self.stdout = io.StringIO("\n".join([lines[0], lines[1], lines[1]]) + "\n")
            self.returncode = None
            self.killed = False

        def wait(self, timeout=None):
            self.returncode = 0 if self.returncode is None else self.returncode
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -1

    process = Process()
    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: process)

    with pytest.raises(ContractError, match="population exceeds"):
        export_perfetto(
            processor,
            trace,
            output,
            "fixture-run",
            REVISION,
            maximum_events=1,
        )

    assert process.killed is True
    assert not output.exists()
    assert not output.with_suffix(".jsonl.tmp").exists()


def test_perfetto_export_watchdog_maps_timeout_without_child_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self):
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None
            self.killed = False

        def wait(self, timeout=None):
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -1

    class ImmediateTimer:
        def __init__(self, _seconds, callback):
            self.callback = callback
            self.daemon = False

        def start(self):
            self.callback()

        def cancel(self):
            return None

    process = Process()
    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(perfetto.threading, "Timer", ImmediateTimer)

    with pytest.raises(ContractError, match="query timed out"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert process.killed is True
    assert not output.exists()


def test_perfetto_export_normalizes_private_processor_start_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "private-processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    private_marker = str(tmp_path / "secret-location")

    def fail_start(*_args, **_kwargs):
        raise OSError(f"cannot execute {private_marker}")

    monkeypatch.setattr(perfetto.subprocess, "Popen", fail_start)

    with pytest.raises(ContractError) as captured:
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert str(captured.value) == "trace processor query could not start (OSError)"
    assert private_marker not in str(captured.value)
    assert not output.exists()


def test_perfetto_export_bounds_unreapable_processor_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self):
            self.stdout = io.StringIO(csv_fixture())
            self.killed = False
            self.wait_timeouts = []

        def wait(self, timeout=None):
            self.wait_timeouts.append(timeout)
            raise perfetto.subprocess.TimeoutExpired("private command", timeout)

        def poll(self):
            return None

        def kill(self):
            self.killed = True

    process = Process()
    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: process)

    with pytest.raises(ContractError, match=r"cleanup failed \(process-reap\)"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert process.killed is True
    assert process.wait_timeouts == [perfetto.TRACE_PROCESSOR_REAP_TIMEOUT_SECONDS] * 2
    assert not output.exists()
    assert not output.with_suffix(".jsonl.tmp").exists()


def test_perfetto_watchdog_construction_failure_reaps_processor_type_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self) -> None:
            self.stdout = io.StringIO(csv_fixture())
            self.killed = False
            self.waits: list[float] = []

        def poll(self):  # noqa: ANN201
            return None

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float) -> int:
            self.waits.append(timeout)
            return -9

    process = Process()
    private = "private-watchdog-constructor"
    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(
        perfetto.threading,
        "Timer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(private)),
    )

    with pytest.raises(ContractError) as captured:
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert str(captured.value) == (
        "trace processor watchdog could not start (RuntimeError)"
    )
    assert private not in str(captured.value)
    assert process.killed is True
    assert process.waits == [perfetto.TRACE_PROCESSOR_REAP_TIMEOUT_SECONDS]
    assert not output.exists()


def test_perfetto_error_cleanup_preserves_replaced_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    temporary = output.with_suffix(".jsonl.tmp")
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    competitor = b"competing normalized population"

    class Stdout(io.StringIO):
        def __init__(self) -> None:
            super().__init__(csv_fixture())
            self.replaced = False

        def close(self) -> None:
            if not self.replaced:
                replacement = tmp_path / "replacement.tmp"
                replacement.write_bytes(competitor)
                os.replace(replacement, temporary)
                self.replaced = True
            super().close()
            raise OSError("private stdout close")

    class Process:
        def __init__(self) -> None:
            self.stdout = Stdout()
            self.killed = False

        def poll(self):  # noqa: ANN201
            return None

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float) -> int:
            return -9

    process = Process()
    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: process)

    with pytest.raises(ContractError) as captured:
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert str(captured.value) == "trace processor cleanup failed (stdout-close)"
    assert "private" not in str(captured.value)
    assert process.killed is True
    assert temporary.read_bytes() == competitor
    assert not output.exists()


def test_perfetto_temporary_cleanup_preserves_a_replacement_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.perfetto as perfetto

    parent = tmp_path / "workspace"
    parent.mkdir()
    temporary = parent / "trace.jsonl.tmp"
    temporary.write_bytes(b"owned")
    identity = perfetto._owned_file_object_identity(perfetto.os.lstat(temporary))
    held = tmp_path / "held-workspace"
    real_rename = perfetto.os.rename
    injected = False

    def replace_parent_before_quarantine(source: Path, destination: Path) -> None:
        nonlocal injected
        if not injected and Path(source) == temporary:
            injected = True
            real_rename(parent, held)
            parent.mkdir()
            temporary.write_bytes(b"competitor")
        real_rename(source, destination)

    monkeypatch.setattr(
        perfetto.os,
        "rename",
        replace_parent_before_quarantine,
    )
    with pytest.raises(ContractError, match="parent changed during cleanup"):
        perfetto._remove_owned_temporary(
            temporary,
            expected_identity=identity,
            label="normalized temporary",
        )

    assert (held / "trace.jsonl.tmp").read_bytes() == b"owned"
    assert not temporary.exists()
    competitors = list(parent.glob(".trace.jsonl.tmp.cleanup-*"))
    assert len(competitors) == 1
    assert competitors[0].read_bytes() == b"competitor"


def test_perfetto_temporary_cleanup_preserves_relocated_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    private = tmp_path / "private"
    parent = private / "leaf"
    parent.mkdir(parents=True)
    temporary = parent / "trace.jsonl.tmp"
    temporary.write_bytes(b"owned")
    identity = perfetto._owned_file_object_identity(os.lstat(temporary))
    retained = tmp_path / "retained"
    real_rename = perfetto.os.rename
    injected = False

    def relocate_before_quarantine(source: Path, destination: Path) -> None:
        nonlocal injected
        if not injected and Path(source) == temporary:
            injected = True
            real_rename(private, retained)
            private.mkdir()
            real_rename(retained / "leaf", parent)
        real_rename(source, destination)

    monkeypatch.setattr(perfetto.os, "rename", relocate_before_quarantine)
    with pytest.raises(ContractError, match="parent changed during cleanup"):
        perfetto._remove_owned_temporary(
            temporary,
            expected_identity=identity,
            label="normalized temporary",
        )

    quarantined = list(parent.glob(".trace.jsonl.tmp.cleanup-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"owned"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_perfetto_temporary_cleanup_rejects_preexisting_ancestor_junction(
    tmp_path: Path,
) -> None:
    import browser_core.perfetto as perfetto

    outer = tmp_path / "workspace"
    inner = outer / "inner"
    inner.mkdir(parents=True)
    temporary = inner / "trace.jsonl.tmp"
    temporary.write_bytes(b"owned")
    identity = perfetto._owned_file_object_identity(os.lstat(temporary))
    foreign = tmp_path / "foreign"
    outer.rename(foreign)
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(outer), str(foreign)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            perfetto._remove_owned_temporary(
                temporary,
                expected_identity=identity,
                label="normalized temporary",
            )
        assert (foreign / "inner" / temporary.name).read_bytes() == b"owned"
    finally:
        if outer.exists():
            outer.rmdir()


def test_perfetto_export_refuses_every_input_output_temporary_alias(
    tmp_path: Path, monkeypatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "source.perfetto-trace"
    output = tmp_path / "normalized.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"source trace")
    monkeypatch.setattr(
        perfetto.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("processor must not start"),
    )

    cases = [
        (trace, None),
        (processor, None),
        (output, output),
        (output, output.with_suffix(".jsonl.tmp")),
    ]
    for normalized, report in cases:
        with pytest.raises(ContractError, match="paths must be distinct"):
            export_perfetto(
                processor,
                trace,
                normalized,
                "fixture-run",
                REVISION,
                report,
            )

    temporary_source = output.with_suffix(".jsonl.tmp")
    temporary_source.write_bytes(b"temporary-shaped source")
    with pytest.raises(ContractError, match="paths must be distinct"):
        export_perfetto(
            processor,
            temporary_source,
            output,
            "fixture-run",
            REVISION,
        )

    assert processor.read_bytes() == b"processor"
    assert trace.read_bytes() == b"source trace"
    assert temporary_source.read_bytes() == b"temporary-shaped source"


def test_perfetto_export_never_overwrites_or_deletes_a_stale_temporary(
    tmp_path: Path, monkeypatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "source.perfetto-trace"
    output = tmp_path / "normalized.jsonl"
    temporary = output.with_suffix(".jsonl.tmp")
    processor.write_bytes(b"processor")
    trace.write_bytes(b"source trace")
    temporary.write_bytes(b"owned by another export")
    monkeypatch.setattr(
        perfetto.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("processor must not start"),
    )

    with pytest.raises(ContractError, match="temporary path already exists"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert temporary.read_bytes() == b"owned by another export"
    assert trace.read_bytes() == b"source trace"
    assert not output.exists()


def test_perfetto_exclusive_publication_preserves_a_destination_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    temporary = tmp_path / "output.tmp"
    destination = tmp_path / "output.jsonl"
    temporary.write_bytes(b"verified normalized population")
    binding = perfetto._stable_file_binding(temporary, label="fixture")

    def race(_source, target, **_kwargs):
        Path(target).write_bytes(b"competitor population")
        raise FileExistsError(target)

    monkeypatch.setattr(perfetto.os, "link", race)

    with pytest.raises(ContractError, match="destination became occupied"):
        perfetto._publish_temporary_exclusive(
            temporary,
            destination,
            expected_binding=binding,
            label="fixture",
        )

    assert temporary.read_bytes() == b"verified normalized population"
    assert destination.read_bytes() == b"competitor population"


def test_perfetto_publication_preserves_postlink_destination_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    temporary = tmp_path / "output.tmp"
    destination = tmp_path / "output.jsonl"
    replacement = tmp_path / "replacement.tmp"
    temporary.write_bytes(b"verified normalized population")
    replacement.write_bytes(b"competitor population")
    binding = perfetto._stable_file_binding(temporary, label="fixture")
    original_link = perfetto.os.link

    def link_then_replace(source: Path, target: Path, **kwargs) -> None:
        original_link(source, target, **kwargs)
        replacement.replace(target)

    monkeypatch.setattr(perfetto.os, "link", link_then_replace)
    with pytest.raises(ContractError, match="linked object changed"):
        perfetto._publish_temporary_exclusive(
            temporary,
            destination,
            expected_binding=binding,
            label="fixture",
        )

    assert temporary.read_bytes() == b"verified normalized population"
    assert destination.read_bytes() == b"competitor population"


def test_perfetto_publication_rejects_a_final_hard_link_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.perfetto as perfetto

    temporary = tmp_path / "output.tmp"
    destination = tmp_path / "output.jsonl"
    alias = tmp_path / "output-alias.jsonl"
    temporary.write_bytes(b"verified normalized population")
    binding = perfetto._stable_file_binding(temporary, label="fixture")
    original_link = perfetto.os.link

    def publish_then_alias(source: Path, target: Path, **kwargs) -> None:
        original_link(source, target, **kwargs)
        original_link(target, alias)

    monkeypatch.setattr(perfetto.os, "link", publish_then_alias)
    with pytest.raises(ContractError, match="linked object changed"):
        perfetto._publish_temporary_exclusive(
            temporary,
            destination,
            expected_binding=binding,
            label="fixture",
        )
    assert temporary.exists() and alias.exists()
    assert not destination.exists()


def test_perfetto_publication_preserves_a_prelink_source_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.perfetto as perfetto

    temporary = tmp_path / "output.tmp"
    destination = tmp_path / "output.jsonl"
    original = tmp_path / "original.tmp"
    temporary.write_bytes(b"verified normalized population")
    binding = perfetto._stable_file_binding(temporary, label="fixture")
    original_link = perfetto.os.link
    competitor = b"competing temporary"

    def swap_then_publish(source: Path, target: Path, **kwargs) -> None:
        Path(source).rename(original)
        Path(source).write_bytes(competitor)
        original_link(source, target, **kwargs)

    monkeypatch.setattr(perfetto.os, "link", swap_then_publish)

    with pytest.raises(ContractError, match="linked object changed"):
        perfetto._publish_temporary_exclusive(
            temporary,
            destination,
            expected_binding=binding,
            label="fixture",
        )

    assert original.read_bytes() == b"verified normalized population"
    assert temporary.read_bytes() == competitor
    assert destination.read_bytes() == competitor


def test_perfetto_publication_preserves_postlink_temporary_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.perfetto as perfetto

    temporary = tmp_path / "output.tmp"
    destination = tmp_path / "output.jsonl"
    temporary.write_bytes(b"verified normalized population")
    binding = perfetto._stable_file_binding(temporary, label="fixture")
    original_link = perfetto.os.link
    competitor = b"postlink competitor"

    def link_then_replace(source: Path, target: Path, **kwargs) -> None:
        original_link(source, target, **kwargs)
        Path(source).unlink()
        Path(source).write_bytes(competitor)

    monkeypatch.setattr(perfetto.os, "link", link_then_replace)

    with pytest.raises(ContractError, match="linked object changed"):
        perfetto._publish_temporary_exclusive(
            temporary,
            destination,
            expected_binding=binding,
            label="fixture",
        )

    assert temporary.read_bytes() == competitor
    assert not destination.exists()


def test_perfetto_export_caps_normalized_bytes_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self):
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())
    monkeypatch.setattr(perfetto, "MAX_NORMALIZED_TRACE_BYTES", 1)
    with pytest.raises(ContractError, match="normalized trace exceeds"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)
    assert not output.exists()
    assert not output.with_suffix(".jsonl.tmp").exists()


def test_streaming_export_refuses_completed_output_before_process_contact(
    tmp_path: Path, monkeypatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")
    output.write_text("completed-before-failure\n", encoding="utf-8")

    class Process:
        def __init__(self):
            self.stdout = io.StringIO('"unexpected"\n"row"\n')
            self.returncode = None
            self.killed = False
            self.waited = False

        def wait(self, timeout=None):
            self.waited = True
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -1

    process = Process()
    monkeypatch.setattr(
        perfetto.subprocess,
        "Popen",
        lambda *_a, **_k: pytest.fail("processor must not start"),
    )

    with pytest.raises(ContractError, match="destination already exists"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert process.killed is False
    assert process.waited is False
    assert output.read_text(encoding="utf-8") == "completed-before-failure\n"
    assert not output.with_suffix(".jsonl.tmp").exists()


def test_streaming_export_rejects_nonzero_processor_after_valid_rows(
    tmp_path: Path, monkeypatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self):
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None
            self.wait_calls = 0

        def wait(self, timeout=None):
            self.wait_calls += 1
            self.returncode = 7
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self):
            raise AssertionError("completed processor must not be killed")

    process = Process()
    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: process)

    with pytest.raises(ContractError, match="exit code 7"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert process.wait_calls == 1
    assert not output.exists()
    assert not output.with_suffix(".jsonl.tmp").exists()


def test_streaming_export_refuses_a_source_trace_that_changes_mid_query(
    tmp_path: Path, monkeypatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor")
    trace.write_bytes(b"trace-a")

    class Process:
        def __init__(self):
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            trace.write_bytes(b"trace-b")
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self):
            raise AssertionError("completed processor must not be killed")

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())

    with pytest.raises(ContractError, match="source trace changed during export"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert trace.read_bytes() == b"trace-b"
    assert not output.exists()
    assert not output.with_suffix(".jsonl.tmp").exists()


def test_streaming_export_refuses_a_processor_that_changes_mid_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import browser_core.perfetto as perfetto

    processor = tmp_path / "trace_processor"
    trace = tmp_path / "trace.perfetto-trace"
    output = tmp_path / "trace.jsonl"
    processor.write_bytes(b"processor-a")
    trace.write_bytes(b"trace")

    class Process:
        def __init__(self):
            self.stdout = io.StringIO(csv_fixture())
            self.returncode = None

        def wait(self, timeout=None):
            processor.write_bytes(b"processor-b-different-size")
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self):
            raise AssertionError("completed processor must not be killed")

    monkeypatch.setattr(perfetto.subprocess, "Popen", lambda *_a, **_k: Process())

    with pytest.raises(ContractError, match="processor changed"):
        export_perfetto(processor, trace, output, "fixture-run", REVISION)

    assert not output.exists()
    assert not output.with_suffix(".jsonl.tmp").exists()


def test_trace_export_schema_declares_redaction_safe_digest_bindings() -> None:
    schema = json.loads(
        (
            Path(__file__).parents[1] / "schemas" / "trace-export-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert schema["$id"] == "browser-core.trace-export/1"
    assert schema["properties"]["source_trace"]["additionalProperties"] is False
    assert schema["properties"]["normalized_trace"]["additionalProperties"] is False


def test_perfetto_export_rejects_unknown_native_schema() -> None:
    with pytest.raises(ContractError, match="native event schema"):
        parse_export_csv(csv_fixture(native_schema="other/1"), "fixture-run", REVISION)


def test_perfetto_export_requires_the_exact_ordered_csv_header() -> None:
    lines = csv_fixture().splitlines()
    extra = lines[0] + ',"extra"\n' + lines[1] + ',"value"\n'
    duplicate = lines[0] + f',"{EXPORT_COLUMNS[0]}"\n' + lines[1] + ',"1234"\n'

    row = next(csv.DictReader(io.StringIO(csv_fixture())))
    reordered_stream = io.StringIO()
    reordered_columns = tuple(reversed(EXPORT_COLUMNS))
    writer = csv.DictWriter(
        reordered_stream, fieldnames=reordered_columns, quoting=csv.QUOTE_ALL
    )
    writer.writeheader()
    writer.writerow(row)

    for malformed in (extra, duplicate, reordered_stream.getvalue()):
        with pytest.raises(ContractError, match="duplicated, reordered, or unexpected"):
            parse_export_csv(malformed, "fixture-run", REVISION)


def test_perfetto_export_rejects_a_short_csv_row_as_structure() -> None:
    lines = csv_fixture().splitlines()
    shortened = lines[0] + "\n" + lines[1].rsplit(",", 1)[0] + "\n"

    with pytest.raises(ContractError, match="row width"):
        parse_export_csv(shortened, "fixture-run", REVISION)


def test_perfetto_export_rejects_unterminated_quoted_native_field() -> None:
    malformed = csv_fixture().rstrip("\r\n")[:-1]
    with pytest.raises(ContractError, match="cannot parse Perfetto CSV"):
        parse_export_csv(malformed, "fixture-run", REVISION)


def test_perfetto_export_rejects_non_stream_event_in_stream_category() -> None:
    with pytest.raises(ContractError, match="trace category"):
        parse_export_csv(
            csv_fixture(trace_category="browser_core.stream"),
            "fixture-run",
            REVISION,
        )


def test_perfetto_export_rejects_empty_result() -> None:
    with pytest.raises(ContractError, match="no supported"):
        parse_export_csv(",".join(EXPORT_COLUMNS) + "\n", "fixture-run", REVISION)


def test_perfetto_csv_normalizes_contexts_and_explicit_request_causality() -> None:
    base = {field: NULL_VALUE for field in EXPORT_COLUMNS}
    rows = [
        {
            **base,
            "ts_monotonic_ns": "100",
            "trace_category": "browser_core.debug",
            "native_name": "BrowserCore.ScriptRun",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "execution",
            "event_name": "script.run",
            "component": "blink.v8",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "script:frame-token:7",
        },
        {
            **base,
            "ts_monotonic_ns": "101",
            "trace_category": "browser_core.debug",
            "native_name": "BrowserCore.FetchCall",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "api",
            "event_name": "fetch",
            "component": "blink.fetch",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "fetch-api:frame-token:1",
            "native_parent_id": "script:frame-token:7",
        },
        {
            **base,
            "ts_monotonic_ns": "102",
            "trace_category": "browser_core.debug",
            "native_name": "BrowserCore.FetchRequestStart",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "network",
            "event_name": "fetch.request.start",
            "component": "blink.fetch",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "fetch-request:frame-token:1",
            "native_parent_id": "fetch-api:frame-token:1",
            "request_id": "fetch-request:frame-token:1",
            "method": "GET",
            "url_class": "https:same-origin:/probe",
            "target_scope": "loopback",
            "body_bytes": "0",
        },
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)

    events = parse_export_csv(output.getvalue(), "fixture-run", REVISION)

    assert [event.get("causal_parent_seq") for event in events] == [None, 0, 1]
    assert events[0]["execution"] == {
        "context_id": "frame-token",
        "frame_id": "frame-token",
        "script_id": "v8:42:frame-token:7",
    }
    assert all(
        event["provenance"]["trace_category"] == "browser_core.debug"
        for event in events
    )
    assert events[2]["request"] == {
        "id": "fetch-request:frame-token:1",
        "method": "GET",
        "url_class": "https:same-origin:/probe",
        "target_scope": "loopback",
        "body_bytes": 0,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.FetchRequestStart"),
        ("component", "blink.network"),
        ("context_kind", "forged"),
        ("native_id", "fetch-api:other-frame:1"),
        ("native_parent_id", "script:other-frame:7"),
        ("duration_ns", "1"),
        ("api", "fetch"),
        ("request_id", "request-1"),
        ("method", "GET"),
        ("url_class", "same-origin"),
        ("target_scope", "loopback"),
        ("body_bytes", "0"),
        ("data_bytes", "1"),
    ],
)
def test_perfetto_rejects_forged_fetch_api_event(field: str, value: str) -> None:
    overrides = {
        "native_name": "BrowserCore.FetchCall",
        "event_category": "api",
        "event_name": "fetch",
        "component": "blink.fetch",
        "api": NULL_VALUE,
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": "7",
        "native_id": "fetch-api:frame-token:1",
        "native_parent_id": "script:frame-token:7",
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
    }
    overrides[field] = value

    error_match = (
        "fetch request event identity"
        if field == "native_name"
        else "fetch API"
    )
    with pytest.raises(ContractError, match=error_match):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("native_name", "BrowserCore.FetchCall", "fetch API event identity"),
        ("component", "blink.network", "fetch request"),
        ("context_kind", "forged", "fetch request"),
        ("native_id", "fetch-request:other-frame:1", "fetch request"),
        (
            "native_parent_id",
            "fetch-api:frame-token:2",
            "causal parent|fetch request",
        ),
        ("request_id", "fetch-request:frame-token:2", "fetch request"),
        ("duration_ns", "1", "fetch request"),
        ("api", "fetch", "fetch request"),
        ("data_bytes", "1", "fetch request"),
    ],
)
def test_perfetto_rejects_forged_fetch_request_event(
    field: str,
    value: str,
    message: str,
) -> None:
    request = {
        "ts_monotonic_ns": "101",
        "native_name": "BrowserCore.FetchRequestStart",
        "event_category": "network",
        "event_name": "fetch.request.start",
        "component": "blink.fetch",
        "context_id": "frame-token",
        "context_kind": "frame",
        "native_id": "fetch-request:frame-token:1",
        "native_parent_id": "fetch-api:frame-token:1",
        "request_id": "fetch-request:frame-token:1",
        "method": "GET",
        "url_class": "https:same-origin:/probe",
        "target_scope": "loopback",
        "body_bytes": "0",
    }
    request[field] = value
    csv_text = csv_rows_fixture(
        [
            {
                "ts_monotonic_ns": "100",
                "native_name": "BrowserCore.FetchCall",
                "event_category": "api",
                "event_name": "fetch",
                "component": "blink.fetch",
                "context_id": "frame-token",
                "context_kind": "frame",
                "native_id": "fetch-api:frame-token:1",
            },
            request,
        ]
    )

    with pytest.raises(ContractError, match=message):
        parse_export_csv(csv_text, "fixture-run", REVISION)


def test_perfetto_rejects_request_body_bytes_above_safe_integer_domain() -> None:
    csv_text = csv_rows_fixture(
        [
            {
                "ts_monotonic_ns": "100",
                "native_name": "BrowserCore.FetchCall",
                "event_category": "api",
                "event_name": "fetch",
                "component": "blink.fetch",
                "context_id": "frame-token",
                "context_kind": "frame",
                "native_id": "fetch-api:frame-token:1",
            },
            {
                "ts_monotonic_ns": "101",
                "native_name": "BrowserCore.FetchRequestStart",
                "event_category": "network",
                "event_name": "fetch.request.start",
                "component": "blink.fetch",
                "context_id": "frame-token",
                "context_kind": "frame",
                "native_id": "fetch-request:frame-token:1",
                "native_parent_id": "fetch-api:frame-token:1",
                "request_id": "fetch-request:frame-token:1",
                "method": "POST",
                "url_class": "https:same-origin:/probe",
                "target_scope": "loopback",
                "body_bytes": "9007199254740992",
            },
        ]
    )

    with pytest.raises(ContractError, match="body_bytes.*safe integer"):
        parse_export_csv(csv_text, "fixture-run", REVISION)


@pytest.mark.parametrize(
    ("thread_name", "context_key", "trace_category", "native_name"),
    [
        (
            "CrRendererMain",
            "frame_id",
            "blink.bindings",
            "Navigator.userAgent.get",
        ),
        (
            "DedicatedWorker thread",
            "worker_id",
            "blink.bindings.encoding",
            "TextEncoder.encode",
        ),
    ],
)
def test_perfetto_csv_normalizes_generated_blink_binding_events(
    thread_name: str,
    context_key: str,
    trace_category: str,
    native_name: str,
) -> None:
    events = parse_export_csv(
        csv_fixture(
            trace_category=trace_category,
            native_name=native_name,
            native_schema=NULL_VALUE,
            api=NULL_VALUE,
            width=NULL_VALUE,
            height=NULL_VALUE,
            origin_clean=NULL_VALUE,
            thread_name=thread_name,
            duration_ns="25",
        ),
        "fixture-run",
        REVISION,
    )

    event = events[0]
    assert event["event"] == {"category": "api", "name": native_name}
    assert event["process"]["type"] == "renderer"
    assert event["provenance"]["component"] == "blink.bindings.generated"
    assert event["provenance"]["trace_category"] == trace_category
    assert event["execution"]["context_id"] == "bindings:42:43"
    assert event["execution"][context_key] == "bindings:42:43"
    assert "script_id" not in event["execution"]
    assert event["detail"]["completion"] == "complete"
    assert event["detail"]["duration_ns"] == 25


def test_generated_binding_does_not_treat_a_script_run_as_callback_realm_evidence() -> None:
    base = {field: NULL_VALUE for field in EXPORT_COLUMNS}
    rows = [
        {
            **base,
            "ts_monotonic_ns": "100",
            "trace_category": "browser_core.debug",
            "native_name": "BrowserCore.ScriptRun",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "execution",
            "event_name": "script.run",
            "component": "blink.v8",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "script:frame-token:7",
        },
        {
            **base,
            "ts_monotonic_ns": "101",
            "trace_category": "blink.bindings",
            "native_name": "Navigator.userAgent.get",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "script_id": "7",
            "duration_ns": "25",
        },
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)

    events = parse_export_csv(output.getvalue(), "fixture-run", REVISION)
    binding = events[1]
    assert binding["execution"]["script_id"] == "v8:42:bindings:43:7"
    assert binding["execution"]["context_id"] == "bindings:42:43"
    assert binding["detail"]["context_attribution"] == "unresolved"
    assert binding["detail"]["script_attribution"] == "script-context-unresolved"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "Navigator userAgent"),
        ("event_category", "api"),
        ("component", "blink.bindings.generated"),
        ("api", "Navigator.userAgent.get"),
        ("context_id", "frame-token"),
        ("native_id", "binding:frame-token:1"),
        ("data_bytes", "1"),
        ("duration_ns", NULL_VALUE),
        (
            "duration_ns",
            str(7 * 24 * 60 * 60 * 1_000_000_000 + 1),
        ),
        ("trace_category", "blink.bindings.encoding"),
    ],
)
def test_perfetto_rejects_forged_generated_binding_event(
    field: str,
    value: str,
) -> None:
    overrides = {
        "trace_category": "blink.bindings",
        "native_name": "Navigator.userAgent.get",
        "native_schema": NULL_VALUE,
        "api": NULL_VALUE,
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
        "duration_ns": "25",
    }
    overrides[field] = value

    with pytest.raises(ContractError, match="generated binding"):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


def test_perfetto_rejects_generated_binding_from_browser_process() -> None:
    with pytest.raises(ContractError, match="generated binding"):
        parse_export_csv(
            csv_fixture(
                trace_category="blink.bindings",
                native_name="Navigator.userAgent.get",
                native_schema=NULL_VALUE,
                api=NULL_VALUE,
                width=NULL_VALUE,
                height=NULL_VALUE,
                origin_clean=NULL_VALUE,
                duration_ns="25",
                process_name="Browser",
                thread_name="CrBrowserMain",
            ),
            "fixture-run",
            REVISION,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("native_name", "BrowserCore.Script", "script run"),
        ("event_category", "api", "script run event identity"),
        ("event_name", "script.execution", "script run event identity"),
        ("component", "v8", "script run"),
        ("native_id", "script:other-frame:7", "script run"),
        ("native_parent_id", "script:frame-token:6", "script run parent"),
        ("script_id", NULL_VALUE, "script run"),
        ("data_bytes", "1", "script run"),
    ],
)
def test_perfetto_rejects_forged_script_run_anchor(
    field: str,
    value: str,
    message: str,
) -> None:
    overrides = {
        "native_name": "BrowserCore.ScriptRun",
        "event_category": "execution",
        "event_name": "script.run",
        "component": "blink.v8",
        "api": NULL_VALUE,
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": "7",
        "native_id": "script:frame-token:7",
        "native_parent_id": NULL_VALUE,
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
    }
    overrides[field] = value

    with pytest.raises(ContractError, match=message):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


def test_generated_binding_retains_script_attribution_when_run_precedes_trace() -> None:
    event = parse_export_csv(
        csv_fixture(
            trace_category="blink.bindings",
            native_name="Navigator.userAgent.get",
            native_schema=NULL_VALUE,
            api=NULL_VALUE,
            width=NULL_VALUE,
            height=NULL_VALUE,
            origin_clean=NULL_VALUE,
            script_id="7",
            duration_ns="25",
        ),
        "fixture-run",
        REVISION,
    )[0]

    assert event["execution"]["script_id"] == "v8:42:bindings:43:7"
    assert event["detail"]["script_attribution"] == "script-context-unresolved"


@pytest.mark.parametrize(
    ("duration", "completion", "expected_duration"),
    [("123456", "complete", 123456), ("-1", "open", None)],
)
def test_perfetto_normalizes_script_execution_scope(
    duration: str, completion: str, expected_duration: int | None
) -> None:
    event = parse_export_csv(
        csv_fixture(
            native_name="BrowserCore.ScriptExecution",
            event_category="execution",
            event_name="script.execution",
            component="blink.v8",
            api=NULL_VALUE,
            context_id="frame-token",
            context_kind="frame",
            script_id="7",
            duration_ns=duration,
            width=NULL_VALUE,
            height=NULL_VALUE,
            origin_clean=NULL_VALUE,
        ),
        "fixture-run",
        REVISION,
    )[0]

    assert event["event"] == {"category": "execution", "name": "script.execution"}
    assert event["detail"]["completion"] == completion
    assert event["detail"].get("duration_ns") == expected_duration
    assert event["execution"]["script_id"] == "v8:42:frame-token:7"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("native_name", "BrowserCore.ScriptRun", "script run event identity"),
        ("event_category", "api", "script execution event identity"),
        ("event_name", "script.run", "script execution event identity"),
        ("component", "v8", "script execution"),
        ("native_id", "script-execution:frame-token:7", "script execution"),
        ("native_parent_id", "script:frame-token:7", "script execution parent"),
        ("script_id", NULL_VALUE, "script execution"),
        ("data_bytes", "1", "script execution"),
    ],
)
def test_perfetto_rejects_forged_script_execution_scope(
    field: str,
    value: str,
    message: str,
) -> None:
    overrides = {
        "native_name": "BrowserCore.ScriptExecution",
        "event_category": "execution",
        "event_name": "script.execution",
        "component": "blink.v8",
        "api": NULL_VALUE,
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": "7",
        "native_id": NULL_VALUE,
        "native_parent_id": NULL_VALUE,
        "duration_ns": "123456",
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
    }
    overrides[field] = value

    with pytest.raises(ContractError, match=message):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


@pytest.mark.parametrize(
    "duration", [NULL_VALUE, "-2", str(7 * 24 * 60 * 60 * 1_000_000_000 + 1)]
)
def test_perfetto_rejects_invalid_script_execution_duration(duration: str) -> None:
    with pytest.raises(ContractError, match="script execution duration"):
        parse_export_csv(
            csv_fixture(
                native_name="BrowserCore.ScriptExecution",
                event_category="execution",
                event_name="script.execution",
                component="blink.v8",
                api=NULL_VALUE,
                context_id="frame-token",
                context_kind="frame",
                script_id="7",
                duration_ns=duration,
                width=NULL_VALUE,
                height=NULL_VALUE,
                origin_clean=NULL_VALUE,
            ),
            "fixture-run",
            REVISION,
        )


def host_callback_row(**overrides: str) -> dict[str, str]:
    row = {
        "ts_monotonic_ns": "200",
        "duration_ns": "50",
        "track_id": "9",
        "trace_category": "browser_core.debug",
        "native_name": "BrowserCore.HostCallbackExecution",
        "event_category": "execution",
        "event_name": "host.callback.execution",
        "component": "blink.bindings.callback",
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": "7",
        "native_parent_id": "script:frame-token:7",
        "callback_interface": "EventListener",
        "callback_operation": "handleEvent",
        "callback_kind": "function",
    }
    row.update(overrides)
    return row


def promise_microtask_row(**overrides: str) -> dict[str, str]:
    row = {
        "ts_monotonic_ns": "180",
        "duration_ns": "100",
        "track_id": "9",
        "trace_category": "browser_core.debug",
        "native_name": "BrowserCore.PromiseMicrotaskExecution",
        "event_category": "execution",
        "event_name": "promise.microtask.execution",
        "component": "blink.scheduler.promise",
        "context_id": "frame-token",
        "context_kind": "frame",
    }
    row.update(overrides)
    return row


def dynamic_code_row(**overrides: str) -> dict[str, str]:
    row = {
        "ts_monotonic_ns": "120",
        "duration_ns": "0",
        "track_id": "9",
        "trace_category": "browser_core.debug",
        "native_name": "BrowserCore.DynamicCodeMaterialized",
        "event_category": "execution",
        "event_name": "dynamic.code.materialized",
        "component": "v8.compiler",
        "dynamic_kind": "eval",
        "cache_status": "compiled",
        "generated_script_id": "8",
        "caller_script_id": "7",
        "source_length": "31",
    }
    row.update(overrides)
    return row


def message_dispatch_row(**overrides: str) -> dict[str, str]:
    row = {
        "ts_monotonic_ns": "190",
        "duration_ns": "0",
        "track_id": "9",
        "trace_category": "browser_core.debug",
        "native_name": "BrowserCore.MessageDispatch",
        "event_category": "message",
        "event_name": "MessagePort.message.dispatch",
        "component": "blink.messaging",
        "context_id": "frame-token",
        "context_kind": "frame",
        "native_id": "message-dispatch:frame-token:1",
        "dispatch_kind": "message",
    }
    row.update(overrides)
    return row


def script_run_row(**overrides: str) -> dict[str, str]:
    row = {
        "ts_monotonic_ns": "100",
        "duration_ns": "0",
        "track_id": "9",
        "trace_category": "browser_core.debug",
        "native_name": "BrowserCore.ScriptRun",
        "event_category": "execution",
        "event_name": "script.run",
        "component": "blink.v8",
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": "7",
        "native_id": "script:frame-token:7",
    }
    row.update(overrides)
    return row


def script_source_identity_row(**overrides: str) -> dict[str, str]:
    row = {
        "ts_monotonic_ns": "90",
        "duration_ns": "0",
        "track_id": "9",
        "trace_category": "browser_core.debug",
        "native_name": "BrowserCore.ScriptSourceIdentity",
        "event_category": "execution",
        "event_name": "script.source.identity",
        "component": "v8.compiler",
        "script_id": "7",
        "source_length": "31",
        "compiler_input_hash_status": "observed",
        "compiler_input_utf16le_sha256": "a" * 64,
    }
    row.update(overrides)
    return row


def test_perfetto_script_source_identity_links_to_run_without_claiming_context() -> None:
    events = parse_export_csv(
        csv_rows_fixture([script_source_identity_row(), script_run_row()]),
        "fixture-run", REVISION,
    )
    assert events[0]["event"] == {"category": "execution", "name": "script.source.identity"}
    assert "execution" not in events[0]
    assert "causal_parent_seq" not in events[0]
    assert events[0]["detail"]["script_id"] == 7
    assert events[0]["detail"]["compiler_input_utf16le_sha256"] == "a" * 64
    assert events[1]["execution"]["script_id"] == "v8:42:frame-token:7"


def test_perfetto_rejects_script_source_identity_with_invented_context() -> None:
    with pytest.raises(ContractError, match="script source identity event"):
        parse_export_csv(
            csv_rows_fixture([script_source_identity_row(context_id="frame-token")]),
            "fixture-run", REVISION,
        )


def script_source_context_row(**overrides: str) -> dict[str, str]:
    row = script_source_identity_row(
        native_name="BrowserCore.ScriptSourceContext",
        event_name="script.source.context",
        component="blink.v8",
        context_id="frame-token",
        context_kind="frame",
    )
    row.update(overrides)
    return row


def test_perfetto_script_source_context_carries_exact_compile_realm() -> None:
    events = parse_export_csv(
        csv_rows_fixture([script_source_context_row(), script_run_row()]),
        "fixture-run", REVISION,
    )
    source = events[0]
    assert source["event"] == {"category": "execution", "name": "script.source.context"}
    assert source["execution"] == {
        "context_id": "frame-token", "frame_id": "frame-token",
        "script_id": "v8:42:frame-token:7",
    }
    assert source["detail"]["compiler_input_utf16le_sha256"] == "a" * 64


def test_perfetto_script_source_and_run_carry_v8_realm_pair() -> None:
    token = "A" * 32
    events = parse_export_csv(csv_rows_fixture([
        script_source_context_row(realm_v8_context_id=token, realm_world_id="0"),
        script_run_row(realm_v8_context_id=token, realm_world_id="0"),
    ]), "fixture-run", REVISION)
    assert [(event["detail"]["v8_context_id"], event["detail"]["realm_id"])
            for event in events] == [(token, 0), (token, 0)]
    with pytest.raises(ContractError, match="realm metadata is incomplete"):
        parse_export_csv(csv_rows_fixture([
            script_source_context_row(realm_v8_context_id=token),
        ]), "fixture-run", REVISION)
    with pytest.raises(ContractError, match="realm token is invalid"):
        parse_export_csv(csv_rows_fixture([
            script_run_row(realm_v8_context_id="bad", realm_world_id="0"),
        ]), "fixture-run", REVISION)
    with pytest.raises(ContractError, match="unrelated native event"):
        parse_export_csv(csv_rows_fixture([
            script_source_identity_row(realm_v8_context_id=token,
                                       realm_world_id="0"),
        ]), "fixture-run", REVISION)


def test_perfetto_rejects_script_source_context_without_realm() -> None:
    with pytest.raises(ContractError, match="script source context event"):
        parse_export_csv(
            csv_rows_fixture([script_source_context_row(context_id="[NULL]")]),
            "fixture-run", REVISION,
        )


def test_perfetto_normalizes_host_callback_with_script_parent() -> None:
    events = parse_export_csv(
        csv_rows_fixture([script_run_row(), host_callback_row()]),
        "fixture-run",
        REVISION,
    )

    callback = events[1]
    assert callback["event"] == {
        "category": "execution",
        "name": "host.callback.execution",
    }
    assert callback["causal_parent_seq"] == 0
    assert callback["execution"] == {
        "context_id": "frame-token",
        "frame_id": "frame-token",
        "script_id": "v8:42:frame-token:7",
    }
    assert callback["detail"] == {
        "native_name": "BrowserCore.HostCallbackExecution",
        "thread_id": 43,
        "completion": "complete",
        "duration_ns": 50,
        "callback_interface": "EventListener",
        "callback_operation": "handleEvent",
        "callback_kind": "function",
    }


def test_perfetto_links_dynamic_materialization_and_generated_code() -> None:
    generated_run = script_run_row(
        ts_monotonic_ns="130",
        script_id="8",
        native_id="script:frame-token:8",
    )
    binding = {
        "ts_monotonic_ns": "140",
        "duration_ns": "1",
        "track_id": "9",
        "trace_category": "blink.bindings",
        "native_name": "Navigator.userAgent.get",
        "native_schema": NULL_VALUE,
        "script_id": "8",
    }
    events = parse_export_csv(
        csv_rows_fixture(
            [script_run_row(), dynamic_code_row(), generated_run, binding]
        ),
        "fixture-run",
        REVISION,
    )

    dynamic = events[1]
    assert dynamic["event"] == {
        "category": "execution",
        "name": "dynamic.code.materialized",
    }
    assert dynamic["causal_parent_seq"] == 0
    assert dynamic["execution"] == {
        "context_id": "frame-token",
        "frame_id": "frame-token",
        "script_id": "v8:42:frame-token:7",
    }
    assert dynamic["detail"] == {
        "native_name": "BrowserCore.DynamicCodeMaterialized",
        "thread_id": 43,
        "dynamic_kind": "eval",
        "cache_status": "compiled",
        "generated_script_id": 8,
        "caller_script_id": 7,
        "caller_status": "observed",
        "source_length": 31,
        "source_length_unit": "utf16-code-units",
    }
    assert events[2]["dynamic_code_parent_seq"] == 1
    assert events[3]["dynamic_code_parent_seq"] == 1


def test_perfetto_retains_dynamic_code_with_missing_caller_parent() -> None:
    event = parse_export_csv(
        csv_rows_fixture([dynamic_code_row(caller_script_id="99")]),
        "fixture-run",
        REVISION,
    )[0]

    assert event["detail"]["caller_status"] == "observed"
    assert event["detail"]["caller_parent_status"] == (
        "script_parent_not_in_trace"
    )
    assert "execution" not in event
    assert "causal_parent_seq" not in event


def test_perfetto_retains_optional_compiler_input_digest() -> None:
    digest = "a" * 64
    event = parse_export_csv(
        csv_rows_fixture([dynamic_code_row(
            compiler_input_hash_status="observed",
            compiler_input_utf16le_sha256=digest,
        )]),
        "fixture-run",
        REVISION,
    )[0]
    assert event["detail"]["compiler_input_hash_status"] == "observed"
    assert event["detail"]["compiler_input_utf16le_sha256"] == digest


def test_perfetto_accepts_exact_legacy_export_columns() -> None:
    newer = csv_rows_fixture([dynamic_code_row()])
    source = io.StringIO(newer)
    reader = csv.DictReader(source)
    old_columns = tuple(column for column in EXPORT_COLUMNS if column not in {
        "compiler_input_hash_status", "compiler_input_utf16le_sha256",
        "realm_v8_context_id", "realm_world_id",
    })
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=old_columns, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for row in reader:
        writer.writerow({key: row[key] for key in old_columns})
    event = parse_export_csv(output.getvalue(), "fixture-run", REVISION)[0]
    assert "compiler_input_hash_status" not in event["detail"]


def test_perfetto_accepts_exact_prior_export_columns() -> None:
    newer = csv_rows_fixture([script_source_context_row()])
    reader = csv.DictReader(io.StringIO(newer))
    prior_columns = tuple(column for column in EXPORT_COLUMNS if column not in {
        "realm_v8_context_id", "realm_world_id",
    })
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=prior_columns, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for row in reader:
        writer.writerow({key: row[key] for key in prior_columns})
    event = parse_export_csv(output.getvalue(), "fixture-run", REVISION)[0]
    assert event["event"]["name"] == "script.source.context"
    assert "v8_context_id" not in event["detail"]


def test_perfetto_rejects_compiler_input_digest_on_unrelated_event() -> None:
    with pytest.raises(ContractError, match="dynamic code metadata"):
        parse_export_csv(
            csv_rows_fixture([script_run_row(
                compiler_input_hash_status="observed",
                compiler_input_utf16le_sha256="a" * 64,
            )]),
            "fixture-run",
            REVISION,
        )


@pytest.mark.parametrize(
    ("status", "digest", "length"),
    [
        (NULL_VALUE, "a" * 64, "31"),
        ("observed", NULL_VALUE, "31"),
        ("observed", "A" * 64, "31"),
        ("over-limit", "a" * 64, "262145"),
        ("over-limit", NULL_VALUE, "31"),
        ("observed", "a" * 64, "262145"),
    ],
)
def test_perfetto_rejects_inconsistent_compiler_input_digest(
    status: str, digest: str, length: str,
) -> None:
    with pytest.raises(ContractError, match="compiler input hash"):
        parse_export_csv(
            csv_rows_fixture([dynamic_code_row(
                compiler_input_hash_status=status,
                compiler_input_utf16le_sha256=digest,
                source_length=length,
            )]),
            "fixture-run",
            REVISION,
        )


def test_perfetto_links_nested_dynamic_code_without_generated_script_run() -> None:
    nested = dynamic_code_row(
        ts_monotonic_ns="130",
        dynamic_kind="function-constructor",
        generated_script_id="9",
        caller_script_id="8",
        source_length="47",
    )
    events = parse_export_csv(
        csv_rows_fixture([script_run_row(), dynamic_code_row(), nested]),
        "fixture-run",
        REVISION,
    )

    assert events[2]["dynamic_code_parent_seq"] == 1
    assert events[2]["detail"]["caller_parent_status"] == (
        "script_parent_not_in_trace"
    )
    assert "execution" not in events[2]


def test_perfetto_retains_dynamic_code_with_unavailable_caller() -> None:
    event = parse_export_csv(
        csv_rows_fixture([dynamic_code_row(caller_script_id="-1")]),
        "fixture-run",
        REVISION,
    )[0]

    assert event["detail"]["caller_status"] == "unavailable"
    assert "caller_parent_status" not in event["detail"]
    assert "execution" not in event
    assert "causal_parent_seq" not in event


def test_perfetto_retains_ambiguous_dynamic_code_caller_unresolved() -> None:
    other_context = script_run_row(
        ts_monotonic_ns="110",
        context_id="frame-other",
        native_id="script:frame-other:7",
    )

    events = parse_export_csv(
        csv_rows_fixture([script_run_row(), other_context, dynamic_code_row()]),
        "fixture-run",
        REVISION,
    )
    dynamic = events[-1]
    assert dynamic["detail"]["caller_parent_status"] == "caller_context_ambiguous"
    assert "execution" not in dynamic and "causal_parent_seq" not in dynamic
    assert [event["seq"] for event in events] == [0, 1, 2]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("event_name", "dynamic.code.executed", "event identity"),
        ("component", "blink.v8", "dynamic code"),
        ("duration_ns", "1", "dynamic code"),
        ("context_id", "frame-token", "dynamic code"),
        ("script_id", "7", "dynamic code"),
        ("native_id", "dynamic:1", "dynamic code"),
        ("dynamic_kind", "module", "dynamic code metadata"),
        ("cache_status", "hit", "dynamic code metadata"),
        ("generated_script_id", "-1", "generated script id"),
        ("caller_script_id", "-2", "caller script id"),
        ("source_length", "-1", "source length"),
    ],
)
def test_perfetto_rejects_forged_dynamic_code_materialization(
    field: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        parse_export_csv(
            csv_rows_fixture([dynamic_code_row(**{field: value})]),
            "fixture-run",
            REVISION,
        )


def test_perfetto_rejects_dynamic_code_fields_on_unrelated_event() -> None:
    with pytest.raises(ContractError, match="unrelated native event"):
        parse_export_csv(
            csv_fixture(dynamic_kind="eval"),
            "fixture-run",
            REVISION,
        )


def test_perfetto_normalizes_exact_promise_microtask_scope() -> None:
    event = parse_export_csv(
        csv_rows_fixture([promise_microtask_row()]),
        "fixture-run",
        REVISION,
    )[0]

    assert event == {
        "schema": "browser-core.trace-event/1",
        "run_id": "fixture-run",
        "seq": 0,
        "ts_monotonic_ns": 180,
        "process": {"pid": 42, "type": "renderer"},
        "execution": {
            "context_id": "frame-token",
            "frame_id": "frame-token",
        },
        "event": {
            "category": "execution",
            "name": "promise.microtask.execution",
        },
        "provenance": {
            "source": "native",
            "component": "blink.scheduler.promise",
            "chromium_revision": REVISION,
            "trace_category": "browser_core.debug",
        },
        "detail": {
            "native_name": "BrowserCore.PromiseMicrotaskExecution",
            "thread_id": 43,
            "completion": "complete",
            "duration_ns": 100,
            "boundary": "v8-isolate-promise-hook-before-after",
            "job_kind": "unclassified",
        },
    }


def test_perfetto_retains_open_promise_microtask_scope() -> None:
    event = parse_export_csv(
        csv_rows_fixture([promise_microtask_row(duration_ns="-1")]),
        "fixture-run",
        REVISION,
    )[0]

    assert event["detail"]["completion"] == "open"
    assert "duration_ns" not in event["detail"]


def test_perfetto_links_binding_inside_promise_microtask() -> None:
    binding = {
        "ts_monotonic_ns": "210",
        "duration_ns": "5",
        "track_id": "9",
        "trace_category": "blink.bindings",
        "native_name": "Navigator.userAgent.get",
        "native_schema": NULL_VALUE,
        "script_id": "7",
    }
    events = parse_export_csv(
        csv_rows_fixture([promise_microtask_row(), binding]),
        "fixture-run",
        REVISION,
    )

    child = events[1]
    assert child["promise_parent_seq"] == 0
    assert child["execution"] == {
        "context_id": "frame-token",
        "frame_id": "frame-token",
        "script_id": "v8:42:frame-token:7",
    }
    assert child["detail"]["script_attribution"] == "promise-contained"
    assert child["detail"]["context_attribution"] == "promise-microtask"


def test_perfetto_nested_callback_keeps_promise_and_callback_containment() -> None:
    binding = {
        "ts_monotonic_ns": "215",
        "duration_ns": "5",
        "track_id": "9",
        "trace_category": "blink.bindings",
        "native_name": "Navigator.platform.get",
        "native_schema": NULL_VALUE,
        "script_id": "7",
    }
    events = parse_export_csv(
        csv_rows_fixture(
            [script_run_row(), promise_microtask_row(), host_callback_row(), binding]
        ),
        "fixture-run",
        REVISION,
    )

    callback = events[2]
    child = events[3]
    assert callback["promise_parent_seq"] == 1
    assert child["promise_parent_seq"] == 1
    assert child["callback_parent_seq"] == 2
    assert child["detail"]["context_attribution"] == "host-callback"


def test_perfetto_promise_containment_is_track_and_duration_bounded() -> None:
    outside_track = {
        "ts_monotonic_ns": "210",
        "duration_ns": "0",
        "track_id": "10",
        "trace_category": "browser_core.debug",
        "native_name": "BrowserCore.CanvasReadback",
        "api": "HTMLCanvasElement.toDataURL",
        "width": "1",
        "height": "1",
        "origin_clean": "true",
    }
    after_scope = {**outside_track, "ts_monotonic_ns": "280", "track_id": "9"}
    events = parse_export_csv(
        csv_rows_fixture([promise_microtask_row(), outside_track, after_scope]),
        "fixture-run",
        REVISION,
    )

    assert "promise_parent_seq" not in events[1]
    assert "promise_parent_seq" not in events[2]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("event_name", "promise.reaction", "event identity"),
        ("component", "v8.promise", "promise microtask"),
        ("track_id", NULL_VALUE, "promise microtask"),
        ("script_id", "7", "promise microtask"),
        ("native_id", "promise:1", "promise microtask"),
        ("duration_ns", NULL_VALUE, "duration is missing"),
        ("callback_kind", "function", "unrelated native event"),
    ],
)
def test_perfetto_rejects_forged_promise_microtask_scope(
    field: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        parse_export_csv(
            csv_rows_fixture([promise_microtask_row(**{field: value})]),
            "fixture-run",
            REVISION,
        )


def test_perfetto_links_exact_message_dispatch_to_event_listener_callback() -> None:
    events = parse_export_csv(
        csv_rows_fixture(
            [
                script_run_row(),
                message_dispatch_row(),
                host_callback_row(
                    message_dispatch_id="message-dispatch:frame-token:1"
                ),
            ]
        ),
        "fixture-run",
        REVISION,
    )

    callback = events[2]
    assert callback["causal_parent_seq"] == 0
    assert callback["message_dispatch_parent_seq"] == 1
    assert "message_dispatch_parent_status" not in callback["detail"]


def test_perfetto_retains_message_callback_when_dispatch_is_not_in_trace() -> None:
    callback = parse_export_csv(
        csv_rows_fixture(
            [
                host_callback_row(
                    message_dispatch_id="message-dispatch:frame-token:1",
                )
            ]
        ),
        "fixture-run",
        REVISION,
    )[0]

    assert "message_dispatch_parent_seq" not in callback
    assert callback["detail"]["message_dispatch_parent_status"] == (
        "message_dispatch_parent_not_in_trace"
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"message_dispatch_id": "message-dispatch:other-frame:1"},
            "host callback",
        ),
        (
            {
                "message_dispatch_id": "message-dispatch:frame-token:1",
                "callback_interface": "MutationCallback",
            },
            "host callback",
        ),
    ],
)
def test_perfetto_rejects_forged_message_dispatch_callback_metadata(
    overrides: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        parse_export_csv(
            csv_rows_fixture([host_callback_row(**overrides)]),
            "fixture-run",
            REVISION,
        )


def test_perfetto_rejects_message_callback_metadata_on_unrelated_event() -> None:
    with pytest.raises(ContractError, match="on an unrelated native event"):
        parse_export_csv(
            csv_fixture(message_dispatch_id="message-dispatch:frame-token:1"),
            "fixture-run",
            REVISION,
        )


def test_perfetto_retains_host_callback_when_script_run_is_not_in_trace() -> None:
    callback = parse_export_csv(
        csv_rows_fixture([host_callback_row()]),
        "fixture-run",
        REVISION,
    )[0]

    assert "causal_parent_seq" not in callback
    assert callback["detail"]["causal_parent_status"] == (
        "script_parent_not_in_trace"
    )


def test_perfetto_links_nested_binding_to_host_callback_without_replacing_cause() -> None:
    binding = {
        "ts_monotonic_ns": "210",
        "duration_ns": "5",
        "track_id": "9",
        "trace_category": "blink.bindings",
        "native_name": "Navigator.userAgent.get",
        "native_schema": NULL_VALUE,
        "script_id": "7",
        "binding_value_count": "1",
        "binding_value_slice_id": "99",
        "binding_value_context_id": "frame-token",
        "binding_value_context_kind": "window",
    }
    events = parse_export_csv(
        csv_rows_fixture([script_run_row(), host_callback_row(), binding]),
        "fixture-run",
        REVISION,
    )

    nested = events[2]
    assert nested["callback_parent_seq"] == 1
    assert nested["execution"]["context_id"] == "frame-token"
    assert "causal_parent_seq" not in nested


def test_perfetto_uses_host_callback_context_when_binding_owner_is_not_recorded() -> None:
    binding = {
        "ts_monotonic_ns": "210",
        "duration_ns": "5",
        "track_id": "9",
        "trace_category": "blink.bindings",
        "native_name": "Navigator.platform.get",
        "native_schema": NULL_VALUE,
        "script_id": "7",
    }
    events = parse_export_csv(
        csv_rows_fixture([script_run_row(), host_callback_row(), binding]),
        "fixture-run",
        REVISION,
    )

    nested = events[2]
    assert nested["callback_parent_seq"] == 1
    assert nested["execution"] == {
        "context_id": "frame-token",
        "frame_id": "frame-token",
        "script_id": "v8:42:frame-token:7",
    }
    assert nested["detail"]["context_attribution"] == "host-callback"
    assert nested["detail"]["script_attribution"] == "callback-contained"


def test_perfetto_callback_containment_is_track_and_duration_bounded() -> None:
    outside_track = {
        "ts_monotonic_ns": "210",
        "duration_ns": "0",
        "track_id": "10",
        "trace_category": "browser_core.debug",
        "native_name": "BrowserCore.CanvasReadback",
        "api": "HTMLCanvasElement.toDataURL",
        "width": "1",
        "height": "1",
        "origin_clean": "true",
    }
    after_scope = {**outside_track, "ts_monotonic_ns": "250", "track_id": "9"}
    events = parse_export_csv(
        csv_rows_fixture(
            [script_run_row(), host_callback_row(), outside_track, after_scope]
        ),
        "fixture-run",
        REVISION,
    )

    assert "callback_parent_seq" not in events[2]
    assert "callback_parent_seq" not in events[3]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("event_name", "callback", "event identity"),
        ("component", "blink.events", "host callback"),
        ("track_id", NULL_VALUE, "host callback"),
        ("native_id", "callback:1", "host callback"),
        ("callback_interface", "Event.Listener", "descriptor"),
        ("callback_operation", "", "missing|descriptor"),
        ("callback_kind", "method", "kind"),
        ("duration_ns", NULL_VALUE, "duration is missing"),
        ("data_bytes", "1", "host callback"),
    ],
)
def test_perfetto_rejects_forged_host_callback_scope(
    field: str,
    value: str,
    message: str,
) -> None:
    row = host_callback_row(**{field: value})

    with pytest.raises(ContractError, match=message):
        parse_export_csv(csv_rows_fixture([row]), "fixture-run", REVISION)


def test_perfetto_rejects_an_oversized_script_identifier() -> None:
    with pytest.raises(ContractError, match="script id exceeds"):
        parse_export_csv(
            csv_fixture(script_id=str(2_147_483_648)), "fixture-run", REVISION
        )


def test_perfetto_export_rejects_missing_native_parent() -> None:
    with pytest.raises(ContractError, match="causal parent"):
        parse_export_csv(
            csv_fixture(
                native_name="fixture.Fetch",
                event_category="api",
                event_name="fetch",
                component="blink.fetch",
                api=NULL_VALUE,
                width=NULL_VALUE,
                height=NULL_VALUE,
                origin_clean=NULL_VALUE,
                native_parent_id="missing",
            ),
            "fixture-run",
            REVISION,
        )


def test_perfetto_export_retains_event_when_module_script_parent_was_not_observed() -> (
    None
):
    events = parse_export_csv(
        csv_fixture(
            native_name="BrowserCore.CryptoDigest",
            event_category="crypto",
            event_name="SubtleCrypto.digest",
            component="blink.webcrypto",
            api=NULL_VALUE,
            width=NULL_VALUE,
            height=NULL_VALUE,
            origin_clean=NULL_VALUE,
            context_id="worker-token",
            context_kind="worker",
            script_id="3",
            native_id="crypto:worker-token:17",
            native_parent_id="script:worker-token:3",
            algorithm="SHA-256",
            data_bytes="32",
        ),
        "fixture-run",
        REVISION,
    )

    assert len(events) == 1
    assert events[0]["event"] == {"category": "crypto", "name": "SubtleCrypto.digest"}
    assert "causal_parent_seq" not in events[0]
    assert events[0]["detail"]["causal_parent_status"] == "script_parent_not_in_trace"


@pytest.mark.parametrize(
    "native_id",
    ["crypto:worker-token:017", "crypto:worker-token:١٧"],
)
def test_perfetto_rejects_noncanonical_context_operation_id(
    native_id: str,
) -> None:
    with pytest.raises(ContractError, match="crypto digest"):
        parse_export_csv(
            csv_fixture(
                native_name="BrowserCore.CryptoDigest",
                event_category="crypto",
                event_name="SubtleCrypto.digest",
                component="blink.webcrypto",
                api=NULL_VALUE,
                width=NULL_VALUE,
                height=NULL_VALUE,
                origin_clean=NULL_VALUE,
                context_id="worker-token",
                context_kind="worker",
                script_id="3",
                native_id=native_id,
                native_parent_id="script:worker-token:3",
                algorithm="SHA-256",
                data_bytes="32",
            ),
            "fixture-run",
            REVISION,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.CryptoDigestResult"),
        ("event_category", "api"),
        ("event_name", "SubtleCrypto.encrypt"),
        ("component", "blink.crypto"),
        ("process_name", "Browser"),
        ("context_kind", "forged"),
        ("native_id", "crypto:other-worker:17"),
        ("native_parent_id", "script:other-worker:3"),
        ("algorithm", "SHA-999"),
        ("data_bytes", str(2**40 + 1)),
        ("duration_ns", "1"),
        ("api", "SubtleCrypto.digest"),
        ("request_id", "request-1"),
        ("method", "POST"),
        ("url_class", "same-origin"),
        ("target_scope", "loopback"),
        ("body_bytes", "32"),
        ("code_bytes", "1"),
    ],
)
def test_perfetto_rejects_forged_crypto_digest_event(
    field: str,
    value: str,
) -> None:
    overrides = {
        "native_name": "BrowserCore.CryptoDigest",
        "event_category": "crypto",
        "event_name": "SubtleCrypto.digest",
        "component": "blink.webcrypto",
        "api": NULL_VALUE,
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
        "context_id": "worker-token",
        "context_kind": "worker",
        "script_id": "3",
        "native_id": "crypto:worker-token:17",
        "native_parent_id": "script:worker-token:3",
        "algorithm": "SHA-256",
        "data_bytes": "32",
    }
    overrides[field] = value
    if field == "process_name":
        overrides["thread_name"] = "CrBrowserMain"

    with pytest.raises(ContractError, match="crypto digest"):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.WasmCompile"),
        ("event_category", "api"),
        ("event_name", "WebAssembly.instantiate"),
        ("component", "blink.wasm"),
        ("process_name", "Browser"),
        ("context_kind", "forged"),
        ("native_id", "wasm:other-frame:1"),
        ("native_id", "wasm:frame-token:0"),
        ("native_id", "wasm:frame-token:2147483648"),
        ("native_parent_id", "script:frame-token:7"),
        ("success", NULL_VALUE),
        ("code_bytes", str(1024**3 + 1)),
        ("duration_ns", "1"),
        ("api", "WebAssembly.compile"),
        ("algorithm", "SHA-256"),
        ("data_bytes", "1"),
        ("request_id", "request-1"),
        ("method", "POST"),
        ("url_class", "same-origin"),
        ("target_scope", "loopback"),
        ("body_bytes", "8"),
        ("reader_mode", "default"),
        ("consumer_mode", "array-buffer"),
        ("dispatch_kind", "message"),
        ("result_kind", "chunk"),
        ("chunk_value_type", "bytes"),
        ("chunk_bytes", "8"),
        ("width", "1"),
        ("height", "1"),
        ("origin_clean", "true"),
        ("script_id", "7"),
    ],
)
def test_perfetto_rejects_forged_wasm_compile_event(
    field: str,
    value: str,
) -> None:
    overrides = {
        "native_name": "BrowserCore.WasmCompiled",
        "event_category": "wasm",
        "event_name": "WebAssembly.compile.completed",
        "component": "v8.wasm",
        "api": NULL_VALUE,
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
        "context_id": "frame-token",
        "context_kind": "frame",
        "native_id": "wasm:frame-token:1",
        "success": "true",
        "async": "true",
        "cached": "false",
        "code_bytes": "8",
    }
    overrides[field] = value
    if field == "process_name":
        overrides["thread_name"] = "CrBrowserMain"

    with pytest.raises(ContractError, match="WASM compile"):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


def test_perfetto_csv_normalizes_native_stream_read_result() -> None:
    base = {field: NULL_VALUE for field in EXPORT_COLUMNS}
    rows = [
        {
            **base,
            "ts_monotonic_ns": "200",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.StreamReadRequest",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "stream.read.request",
            "component": "blink.streams",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "stream-read:frame-token:1",
            "native_parent_id": "script:frame-token:7",
            "reader_mode": "default",
        },
        {
            **base,
            "ts_monotonic_ns": "201",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.StreamReadResult",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "stream.read.result",
            "component": "blink.streams",
            "context_id": "frame-token",
            "context_kind": "frame",
            "native_id": "stream-read:frame-token:1:result",
            "native_parent_id": "stream-read:frame-token:1",
            "reader_mode": "default",
            "result_kind": "chunk",
            "chunk_value_type": "bytes",
            "chunk_bytes": "3",
        },
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)

    events = parse_export_csv(output.getvalue(), "fixture-run", REVISION)

    assert events[1]["causal_parent_seq"] == 0
    assert events[1]["event"] == {"category": "stream", "name": "stream.read.result"}
    assert events[1]["detail"]["reader_mode"] == "default"
    assert all(
        event["provenance"]["trace_category"] == "browser_core.stream"
        for event in events
    )
    assert events[1]["detail"]["result_kind"] == "chunk"
    assert events[1]["value"] == {"type": "bytes", "length": 3, "redaction": "metadata"}

    for row in rows:
        row["trace_category"] = "browser_core.debug"
    legacy_output = io.StringIO()
    legacy_writer = csv.DictWriter(
        legacy_output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL
    )
    legacy_writer.writeheader()
    legacy_writer.writerows(rows)
    with pytest.raises(ContractError, match="trace category"):
        parse_export_csv(legacy_output.getvalue(), "legacy-fixture-run", REVISION)


@pytest.mark.parametrize(
    ("index", "field", "value"),
    [
        (0, "native_id", "forged-request"),
        (0, "native_parent_id", "script:frame-token:8"),
        (0, "request_id", "ignored-request"),
        (1, "native_id", "stream-read:frame-token:1:other"),
        (1, "script_id", "7"),
        (1, "request_id", "ignored-result"),
        (1, "chunk_bytes", str(32 * 1024 * 1024 * 1024)),
        (1, "tid", "44"),
    ],
)
def test_perfetto_rejects_forged_native_stream_read_pair(
    index: int,
    field: str,
    value: str,
) -> None:
    base = {column: NULL_VALUE for column in EXPORT_COLUMNS}
    rows = [
        {
            **base,
            "ts_monotonic_ns": "200",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.StreamReadRequest",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "stream.read.request",
            "component": "blink.streams",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "stream-read:frame-token:1",
            "native_parent_id": "script:frame-token:7",
            "reader_mode": "default",
        },
        {
            **base,
            "ts_monotonic_ns": "201",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.StreamReadResult",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "stream.read.result",
            "component": "blink.streams",
            "context_id": "frame-token",
            "context_kind": "frame",
            "native_id": "stream-read:frame-token:1:result",
            "native_parent_id": "stream-read:frame-token:1",
            "reader_mode": "default",
            "result_kind": "chunk",
            "chunk_value_type": "bytes",
            "chunk_bytes": "3",
        },
    ]
    rows[index][field] = value

    with pytest.raises(ContractError, match="stream read|stream result"):
        parse_export_csv(csv_rows_fixture(rows), "fixture-run", REVISION)


def test_perfetto_csv_normalizes_high_level_body_consumer_without_values() -> None:
    assert "consumer_mode" in EXPORT_COLUMNS
    event = parse_export_csv(
        csv_fixture(
            trace_category="browser_core.stream",
            native_name="BrowserCore.BodyConsume",
            event_category="stream",
            event_name="body.consume",
            component="blink.fetch-body",
            api=NULL_VALUE,
            context_id="frame-token",
            context_kind="frame",
            script_id="7",
            native_id="body-consume:frame-token:1",
            native_parent_id="script:frame-token:7",
            consumer_mode="text",
            width=NULL_VALUE,
            height=NULL_VALUE,
            origin_clean=NULL_VALUE,
        ),
        "fixture-run",
        REVISION,
    )[0]

    assert event["event"] == {"category": "stream", "name": "body.consume"}
    assert event["detail"]["consumer_mode"] == "text"
    assert event["execution"]["script_id"] == "v8:42:frame-token:7"
    assert "value" not in event


def test_perfetto_csv_normalizes_message_dispatch_without_payload() -> None:
    assert "dispatch_kind" in EXPORT_COLUMNS
    event = parse_export_csv(
        csv_fixture(
            native_name="BrowserCore.MessageDispatch",
            event_category="message",
            event_name="MessagePort.message.dispatch",
            component="blink.messaging",
            api=NULL_VALUE,
            context_id="frame-token",
            context_kind="frame",
            script_id=NULL_VALUE,
            native_id="message-dispatch:frame-token:1",
            native_parent_id=NULL_VALUE,
            dispatch_kind="message",
            width=NULL_VALUE,
            height=NULL_VALUE,
            origin_clean=NULL_VALUE,
        ),
        "fixture-run",
        REVISION,
    )[0]

    assert event["event"] == {
        "category": "message",
        "name": "MessagePort.message.dispatch",
    }
    assert event["detail"]["causal_parent_status"] == "message_parent_unavailable"
    assert "value" not in event


@pytest.mark.parametrize("dispatch_kind", ["", "MESSAGE", "listener-complete"])
def test_perfetto_csv_rejects_unknown_message_dispatch_kind(
    dispatch_kind: str,
) -> None:
    with pytest.raises(ContractError, match="message dispatch"):
        parse_export_csv(
            csv_fixture(
                native_name="BrowserCore.MessageDispatch",
                event_category="message",
                event_name="MessagePort.message.dispatch",
                component="blink.messaging",
                api=NULL_VALUE,
                context_id="frame-token",
                context_kind="frame",
                script_id=NULL_VALUE,
                native_id="message-dispatch:frame-token:1",
                native_parent_id=NULL_VALUE,
                dispatch_kind=dispatch_kind or NULL_VALUE,
                width=NULL_VALUE,
                height=NULL_VALUE,
                origin_clean=NULL_VALUE,
            ),
            "fixture-run",
            REVISION,
        )


def test_perfetto_message_dispatch_joins_cross_process_post() -> None:
    events = parse_export_csv(
        csv_rows_fixture(
            [
                {
                    "ts_monotonic_ns": "100",
                    "native_name": "BrowserCore.MessagePost",
                    "event_category": "message",
                    "event_name": "MessagePort.postMessage",
                    "component": "blink.messaging",
                    "context_id": "worker-sender",
                    "context_kind": "worker",
                    "native_id": "message:7",
                },
                {
                    "ts_monotonic_ns": "101",
                    "native_name": "BrowserCore.MessageDispatch",
                    "event_category": "message",
                    "event_name": "MessagePort.message.dispatch",
                    "component": "blink.messaging",
                    "pid": "84",
                    "tid": "85",
                    "context_id": "frame-receiver",
                    "context_kind": "frame",
                    "native_id": "message-dispatch:frame-receiver:9",
                    "native_parent_id": "message:7",
                    "dispatch_kind": "message",
                },
            ]
        ),
        "fixture-run",
        REVISION,
    )

    assert events[1]["causal_parent_seq"] == 0
    assert events[0]["process"]["pid"] == 42
    assert events[1]["process"]["pid"] == 84
    assert "causal_parent_status" not in events[1]["detail"]


@pytest.mark.parametrize("message_id", ["message:007", "message:٧"])
def test_perfetto_rejects_noncanonical_transport_message_id(
    message_id: str,
) -> None:
    with pytest.raises(ContractError, match="message post"):
        parse_export_csv(
            csv_rows_fixture(
                [
                    {
                        "ts_monotonic_ns": "100",
                        "native_name": "BrowserCore.MessagePost",
                        "event_category": "message",
                        "event_name": "MessagePort.postMessage",
                        "component": "blink.messaging",
                        "context_id": "worker-sender",
                        "context_kind": "worker",
                        "native_id": message_id,
                    },
                    {
                        "ts_monotonic_ns": "101",
                        "native_name": "BrowserCore.MessageDispatch",
                        "event_category": "message",
                        "event_name": "MessagePort.message.dispatch",
                        "component": "blink.messaging",
                        "pid": "84",
                        "tid": "85",
                        "context_id": "frame-receiver",
                        "context_kind": "frame",
                        "native_id": "message-dispatch:frame-receiver:9",
                        "native_parent_id": message_id,
                        "dispatch_kind": "message",
                    },
                ]
            ),
            "fixture-run",
            REVISION,
        )


def test_perfetto_message_post_accepts_mojo_trace_id_and_script_parent() -> None:
    events = parse_export_csv(
        csv_rows_fixture(
            [
                {
                    "ts_monotonic_ns": "100",
                    "duration_ns": "0",
                    "native_name": "BrowserCore.ScriptRun",
                    "event_category": "execution",
                    "event_name": "script.run",
                    "component": "blink.v8",
                    "context_id": "frame-sender",
                    "context_kind": "frame",
                    "script_id": "7",
                    "native_id": "script:frame-sender:7",
                },
                {
                    "ts_monotonic_ns": "101",
                    "duration_ns": "0",
                    "native_name": "BrowserCore.MessagePost",
                    "event_category": "message",
                    "event_name": "MessagePort.postMessage",
                    "component": "blink.messaging",
                    "context_id": "frame-sender",
                    "context_kind": "frame",
                    "script_id": "7",
                    "native_id": "message:4294967297",
                    "native_parent_id": "script:frame-sender:7",
                },
            ]
        ),
        "fixture-run",
        REVISION,
    )

    assert events[1]["causal_parent_seq"] == 0
    assert "causal_parent_status" not in events[1]["detail"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.MessageDispatch"),
        ("component", "blink.messaging.listener"),
        ("process_name", "Browser"),
        ("context_kind", "forged"),
        ("native_id", "message:frame-token:2147483648"),
        ("native_id", "message:not-a-mojo-id"),
        ("native_parent_id", "script:other-frame:7"),
        ("duration_ns", "1"),
        ("api", "MessagePort.postMessage"),
        ("request_id", "request-1"),
        ("method", "POST"),
        ("data_bytes", "1"),
    ],
)
def test_perfetto_message_post_rejects_forged_metadata(
    field: str,
    value: str,
) -> None:
    overrides = {
        "native_name": "BrowserCore.MessagePost",
        "event_category": "message",
        "event_name": "MessagePort.postMessage",
        "component": "blink.messaging",
        "api": NULL_VALUE,
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": "7",
        "native_id": "message:4294967297",
        "native_parent_id": "script:frame-token:7",
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
    }
    overrides[field] = value
    if field == "process_name":
        overrides["thread_name"] = "BrowserMain"

    error_match = (
        "message dispatch event identity"
        if field == "native_name"
        else "message post"
    )
    with pytest.raises(ContractError, match=error_match):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


@pytest.mark.parametrize(
    ("script_id", "native_parent_id"),
    [("7", NULL_VALUE), (NULL_VALUE, "script:frame-token:7")],
)
def test_perfetto_message_post_rejects_partial_script_parent_metadata(
    script_id: str,
    native_parent_id: str,
) -> None:
    with pytest.raises(ContractError, match="message post parent"):
        parse_export_csv(
            csv_fixture(
                native_name="BrowserCore.MessagePost",
                event_category="message",
                event_name="MessagePort.postMessage",
                component="blink.messaging",
                api=NULL_VALUE,
                context_id="frame-token",
                context_kind="frame",
                script_id=script_id,
                native_id="message:4294967297",
                native_parent_id=native_parent_id,
                width=NULL_VALUE,
                height=NULL_VALUE,
                origin_clean=NULL_VALUE,
            ),
            "fixture-run",
            REVISION,
        )


def test_perfetto_message_dispatch_marks_parent_not_in_trace() -> None:
    event = parse_export_csv(
        csv_fixture(
            native_name="BrowserCore.MessageDispatch",
            event_category="message",
            event_name="MessagePort.message.dispatch",
            component="blink.messaging",
            api=NULL_VALUE,
            context_id="frame-token",
            context_kind="frame",
            script_id=NULL_VALUE,
            native_id="message-dispatch:frame-token:1",
            native_parent_id="message:8",
            dispatch_kind="messageerror",
            width=NULL_VALUE,
            height=NULL_VALUE,
            origin_clean=NULL_VALUE,
        ),
        "fixture-run",
        REVISION,
    )[0]

    assert event["detail"]["causal_parent_status"] == "message_parent_not_in_trace"
    assert "causal_parent_seq" not in event


def test_perfetto_message_dispatch_rejects_resolved_non_message_parent() -> None:
    csv_text = csv_rows_fixture(
        [
            {
                "ts_monotonic_ns": "100",
                "native_name": "fixture.NonMessage",
                "event_category": "api",
                "event_name": "fixture.non-message",
                "component": "fixture",
                "api": NULL_VALUE,
                "context_id": "frame-sender",
                "context_kind": "frame",
                "native_id": "message:forged:1",
            },
            {
                "ts_monotonic_ns": "101",
                "native_name": "BrowserCore.MessageDispatch",
                "event_category": "message",
                "event_name": "MessagePort.message.dispatch",
                "component": "blink.messaging",
                "context_id": "frame-receiver",
                "context_kind": "frame",
                "native_id": "message-dispatch:frame-receiver:2",
                "native_parent_id": "message:forged:1",
                "dispatch_kind": "message",
            },
        ]
    )

    with pytest.raises(ContractError, match="message dispatch"):
        parse_export_csv(csv_text, "fixture-run", REVISION)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("native_name", "BrowserCore.MessageDelivery"),
        ("component", "blink.messaging.listener"),
        ("process_name", "Browser"),
        ("context_kind", "forged"),
        ("native_id", "message-dispatch:other-frame:1"),
        ("native_id", "message-dispatch:frame-token:0"),
        ("native_id", "message-dispatch:frame-token:2147483648"),
        ("native_parent_id", "message:0"),
        ("native_parent_id", "message:18446744073709551616"),
        ("native_parent_id", "message:frame-token:1"),
        ("native_parent_id", "message:forged"),
        ("script_id", "7"),
        ("duration_ns", "1"),
        ("api", "MessagePort.message.dispatch"),
        ("request_id", "request-1"),
        ("method", "POST"),
        ("data_bytes", "1"),
    ],
)
def test_perfetto_message_dispatch_rejects_forged_metadata(
    field: str,
    value: str,
) -> None:
    overrides = {
        "native_name": "BrowserCore.MessageDispatch",
        "event_category": "message",
        "event_name": "MessagePort.message.dispatch",
        "component": "blink.messaging",
        "api": NULL_VALUE,
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": NULL_VALUE,
        "native_id": "message-dispatch:frame-token:1",
        "native_parent_id": NULL_VALUE,
        "dispatch_kind": "message",
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
    }
    overrides[field] = value
    if field == "process_name":
        overrides["thread_name"] = "BrowserMain"

    with pytest.raises(ContractError, match="message dispatch"):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


def test_perfetto_body_consumer_requires_matching_earlier_script_parent() -> None:
    base = {field: NULL_VALUE for field in EXPORT_COLUMNS}
    rows = [
        {
            **base,
            "ts_monotonic_ns": "100",
            "trace_category": "browser_core.debug",
            "native_name": "BrowserCore.ScriptRun",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "execution",
            "event_name": "script.run",
            "component": "blink.v8",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "script:frame-token:7",
        },
        {
            **base,
            "ts_monotonic_ns": "101",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.BodyConsume",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "body.consume",
            "component": "blink.fetch-body",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "body-consume:frame-token:1",
            "native_parent_id": "script:frame-token:7",
            "consumer_mode": "json",
        },
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)

    events = parse_export_csv(output.getvalue(), "fixture-run", REVISION)

    assert events[1]["causal_parent_seq"] == 0
    assert "causal_parent_status" not in events[1]["detail"]


@pytest.mark.parametrize(
    ("script_id", "native_parent_id"),
    [("7", NULL_VALUE), (NULL_VALUE, "script:frame-token:7")],
)
def test_perfetto_body_consumer_rejects_partial_script_parent_metadata(
    script_id: str,
    native_parent_id: str,
) -> None:
    with pytest.raises(ContractError, match="body consumer parent"):
        parse_export_csv(
            csv_fixture(
                trace_category="browser_core.stream",
                native_name="BrowserCore.BodyConsume",
                event_category="stream",
                event_name="body.consume",
                component="blink.fetch-body",
                api=NULL_VALUE,
                context_id="frame-token",
                context_kind="frame",
                script_id=script_id,
                native_id="body-consume:frame-token:1",
                native_parent_id=native_parent_id,
                consumer_mode="text",
                width=NULL_VALUE,
                height=NULL_VALUE,
                origin_clean=NULL_VALUE,
            ),
            "fixture-run",
            REVISION,
        )


@pytest.mark.parametrize("consumer_mode", ["", "TEXT", "private-mode"])
def test_perfetto_csv_rejects_unknown_high_level_body_consumer(
    consumer_mode: str,
) -> None:
    overrides = {
        "trace_category": "browser_core.stream",
        "native_name": "BrowserCore.BodyConsume",
        "event_category": "stream",
        "event_name": "body.consume",
        "component": "blink.fetch-body",
        "api": NULL_VALUE,
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": "7",
        "native_id": "body-consume:frame-token:1",
        "native_parent_id": "script:frame-token:7",
        "consumer_mode": consumer_mode or NULL_VALUE,
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
    }

    with pytest.raises(ContractError, match="body consumer"):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


@pytest.mark.parametrize(
    ("field", "value", "error_match"),
    [
        (
            "native_name",
            "BrowserCore.StreamReadRequest",
            "stream request event identity",
        ),
        ("component", "blink.streams", "body consumer event"),
        ("trace_category", "browser_core.debug", "trace category"),
        ("process_name", "Browser", "body consumer event"),
        ("context_kind", "forged", "body consumer event"),
        ("native_id", "body-consume:other-frame:1", "body consumer event"),
        ("native_id", "body-consume:frame-token:0", "body consumer event"),
        ("native_id", "body-consume:frame-token:2147483648", "body consumer event"),
        ("duration_ns", "1", "body consumer event"),
        ("api", "Response.text", "body consumer event"),
        ("request_id", "request-1", "body consumer event"),
        ("method", "GET", "body consumer event"),
        ("url_class", "same-origin", "body consumer event"),
        ("target_scope", "same-origin", "body consumer event"),
        ("body_bytes", "0", "body consumer event"),
        ("reader_mode", "default", "body consumer event"),
        ("result_kind", "chunk", "body consumer event"),
        ("chunk_value_type", "bytes", "body consumer event"),
        ("chunk_bytes", "1", "body consumer event"),
        ("native_id", NULL_VALUE, "body consumer event"),
        ("native_parent_id", "script:other-frame:7", "body consumer parent"),
    ],
)
def test_perfetto_rejects_forged_high_level_body_consumer_metadata(
    field: str,
    value: str,
    error_match: str,
) -> None:
    overrides = {
        "trace_category": "browser_core.stream",
        "native_name": "BrowserCore.BodyConsume",
        "event_category": "stream",
        "event_name": "body.consume",
        "component": "blink.fetch-body",
        "api": NULL_VALUE,
        "context_id": "frame-token",
        "context_kind": "frame",
        "script_id": "7",
        "native_id": "body-consume:frame-token:1",
        "native_parent_id": "script:frame-token:7",
        "consumer_mode": "text",
        "width": NULL_VALUE,
        "height": NULL_VALUE,
        "origin_clean": NULL_VALUE,
    }
    overrides[field] = value
    if field == "process_name":
        overrides["thread_name"] = "BrowserMain"

    with pytest.raises(ContractError, match=error_match):
        parse_export_csv(csv_fixture(**overrides), "fixture-run", REVISION)


def test_perfetto_rejects_non_script_event_forging_body_parent_id() -> None:
    base = {field: NULL_VALUE for field in EXPORT_COLUMNS}
    rows = [
        {
            **base,
            "ts_monotonic_ns": "100",
            "trace_category": "browser_core.debug",
            "native_name": "Navigator.userAgent.get",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "api",
            "event_name": "Navigator.userAgent",
            "component": "blink.navigator",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "script:frame-token:7",
        },
        {
            **base,
            "ts_monotonic_ns": "101",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.BodyConsume",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "body.consume",
            "component": "blink.fetch-body",
            "context_id": "frame-token",
            "context_kind": "frame",
            "script_id": "7",
            "native_id": "body-consume:frame-token:1",
            "native_parent_id": "script:frame-token:7",
            "consumer_mode": "text",
        },
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)

    with pytest.raises(ContractError, match="body consumer parent"):
        parse_export_csv(output.getvalue(), "fixture-run", REVISION)


@pytest.mark.parametrize(
    (
        "request_mode",
        "result_mode",
        "result_kind",
        "chunk_value_type",
        "chunk_bytes",
        "error_match",
    ),
    [
        ("default", "byob", "closed", "none", "0", "parent is inconsistent"),
        ("byob", "byob", "chunk", "other", "0", "metadata is inconsistent"),
        ("default", "default", "chunk", "none", "0", "metadata is inconsistent"),
        ("default", "default", "closed", "bytes", "0", "metadata is inconsistent"),
        ("default", "default", "error", "bytes", "1", "metadata is inconsistent"),
    ],
)
def test_perfetto_csv_rejects_impossible_stream_result_metadata(
    request_mode: str,
    result_mode: str,
    result_kind: str,
    chunk_value_type: str,
    chunk_bytes: str,
    error_match: str,
) -> None:
    base = {field: NULL_VALUE for field in EXPORT_COLUMNS}
    rows = [
        {
            **base,
            "ts_monotonic_ns": "200",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.StreamReadRequest",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "stream.read.request",
            "component": "blink.streams",
            "context_id": "frame-token",
            "context_kind": "frame",
                "native_id": "stream-read:frame-token:1",
            "reader_mode": request_mode,
        },
        {
            **base,
            "ts_monotonic_ns": "201",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.StreamReadResult",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "stream.read.result",
            "component": "blink.streams",
            "context_id": "frame-token",
            "context_kind": "frame",
                "native_id": "stream-read:frame-token:1:result",
                "native_parent_id": "stream-read:frame-token:1",
            "reader_mode": result_mode,
            "result_kind": result_kind,
            "chunk_value_type": chunk_value_type,
            "chunk_bytes": chunk_bytes,
        },
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)
    csv_text = output.getvalue()

    with pytest.raises(ContractError, match=error_match):
        parse_export_csv(csv_text, "fixture-run", REVISION)


def test_perfetto_csv_rejects_stream_result_context_mismatch() -> None:
    base = {field: NULL_VALUE for field in EXPORT_COLUMNS}
    rows = [
        {
            **base,
            "ts_monotonic_ns": "200",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.StreamReadRequest",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "stream.read.request",
            "component": "blink.streams",
            "context_id": "frame-a",
            "context_kind": "frame",
            "native_id": "stream-read:frame-a:1",
            "reader_mode": "default",
        },
        {
            **base,
            "ts_monotonic_ns": "201",
            "trace_category": "browser_core.stream",
            "native_name": "BrowserCore.StreamReadResult",
            "pid": "42",
            "process_name": "Renderer",
            "tid": "43",
            "thread_name": "CrRendererMain",
            "native_schema": "browser-core.native/1",
            "event_category": "stream",
            "event_name": "stream.read.result",
            "component": "blink.streams",
            "context_id": "frame-b",
            "context_kind": "frame",
            "native_id": "stream-read:frame-a:1:result",
            "native_parent_id": "stream-read:frame-a:1",
            "reader_mode": "default",
            "result_kind": "chunk",
            "chunk_value_type": "bytes",
            "chunk_bytes": "1",
        },
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EXPORT_COLUMNS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)

    with pytest.raises(ContractError, match="parent is inconsistent"):
        parse_export_csv(output.getvalue(), "fixture-run", REVISION)
