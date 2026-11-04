import hashlib
import os

import pytest

import browser_core.recording_interruption as interruption_module
import browser_core.recording_source as recording_source_module
from browser_core.contracts import ContractError
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.live_trace import require_new_live_artifacts
from browser_core.recording_assembly import assemble_recording
from browser_core.recording_interruption import interruption_marker_path
from browser_core.recording_limits import limit_marker_path
from browser_core.recording_parts import done_marker_path
from browser_core.recording_source import RecordingSource
from test_recording_recovery import source, FakeDecoder


def configure(source, parts):
    source.session['live_trace']['byte_limit'] = 4 * 1024 * 1024
    if parts:
        source.session['live_trace']['parts'] = {'schema':'browser-core.recording-parts/1', 'max_parts':3}
    source.save()
    return interruption_marker_path(source.final)


@pytest.mark.parametrize('parts', [False, True])
@pytest.mark.parametrize('tail', [b'', b'\x0a\x03x'])
def test_service_interruption_retains_prefix_while_browser_runs_and_after_reopen(source, monkeypatch, parts, tail):
    marker = configure(source, parts)
    monkeypatch.setattr('browser_core.incremental_inspection.TraceProcessorPipe', FakeDecoder)
    before = source.path.read_bytes()
    with IncrementalInspection(source.document, source.document.parent) as reader:
        assert reader.read()['source_phase'] == 'live-prefix'
        with source.path.open('ab') as stream:
            stream.write(tail)
        marker.write_bytes(b'')
        result = reader.read()
        assert result['source_phase'] == 'interrupted-recording'
        assert result['browser_running'] and result['recording_settled']
        assert result['recovery_incomplete'] and not result['complete']
        assert result['incomplete_tail_bytes'] == len(tail)
        assert result['source_sha256'] == hashlib.sha256(before).hexdigest()
        assert b''.join(reader.decoder.chunks) == before
        assert reader.read()['source_phase'] == 'interrupted-recording'
        assert reader.decoder.finalizations == 1
    source.status.update(running=False, state='stopped')
    with IncrementalInspection(source.document, source.document.parent) as reopened:
        final = reopened.read()
        assert final['recovery_incomplete'] and not final['complete']
        assert final['source_sha256'] == result['source_sha256']
    output = source.document.parent / 'assembled.pftrace'
    with pytest.raises(ContractError, match='allow-incomplete'):
        assemble_recording(source.document, source.document.parent, output)
    receipt = assemble_recording(source.document, source.document.parent, output, allow_incomplete=True)
    assert receipt['source_phase'] == 'interrupted-recording' and not receipt['complete']
    assert output.read_bytes() == before and source.path.read_bytes() == before + tail


@pytest.mark.parametrize('parts', [False, True])
@pytest.mark.parametrize('kind', ['nonempty', 'directory', 'hardlink', 'removed', 'replaced', 'limit', 'final'])
def test_bad_changed_or_conflicting_interruption_markers_are_rejected(source, parts, kind):
    marker = configure(source, parts)
    marker.write_bytes(b'')
    if kind == 'nonempty': marker.write_bytes(b'x')
    elif kind == 'directory': marker.unlink(); marker.mkdir()
    elif kind == 'hardlink': os.link(marker, marker.with_name('alias'))
    elif kind == 'limit': limit_marker_path(source.final).write_bytes(b'')
    elif kind == 'final':
        if parts: done_marker_path(source.final).write_bytes(b'')
        else: source.path.rename(source.final)
    else:
        assert source.reader.resolve().phase == 'interrupted-recording'
        marker.rename(marker.with_name('original-marker'))
        if kind == 'replaced': marker.write_bytes(b'')
    with pytest.raises(ContractError): source.reader.resolve()


def test_interruption_marker_replacement_during_first_observation_is_rejected(
    source, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = configure(source, False)
    marker.write_bytes(b"")
    held = marker.with_name("held-interruption-marker")
    original = interruption_module._require_regular
    checks = 0

    def replace_after_handle_check(metadata: os.stat_result) -> None:
        nonlocal checks
        original(metadata)
        checks += 1
        if checks == 2:
            marker.rename(held)
            marker.write_bytes(b"")

    monkeypatch.setattr(interruption_module, "_require_regular", replace_after_handle_check)
    with pytest.raises(ContractError):
        interruption_module.observe_interruption(source.final)
    assert checks >= 2
    assert held.is_file() and marker.is_file()


def test_recording_source_rechecks_interruption_published_during_source_binding(
    source, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = configure(source, False)
    original = recording_source_module.bind_recording_file
    published = False

    def bind_then_interrupt(path, expected=None):
        nonlocal published
        binding = original(path, expected)
        if not published:
            marker.write_bytes(b"")
            published = True
        return binding

    monkeypatch.setattr(recording_source_module, "bind_recording_file", bind_then_interrupt)
    with pytest.raises(ContractError, match="marker changed"):
        source.reader.resolve()
    assert published and marker.is_file()


def test_segmented_recording_rechecks_done_marker_published_during_binding(
    source, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(source, True)
    marker = done_marker_path(source.final)
    original = recording_source_module.bind_recording_file
    binds = 0

    def bind_then_finish(path, expected=None):
        nonlocal binds
        binding = original(path, expected)
        binds += 1
        if binds == 2:
            marker.write_bytes(b"")
        return binding

    monkeypatch.setattr(recording_source_module, "bind_recording_file", bind_then_finish)
    with pytest.raises(ContractError, match="marker changed"):
        source.reader.resolve()
    assert binds >= 2 and marker.is_file()


@pytest.mark.parametrize('parts', [False, True])
def test_interruption_name_is_reserved_before_launch_and_during_assembly(source, parts):
    marker = configure(source, parts)
    with pytest.raises(ContractError, match='original recording'):
        assemble_recording(source.document, source.document.parent, marker, allow_incomplete=True)
    source.path.unlink()
    marker.write_bytes(b'')
    with pytest.raises(ContractError, match='already exists'):
        require_new_live_artifacts(source.final, recording_parts=3 if parts else None)
    assert marker.read_bytes() == b''


@pytest.mark.parametrize('parts', [False, True])
def test_one_shot_readers_report_interruption_while_browser_remains_open(source, monkeypatch, parts):
    from types import SimpleNamespace
    from browser_core.inspection import live_inspection
    from browser_core.live_trace import live_trace_summary
    marker = configure(source, parts)
    marker.write_bytes(b'')
    monkeypatch.setattr('browser_core.inspection.read_inspection', lambda *a, **k: {'events':[]})
    monkeypatch.setattr('browser_core.bounded_process.run_with_bounded_stdout', lambda *a, **k:
        SimpleNamespace(returncode=0, stdout=b'name,category,events,total_groups,total_events\n'))
    for read in (live_inspection, live_trace_summary):
        result = read(source.document, source.document.parent)
        assert result['source_phase'] == 'interrupted-recording'
        assert result['browser_running'] and not result['complete']
