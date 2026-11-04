from __future__ import annotations

import csv
import hashlib
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
from browser_core.live_trace import _copy_packets, _open_shared_source, snapshot_live_trace


def test_live_snapshot_ignores_inflight_packet_and_cleans_temporary_file(tmp_path):
    source = tmp_path / 'record.pftrace.live'
    complete = b'\x0a\x03abc\x0a\x02de'
    source.write_bytes(complete + b'\x0a\x05fg')
    with snapshot_live_trace(source) as snapshot:
        temporary = snapshot.path
        assert temporary.read_bytes() == complete
        assert snapshot.bytes == len(complete)
        assert snapshot.packets == 2
        assert snapshot.incomplete_tail_bytes == 4
        assert snapshot.sha256 == hashlib.sha256(complete).hexdigest()
        source.write_bytes(complete + b'\x0a\x05fghij')
        assert temporary.read_bytes() == complete
    assert not temporary.exists()
    with snapshot_live_trace(source) as snapshot:
        assert snapshot.packets == 3
        assert snapshot.incomplete_tail_bytes == 0


def test_live_snapshot_preserves_replaced_private_directory_on_exit(
        tmp_path, monkeypatch):
    import browser_core.live_trace as live

    source = tmp_path / 'record.pftrace.live'
    source.write_bytes(b'\x0a\x00')
    folder = tempfile.TemporaryDirectory(dir=tmp_path)
    original_name = Path(folder.name)
    retained = tmp_path / 'retained-snapshot'
    sentinel = original_name / 'unrelated.txt'
    cleanup = folder.cleanup
    calls = []
    monkeypatch.setattr(folder, 'cleanup', lambda: calls.append('cleanup'))
    monkeypatch.setattr(live, 'TemporaryDirectory', lambda **kwargs: folder)
    try:
        with pytest.raises(ContractError, match='snapshot directory.*cleanup'):
            with snapshot_live_trace(source) as snapshot:
                assert snapshot.path.parent == original_name
                assert original_name.resolve().parent == tmp_path.resolve()
                original_name.rename(retained)
                original_name.mkdir()
                sentinel.write_text('preserve', encoding='utf-8')
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        monkeypatch.setattr(folder, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        if original_name.exists():
            original_name.rmdir()
        retained.rename(original_name)
        cleanup()


def test_live_snapshot_preserves_copy_after_ancestor_changes(tmp_path, monkeypatch):
    import browser_core.live_trace as live

    source = tmp_path / 'record.pftrace.live'
    source.write_bytes(b'\x0a\x00')
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    folder = tempfile.TemporaryDirectory(dir=private_parent)
    name = Path(folder.name).name
    current_folder = private_parent / name
    retained_folder = retained_parent / name
    sentinel = current_folder / 'unrelated.txt'
    monkeypatch.setattr(live, 'TemporaryDirectory', lambda **kwargs: folder)
    swapped = False
    try:
        with pytest.raises(ContractError, match='snapshot directory.*cleanup'):
            with snapshot_live_trace(source) as snapshot:
                assert snapshot.path.read_bytes() == b'\x0a\x00'
                private_parent.rename(retained_parent)
                private_parent.mkdir()
                retained_folder.rename(current_folder)
                swapped = True
                sentinel.write_text('preserve', encoding='utf-8')
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        sentinel.unlink(missing_ok=True)
        if swapped:
            if current_folder.exists():
                current_folder.rename(retained_folder)
            private_parent.rmdir()
            retained_parent.rename(private_parent)
        folder.cleanup()


@pytest.mark.parametrize('tail', [b'\x0a', b'\x0a\x80', b'\x0a\x80\x80', b'\x0a\x03x'])
def test_partial_header_or_body_is_not_misreported_as_complete(tmp_path, tail):
    path = tmp_path / 'trace'
    path.write_bytes(b'\x0a\x00' + tail)
    with snapshot_live_trace(path) as snapshot:
        assert snapshot.path.read_bytes() == b'\x0a\x00'
        assert snapshot.packets == 1
        assert snapshot.incomplete_tail_bytes == len(tail)


@pytest.mark.parametrize('body', [b'\x0b\x00', b'\x0a' + b'\xff' * 10,
                                  b'\x0a\xff\xff\xff\x7f'])
def test_invalid_envelopes_and_unbounded_packet_lengths_fail(tmp_path, body):
    path = tmp_path / 'trace'
    path.write_bytes(body)
    with pytest.raises(ContractError):
        with snapshot_live_trace(path):
            pytest.fail('invalid trace admitted')


def test_snapshot_does_not_consume_later_appends():
    output = io.BytesIO()
    size, packets, digest = _copy_packets(io.BytesIO(b'\x0a\x01a\x0a\x01b'), output, 3)
    assert (size, packets, output.getvalue()) == (3, 1, b'\x0a\x01a')


def test_packet_copy_rejects_a_short_snapshot_write():
    class ShortWriter(io.BytesIO):
        def write(self, body):
            return 0

    body = b'\x0a\x01a'
    with pytest.raises(ContractError, match='short write'):
        _copy_packets(io.BytesIO(body), ShortWriter(), len(body))


def test_explicit_packet_budget_is_exact_and_preserves_legacy_default(monkeypatch):
    monkeypatch.setattr('browser_core.live_trace.MAX_LIVE_PACKETS', 2)
    body = b'\x0a\x00' * 3
    with pytest.raises(ContractError, match='packet count'):
        _copy_packets(io.BytesIO(body), io.BytesIO(), len(body))
    output = io.BytesIO()
    assert _copy_packets(io.BytesIO(body), output, len(body), packet_limit=3)[1] == 3
    assert output.getvalue() == body
    with pytest.raises(ContractError, match='packet count'):
        _copy_packets(io.BytesIO(body + b'\x0a\x00'), io.BytesIO(), len(body)+2, packet_limit=3)


@pytest.mark.parametrize('limit', [0, -1, True, 3.0, 40_000_001])
def test_invalid_packet_budgets_fail_before_reading(limit):
    with pytest.raises(ContractError, match='packet budget'):
        _copy_packets(io.BytesIO(), io.BytesIO(), 0, packet_limit=limit)


def test_truncation_during_read_is_failure():
    with pytest.raises(ContractError, match='shrank'):
        _copy_packets(io.BytesIO(b'\x0a\x03a'), io.BytesIO(), 5)


def _packet(payload):
    length = len(payload)
    encoded = bytearray()
    while length > 127:
        encoded.append((length & 127) | 128)
        length >>= 7
    encoded.append(length)
    return b'\x0a' + bytes(encoded) + payload


@pytest.mark.parametrize('block_bytes', [1, 2, 7, 64, 4096])
@pytest.mark.parametrize('short_read', [1, 19, 65536])
def test_packet_copy_preserves_boundaries_and_digest_across_short_reads(monkeypatch, block_bytes, short_read):
    import browser_core.live_trace as live
    monkeypatch.setattr(live, 'COPY_BLOCK_BYTES', block_bytes)
    packets = [_packet(payload) for payload in (b'', b'\x0a\xff', b'x'*127, b'y'*128, b'z'*8193)]
    body = b''.join(packets)
    ends = []
    for packet in packets:
        ends.append((ends[-1] if ends else 0) + len(packet))
    budgets = {0, len(body), *(end+delta for end in ends for delta in (-2, -1, 0, 1)
                            if 0 <= end+delta <= len(body))}
    class ShortReader(io.BytesIO):
        def read(self, requested):
            return super().read(min(requested, short_read))
    for budget in budgets:
        expected_ends = [end for end in ends if end <= budget]
        expected_size = expected_ends[-1] if expected_ends else 0
        expected = body[:expected_size]
        output = io.BytesIO()
        # Later appended bytes are present but never part of the initial budget.
        actual = _copy_packets(ShortReader(body + _packet(b'later')), output, budget)
        assert actual == (expected_size, len(expected_ends), hashlib.sha256(expected).hexdigest())
        assert output.getvalue() == expected


@pytest.mark.parametrize('block_bytes', [1, 3, 17, 4096])
def test_packet_limits_and_malformed_headers_hold_across_copy_blocks(monkeypatch, block_bytes):
    import browser_core.live_trace as live
    monkeypatch.setattr(live, 'COPY_BLOCK_BYTES', block_bytes)
    monkeypatch.setattr(live, 'MAX_LIVE_PACKET_BYTES', 64)
    prefix = _packet(b'first') + _packet(b'')
    for tail, message in [(_packet(b'x'*65), 'packet exceeds'),
                          (b'\x0a'+b'\xff'*10, 'length overflows'),
                          (b'\x0b\x00', 'invalid packet envelope')]:
        with pytest.raises(ContractError, match=message):
            _copy_packets(io.BytesIO(prefix+tail), io.BytesIO(), len(prefix+tail))
    with pytest.raises(ContractError, match='packet count'):
        _copy_packets(io.BytesIO(prefix), io.BytesIO(), len(prefix), packet_limit=1)
    # A third incomplete packet does not exceed the two-complete-packet budget.
    output = io.BytesIO()
    actual = _copy_packets(io.BytesIO(prefix+b'\x0a\x02a'), output, len(prefix)+3, packet_limit=2)
    assert actual == (len(prefix), 2, hashlib.sha256(prefix).hexdigest())
    assert output.getvalue() == prefix


def test_maximum_width_zero_length_varint_remains_accepted(monkeypatch):
    # The wire format permits non-minimal uint64 varints. Do not accidentally
    # tighten the existing trace language while changing buffering.
    monkeypatch.setattr('browser_core.live_trace.COPY_BLOCK_BYTES', 3)
    body = b'\x0a' + b'\x80'*9 + b'\x00'
    output = io.BytesIO()
    assert _copy_packets(io.BytesIO(body), output, len(body)) == (len(body), 1, hashlib.sha256(body).hexdigest())
    assert output.getvalue() == body


def test_open_reader_does_not_block_producer_final_rename(tmp_path):
    source = tmp_path / 'trace.live'
    final = tmp_path / 'trace'
    source.write_bytes(b'\x0a\x01a')
    with _open_shared_source(source) as reader:
        source.rename(final)
        assert reader.read() == final.read_bytes()


def test_additional_hardlink_is_not_an_owned_live_artifact(tmp_path):
    source = tmp_path / 'trace'
    source.write_bytes(b'\x0a\x00')
    os.link(source, tmp_path / 'alias')
    with pytest.raises(ContractError, match='one regular'):
        with snapshot_live_trace(source):
            pytest.fail('alias admitted')


def test_empty_source_is_explicitly_empty(tmp_path):
    source = tmp_path / 'trace'
    source.touch()
    with snapshot_live_trace(source) as snapshot:
        assert snapshot.bytes == snapshot.packets == snapshot.incomplete_tail_bytes == 0


def test_relative_source_is_rejected():
    with pytest.raises(ContractError, match='absolute'):
        with snapshot_live_trace(Path('trace')):
            pytest.fail('relative source admitted')


@pytest.mark.parametrize('suffix', ['', '.live'])
def test_existing_recording_is_preserved_and_refused(tmp_path, suffix):
    from browser_core.live_trace import require_new_live_artifacts
    final = tmp_path/'trace'
    existing = Path(str(final)+suffix)
    existing.write_bytes(b'original evidence')
    with pytest.raises(ContractError, match='already exists'):
        require_new_live_artifacts(final)
    assert existing.read_bytes() == b'original evidence'


@pytest.mark.parametrize('body', [
    b'',
    b'wrong,category,events,total_groups,total_events\n',
    b'name,category,events,total_groups,total_events\na,blink.bindings,1,2,2\nb,blink.bindings,1,3,3\n',
    b'name,category,events,total_groups,total_events\na,blink.bindings,1,2,2\n',
    b'name,category,events,total_groups,total_events\na,blink.bindings,1,1,2\n',
    b'name,category,events,total_groups,total_events\na,blink.bindings,1,2,2\na,blink.bindings,1,2,2\n',
    b'name,category,events,total_groups,total_events\na,blink.bindings,1,2,3\nb,blink.bindings,2,2,3\n',
    b'name,category,events,total_groups,total_events\na,other,1,1,1\n',
    b'name,category,events,total_groups,total_events\na,blink.bindings,+1,1,1\n',
    b'name,category,events,total_groups,total_events\na,blink.bindings,1,01,1\n',
    b'name,category,events,total_groups,total_events\na,blink.bindings,1,1,"1',
])
def test_live_summary_rejects_invalid_native_population(tmp_path, monkeypatch, body):
    import browser_core.live_trace as live
    source=tmp_path/'trace.live';source.write_bytes(b'\x0a\x01x')
    session={'run_id':'owned-run','trace_path':str(tmp_path/'trace'), 'live_trace':{}}
    monkeypatch.setattr(live,'verified_live_source',lambda *args:(session,tmp_path/'chrome.exe',source))
    monkeypatch.setattr('browser_core.recording_limits.observe_recording_limit',lambda *args:(None,None))
    monkeypatch.setattr('browser_core.recording_interruption.observe_interruption',lambda *args:None)
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args:{'run_id':'owned-run','running':True})
    monkeypatch.setattr('browser_core.bounded_process.run_with_bounded_stdout',
                        lambda *args,**kwargs:SimpleNamespace(returncode=0,stdout=body))
    with pytest.raises(ContractError,match='invalid counters'):
        live.live_trace_summary(tmp_path/'session.json',tmp_path)


def test_live_summary_stops_parsing_at_first_group_over_limit(tmp_path, monkeypatch):
    import browser_core.live_trace as live

    source=tmp_path/'trace.live';source.write_bytes(b'\x0a\x01x')
    session={'run_id':'owned-run','trace_path':str(tmp_path/'trace'), 'live_trace':{}}
    monkeypatch.setattr(live,'verified_live_source',lambda *args:(session,tmp_path/'chrome.exe',source))
    monkeypatch.setattr('browser_core.recording_limits.observe_recording_limit',lambda *args:(None,None))
    monkeypatch.setattr('browser_core.recording_interruption.observe_interruption',lambda *args:None)
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args:{'run_id':'owned-run','running':True})
    body=(b'name,category,events,total_groups,total_events\n'
          + b'a,blink.bindings,1,3,3\n'*3)
    monkeypatch.setattr('browser_core.bounded_process.run_with_bounded_stdout',
                        lambda *args,**kwargs:SimpleNamespace(returncode=0,stdout=body))
    original_reader=csv.DictReader

    class CountedReader:
        def __init__(self,*args,**kwargs):
            self.reader=original_reader(*args,**kwargs)
            self.reads=0

        @property
        def fieldnames(self):
            return self.reader.fieldnames

        def __iter__(self):
            return self

        def __next__(self):
            self.reads+=1
            if self.reads>2:
                raise AssertionError('parsed beyond the first excess group')
            return next(self.reader)

    monkeypatch.setattr(live.csv,'DictReader',CountedReader)
    with pytest.raises(ContractError,match='invalid counters'):
        live.live_trace_summary(tmp_path/'session.json',tmp_path,limit=1)


@pytest.mark.parametrize('transition, expected_phase', [
    ('none', 'live-prefix'),
    ('limit', 'limited-recording'),
    ('final', 'finalized-recording'),
])
def test_live_summary_reconciles_completion_during_query(tmp_path, monkeypatch, transition, expected_phase):
    import browser_core.live_trace as live
    from browser_core.recording_limits import MIB, limit_marker_path
    from browser_core.recording_source import bind_recording_file

    source = tmp_path/'trace.live'
    source.write_bytes(b'\x0a\x01x')
    final = tmp_path/'trace'
    session = {'run_id': 'owned-run', 'trace_path': str(final),
               'live_trace': {'path': str(source), 'byte_limit': 4*MIB,
                              'file_binding': bind_recording_file(source)}}
    monkeypatch.setattr(live, 'verified_live_source',
                        lambda *args: (session, tmp_path/'chrome.exe', source))
    monkeypatch.setattr(live, 'require_live_session_binding', lambda *args: None)
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args: {'run_id': 'owned-run', 'running': True})

    def finish_during_query(*args, **kwargs):
        if transition == 'limit':
            limit_marker_path(final).write_bytes(b'')
        elif transition == 'final':
            source.rename(final)
        return SimpleNamespace(returncode=0,
                               stdout=b'name,category,events,total_groups,total_events\n')

    monkeypatch.setattr('browser_core.bounded_process.run_with_bounded_stdout',
                        finish_during_query)
    result = live.live_trace_summary(tmp_path/'session.json', tmp_path)
    assert result['source_phase'] == expected_phase
    assert result['complete'] is False
    assert result['bytes'] == 3 and result['browser_running'] is True
    assert ('recording_limit' in result) is (transition == 'limit')


def test_live_summary_rejects_replaced_live_file_after_query(tmp_path, monkeypatch):
    import browser_core.live_trace as live
    from browser_core.recording_limits import MIB
    from browser_core.recording_source import bind_recording_file

    source = tmp_path / 'trace.live'
    source.write_bytes(b'\x0a\x01x')
    session = {'run_id': 'owned-run', 'trace_path': str(tmp_path / 'trace'),
               'live_trace': {'path': str(source), 'byte_limit': 4*MIB,
                              'file_binding': bind_recording_file(source)}}
    monkeypatch.setattr(live, 'verified_live_source',
                        lambda *args: (session, tmp_path / 'chrome.exe', source))
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args: {'run_id': 'owned-run', 'running': True})

    def replace_live_file(*args, **kwargs):
        source.rename(tmp_path / 'retired-live')
        source.write_bytes(b'\x0a\x01x')
        return SimpleNamespace(returncode=0,
                               stdout=b'name,category,events,total_groups,total_events\n')

    monkeypatch.setattr('browser_core.bounded_process.run_with_bounded_stdout',
                        replace_live_file)
    with pytest.raises(ContractError, match='original file binding'):
        live.live_trace_summary(tmp_path / 'session.json', tmp_path)


@pytest.mark.parametrize('change', ['replace-marker', 'replace-final'])
def test_live_summary_refuses_ambiguous_completion_during_query(tmp_path, monkeypatch, change):
    import browser_core.live_trace as live
    from browser_core.recording_limits import MIB, limit_marker_path
    from browser_core.recording_source import bind_recording_file

    source = tmp_path/'trace.live'
    source.write_bytes(b'\x0a\x01x')
    final = tmp_path/'trace'
    marker = limit_marker_path(final)
    session = {'run_id': 'owned-run', 'trace_path': str(final),
               'live_trace': {'path': str(source), 'byte_limit': 4*MIB,
                              'file_binding': bind_recording_file(source)}}
    if change == 'replace-marker':
        marker.write_bytes(b'')
    monkeypatch.setattr(live, 'verified_live_source',
                        lambda *args: (session, tmp_path/'chrome.exe', source))
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args: {'run_id': 'owned-run', 'running': True})

    def change_during_query(*args, **kwargs):
        if change == 'replace-marker':
            marker.rename(tmp_path/'old-limit')
            marker.write_bytes(b'')
        else:
            source.rename(tmp_path/'moved-live')
            final.write_bytes(b'\x0a\x01x')
        return SimpleNamespace(returncode=0,
                               stdout=b'name,category,events,total_groups,total_events\n')

    monkeypatch.setattr('browser_core.bounded_process.run_with_bounded_stdout',
                        change_during_query)
    with pytest.raises(ContractError, match='phase changed|file binding|matches'):
        live.live_trace_summary(tmp_path/'session.json', tmp_path)


def test_segmented_live_summary_reconciles_done_marker_during_query(tmp_path, monkeypatch):
    import browser_core.live_trace as live
    from browser_core.recording_limits import MIB
    from browser_core.recording_parts import done_marker_path
    from browser_core.recording_source import bind_recording_file

    source = tmp_path/'trace.live'
    source.write_bytes(b'\x0a\x01x')
    final = tmp_path/'trace'
    session = {'run_id': 'owned-run', 'trace_path': str(final),
               'live_trace': {'path': str(source), 'byte_limit': 4*MIB,
                              'parts': {'schema': 'browser-core.recording-parts/1',
                                        'max_parts': 2},
                              'file_binding': bind_recording_file(source)}}
    monkeypatch.setattr(live, 'verified_live_source',
                        lambda *args: (session, tmp_path/'chrome.exe', source))
    monkeypatch.setattr(live, 'require_live_session_binding', lambda *args: None)
    monkeypatch.setattr('browser_core.lifecycle.session_status',
                        lambda *args: {'run_id': 'owned-run', 'running': True})

    def finish_during_query(*args, **kwargs):
        done_marker_path(final).write_bytes(b'')
        return SimpleNamespace(returncode=0,
                               stdout=b'name,category,events,total_groups,total_events\n')

    monkeypatch.setattr('browser_core.bounded_process.run_with_bounded_stdout',
                        finish_during_query)
    result = live.live_trace_summary(tmp_path/'session.json', tmp_path)
    assert result['source_phase'] == 'finalized-recording'
    assert result['complete'] is False and result['bytes'] == 3


def test_live_readiness_waits_for_a_whole_packet(tmp_path, monkeypatch):
    import browser_core.live_trace as live
    path = tmp_path/'trace.live'
    path.write_bytes(b'\x0a\x03a')
    class Writer:
        polls = 0
        def poll(self):
            self.polls += 1
            if self.polls == 2:
                path.write_bytes(b'\x0a\x03abc')
            return None
    writer = Writer()
    monkeypatch.setattr(live.time, 'sleep', lambda seconds: None)
    live.wait_for_live_trace(path, writer, timeout_seconds=1)
    assert writer.polls >= 3


def test_live_readiness_rejects_exited_browser_even_with_trace_bytes(tmp_path):
    from types import SimpleNamespace
    from browser_core.live_trace import wait_for_live_trace
    path = tmp_path/'trace.live'
    path.write_bytes(b'\x0a\x00')
    with pytest.raises(ContractError, match='stopped'):
        wait_for_live_trace(path, SimpleNamespace(poll=lambda: 1), timeout_seconds=1)


def test_live_readiness_has_a_deadline_when_native_writer_stays_empty(tmp_path, monkeypatch):
    import browser_core.live_trace as live
    from types import SimpleNamespace
    path = tmp_path/'trace.live'
    path.touch()
    ticks = iter([0, 0, 2, 2])
    monkeypatch.setattr(live.time, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(live.time, 'sleep', lambda seconds: None)
    with pytest.raises(ContractError, match='deadline'):
        live.wait_for_live_trace(path, SimpleNamespace(poll=lambda: None), timeout_seconds=1)
