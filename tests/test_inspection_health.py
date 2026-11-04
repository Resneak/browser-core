import csv
import io
import sqlite3

import pytest

from browser_core.contracts import ContractError
from browser_core.inspection_health import (
    HEALTH_SQL, OBSERVER_OMISSION_COUNTER, decode_health, retain_health,
)


def query(rows, slices=()):
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE stats(name TEXT,severity TEXT,value INTEGER)')
        db.executemany('INSERT INTO stats VALUES (?,?,?)',rows)
        # Mirror the live decoder: the public slice view does not exist yet.
        db.execute('CREATE TABLE __intrinsic_slice(name TEXT,category TEXT)')
        db.executemany('INSERT INTO __intrinsic_slice VALUES (?,?)',slices)
        result=db.execute(HEALTH_SQL)
        stream=io.StringIO();writer=csv.writer(stream)
        writer.writerow([c[0] for c in result.description]);writer.writerows(result)
        return decode_health(stream.getvalue().encode())


def test_absent_statistics_are_not_reported_as_a_clean_capture():
    health=query([])
    assert health['status']=='awaiting-capture-stats'
    assert not health['proves_complete']
    clean=query([('traced_buf_buffer_size','info',65536)])
    assert clean['status']=='no-issues-reported' and not clean['proves_complete']


def test_loss_counters_labelled_info_are_reported_but_normal_read_behaviour_is_not():
    health=query([('traced_buf_buffer_size','info',65536),
                  ('traced_buf_chunks_overwritten','info',2),
                  ('traced_buf_chunks_overwritten','info',3),
                  ('traced_buf_bytes_overwritten','info',4096),
                  ('traced_buf_chunks_discarded','info',1),
                  ('traced_buf_readaheads_failed','info',20),
                  ('traced_buf_chunks_committed_out_of_order','info',99),
                  ('traced_buf_write_wrap_count','info',2)])
    assert health['status']=='issues-reported'
    assert {r['name']:r['value'] for r in health['counters']}=={
        'traced_buf_chunks_overwritten':5,'traced_buf_bytes_overwritten':4096,
        'traced_buf_chunks_discarded':1}
    assert all(r['kind']=='loss' for r in health['counters'])


def test_parser_errors_and_service_packet_loss_remain_distinct_counter_units():
    health=query([('track_event_tokenizer_errors','info',4),
                  ('traced_buf_trace_writer_packet_loss','data_loss',3),
                  ('track_event_missing_timestamp','error',2)])
    assert {r['kind'] for r in health['counters']}=={'loss','error'}
    assert len(health['counters'])==3 and not health['proves_complete']


def test_stop_timeout_diagnostics_are_explicit_agent_visible_errors():
    health=query([
        ('traced_buf_buffer_size','info',65536),
        ('traced_data_source_stop_timeouts','error',1),
        ('traced_data_source_stop_timeout_pending_instances','error',3),
        ('traced_data_source_stop_timeout_pending_producers','error',2),
        ('traced_data_source_stop_timeout_details_truncated','error',1),
        # Indexed identity details remain outside this aggregate health view;
        # summing ephemeral IDs and diagnostic hashes would destroy meaning.
        ('traced_data_source_stop_timeout_producer_id','info',7),
        ('traced_data_source_stop_timeout_producer_name_hash','info',13),
    ])
    assert health['status']=='issues-reported'
    assert {row['name']:row['value'] for row in health['counters']}=={
        'traced_data_source_stop_timeouts':1,
        'traced_data_source_stop_timeout_pending_instances':3,
        'traced_data_source_stop_timeout_pending_producers':2,
        'traced_data_source_stop_timeout_details_truncated':1,
    }
    assert all(row['kind']=='error' for row in health['counters'])


def test_old_warnings_survive_later_counter_resets_without_summing_units():
    previous=query([('traced_buf_buffer_size','info',32),('traced_buf_chunks_overwritten','info',8)])
    current=query([('traced_buf_chunks_overwritten','info',2)])
    retained=retain_health(previous,current)
    assert retained['capture_stats_seen'] and retained['counters'][0]['value']==8
    cleared=retain_health(retained,query([]))
    assert cleared['status']=='issues-reported' and cleared['counters']==retained['counters']


def test_retained_counter_cannot_silently_change_loss_classification():
    previous=query([('a_counter','error',10)])
    current=query([('a_counter','data_loss',1)])
    with pytest.raises(ContractError,match='classification'):
        retain_health(previous,current)


def test_native_omissions_are_visible_without_final_capture_statistics():
    health = query([], [
        ('BrowserCoreInspection.OmittedBinding','browser_core.debug'),
        ('BrowserCoreInspection.OmittedBinding','browser_core.debug'),
        ('BrowserCoreInspection.BindingValue','browser_core.debug'),
        ('BrowserCoreInspection.OmittedBinding','unrelated'),
    ])
    assert health['status']=='issues-reported' and not health['capture_stats_seen']
    assert health['counters']==[{'name':OBSERVER_OMISSION_COUNTER,
        'severity':'data_loss','value':2,'kind':'loss'}]
    assert health['proves_complete'] is False


def test_old_recordings_without_omission_events_keep_their_health_shape():
    health = query([('traced_buf_buffer_size','info',65536)],
                   [('BrowserCoreInspection.BindingValue','browser_core.debug')])
    assert health=={'status':'no-issues-reported','capture_stats_seen':True,
        'counters':[],'counters_truncated':False,'sorter_dropped_events':0,'proves_complete':False}


def test_native_omission_total_survives_a_full_unrelated_counter_list():
    stats = [(f'a_error_{index:03}','error',1) for index in range(150)]
    native = [('BrowserCoreInspection.OmittedBinding','browser_core.debug')]*3
    health = query(stats,native)
    assert health['counters_truncated'] and len(health['counters'])==128
    assert health['counters'][0]['name']==OBSERVER_OMISSION_COUNTER
    assert health['counters'][0]['value']==3
    retained = retain_health(query(stats),query([],native))
    assert retained['counters'][0]==health['counters'][0]
    assert retained['counters_truncated'] and len(retained['counters'])==128


def test_omission_total_retains_its_high_water_mark_without_double_counting():
    native = [('BrowserCoreInspection.OmittedBinding','browser_core.debug')]
    first = query([],native*3)
    retained = retain_health(first,query([],native))
    retained = retain_health(retained,query([]))
    assert retained['counters']==first['counters']
    assert retained['counters'][0]['value']==3


def test_known_omissions_remain_valid_in_portable_evidence_metadata():
    from browser_core.evidence_contract import validate_health
    health = query([('traced_buf_buffer_size','info',65536)],
                   [('BrowserCoreInspection.OmittedBinding','browser_core.debug')])
    validate_health(health)
    validate_health(retain_health(health,query([])))


def test_existing_bounded_health_metadata_keeps_its_counter_order():
    from browser_core.evidence_contract import validate_health
    health = query([('a_prior_error','error',1)],
                   [('BrowserCoreInspection.OmittedBinding','browser_core.debug')])
    health['counters'].reverse()
    original_order = [row['name'] for row in health['counters']]
    validate_health(health)
    assert [row['name'] for row in health['counters']]==original_order


def test_reserved_counter_collision_is_rejected_as_ambiguous():
    with pytest.raises(ContractError,match='diagnostics violate'):
        query([(OBSERVER_OMISSION_COUNTER,'error',7)],
              [('BrowserCoreInspection.OmittedBinding','browser_core.debug')])


def test_sorter_loss_cannot_hide_behind_a_full_diagnostic_list():
    health=query([(f'a_error_{i:03}','error',1) for i in range(150)]+
                 [('sorter_push_event_out_of_order','error',9)])
    assert len(health['counters'])==128 and health['counters_truncated']
    assert health['sorter_dropped_events']==9
    assert retain_health(health,query([]))['sorter_dropped_events']==9


@pytest.mark.parametrize('body',[
    b'',b'name,name,value\n',
    b'name,severity,value\n__capture_stats_present,meta,0\n',
    b'name,severity,value\n__capture_stats_present,meta,0,extra\n__sorter_dropped,meta,0\n',
    b'name,severity,value\n__capture_stats_present,meta,-1\n__sorter_dropped,meta,0\n',
    b'name,severity,value\n__capture_stats_present,meta,0\n__sorter_dropped,meta,0\ntraced_buf_readaheads_failed,info,1\n',
    b'name,severity,value\n__capture_stats_present,meta,0\n__sorter_dropped,meta,0\na,error,1\na,error,2\n',
    b'name,severity,value\n__capture_stats_present,meta,1\n__sorter_dropped,meta,"0',
])
def test_ambiguous_or_unexpected_diagnostics_fail_closed(body):
    with pytest.raises(ContractError):decode_health(body)


def test_oversized_native_diagnostics_are_rejected_before_csv_parsing(monkeypatch):
    def unexpected_parser(*args, **kwargs):
        raise AssertionError('oversized diagnostics reached the CSV parser')

    monkeypatch.setattr('browser_core.inspection_health.csv.DictReader', unexpected_parser)
    with pytest.raises(ContractError, match='bounded contract'):
        decode_health(b'name,severity,value\n' + b'a' * (64 * 1024))


def test_maximum_valid_diagnostic_rows_fit_the_response_byte_budget():
    rows = [(f'a{index:03}' + 'x' * 124, 'data_loss', 2**63-1)
            for index in range(128)]
    health = query(rows)
    assert len(health['counters']) == 128
    assert not health['counters_truncated']
