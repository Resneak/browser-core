"""Bounded evidence metadata: descriptive data, never executable paths or CDP endpoints."""
from __future__ import annotations
import csv
import io
import re
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from .contracts import ContractError
from .control_files import canonical_json_bytes
from .inspection_contract import supported_recording_capture
from .inspection_health import decode_health, MAX_HEALTH_COUNTERS

SCHEMA = 'browser-core.inspection-evidence/1'
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_RECORDING_BYTES = 4 * 1024 * 1024 * 1024
PHASES = {'live-prefix','finalized-recording','recovered-prefix','interrupted-recording','limited-recording'}


def _require(condition):
    if not condition:
        raise ContractError('evidence metadata violates its bounded contract')


def _keys(value, fields):
    _require(isinstance(value,dict) and set(value)==set(fields.split()))


def _number(value, maximum=2**63-1, minimum=0):
    _require(type(value) is int and minimum<=value<=maximum)


def _text(value, maximum=256):
    _require(isinstance(value,str) and len(value)<=maximum and not any(ord(c)<32 for c in value))


def _hex(value, length=64):
    _require(isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None)


def _time(value):
    _text(value,64)
    try:_require(datetime.fromisoformat(value.replace('Z','+00:00')).utcoffset() is not None)
    except ValueError:raise ContractError('invalid evidence timestamp') from None


def _build(value):
    _keys(value,'provenance executable_sha256_16 runtime_bundle_sha256_16 attestation_created_at')
    _require(value['provenance']=='attested-browser-core')
    _hex(value['executable_sha256_16'],16);_hex(value['runtime_bundle_sha256_16'],16)
    _time(value['attestation_created_at'])


def _label(value):
    _require(isinstance(value,dict))
    if value.get('status')=='unavailable':_keys(value,'status')
    elif value.get('status')=='unresolved':
        _keys(value,'status reason')
        _require(value['reason']=='ambiguous-script-id-in-context')
    else:
        _keys(value,'status display url_sha256 not_fetch_provenance')
        _require(value['status']=='debugger-reported' and value['not_fetch_provenance'] is True)
        _text(value['display'],512)
        _require('\x7f' not in value['display'])
        try:_require(len(value['display'].encode('utf-8'))<=512)
        except UnicodeError:raise ContractError('invalid debugger source display') from None
        display=value['display']
        if display not in ('(anonymous script)', 'about:blank',
                           '(non-network source label)', '(source label unavailable)'):
            parsed=urlsplit(display)
            _require(parsed.scheme in ('http','https') and parsed.hostname
                     and parsed.username is None and parsed.password is None
                     and not parsed.query and not parsed.fragment and '\\' not in display
                     and urlunsplit((parsed.scheme,parsed.netloc,parsed.path,'',''))==display)
            _require(parsed.port is None or 1<=parsed.port<=65535)
        _hex(value['url_sha256'])


def validate_contexts(value):
    _keys(value,'attempts last_attempt probes conflicts match_limit_reached')
    _number(value['attempts'],4)
    _require(type(value['match_limit_reached']) is bool)
    _require(isinstance(value['conflicts'],list) and len(value['conflicts'])<=1000)
    for key in value['conflicts']:
        _require(isinstance(key,list) and len(key)==2)
        _number(key[0]);_require(isinstance(key[1],str) and re.fullmatch('[0-9a-fA-F-]{1,64}',key[1]) is not None)
    last=value['last_attempt']
    _require((value['attempts']==0)==(last is None))
    if last is not None:
        _require(isinstance(last,dict))
        if last.get('status')=='unavailable':_keys(last,'status')
        else:
            _keys(last,'probes_requested probe_callers_verified unavailable_contexts_or_commands truncated')
            _number(last['probes_requested'],64);_number(last['probe_callers_verified'],last['probes_requested'])
            _number(last['unavailable_contexts_or_commands'],16384);_require(type(last['truncated']) is bool)
    _require(isinstance(value['probes'],list) and len(value['probes'])<=64*value['attempts'])
    if value['attempts']==1:
        expected=0 if 'status' in last else last['probes_requested']
        _require(len(value['probes'])==expected)
    elif last is not None and 'status' not in last:
        _require(len(value['probes'])>=last['probes_requested'])
    for probe in value['probes']:
        _keys(probe,'marker probe_script_id sources metadata')
        _require(isinstance(probe['marker'],list) and len(probe['marker'])==2)
        for number in probe['marker']:_number(number,999999999,100000000)
        if probe['probe_script_id'] is not None:_number(probe['probe_script_id'])
        _require(isinstance(probe['sources'],dict) and len(probe['sources'])<=2048)
        for key,label in probe['sources'].items():
            _require(re.fullmatch('[0-9]{1,19}',key) is not None);_label(label)
        m=probe['metadata'];_require(isinstance(m,dict))
        common='kind document isolated_probe target_id cdp_context_unique_id identified_at_utc '
        if m.get('kind')=='worker':
            _keys(m,common+'target_type');_require(m['target_type'] in ('worker','shared_worker') and m['isolated_probe'] is False)
        else:
            _keys(m,common+'frame_id parent_frame_id')
            _require(m['kind'] in ('page','frame') and m['isolated_probe'] is True)
            _text(m['frame_id'])
            if m['parent_frame_id'] is not None:_text(m['parent_frame_id'])
        _text(m['target_id']);_text(m['cdp_context_unique_id']);_time(m['identified_at_utc']);_label(m['document'])
    if last is not None and 'status' not in last:
        verified=sum(probe['probe_script_id'] is not None for probe in value['probes'])
        _require(verified>=last['probe_callers_verified'])
        if value['attempts']==1:
            _require(verified==last['probe_callers_verified'])
    return value


def validate_health(value):
    if value is None:return None
    _keys(value,'status capture_stats_seen counters counters_truncated sorter_dropped_events proves_complete')
    _require(type(value['capture_stats_seen']) is bool and type(value['counters_truncated']) is bool and value['proves_complete'] is False)
    _require(isinstance(value['counters'],list) and len(value['counters'])<=MAX_HEALTH_COUNTERS)
    _number(value['sorter_dropped_events'])
    output=io.StringIO();writer=csv.writer(output);writer.writerow(['name','severity','value'])
    writer.writerow(['__capture_stats_present','meta',int(value['capture_stats_seen'])])
    writer.writerow(['__sorter_dropped','meta',value['sorter_dropped_events']])
    for row in value['counters']:
        _keys(row,'name severity value kind');_text(row['name'],128);_number(row['value'])
        writer.writerow([row['name'],row['severity'],row['value']])
    parsed=decode_health(output.getvalue().encode())
    parsed['counters_truncated']=value['counters_truncated']
    if parsed['counters_truncated']:parsed['status']='issues-reported'
    _require(parsed==value)
    return value


def _validate_metadata(value):
    fields='schema exported_at capture producer_build export_reader_build recording contexts health'
    if isinstance(value,dict) and 'producer_chromium_revision' in value:
        fields+=' producer_chromium_revision'
        _hex(value['producer_chromium_revision'],40)
    _keys(value,fields)
    _require(value['schema']==SCHEMA and supported_recording_capture(value['capture']))
    _time(value['exported_at']);_build(value['producer_build']);_build(value['export_reader_build'])
    r=value['recording'];_keys(r,'bytes sha256 packets source_bytes excluded_tail_bytes source_phase run_id')
    _number(r['bytes'],MAX_RECORDING_BYTES);_hex(r['sha256']);_number(r['packets'],40000000)
    _number(r['source_bytes'],MAX_RECORDING_BYTES);_number(r['excluded_tail_bytes'],MAX_RECORDING_BYTES)
    _require(r['bytes']+r['excluded_tail_bytes']==r['source_bytes'] and r['source_phase'] in PHASES)
    _require(r['source_phase']!='finalized-recording' or r['excluded_tail_bytes']==0)
    _text(r['run_id'],128);_require(re.fullmatch('[A-Za-z0-9-]{1,128}',r['run_id']) is not None)
    validate_contexts(value['contexts']);validate_health(value['health'])
    _require(len(canonical_json_bytes(value))<=MAX_METADATA_BYTES)
    return value


def validate_metadata(value):
    try:return _validate_metadata(value)
    except (TypeError,ValueError,KeyError,OverflowError,RecursionError):
        raise ContractError('invalid bounded evidence metadata') from None
