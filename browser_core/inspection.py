"""Private native value readout. This is not a portable metadata-only export."""
from __future__ import annotations

import csv
import io
import math
from pathlib import Path
import re
import struct

from .bounded_process import run_with_bounded_stdout
from .contracts import ContractError
from .control_files import decode_strict_json_bytes
from .live_trace import (snapshot_live_trace, verified_live_source,
                         reconcile_live_source_phase, require_live_session_binding)
from .inspection_contract import (CAPTURE_V1, APIS_V1, CRYPTO_INPUT_API,
    V1_PARAMETERS, supported_capture, parameter_count,
    capture_apis, supported_completion)
from .crypto_input import validate_crypto_input, validate_crypto_parameters
from .inspection_context import decode_context
from .binding_context import JS_STACK_COLUMNS, decode_js_stack

SCHEMA = 'browser-core.inspection/1'
ALLOWLIST = 'fingerprint-v1'
PARAMETER_APIS = frozenset(V1_PARAMETERS)
APIS = APIS_V1


def _integer(value, minimum=0, maximum=2**63-1):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError('invalid integer')
    return value


def _copied_integer(item, minimum, maximum):
    number=item.get('value')
    if (set(item) != {'type','value'} or type(number) not in (int,float)
            or not minimum <= number <= maximum or int(number) != number):
        raise ValueError('invalid copied integer vector element')


def _copied_float32(item):
    if 'value' not in item:
        return
    try:
        copied=struct.unpack('<f',struct.pack('<f',item['value']))[0]
    except (OverflowError,struct.error) as exc:
        raise ValueError('invalid copied float32 vector element') from exc
    if copied!=item['value']:
        raise ValueError('invalid copied float32 vector element')


def _extended_value(value):
    kind=value['type'];fields=set(value)
    raw_length=value.get('length')
    length=int(raw_length) if isinstance(raw_length,float) and raw_length.is_integer() else raw_length
    if kind=='ImageData':
        if fields!={'type','width','height','data'}:raise ValueError('invalid image observation')
        width=_integer(value['width'],minimum=1,maximum=2**31-1)
        height=_integer(value['height'],minimum=1,maximum=2**31-1)
        data=value['data']
        if not isinstance(data,dict) or data.get('type') not in ('Uint8ClampedArray','Float32Array','object'):
            raise ValueError('unsupported image buffer')
        _value(data,extended=True)
        if data['type']!='object' and data['length']!=width*height*4:
            raise ValueError('image dimensions disagree with buffer')
        return True
    if kind=='string-array':
        length=_integer(length,maximum=2**32-1)
        if fields=={'type','length','values'}:
            values=value['values']
            if not isinstance(values,list) or len(values)!=length or length>64:
                raise ValueError('invalid string array')
            for item in values:
                _value(item)
                if item['type']!='string' or 'value' not in item or item['length']>128:
                    raise ValueError('invalid string array element')
            if sum(len(i['value'].encode('utf-8')) for i in values)>4096:
                raise ValueError('string array too large')
        else:
            reason=value.get('omitted')
            if (fields!={'type','length','omitted'} or
                    reason not in ('length-limit','not-own-string-data') or
                    length==0 or (length>64 and reason!='length-limit')):
                raise ValueError('invalid string array omission')
        return True
    if 'sha256' in value:
        if not isinstance(value['sha256'],str) or re.fullmatch('[0-9a-f]{64}',value['sha256']) is None:
            raise ValueError('invalid value digest')
        length=_integer(length,maximum=2**31-1)
        byte_length=_integer(value.get('byte_length'),maximum=1024*1024)
        if kind=='string':
            if fields!={'type','length','byte_length','sha256','prefix'} or not 1024<length<=262144 or not length<=byte_length<=3*length:
                raise ValueError('invalid digested string')
            if (not isinstance(value['prefix'],str) or
                    not 253<=len(value['prefix'].encode('utf-8'))<=256):
                raise ValueError('invalid string prefix')
        elif kind in ('Int32Array','Float32Array','Float64Array','Uint8Array','Uint8ClampedArray'):
            size=8 if kind=='Float64Array' else 1 if kind in ('Uint8Array','Uint8ClampedArray') else 4
            if fields!={'type','length','byte_length','sha256','prefix_values'} or length<=64 or byte_length!=length*size:
                raise ValueError('invalid digested vector')
            prefix=value['prefix_values']
            if not isinstance(prefix,list) or len(prefix)!=64:raise ValueError('invalid vector prefix')
            for item in prefix:
                _value(item)
                if item['type']!='number':raise ValueError('invalid vector element')
                if kind=='Int32Array':
                    _copied_integer(item,-2**31,2**31-1)
                elif kind=='Float32Array':
                    _copied_float32(item)
                elif kind in ('Uint8Array','Uint8ClampedArray'):
                    _copied_integer(item,0,255)
        else:raise ValueError('digest on unsupported value')
        return True
    if kind in ('Uint8Array','Uint8ClampedArray','Float64Array'):
        copy=dict(value,type='Float32Array');_value(copy,copied_float32=False)
        if kind in ('Uint8Array','Uint8ClampedArray') and 'values' in value:
            for item in value['values']:
                _copied_integer(item,0,255)
        return True
    return False


def _value(value, *, extended=False, copied_float32=True):
    if not isinstance(value, dict) or 'type' not in value:
        raise ValueError('invalid observation')
    if extended and _extended_value(value):return value
    kind = value['type']
    fields = set(value)
    if kind == 'number':
        if fields == {'type', 'value'}:
            number = value['value']
            if (isinstance(number, bool) or not isinstance(number, (int, float))
                    or not math.isfinite(number)
                    or (number == 0 and math.copysign(1.0, number) < 0)
                    or (type(number) is int and float(number) != number)):
                raise ValueError('invalid number')
        elif fields != {'type', 'special'} or value['special'] not in ('nan', 'infinity', '-infinity', '-0'):
            raise ValueError('invalid special number')
    elif kind in ('undefined', 'null'):
        if fields != {'type'}:
            raise ValueError('invalid empty primitive')
    elif kind == 'boolean':
        if fields not in ({'type'}, {'type', 'value'}) or ('value' in value and type(value['value']) is not bool):
            raise ValueError('invalid boolean')
    elif kind == 'string':
        _integer(value.get('length'), maximum=2**31-1)
        if fields == {'type', 'length', 'value'}:
            if (not isinstance(value['value'], str) or value['length'] > 1024
                    or len(value['value'].encode('utf-8')) > 4096
                    or len(value['value'].encode('utf-16-le')) // 2 != value['length']):
                raise ValueError('invalid string')
        else:
            reason=value.get('omitted')
            if (fields != {'type', 'length', 'omitted'} or
                    reason not in ('length-limit', 'input-not-numeric') or
                    (reason=='length-limit' and value['length']<=1024)):
                raise ValueError('invalid string omission')
    elif kind in ('Int32Array', 'Float32Array'):
        length = value.get('length')
        if isinstance(length, float) and length.is_integer():
            length = int(length)
        _integer(length, maximum=2**53-1)
        if fields == {'type', 'length', 'values'}:
            if not isinstance(value['values'], list) or len(value['values']) != length or length > 64:
                raise ValueError('invalid vector')
            for item in value['values']:
                _value(item)
                if item['type'] != 'number':
                    raise ValueError('invalid vector element')
                if kind == 'Int32Array':
                    _copied_integer(item,-2**31,2**31-1)
                elif copied_float32:
                    _copied_float32(item)
        elif fields != {'type', 'length', 'omitted'} or value['omitted'] not in ('buffer-not-readable-or-length-limit', 'buffer-changed'):
            raise ValueError('invalid vector omission')
    elif kind == 'unavailable':
        if value != {'type': 'unavailable', 'omitted': 'exception'}:
            raise ValueError('invalid unavailable result')
    elif kind == 'array':
        # Arrays carry numeric length metadata only; elements are never inspected.
        length = value.get('length')
        if isinstance(length, float) and length.is_integer():
            length = int(length)
        if length is not None:
            _integer(length, maximum=2**53-1)
        if value != {'type': kind, 'omitted': 'no-object-inspection'} and \
                value != {'type': kind, 'length': length, 'omitted': 'no-object-inspection'}:
            raise ValueError('invalid array observation')
    elif kind in ('proxy', 'symbol', 'bigint', 'object'):
        if value != {'type': kind, 'omitted': 'no-object-inspection'}:
            raise ValueError('invalid object observation')
    else:
        raise ValueError('unknown observation type')
    return value


class InspectionEvents(list):
    """List-compatible result whose envelope version is not copied into rows."""
    def __init__(self,capture=None):
        super().__init__();self.capture=capture


def decode_rows(body: bytes, *, limit: int, capture=None) -> tuple[list[dict], int]:
    """Admit the exact native private shape; never forward arbitrary trace args."""
    columns = {'id', 'ts', 'pid', 'tid', 'schema', 'api', 'allowlist', 'context_id',
               'context_kind', 'realm_id', 'script_id', 'completion', 'parameters_json',
               'result_json', 'total_events'}
    try:
        if type(body) is not bytes:
            raise ValueError('native result must be bytes')
        reader = csv.DictReader(io.StringIO(body.decode('utf-8')), strict=True)
        if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError('missing or ambiguous result columns')
        extra_columns = set(reader.fieldnames) - columns
        if extra_columns not in (set(), {'context_metadata_json'}, {'context_metadata_json', *JS_STACK_COLUMNS}):
            raise ValueError('missing or ambiguous result columns')
        columns |= extra_columns
        if set(reader.fieldnames) != columns:
            raise ValueError('missing or ambiguous result columns')
        rows = []
        for row in reader:
            rows.append(row)
            if len(rows) > limit:
                raise ValueError('too many rows')
        if capture is not None and not supported_capture(capture):raise ValueError('unsupported capture')
        output = InspectionEvents(capture)
        total = None
        for raw in rows:
            observed_capture={'schema':raw['schema'],'allowlist':raw['allowlist']}
            if not supported_capture(observed_capture):raise ValueError('unsupported native version')
            if output.capture is None:output.capture=observed_capture
            extended=observed_capture!=CAPTURE_V1
            crypto_input=raw['api']==CRYPTO_INPUT_API
            if set(raw) != columns or observed_capture!=output.capture or raw['api'] not in capture_apis(observed_capture):
                raise ValueError('unknown native observation')
            id_fields = ('id', 'ts', 'pid', 'tid', 'realm_id', 'script_id')
            item = {key: _integer(int(raw[key]), minimum=-1 if key == 'script_id' else 0,
                                  maximum=2**31-1 if key in ('realm_id','script_id') else 2**63-1)
                    for key in id_fields}
            if any(raw[key] != str(item[key]) for key in id_fields):
                raise ValueError('noncanonical native integer')
            count = _integer(int(raw['total_events']), minimum=len(rows))
            if raw['total_events'] != str(count):
                raise ValueError('noncanonical native population')
            if total is not None and count != total:
                raise ValueError('inconsistent population')
            total = count
            if (re.fullmatch(r'[0-9a-fA-F]{32}', raw['context_id']) is None or
                    int(raw['context_id'],16)==0):
                raise ValueError('invalid context id')
            if raw['context_kind'] not in ('window', 'worker', 'other') or not supported_completion(observed_capture,raw['api'],raw['completion']):
                raise ValueError('invalid execution classification')
            if len(raw['parameters_json']) > 16384 or len(raw['result_json']) > 32768:
                raise ValueError('oversized value')
            if any(re.fullmatch(r'(?:[0-9A-Fa-f]{2})+', raw[key]) is None
                   for key in ('parameters_json', 'result_json')):
                raise ValueError('noncanonical native value transport')
            # Trace processor's text output does not RFC-escape embedded JSON
            # quotes. SQL hex transport preserves the exact UTF-8 bytes.
            parameters = decode_strict_json_bytes(bytes.fromhex(raw['parameters_json']),
                                                  label='native inspection parameters')
            result = decode_strict_json_bytes(bytes.fromhex(raw['result_json']),
                                              label='native inspection result')
            result = validate_crypto_input(result) if crypto_input else _value(result,extended=extended)
            if (result['type']=='boolean' and 'value' not in result or
                    result['type']=='string' and result.get('omitted')=='input-not-numeric'):
                raise ValueError('result has an input-only value shape')
            if result['type']=='ImageData' and raw['api'] not in ('CanvasRenderingContext2D.getImageData','OffscreenCanvasRenderingContext2D.getImageData'):
                raise ValueError('image observation on unrelated API')
            if result['type']=='string-array' and raw['api'] not in (
                    'Navigator.languages.get','WorkerNavigator.languages.get',
                    'WebGLRenderingContext.getSupportedExtensions',
                    'WebGL2RenderingContext.getSupportedExtensions'):
                raise ValueError('string sequence on unrelated API')
            if crypto_input:
                validate_crypto_parameters(parameters)
            elif not isinstance(parameters, dict) or set(parameters) != {'count', 'observed'}:
                raise ValueError('invalid parameters')
            _integer(parameters['count'], maximum=2**31-1)
            observed = parameters['observed']
            expected = min(parameter_count(raw['api'],extended),parameters['count'])
            if not isinstance(observed, list) or len(observed) != expected:
                raise ValueError('wrong parameter population')
            for value in observed:
                _value(value)
                if value['type']=='string' and value.get('omitted')!='input-not-numeric':
                    raise ValueError('input has a result-only value shape')
                if value['type'] != 'number' and set(value) & {'value', 'values'}:
                    raise ValueError('unallowed raw input')
            if (raw['completion'] == 'exception') != (result['type'] == 'unavailable'):
                raise ValueError('result disagrees with completion')
            item.update({key: raw[key] for key in ('api', 'context_id', 'context_kind', 'completion')})
            item.update(parameters=parameters, result=result)
            native_context = decode_context(raw.get('context_metadata_json', ''),
                context_id=item['context_id'], context_kind=item['context_kind'], realm_id=item['realm_id'])
            if native_context is not None:
                item['native_context'] = native_context
            js_stack = decode_js_stack(raw)
            if js_stack is not None:
                item['js_stack'] = js_stack
            output.append(item)
        if len({item['id'] for item in output}) != len(output):
            raise ValueError('duplicate event id')
        return output, total or 0
    except (ValueError, TypeError, KeyError, OverflowError, UnicodeError, csv.Error):
        raise ContractError('native inspection output violates its bounded local contract') from None


def inspection_sql(limit: int, *, incremental: bool = False) -> str:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ContractError('inspection limit must be from 1 to 1000')
    population = inspection_from(incremental=incremental)
    # Count the same joined population, but extract observation fields only
    # after pagination. A window over the full value projection evaluates and
    # materializes those fields even when the caller requests just one row.
    total = f'(SELECT COUNT(*) {population})'
    return f"""WITH selected AS (
SELECT s.id, s.ts, s.arg_set_id, s.parent_id, s.track_id, p.pid, t.tid
{population}
ORDER BY s.ts DESC, s.id DESC LIMIT {limit}
)
{_inspection_projection('s.pid', 's.tid', total, incremental=incremental)}
FROM selected s ORDER BY s.ts DESC, s.id DESC"""


def inspection_from(*, incremental: bool = False) -> str:
    """The same native population for value, history and membership queries."""
    # Public views and materialized thread_track are created only at EOF in
    # this pin. Live queries must use the mutable intrinsic tables directly.
    joins = ("""FROM __intrinsic_slice s JOIN __intrinsic_track tt ON s.track_id=tt.id
JOIN __intrinsic_thread t ON EXTRACT_ARG(tt.dimension_arg_set_id, 'utid')=t.id
JOIN __intrinsic_process p ON t.upid=p.id""" if incremental else """FROM slice s JOIN thread_track tt ON s.track_id=tt.id
JOIN thread t ON tt.utid=t.utid JOIN process p ON t.upid=p.upid""")
    return joins+"\nWHERE s.name='BrowserCoreInspection.BindingValue' AND s.category='browser_core.debug'"


def inspection_select(*, incremental: bool = False) -> str:
    """Shared exact value projection, with population counted before pagination."""
    return (_inspection_projection('p.pid', 't.tid', 'COUNT(*) OVER ()', incremental=incremental)
            + '\n' + inspection_from(incremental=incremental))


def _inspection_projection(pid: str, tid: str, total: str, *, incremental: bool = False) -> str:
    # Only the direct matching generated binding can supply stack context for
    # its value child. Temporal proximity or a reused script ID cannot join it.
    table = '__intrinsic_slice' if incremental else 'slice'
    parent = f"""FROM {table} b WHERE b.id=s.parent_id AND b.track_id=s.track_id
AND b.category IN ('blink.bindings','blink.bindings.encoding')
AND b.name=EXTRACT_ARG(s.arg_set_id, 'debug.api') AND s.ts>=b.ts
AND (b.dur=-1 OR s.ts<=b.ts+b.dur)"""
    # This pinned Perfetto build has no SQLite JSON functions. The closed
    # annotation strings contain no CSV metacharacters; malformed data fails
    # the existing CSV/stack validators rather than being guessed or repaired.
    stack = ',\n'.join(f"(SELECT EXTRACT_ARG(b.arg_set_id, 'debug.{column}') {parent}) AS {column}"
                       for column in JS_STACK_COLUMNS)
    return f"""SELECT s.id, s.ts, {pid}, {tid},
EXTRACT_ARG(s.arg_set_id, 'debug.schema') AS schema,
EXTRACT_ARG(s.arg_set_id, 'debug.api') AS api,
EXTRACT_ARG(s.arg_set_id, 'debug.allowlist') AS allowlist,
EXTRACT_ARG(s.arg_set_id, 'debug.context_id') AS context_id,
EXTRACT_ARG(s.arg_set_id, 'debug.context_kind') AS context_kind,
EXTRACT_ARG(s.arg_set_id, 'debug.realm_id') AS realm_id,
EXTRACT_ARG(s.arg_set_id, 'debug.script_id') AS script_id,
EXTRACT_ARG(s.arg_set_id, 'debug.completion') AS completion,
HEX(CAST(EXTRACT_ARG(s.arg_set_id, 'debug.parameters_json') AS BLOB)) AS parameters_json,
HEX(CAST(EXTRACT_ARG(s.arg_set_id, 'debug.result_json') AS BLOB)) AS result_json,
HEX(CAST(EXTRACT_ARG(s.arg_set_id, 'debug.context_metadata_json') AS BLOB)) AS context_metadata_json,
{stack},
{total} AS total_events"""


def inspection_result(events: list[dict], total: int, limit: int, *, capture=None) -> dict:
    capture=capture or getattr(events,'capture',None) or CAPTURE_V1
    return {**capture, 'events': events,
            'total_events': total, 'shown_events': len(events), 'limit': limit,
            'private_values': True}


def _require_latest_order(events):
    if any((earlier['ts'],earlier['id']) <= (later['ts'],later['id'])
           for earlier,later in zip(events,events[1:])):
        raise ContractError('native latest inspection rows are out of order')


def _require_latest_population(events, total, limit):
    if len(events) < limit and total != len(events):
        raise ContractError('native latest inspection count disagrees with its short page')


def read_inspection(processor: Path, trace: Path, *, limit: int = 100, capture=None) -> dict:
    sql = inspection_sql(limit)
    result = run_with_bounded_stdout([str(processor), 'query', str(trace), sql],
        maximum_stdout=16*1024*1024, timeout_seconds=30, label='native value inspection')
    if result.returncode:
        raise ContractError('native value inspection query failed')
    events, total = decode_rows(result.stdout, limit=limit,capture=capture)
    _require_latest_order(events)
    _require_latest_population(events, total, limit)
    return inspection_result(events, total, limit)


def live_inspection(session_path: Path, repository_root: Path, *, limit: int = 100) -> dict:
    from .lifecycle import session_status

    session, executable, source = verified_live_source(session_path, repository_root)
    from .recording_limits import observe_recording_limit
    recording_limit,limit_binding=observe_recording_limit(session,source)
    if not supported_capture(session.get('value_capture')):
        raise ContractError('session was not launched with native value inspection')
    parts=None
    phase='limited-recording' if recording_limit else 'live-prefix'
    from .recording_interruption import observe_interruption
    interrupted=observe_interruption(Path(session['trace_path']))
    if interrupted is not None:
        if recording_limit:
            raise ContractError('recording has conflicting completion markers')
        phase='interrupted-recording'
    if 'parts' in session['live_trace']:
        from .recording_parts import PartsSource
        parts=PartsSource(session)
        phase,recording_limit,_=parts.describe(running=True)
    with snapshot_live_trace(source,**({'parts':parts} if parts is not None else {})) as snapshot:
        result = read_inspection(executable.with_name('trace_processor_shell.exe'), snapshot.path, limit=limit,capture=session['value_capture'])
        state=session_status(session_path)
        browser_running=state.get('run_id')==session['run_id'] and state.get('running') is True
        phase,recording_limit=reconcile_live_source_phase(
            session,source,parts,(phase,recording_limit,limit_binding,interrupted),
            running=browser_running,
        )
        require_live_session_binding(session_path, session)
        result.update(run_id=session['run_id'], complete=False, source_phase=phase,
                      source_sha256=snapshot.sha256, snapshot_bytes=snapshot.bytes,
                      source_bytes=snapshot.source_bytes, incomplete_tail_bytes=snapshot.incomplete_tail_bytes,
                      browser_running=browser_running)
        if recording_limit:
            result['recording_limit'] = recording_limit
        return result
