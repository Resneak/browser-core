"""Bounded private history queries and panel-local authenticated page cursors."""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import re

from .contracts import ContractError
from .inspection import _inspection_projection, inspection_from


def _decimal_filter(value, label, *, maximum=2**63-1):
    if (not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,18}', value)
            or int(value) > maximum):
        raise ContractError(f'{label} must be an exact nonnegative integer ID')
    return value


def _context_scope(scope):
    if scope is None:
        return None
    if not isinstance(scope, dict) or set(scope) != {'pid', 'context_id', 'realm_id'}:
        raise ContractError('history scope must identify a process, native context and world')
    context_id = scope['context_id']
    if (not isinstance(context_id, str) or
            re.fullmatch(r'[0-9a-fA-F]{32}', context_id) is None or
            int(context_id, 16) == 0):
        raise ContractError('history scope has an invalid native context ID')
    return {'pid': _decimal_filter(scope['pid'], 'history process'),
            'context_id': context_id.upper(),
            'realm_id': _decimal_filter(scope['realm_id'], 'history world', maximum=2**31-1)}


def history_filters(search='', script='', context='', *, scope=None, start_ns='', end_ns='', apis=()):
    if not all(isinstance(value, str) for value in (search, script, context)):
        raise ContractError('history filters must be text')
    try:
        if len(search) > 256 or len(search.encode('utf-8')) > 1024:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ContractError('history search must be at most 256 valid characters') from None
    if script and (not re.fullmatch(r'-1|0|[1-9][0-9]{0,18}', script) or int(script) > 2**31-1):
        raise ContractError('history script must be an exact integer ID')
    if context not in ('', 'window', 'worker', 'other'):
        raise ContractError('unknown history context')
    if not isinstance(apis, (list, tuple)) or len(apis) > 32:
        raise ContractError('history API filters must be a bounded list')
    normalized_apis = []
    for api in apis:
        if (not isinstance(api, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,255}', api)
                or len(api.encode('utf-8')) > 256 or api in normalized_apis):
            raise ContractError('history API filter is invalid or duplicated')
        normalized_apis.append(api)
    normalized_apis.sort()
    scope = _context_scope(scope)
    for value, label in ((start_ns, 'history start'), (end_ns, 'history end')):
        if value != '':
            _decimal_filter(value, label)
    if start_ns and end_ns and int(start_ns) > int(end_ns):
        raise ContractError('history start must not be after its end')
    filters = {'search': search, 'script': script, 'context': context}
    if normalized_apis:
        filters['apis'] = normalized_apis
    if scope is not None:
        filters['scope'] = scope
    if start_ns:
        filters['start_ns'] = start_ns
    if end_ns:
        filters['end_ns'] = end_ns
    return filters


def _integer(value):
    if type(value) is not int or not 0 <= value <= 2**63-1:
        raise ContractError('invalid history boundary')
    return value


def decode_highwater(body):
    """Require one exact native insertion boundary before freezing a search."""
    try:
        if not isinstance(body, bytes) or len(body) > 128:
            raise ValueError()
        rows=list(csv.reader(io.StringIO(body.decode('utf-8'), newline=''), strict=True))
        if len(rows)!=2 or rows[0]!=['highwater'] or len(rows[1])!=1:
            raise ValueError()
        value=rows[1][0]
        if re.fullmatch(r'0|[1-9][0-9]{0,18}', value) is None:
            raise ValueError()
        return _integer(int(value))
    except (ValueError, TypeError, UnicodeError, csv.Error, ContractError):
        raise ContractError('history boundary violates its native contract') from None


def query_digest(filters, limit):
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ContractError('history limit must be from 1 to 1000')
    return hashlib.sha256(json.dumps([filters, limit], sort_keys=True).encode()).hexdigest()


def encode_cursor(key, query, highwater, timestamp=None, event_id=None):
    if timestamp is not None or event_id is not None:
        timestamp, event_id = _integer(timestamp), _integer(event_id)
    body=json.dumps([query, _integer(highwater), timestamp, event_id], separators=(',', ':')).encode()
    signature=hmac.digest(key, body, 'sha256')
    return base64.urlsafe_b64encode(body+signature).decode()


def decode_cursor(key, query, cursor):
    try:
        if not isinstance(cursor, str) or len(cursor) > 512:
            raise ValueError()
        raw=base64.b64decode(cursor.encode('ascii'), altchars=b'-_', validate=True)
        body, signature=raw[:-32], raw[-32:]
        if not hmac.compare_digest(signature, hmac.digest(key, body, 'sha256')):
            raise ValueError()
        values=json.loads(body)
        if not isinstance(values, list) or len(values)!=4 or values[0]!=query:
            raise ValueError()
        highwater=_integer(values[1])
        timestamp, event_id=values[2:]
        if timestamp is not None or event_id is not None:
            timestamp, event_id=map(_integer, (timestamp, event_id))
        if event_id is not None and event_id > highwater:
            raise ValueError()
        return highwater, timestamp, event_id
    except (ValueError, TypeError, UnicodeError, ContractError):
        raise ContractError('history cursor is invalid or belongs to a different search') from None


def history_conditions(filters, highwater):
    filters=history_filters(**filters)
    highwater=_integer(highwater)
    conditions=[f's.id <= {highwater}']
    # Cheap intrinsic bounds precede argument extraction for narrow time ranges.
    if 'start_ns' in filters:
        conditions.append(f"s.ts >= {int(filters['start_ns'])}")
    if 'end_ns' in filters:
        conditions.append(f"s.ts <= {int(filters['end_ns'])}")
    if filters['search']:
        # Hex text literals keep even quotes, SQL syntax and NUL literal data.
        literal="CAST(X'"+filters['search'].encode('utf-8').hex()+"' AS TEXT)"
        fields=('api', 'parameters_json', 'result_json')
        conditions.append('('+' OR '.join(
            f"INSTR(LOWER(COALESCE(EXTRACT_ARG(s.arg_set_id, 'debug.{field}'), '')), LOWER({literal})) > 0"
            for field in fields)+')')
    if filters['script']:
        conditions.append(f"EXTRACT_ARG(s.arg_set_id, 'debug.script_id') = {int(filters['script'])}")
    if filters['context']:
        conditions.append(f"EXTRACT_ARG(s.arg_set_id, 'debug.context_kind') = '{filters['context']}'")
    if apis := filters.get('apis'):
        literals = ["CAST(X'" + api.encode('utf-8').hex() + "' AS TEXT)" for api in apis]
        conditions.append(
            "EXTRACT_ARG(s.arg_set_id, 'debug.api') IN (" + ','.join(literals) + ')'
        )
    if scope := filters.get('scope'):
        conditions.extend((f"p.pid = {int(scope['pid'])}",
            f"UPPER(EXTRACT_ARG(s.arg_set_id, 'debug.context_id')) = '{scope['context_id']}'",
            f"EXTRACT_ARG(s.arg_set_id, 'debug.realm_id') = {int(scope['realm_id'])}"))
    return ' AND '.join(conditions)


def history_sql(filters, highwater, *, before=None, limit=1000):
    conditions=history_conditions(filters, highwater)
    query_digest(filters, limit)
    population=inspection_from(incremental=True)+' AND '+conditions
    columns='SELECT s.id, s.ts, s.arg_set_id, s.parent_id, s.track_id, p.pid, t.tid'
    if before is None:
        # A short first page contains the entire matching population. Reuse
        # its count instead of scanning an expensive sparse filter twice.
        selected=f'{columns}\n{population} ORDER BY s.ts DESC,s.id DESC LIMIT {limit+1}'
        total=(f'CASE WHEN (SELECT COUNT(*) FROM selected)<{limit+1} '
               f'THEN (SELECT COUNT(*) FROM selected) ELSE (SELECT COUNT(*) {population}) END')
        ctes=f'WITH selected AS MATERIALIZED ({selected})'
    else:
        # Later pages still report the population before the page boundary.
        # Retain only ownership IDs and argument-set references while counting
        # and paging; project observation fields for selected rows afterward.
        timestamp, event_id=map(_integer, before)
        boundary=f'WHERE ts < {timestamp} OR (ts = {timestamp} AND id < {event_id})'
        matches=f'{columns}\n{population}'
        selected=f'SELECT * FROM matches {boundary} ORDER BY ts DESC,id DESC LIMIT {limit+1}'
        ctes=f'WITH matches AS MATERIALIZED ({matches}),selected AS ({selected})'
        total='(SELECT COUNT(*) FROM matches)'
    return (ctes+'\n'+_inspection_projection('s.pid','s.tid',total,incremental=True)
            +' FROM selected s ORDER BY s.ts DESC,s.id DESC')
