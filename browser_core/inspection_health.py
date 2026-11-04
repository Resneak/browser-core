"""Bounded Perfetto diagnostics; zero reported problems never proves completeness."""
from __future__ import annotations

import csv
import io
import re

from .contracts import ContractError

MAX_HEALTH_COUNTERS = 128
# The closed CSV fields are at most 128 + 9 + 19 bytes per row, plus separators.
# Reject a malformed decoder response before materializing rows or large fields.
MAX_HEALTH_BYTES = 32 * 1024
OBSERVER_OMISSION_COUNTER = 'browser_core_observer_omissions'
# This pin labels these loss counters as info. Buffer wrap, readahead and
# out-of-order commit counters are NOT evidence of loss by themselves.
EXPLICIT_LOSS_COUNTERS = frozenset((
    'traced_buf_bytes_overwritten', 'traced_buf_chunks_overwritten',
    'traced_buf_chunks_discarded',
))
EXPLICIT_ERROR_COUNTERS = frozenset((
    'track_event_parser_errors', 'track_event_tokenizer_errors',
    'traced_data_source_stop_timeouts',
    'traced_data_source_stop_timeout_pending_instances',
    'traced_data_source_stop_timeout_pending_producers',
    'traced_data_source_stop_timeout_details_truncated',
))
_selected = ','.join("'"+name+"'" for name in sorted(EXPLICIT_LOSS_COUNTERS | EXPLICIT_ERROR_COUNTERS))
# Like live value queries, use the mutable table: the public slice view is
# created only at EOF by the pinned decoder. This also works after EOF.
HEALTH_SQL = f"""SELECT name, severity, value FROM (
SELECT '__capture_stats_present' AS name, 'meta' AS severity, COUNT(*) AS value
FROM stats WHERE name='traced_buf_buffer_size' AND value>0
UNION ALL
SELECT '__sorter_dropped', 'meta', COALESCE(SUM(value),0)
FROM stats WHERE name='sorter_push_event_out_of_order'
UNION ALL
SELECT '{OBSERVER_OMISSION_COUNTER}', 'data_loss', COUNT(*)
FROM __intrinsic_slice WHERE name='BrowserCoreInspection.OmittedBinding'
AND category='browser_core.debug'
HAVING COUNT(*)>0
UNION ALL
SELECT name, severity, SUM(value) AS value FROM stats
WHERE value!=0 AND (severity IN ('data_loss','error') OR name IN ({_selected}))
GROUP BY name, severity
) ORDER BY CASE WHEN name IN ('__capture_stats_present','__sorter_dropped') THEN 0
WHEN name='{OBSERVER_OMISSION_COUNTER}' THEN 1 ELSE 2 END,
name, severity LIMIT {MAX_HEALTH_COUNTERS+3}"""


def decode_health(body: bytes) -> dict:
    try:
        if type(body) is not bytes or len(body) > MAX_HEALTH_BYTES:
            raise ValueError()
        reader = csv.DictReader(io.StringIO(body.decode('utf-8')), strict=True)
        if reader.fieldnames != ['name', 'severity', 'value']:
            raise ValueError()
        rows = list(reader)
        if not 2 <= len(rows) <= MAX_HEALTH_COUNTERS+3:
            raise ValueError()
        first = rows.pop(0)
        if first['name'] != '__capture_stats_present' or first['severity'] != 'meta':
            raise ValueError()
        def number(raw):
            if not re.fullmatch(r'0|[1-9][0-9]{0,18}', raw):
                raise ValueError()
            value = int(raw)
            if value > 2**63-1:
                raise ValueError()
            return value
        present = number(first['value']) > 0
        sorter = rows.pop(0)
        if sorter['name'] != '__sorter_dropped' or sorter['severity'] != 'meta':
            raise ValueError()
        dropped = number(sorter['value'])
        if set(first) != {'name','severity','value'} or set(sorter) != set(first):
            raise ValueError()
        counters = []
        seen = set()
        for row in rows:
            if set(row) != {'name', 'severity', 'value'}:
                raise ValueError()
            name, severity = row['name'], row['severity']
            if not re.fullmatch(r'[a-z][a-z0-9_]{0,127}', name):
                raise ValueError()
            if severity not in ('data_loss','error','info'):
                raise ValueError()
            if severity == 'info' and name not in EXPLICIT_LOSS_COUNTERS | EXPLICIT_ERROR_COUNTERS:
                raise ValueError()
            if name in seen:
                raise ValueError()
            seen.add(name)
            value = number(row['value'])
            if not value:
                raise ValueError()
            counters.append({'name':name, 'severity':severity, 'value':value,
                             'kind':'loss' if severity=='data_loss' or name in EXPLICIT_LOSS_COUNTERS else 'error'})
        # A known omitted-observation total must remain visible even when many
        # unrelated diagnostics fill the bounded list. Preserve other row order.
        if len(counters)>MAX_HEALTH_COUNTERS:
            counters.sort(key=lambda row:row['name']!=OBSERVER_OMISSION_COUNTER)
        return _result(present, counters[:MAX_HEALTH_COUNTERS], len(counters)>MAX_HEALTH_COUNTERS, dropped)
    except (ValueError, TypeError, KeyError, UnicodeError, csv.Error):
        raise ContractError('recording diagnostics violate their bounded contract') from None


def _result(present, counters, truncated, dropped):
    return {'status':'issues-reported' if counters or truncated or dropped else
            ('no-issues-reported' if present else 'awaiting-capture-stats'),
            'capture_stats_seen':present, 'counters':counters,
            'counters_truncated':truncated, 'sorter_dropped_events':dropped, 'proves_complete':False}


def retain_health(previous: dict | None, current: dict) -> dict:
    """Retain earlier warnings even if a later stats packet resets a counter.

    Values are per-counter high-water marks, never a sum of unlike loss units.
    Inputs come only from decode_health or this function within one inspector.
    """
    if previous is None:
        return current
    counters = {row['name']:row for row in previous['counters']}
    for row in current['counters']:
        old = counters.get(row['name'])
        if old is not None and (row['severity'],row['kind']) != (old['severity'],old['kind']):
            raise ContractError('recording diagnostic classification changed')
        if old is None or row['value'] > old['value']:
            counters[row['name']] = row
    rows = sorted(counters.values(), key=lambda row:(row['name']!=OBSERVER_OMISSION_COUNTER,row['name']))
    return _result(previous['capture_stats_seen'] or current['capture_stats_seen'],
                   rows[:MAX_HEALTH_COUNTERS], len(rows)>MAX_HEALTH_COUNTERS or
                   previous['counters_truncated'] or current['counters_truncated'],
                   max(previous['sorter_dropped_events'],current['sorter_dropped_events']))
