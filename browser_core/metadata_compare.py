"""Compare what ran in two to eight windows of one validated, value-free recording.

One call decodes one bounded snapshot and validates the whole population with the
same checks as the metadata query, then counts matching events per window.
Windows are explicit recording-clock intervals or one per occurrence of an anchor
event, such as each trial's request. Rows key on API name and context kind, never
on per-run context, script or event identities, so a reload or a new worker does
not appear as a difference by itself.

A window is a time interval. Membership does not assign an event to an action,
request or script, and a zero count does not prove that code did not run.
"""
from __future__ import annotations

from collections import Counter
from contextlib import closing
import heapq
import json
import re
import sys
from pathlib import Path

from .contracts import ContractError, RUN_ID_RE, URL_CLASS_RE
from .evidence_bundle import OpenEvidence
from .inspection_contract import CAPTURE_OFF
from .inspection_history import history_filters
from .metadata_inventory import analyst_activity as validate_activity
from .metadata_query import MetadataQueryError, _matches, _metadata_query, portable_context_selector
from .recording_source import RecordingSource

SCHEMA = 'browser-core.metadata-compare/1'
MAX_OUTPUT_BYTES = 16 * 1024
MIN_WINDOWS, MAX_WINDOWS = 2, 8
MAX_NS = 2**63 - 1
ANCHOR_DEFAULT = 'fetch.request.start'
MAX_DIFFERENCE_ROWS = 64
MAX_COMPARISON_ROWS = 72
MAX_REQUESTS_PER_WINDOW, MAX_REQUEST_ROWS = 8, 40
MAX_CODE_PER_WINDOW, MAX_CODE_ROWS = 6, 32
MAX_CONTEXTS_PER_WINDOW = 3
# Counters keep exact totals, but a hostile trace can mint a fresh API or
# context key on every event. Bound those populations before report sorting.
MAX_COMPARISON_GROUPS_PER_WINDOW = 8192
# Landmark rows kept in memory per window before selection. Totals stay exact.
MAX_RETAINED_LANDMARKS = 256
OPTION_HINT = ('Give 2-8 --window START_NS:END_NS (recording-clock nanoseconds, START <= END), '
               'or --anchor-api with optional --anchor-url-class and --anchor-method for fetch.request.start, '
               '--direction before|after, --boundary same-api|anchor, --span-ns and --max-windows 2-8. '
               'Do not combine the two.')
ANCHOR_HINT = ('Fewer than two events matched the anchor. List candidates with trace session-query '
               '--api fetch.request.start and copy an exact request url_class and method.')
AMBIGUOUS_ANCHOR_HINT = ('Selected anchors or an anchor and another event with its API share one '
                         'recording-clock timestamp. Choose another anchor or explicit '
                         'non-overlapping windows; nanosecond-only windows cannot separate them.')
POPULATION_HINT = ('Too many distinct API or context groups fell in one window. '
                   'Narrow the windows or apply more selective API/context filters.')
DIFFERENCE_TRUNCATED_HINT = (
    'More differing rows exist: repeat with --api for the rows you need, or narrow the windows.')
ANCHOR_CLASS_OMITTED_HINT = (
    'One or more anchor url_class values were omitted to fit the output byte limit; '
    'use a focused session-query for the exact request classes.')

_API = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,255}')
_DECIMAL = re.compile(r'0|[1-9][0-9]{0,18}')
_METHOD = re.compile(r'[A-Za-z]{1,32}')


class CompareOptionError(ContractError):
    """A fixed, input-free diagnostic for invalid comparison options."""
    def __init__(self, code, hint, **fields):
        self.code, self.hint, self.fields = code, hint, fields
        super().__init__(code)


class ComparePopulationError(ContractError):
    """A fixed diagnostic for a bounded comparison population."""
    code = 'compare-population-over-limit'
    hint = POPULATION_HINT

    def __init__(self):
        super().__init__('comparison distinct group limit exceeded')


def _invalid():
    return CompareOptionError('compare-options-invalid', OPTION_HINT)


def _decimal(value):
    if type(value) is int:
        if not 0 <= value <= MAX_NS:
            raise _invalid()
        return value
    if type(value) is not str or _DECIMAL.fullmatch(value) is None or int(value) > MAX_NS:
        raise _invalid()
    return int(value)


def _kind(event):
    execution = event.get('execution') or {}
    return 'worker' if execution.get('worker_id') else ('window' if execution.get('frame_id') else 'other')


def _us(offset_ns):
    # Exact integer truncation toward zero, so an offset never crosses the reference.
    whole = abs(offset_ns) // 1000
    return whole if offset_ns >= 0 else -whole


def _retain_nearest(rows, candidate):
    """Keep the nearest landmarks even when a window has more than the memory cap."""
    priority = (-candidate[0], -candidate[1], -candidate[2], candidate)
    if len(rows) < MAX_RETAINED_LANDMARKS:
        heapq.heappush(rows, priority)
    elif priority[:3] > rows[0][:3]:
        heapq.heapreplace(rows, priority)


def comparison_spec(*, windows=(), anchor_api='', anchor_url_class='', anchor_method='',
                    direction='before', span_ns='', max_windows=MAX_WINDOWS, boundary='same-api'):
    """Validate one window mode before opening any source."""
    if not isinstance(windows, (list, tuple)) or any(type(item) is not str for item in windows):
        raise _invalid()
    if type(max_windows) is not int or isinstance(max_windows, bool) or not MIN_WINDOWS <= max_windows <= MAX_WINDOWS:
        raise _invalid()
    anchored = bool(anchor_api or anchor_url_class or anchor_method)
    if windows and anchored or not windows and not anchored:
        raise _invalid()
    if boundary not in ('same-api', 'anchor'):
        raise _invalid()
    if windows:
        if (not MIN_WINDOWS <= len(windows) <= MAX_WINDOWS or span_ns or direction != 'before'
                or max_windows != MAX_WINDOWS
                or boundary != 'same-api'):
            raise _invalid()
        parsed = []
        for item in windows:
            start, separator, end = item.partition(':')
            if not separator:
                raise _invalid()
            start, end = _decimal(start), _decimal(end)
            if start > end:
                raise _invalid()
            parsed.append((start, end))
        return {'mode': 'explicit', 'windows': [[str(s), str(e)] for s, e in parsed]}
    api = anchor_api or ANCHOR_DEFAULT
    if type(api) is not str or _API.fullmatch(api) is None:
        raise _invalid()
    if (anchor_url_class or anchor_method) and api != ANCHOR_DEFAULT:
        raise _invalid()
    if type(anchor_url_class) is not str:
        raise _invalid()
    try:
        anchor_url_bytes = anchor_url_class.encode('utf-8')
    except UnicodeEncodeError:
        raise _invalid() from None
    if len(anchor_url_bytes) > 1024:
        raise _invalid()
    if (anchor_url_class and URL_CLASS_RE.fullmatch(anchor_url_class) is None
            and (not anchor_url_class.startswith('/')
                 or URL_CLASS_RE.fullmatch('same-origin:' + anchor_url_class) is None)):
        raise _invalid()
    if type(anchor_method) is not str or (anchor_method and _METHOD.fullmatch(anchor_method) is None):
        raise _invalid()
    if direction not in ('before', 'after'):
        raise _invalid()
    span = None
    if span_ns not in ('', None):
        span = _decimal(span_ns)
        if span == 0:
            raise _invalid()
    return {'mode': 'anchor', 'anchor': {'api': api, 'url_class': anchor_url_class or None,
            'method': anchor_method.upper() or None, 'direction': direction, 'boundary': boundary,
            'span_ns': None if span is None else str(span), 'max_windows': max_windows}}


class WindowComparison:
    """Private collector driven by the metadata query's validated event loop."""
    schema = SCHEMA

    def __init__(self, spec, filters, activities):
        self.spec, self.filters, self.activities = spec, filters, activities
        self.contract = {'spec': spec, 'analyst_activity': activities}
        # Landmarks ignore --api but keep the context, script and portable filters.
        self.context_filters = {key: value for key, value in filters.items() if key != 'apis'}
        self.anchor = spec.get('anchor')
        self.windows = []
        self.anchors = []
        self.anchors_total = 0
        self.first_ts = self.last_ts = None

    # Pass 1: anchors and snapshot bounds. Only the latest N+1 anchors are kept.
    def _is_anchor(self, event):
        anchor = self.anchor
        if event['event']['name'] != anchor['api']:
            return False
        if anchor['url_class'] is None and anchor['method'] is None:
            return True
        request = event.get('request') or {}
        return ((anchor['url_class'] is None or _url_class_matches(request.get('url_class'), anchor['url_class']))
                and (anchor['method'] is None or str(request.get('method', '')).upper() == anchor['method']))

    def prepare(self, events):
        """events() yields the validated population again for each bounded pass."""
        latest = []
        keep = (self.anchor['max_windows'] + 1) if self.anchor else 0
        with closing(events()) as trace_events:
            for event in trace_events:
                timestamp = event['ts_monotonic_ns']
                self.first_ts = timestamp if self.first_ts is None else min(self.first_ts, timestamp)
                self.last_ts = timestamp if self.last_ts is None else max(self.last_ts, timestamp)
                if self.anchor and self._is_anchor(event):
                    self.anchors_total += 1
                    item = (timestamp, event['seq'], _request(event), _kind(event))
                    if len(latest) < keep:
                        heapq.heappush(latest, item)
                    else:
                        heapq.heappushpop(latest, item)
        if self.anchor:
            anchors = sorted(latest)
            if len(anchors) < MIN_WINDOWS:
                raise CompareOptionError('compare-anchors-insufficient', ANCHOR_HINT,
                                         anchors_matched=self.anchors_total)
            selected = anchors[-self.anchor['max_windows']:]
            neighbors = self._anchor_neighbors(anchors, selected)
            if self.anchor['boundary'] == 'same-api':
                neighbors = self._same_api_neighbors(events, selected)
            # The first selected anchor can share its timestamp with the last
            # discarded one, even when its window opens in the other direction.
            preceding = anchors[-len(selected) - 1] if len(anchors) > len(selected) else None
            if (len({anchor[0] for anchor in selected}) != len(selected)
                    or preceding is not None and preceding[0] == selected[0][0]
                    or any(neighbor is not None and neighbor[0] == anchor[0]
                           for anchor, neighbor in zip(selected, neighbors))):
                raise CompareOptionError('compare-anchors-ambiguous-timestamp',
                                         AMBIGUOUS_ANCHOR_HINT)
            self._anchor_windows(selected, neighbors)
        else:
            for start, end in self.spec['windows']:
                self.windows.append({'start': int(start), 'end': int(end), 'reference': int(start),
                                     'edge': 'explicit', 'anchor': None,
                                     'past_end': self.last_ts is None or int(end) > self.last_ts})
        self.counts = [Counter() for _ in self.windows]
        self.generated = [Counter() for _ in self.windows]
        self.first = [dict() for _ in self.windows]
        self.contexts = [Counter() for _ in self.windows]
        self.events = [0] * len(self.windows)
        self.generated_events = [0] * len(self.windows)
        self.requests = [[] for _ in self.windows]
        self.requests_total = [0] * len(self.windows)
        self.code = [[] for _ in self.windows]
        self.code_total = [0] * len(self.windows)

    def _anchor_neighbors(self, anchors, selected):
        """Nearest other matching anchor on the window's open side, or None."""
        before = self.anchor['direction'] == 'before'
        offset = len(anchors) - len(selected)
        result = []
        for index in range(len(selected)):
            position = offset + index + (-1 if before else 1)
            result.append(anchors[position][:2] if 0 <= position < len(anchors) else None)
        return result

    def _same_api_neighbors(self, events, selected):
        """Nearest other event with the anchor's name, whatever its request fields.

        For request anchors this is the previous (or next) request of any kind, so
        a window holds what ran between two requests. One more bounded pass keeps
        only one candidate per selected anchor.
        """
        before = self.anchor['direction'] == 'before'
        keys = [anchor[:2] for anchor in selected]
        best = [None] * len(keys)
        name = self.anchor['api']
        with closing(events()) as trace_events:
            for event in trace_events:
                if event['event']['name'] != name:
                    continue
                key = (event['ts_monotonic_ns'], event['seq'])
                for index, anchor in enumerate(keys):
                    if key != anchor and key[0] == anchor[0]:
                        # Timestamp-only bounds cannot separate either side of
                        # another request at the anchor's nanosecond.
                        best[index] = key
                    elif before and key < anchor and (best[index] is None or key > best[index]):
                        best[index] = key
                    elif not before and key > anchor and (best[index] is None or key < best[index]):
                        best[index] = key
        return best

    def _anchor_windows(self, selected, neighbors):
        span = None if self.anchor['span_ns'] is None else int(self.anchor['span_ns'])
        before = self.anchor['direction'] == 'before'
        side = 'anchor' if self.anchor['boundary'] == 'anchor' else 'same-api'
        for anchor, neighbor in zip(selected, neighbors):
            timestamp = anchor[0]
            if before:
                limits = [(timestamp - span, 'span')] if span is not None else []
                limits.append((neighbor[0] + 1, 'previous-' + side) if neighbor is not None
                              else (self.first_ts, 'recording-start'))
                start, edge = max(limits, key=lambda item: item[0])
                start = min(max(start, 0), timestamp)
                window = {'start': start, 'end': timestamp, 'edge': edge, 'past_end': False}
            else:
                limits = [(timestamp + span, 'span')] if span is not None else []
                limits.append((neighbor[0] - 1, 'next-' + side) if neighbor is not None
                              else (self.last_ts, 'snapshot-end'))
                end, edge = min(limits, key=lambda item: item[0])
                end = max(min(end, MAX_NS), timestamp)
                # The last window stops at the snapshot; the requested span may extend beyond it.
                window = {'start': timestamp, 'end': end, 'edge': edge,
                          'past_end': neighbor is None and (span is None or timestamp + span > self.last_ts)}
            window.update(reference=timestamp, anchor=anchor)
            self.windows.append(window)
            self.anchors.append(anchor)

    # Pass 2: the metadata query's validated loop calls add() for every event.
    def add(self, event):
        timestamp = event['ts_monotonic_ns']
        inside = [index for index, window in enumerate(self.windows)
                  if window['start'] <= timestamp <= window['end']]
        if not inside:
            return
        name = event['event']['name']
        landmark = name in ('fetch.request.start', 'dynamic.code.materialized')
        if landmark and _matches(event, self.context_filters):
            for index in inside:
                offset = timestamp - self.windows[index]['reference']
                if name == 'fetch.request.start':
                    self.requests_total[index] += 1
                    _retain_nearest(self.requests[index],
                                    (abs(offset), offset, event['seq'], _request(event)))
                else:
                    detail = event.get('detail') or {}
                    self.code_total[index] += 1
                    _retain_nearest(self.code[index],
                                    (abs(offset), offset, event['seq'], _kind(event),
                                     _closed(detail.get('dynamic_kind')), _closed(detail.get('cache_status')),
                                     detail.get('source_length') if type(detail.get('source_length')) is int else None))
        if not _matches(event, self.filters):
            return
        key = (name, _kind(event))
        execution = event.get('execution') or {}
        context = (str(event['process']['pid']), execution.get('context_id') or '', key[1])
        in_generated = event.get('dynamic_code_parent_seq') is not None
        for index in inside:
            if ((key not in self.counts[index]
                    and len(self.counts[index]) >= MAX_COMPARISON_GROUPS_PER_WINDOW)
                    or (context not in self.contexts[index]
                        and len(self.contexts[index]) >= MAX_COMPARISON_GROUPS_PER_WINDOW)):
                raise ComparePopulationError()
            self.events[index] += 1
            self.counts[index][key] += 1
            self.contexts[index][context] += 1
            if in_generated:
                self.generated[index][key] += 1
                self.generated_events[index] += 1
            first = self.first[index].get(key)
            if first is None or timestamp < first:
                self.first[index][key] = timestamp

    def result(self, base, *, producer_revision):
        count = len(self.windows)
        result = {key: base[key] for key in ('schema', 'status', 'run_id', 'capture', 'reader_runtime',
                                              'snapshot', 'recording_health')}
        result['schema'] = SCHEMA
        result['producer_chromium_revision'] = producer_revision
        if 'bundle' in base:
            result['bundle'] = base['bundle']
        snapshot_end = self.last_ts
        source_phase = base['snapshot']['source_phase']
        live = source_phase == 'live-prefix'
        result['query'] = {'filters': self.filters, 'query_sha256': base['query']['query_sha256'],
            'mode': self.spec['mode'], 'snapshot_max_seq': base['query']['snapshot_max_seq'],
            'snapshot_first_ns': None if self.first_ts is None else str(self.first_ts),
            'snapshot_last_ns': None if snapshot_end is None else str(snapshot_end)}
        if self.anchor:
            result['query']['anchor'] = dict(self.anchor, anchors_matched=self.anchors_total,
                anchors_used=count, selection='latest', truncated=self.anchors_total > count)
        overlap = any(self.windows[i]['end'] >= self.windows[j]['start']
                      and self.windows[j]['end'] >= self.windows[i]['start']
                      for i in range(count) for j in range(i + 1, count))
        result['windows'] = {'columns': ['window', 'start_ns', 'end_ns', 'reference_ns', 'edge', 'events',
                                         'apis', 'events_in_generated_code', 'requests', 'code_materializations',
                                         'extends_past_snapshot'],
            'rows': [[index + 1, str(window['start']), str(window['end']), str(window['reference']),
                      window['edge'], self.events[index], len(self.counts[index]),
                      self.generated_events[index], self.requests_total[index], self.code_total[index],
                      window['past_end']]
                     for index, window in enumerate(self.windows)]}
        if self.anchor:
            result['anchors'] = {'columns': ['window', 'seq', 'ts_ns', 'context_kind', 'method', 'url_class',
                                             'target_scope', 'body_bytes'],
                'rows': [[index + 1, str(anchor[1]), str(anchor[0]), anchor[3], *anchor[2]]
                         for index, anchor in enumerate(self.anchors)]}
        differences, constant = [], []
        keys = sorted(set().union(*self.counts)) if count else []
        for key in keys:
            counts = [self.counts[index][key] for index in range(count)]
            generated = [self.generated[index][key] for index in range(count)]
            present = sum(1 for value in counts if value)
            if present == count and len(set(counts)) == 1:
                constant.append((-counts[0], key, [key[0], key[1], counts[0], sum(generated)]))
                continue
            first = [None if key not in self.first[index] else
                     _us(self.first[index][key] - self.windows[index]['reference']) for index in range(count)]
            peak = max(counts)
            spread = (peak - min(counts)) / peak
            order = (0, present, -peak, key) if present < count else (1, -spread, -peak, key)
            differences.append((order, [key[0], key[1], 'some-windows' if present < count else 'count-varies',
                                        counts, generated if any(generated) else None, first]))
        differences.sort(key=lambda item: item[0])
        constant.sort(key=lambda item: item[:2])
        result['differences'] = _bounded(['api', 'context_kind', 'pattern', 'counts', 'in_generated_code',
                                          'first_offset_us'], [row for _, row in differences], MAX_DIFFERENCE_ROWS)
        # Unchanged rows use the room that differing rows leave free.
        result['constant'] = _bounded(['api', 'context_kind', 'count_per_window', 'in_generated_code_total'],
            [row for *_, row in constant],
            MAX_COMPARISON_ROWS - result['differences']['reported'])
        requests = []
        for index in range(count):
            nearest = sorted(item[3] for item in self.requests[index])[:MAX_REQUESTS_PER_WINDOW]
            for _, offset, seq, request in sorted(nearest, key=lambda item: (item[1], item[2])):
                requests.append([index + 1, _us(offset), *request])
        result['requests'] = _bounded(['window', 'offset_us', 'method', 'url_class', 'target_scope',
                                       'body_bytes'], requests, MAX_REQUEST_ROWS,
                                      total=sum(self.requests_total))
        code = []
        for index in range(count):
            nearest = sorted(item[3] for item in self.code[index])[:MAX_CODE_PER_WINDOW]
            for _, offset, seq, kind, dynamic_kind, cache, length in sorted(nearest, key=lambda item: (item[1], item[2])):
                code.append([index + 1, _us(offset), kind, dynamic_kind, cache, length])
        result['generated_code'] = _bounded(['window', 'offset_us', 'context_kind', 'dynamic_kind',
                                             'cache_status', 'source_length_utf16'], code, MAX_CODE_ROWS,
                                            total=sum(self.code_total))
        contexts = []
        for index in range(count):
            for (pid, context_id, kind), events in sorted(self.contexts[index].items(),
                                                          key=lambda item: (-item[1], item[0]))[:MAX_CONTEXTS_PER_WINDOW]:
                contexts.append([index + 1, pid, context_id, kind, events])
        result['contexts'] = _bounded(['window', 'pid', 'context_id', 'kind', 'events'], contexts,
                                      count * MAX_CONTEXTS_PER_WINDOW,
                                      total=sum(len(item) for item in self.contexts))
        result['limits'] = {
            'zero_count': ('not recorded in this validated snapshot for the enabled native categories '
                           'and filters; not proof that the code did not run'),
            'absence_proves_nonexecution': False,
            'window_membership': 'recording-clock time only; does not assign an event to an action, request or script',
            'window_membership_proves_causality': False,
            'event_ownership': 'unresolved',
            'analyst_activity': 'declared' if self.activities else 'unknown',
            'declared_activities': self.activities,
            'generated_code': ('events joined to a retained eval or Function materialization; unlinked events '
                               'may also run in generated code; the response that delivered the code is not identified'),
            'rows_compare': 'API name and context kind; per-run context, script and event IDs are not compared',
            'landmarks': 'requests and generated_code ignore --api; other filters apply',
            'offsets': 'microseconds from each window reference_ns (the anchor, or the explicit start)',
            'windows_overlap': overlap,
            'snapshot_is_live_prefix': live,
            'source_text_included': False,
            'source_url_to_script_mapping_established': False,
            'response_to_generated_code_mapping_established': False,
            'values_included': False,
        }
        result['semantics'] = {'private_values_included': False, 'private_value_records': 0,
            'population': 'validated-portable-native-events', 'full_snapshot_decode': True,
            'population_validated_before_filtering': True, 'event_rows_included': False,
            'query_launched_browser': False, 'active_probe': False, 'proves_capture_complete': False,
            'server_side_architecture_observed': False}
        hints = []
        if result['differences']['truncated']:
            hints.append(DIFFERENCE_TRUNCATED_HINT)
        if self.anchor and result['query']['anchor']['truncated']:
            hints.append('More anchors matched than windows were used: narrow --anchor-url-class/--anchor-method, '
                         'or give explicit --window values for earlier trials.')
        if not any(self.events):
            hints.append('No matching event fell in any window: check the filters and window bounds.')
        if any(row[-1] for row in result['windows']['rows']):
            if live:
                hints.append('A window extends past the live snapshot: repeat after the trial finishes or collect first.')
            elif source_phase == 'finalized-recording':
                hints.append('A window extends past the last recorded event; later events were not observed in this recording.')
            else:
                hints.append('A window extends past the stopped incomplete recording prefix; later events are unavailable here.')
        result['hints'] = hints
        result['output'] = {'max_rendered_json_bytes': MAX_OUTPUT_BYTES, 'rendered_json_bytes': 0,
                            'byte_limit_applied': False, 'transport_delivery_verified': False}
        return bound_output(result)


def _url_class_matches(recorded, wanted):
    """Exact class, or its path part when the caller gives only a path such as /api/collect."""
    if type(recorded) is not str:
        return False
    origin_or_scheme, _, remainder = recorded.partition(':')
    path = (remainder if origin_or_scheme in ('same-origin', 'cross-origin')
            else remainder.partition(':')[2])
    return recorded == wanted or (wanted.startswith('/') and path == wanted)


def _closed(value):
    return value if type(value) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', value) else None


def _request(event):
    """Value-free request fields only; body digests and URLs are never copied."""
    request = event.get('request') or {}
    body = request.get('body_bytes')
    return (request.get('method') if type(request.get('method')) is str else None,
            request.get('url_class') if type(request.get('url_class')) is str else None,
            request.get('target_scope') if type(request.get('target_scope')) is str else None,
            body if type(body) is int and not isinstance(body, bool) else None)


def _bounded(columns, rows, limit, *, total=None):
    reported = rows[:limit]
    total = len(rows) if total is None else total
    return {'columns': columns, 'total': total, 'reported': len(reported),
            'truncated': len(reported) < total, 'rows': reported}


def _compact(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def render(value, level=0):
    """Deterministic ASCII JSON: objects indented, each table row on one line."""
    pad = '  ' * (level + 1)
    if isinstance(value, dict):
        if not value:
            return '{}'
        body = ',\n'.join(pad + _compact(key) + ': ' + render(value[key], level + 1) for key in sorted(value))
        return '{\n' + body + '\n' + '  ' * level + '}'
    if isinstance(value, list) and value and any(isinstance(item, (dict, list)) for item in value):
        body = ',\n'.join(pad + (render(item, level + 1) if isinstance(item, dict) else _compact(item))
                          for item in value)
        return '[\n' + body + '\n' + '  ' * level + ']'
    return _compact(value)


def rendered_bytes(result):
    try:
        return (render(result) + '\n').encode('ascii')
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError('comparison output is invalid') from None


def bound_output(result):
    """Prune detail rows and oversized anchor classes; keep window identities."""
    order = ('constant', 'contexts', 'generated_code', 'requests')
    while True:
        while True:
            size = len(rendered_bytes(result))
            if result['output']['rendered_json_bytes'] == size:
                break
            result['output']['rendered_json_bytes'] = size
        if size <= MAX_OUTPUT_BYTES:
            return result
        anchors = result.get('anchors')
        classes = ([row for row in anchors['rows'] if type(row[5]) is str]
                   if anchors is not None else [])
        oversized = [row for row in classes if len(_compact(row[5])) > 512]
        table = next((result[name] for name in order if result[name]['rows']), None)
        if oversized or (classes and table is None and not result['differences']['rows']):
            row = max(oversized or classes, key=lambda item: len(_compact(item[5])))
            anchors.setdefault('url_classes_omitted_windows', []).append(row[0])
            anchors['url_classes_omitted_windows'].sort()
            row[5] = None
            if ANCHOR_CLASS_OMITTED_HINT not in result['hints']:
                result['hints'].append(ANCHOR_CLASS_OMITTED_HINT)
            result['output']['byte_limit_applied'] = True
            continue
        if table is not None:
            table['rows'].pop()
            table['reported'] = len(table['rows'])
            table['truncated'] = table['reported'] < table['total']
            result['output']['byte_limit_applied'] = True
            continue
        if result['differences']['rows']:
            table = result['differences']
            if DIFFERENCE_TRUNCATED_HINT not in result['hints']:
                result['hints'].append(DIFFERENCE_TRUNCATED_HINT)
            table['rows'].pop()
            table['reported'] = len(table['rows'])
            table['truncated'] = table['reported'] < table['total']
            result['output']['byte_limit_applied'] = True
            continue
        raise ContractError('comparison exceeds its output limit')


def compare_windows(source, *, windows=(), anchor_api='', anchor_url_class='', anchor_method='',
                    direction='before', span_ns='', max_windows=MAX_WINDOWS, boundary='same-api',
                    apis=(), script_id='',
                    context_kind='', portable_context=None, analyst_activity=(), expected_run_id=None,
                    bundle_sha256=None, expected_digest_matched=False):
    """Compare windows of an already-bound metadata source; never return event rows."""
    spec = comparison_spec(windows=windows, anchor_api=anchor_api, anchor_url_class=anchor_url_class,
        anchor_method=anchor_method, direction=direction, span_ns=span_ns, max_windows=max_windows,
        boundary=boundary)
    activities = validate_activity(analyst_activity)
    filters = history_filters(apis=apis, script=script_id, context=context_kind)
    selector = portable_context_selector(portable_context)
    if selector is not None:
        filters['portable_context'] = selector
    if expected_run_id is not None and (type(expected_run_id) is not str or RUN_ID_RE.fullmatch(expected_run_id) is None):
        raise ContractError('comparison run binding is invalid')
    if (bundle_sha256 is not None and (type(bundle_sha256) is not str
                                       or re.fullmatch(r'[0-9a-f]{64}', bundle_sha256) is None)
            or type(expected_digest_matched) is not bool
            or expected_digest_matched and bundle_sha256 is None):
        raise ContractError('comparison digest binding is invalid')
    if not callable(getattr(source, 'resolve', None)):
        raise ContractError('comparison requires a bound recording source')
    return _metadata_query(source, filters=filters, limit=1, expected_run_id=expected_run_id,
        bundle_sha256=bundle_sha256, expected_digest_matched=expected_digest_matched,
        _compare=WindowComparison(spec, filters, activities))


def _absolute(value, label):
    if not isinstance(value, Path) or not value.is_absolute():
        raise ContractError(f'comparison {label} must be an absolute path')


def session_compare(session_path: Path, root: Path, *, expected_run_id: str,
                    reader_executable: Path | None = None, **options):
    """Compare windows of one fixed snapshot of the explicitly bound live or stopped run."""
    comparison_spec(**{key: options[key] for key in options if key in _SPEC_KEYS})
    _absolute(session_path, 'session')
    _absolute(root, 'repository root')
    if (type(expected_run_id) is not str or RUN_ID_RE.fullmatch(expected_run_id) is None
            or session_path.name != expected_run_id + '.json'):
        raise ContractError('comparison run binding is invalid')
    if reader_executable is not None:
        _absolute(reader_executable, 'reader')
    source = RecordingSource(session_path, root, reader_executable)
    try:
        return compare_windows(source, expected_run_id=expected_run_id, **options)
    except ContractError as error:
        if str(error) == 'session has no live recording':
            raise MetadataQueryError('session-recording-unavailable') from None
        if str(error) in {'unsupported recording capture contract',
                          'session value capture must be an object',
                          'session value capture requires the supported local allowlist'}:
            raise MetadataQueryError('capture-contract-unsupported') from None
        raise


def evidence_compare(path: Path, root: Path, reader: Path, *, expected_sha256=None, **options):
    """Compare windows of an immutable bundle verified by the existing bounded opener."""
    from .metadata_inventory_query import _source_recording
    comparison_spec(**{key: options[key] for key in options if key in _SPEC_KEYS})
    for value, label in ((path, 'bundle'), (root, 'repository root'), (reader, 'reader')):
        _absolute(value, label)
    if expected_sha256 is not None and (type(expected_sha256) is not str
                                        or re.fullmatch(r'[0-9a-f]{64}', expected_sha256) is None):
        raise ContractError('comparison digest is invalid')
    bundle = OpenEvidence(path, root, reader, expected_sha256=expected_sha256)
    try:
        if bundle.metadata['capture'] != CAPTURE_OFF:
            raise ContractError('comparison requires a value-free capture')
        result = compare_windows(bundle.source, bundle_sha256=bundle.sha256,
                                 expected_digest_matched=expected_sha256 is not None, **options)
        result['source_recording'] = _source_recording(bundle.metadata.get('recording'), result)
        result = bound_output(result)
        bundle.source.resolve()
        return result
    finally:
        bundle.close()


_SPEC_KEYS = ('windows', 'anchor_api', 'anchor_url_class', 'anchor_method', 'direction', 'span_ns',
              'max_windows', 'boundary')
COMPARE_COMMANDS = ('session-compare', 'evidence-compare')


def compare_command(argv):
    return len(argv) >= 2 and argv[0] == 'trace' and argv[1] in COMPARE_COMMANDS


def emit_compare_argument_error():
    try:
        _emit({'schema': SCHEMA, 'status': 'error', 'code': 'compare-options-invalid',
               'hint': OPTION_HINT})
    except (ContractError, OSError, KeyboardInterrupt):
        pass
    return 2


def _emit(result):
    body = rendered_bytes(result)
    if len(body) > MAX_OUTPUT_BYTES:
        raise ContractError('comparison CLI output exceeds byte limit')
    if result.get('status') == 'ok' and result['output']['rendered_json_bytes'] != len(body):
        raise ContractError('comparison CLI output byte count changed')
    output = getattr(sys.stdout, 'buffer', None)
    if output is None:
        raise ContractError('comparison CLI requires binary stdout')
    try:
        written = output.write(body)
        if type(written) is not int or written != len(body):
            raise ContractError('comparison CLI output wrote incomplete bytes')
        output.flush()
    except OSError:
        raise ContractError('comparison CLI output transport failed') from None


def add_compare_commands(trace_sub, root):
    """Register session-compare and evidence-compare beside the existing queries."""
    def run(args):
        try:
            selector = None
            if args.portable_pid is not None or args.portable_context_id is not None:
                selector = {'pid': args.portable_pid, 'context_id': args.portable_context_id}
            options = dict(windows=args.window, anchor_api=args.anchor_api,
                anchor_url_class=args.anchor_url_class, anchor_method=args.anchor_method,
                direction=args.direction, span_ns=args.span_ns, max_windows=args.max_windows,
                boundary=args.boundary, apis=args.api, script_id=args.script_id, context_kind=args.context_kind,
                portable_context=selector, analyst_activity=args.analyst_activity)
            if args.compare_source == 'session':
                result = session_compare(args.session.absolute(), root, expected_run_id=args.expected_run_id,
                    reader_executable=args.reader_executable.absolute() if args.reader_executable else None,
                    **options)
            else:
                result = evidence_compare(args.bundle.resolve(), root, args.reader_executable.absolute(),
                                          expected_sha256=args.expected_sha256, **options)
        except CompareOptionError as error:
            _emit({'schema': SCHEMA, 'status': 'error', 'code': error.code, 'hint': error.hint, **error.fields})
            return 2
        except ComparePopulationError as error:
            _emit({'schema': SCHEMA, 'status': 'error', 'code': error.code, 'hint': error.hint})
            return 2
        except MetadataQueryError as error:
            _emit({'schema': SCHEMA, 'status': 'error', 'code': error.code})
            return 2
        except (ContractError, OSError):
            _emit({'schema': SCHEMA, 'status': 'error', 'code': 'query-unavailable'})
            return 2
        except KeyboardInterrupt:
            _emit({'schema': SCHEMA, 'status': 'error', 'code': 'interrupted'})
            return 130
        _emit(result)
        return 0

    for source in ('session', 'evidence'):
        parser = trace_sub.add_parser(source + '-compare',
            help='compare what ran in 2-8 windows of one validated metadata snapshot, such as each '
                 "trial's request; value-free; 16 KiB JSON")
        if source == 'session':
            parser.add_argument('--session', type=Path, required=True)
            parser.add_argument('--expected-run-id', required=True)
            parser.add_argument('--reader-executable', type=Path)
        else:
            parser.add_argument('--bundle', type=Path, required=True)
            parser.add_argument('--reader-executable', type=Path, required=True)
            parser.add_argument('--expected-sha256')
        parser.add_argument('--window', action='append', default=[], metavar='START_NS:END_NS',
            help='inclusive recording-clock interval; repeat 2-8 times; not with --anchor-*')
        parser.add_argument('--anchor-api', default='',
            help=f'one window per occurrence of this exact event name (default {ANCHOR_DEFAULT} '
                 'when --anchor-url-class or --anchor-method is given)')
        parser.add_argument('--anchor-url-class', default='',
            help='request url_class of the anchor, exactly (http:same-origin:/api/collect) or by path (/api/collect)')
        parser.add_argument('--anchor-method', default='', help='request method of the anchor, e.g. POST')
        parser.add_argument('--direction', choices=('before', 'after'), default='before',
            help='before: each window ends at its anchor; after: each window starts at its anchor')
        parser.add_argument('--boundary', choices=('same-api', 'anchor'), default='same-api',
            help='where a window stops on its open side: the nearest other event with the anchor API name '
                 '(default; for requests, the previous or next request of any kind) or the nearest other '
                 'matching anchor')
        parser.add_argument('--span-ns', default='',
            help='optional maximum window length in nanoseconds (for example 50000000 = 50 ms)')
        parser.add_argument('--max-windows', type=int, default=MAX_WINDOWS,
            help='use the latest N anchors, 2-8 (default 8)')
        parser.add_argument('--api', action='append', default=[], help='exact event name to count; repeat up to 32')
        parser.add_argument('--script-id', default='')
        parser.add_argument('--context-kind', choices=('window', 'worker', 'other'), default='')
        parser.add_argument('--portable-pid', help='exact recorded PID; requires --portable-context-id')
        parser.add_argument('--portable-context-id', help='exact recorded context ID; requires --portable-pid')
        parser.add_argument('--analyst-activity', action='append', default=[],
            choices=('browser-control', 'page-evaluation', 'source-acquisition'))
        parser.set_defaults(func=run, compare_source=source)
