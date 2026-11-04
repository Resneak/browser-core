"""Offline, payload-free inventory of an existing verified evidence bundle."""
from __future__ import annotations

import csv
import hashlib
import io
import re
from pathlib import Path

from .bounded_process import run_with_bounded_stdout
from .contracts import ContractError
from .evidence_bundle import OpenEvidence
from .inspection_contract import CRYPTO_INPUT_API, capture_apis, supported_capture
from .inspection_health import (
    EXPLICIT_ERROR_COUNTERS, EXPLICIT_LOSS_COUNTERS, HEALTH_SQL,
    OBSERVER_OMISSION_COUNTER, decode_health,
)

SCHEMA = 'browser-core.evidence-summary/1'
MAX_SUMMARY_BYTES = 128 * 1024
METRICS = (
    'binding_value_records', 'thread_process_linked_records',
    'thread_process_unlinked_records', 'capture_envelope_matching_records',
    'capture_envelope_mismatched_records', 'recognized_api_records',
    'unrecognized_api_records', 'completion_compatible_records',
    'completion_incompatible_records', 'queryable_records',
)


def summary_sql(capture: dict) -> str:
    """All emitted labels are closed constants; no payload or URL is selected.

    Count orphaned slices too: the ordinary value reader's inner joins exclude
    those. Envelope compatibility does not validate values or context metadata.
    """
    if not supported_capture(capture):
        raise ContractError('unsupported summary capture')
    apis = sorted(capture_apis(capture))
    names = ','.join("'" + api + "'" for api in apis)
    envelope = f"schema='{capture['schema']}' AND allowlist='{capture['allowlist']}'"
    known = f'api IN ({names})'
    completion = (f"((api='{CRYPTO_INPUT_API}' AND completion='input-copied') OR "
                  f"(api!='{CRYPTO_INPUT_API}' AND completion IN ('returned','exception')))")
    conditions = ('1', 'linked=1', 'linked=0', 'envelope=1', 'envelope=0',
                  'envelope=1 AND known=1', 'envelope=1 AND known=0',
                  'envelope=1 AND known=1 AND compatible=1',
                  'envelope=1 AND known=1 AND compatible=0',
                  'linked=1 AND envelope=1 AND known=1 AND compatible=1')
    queries = [f"SELECT 'metric' AS kind, '{name}' AS label, COUNT(*) AS records, "
               "COALESCE(CAST(MIN(ts) AS TEXT),'') AS first_ns, "
               "COALESCE(CAST(MAX(ts) AS TEXT),'') AS last_ns "
               f'FROM classified WHERE {condition}'
               for name, condition in zip(METRICS, conditions)]
    queries.append("SELECT 'api', api, COUNT(*), CAST(MIN(ts) AS TEXT), CAST(MAX(ts) AS TEXT) "
                   'FROM classified WHERE envelope=1 AND known=1 AND compatible=1 GROUP BY api')
    return f"""WITH raw AS MATERIALIZED (
SELECT s.ts,
EXTRACT_ARG(s.arg_set_id,'debug.schema') AS schema,
EXTRACT_ARG(s.arg_set_id,'debug.allowlist') AS allowlist,
EXTRACT_ARG(s.arg_set_id,'debug.api') AS api,
EXTRACT_ARG(s.arg_set_id,'debug.completion') AS completion,
EXISTS(SELECT 1 FROM __intrinsic_track tt
JOIN __intrinsic_thread t ON EXTRACT_ARG(tt.dimension_arg_set_id,'utid')=t.id
JOIN __intrinsic_process p ON t.upid=p.id WHERE tt.id=s.track_id) AS linked
FROM __intrinsic_slice s
WHERE s.name='BrowserCoreInspection.BindingValue' AND s.category='browser_core.debug'
), classified AS MATERIALIZED (
SELECT ts,api,linked,COALESCE(({envelope}),0) AS envelope,
COALESCE(({known}),0) AS known,COALESCE(({completion}),0) AS compatible FROM raw
)
""" + '\nUNION ALL\n'.join(queries) + '\nORDER BY kind,label'


def decode_summary(body: bytes, capture: dict) -> dict:
    """Reject unbounded, inconsistent or unknown decoder results without echo."""
    apis = capture_apis(capture)
    try:
        if not apis or type(body) is not bytes or len(body) > MAX_SUMMARY_BYTES:
            raise ValueError()
        reader = csv.DictReader(io.StringIO(body.decode('utf-8')), strict=True)
        columns = ['kind', 'label', 'records', 'first_ns', 'last_ns']
        if reader.fieldnames != columns:
            raise ValueError()
        groups = {'metric': {}, 'api': {}}
        for index, row in enumerate(reader):
            if index >= len(METRICS) + len(apis) or set(row) != set(columns):
                raise ValueError()
            kind, label = row['kind'], row['label']
            if kind not in groups or label not in (METRICS if kind == 'metric' else apis):
                raise ValueError()
            if label in groups[kind]:
                raise ValueError()
            def number(raw, maximum):
                if not isinstance(raw, str) or not re.fullmatch(r'0|[1-9][0-9]{0,18}', raw):
                    raise ValueError()
                value = int(raw)
                if value > maximum:
                    raise ValueError()
                return value
            count = number(row['records'], 2**53-1)
            first, last = row['first_ns'], row['last_ns']
            if count:
                first_number, last_number = number(first, 2**63-1), number(last, 2**63-1)
                if first_number > last_number or (count == 1 and first_number != last_number):
                    raise ValueError()
            elif first != '' or last != '' or kind == 'api':
                raise ValueError()
            groups[kind][label] = {'records': count, 'first_ns': first or None, 'last_ns': last or None}
        metrics = groups['metric']
        if set(metrics) != set(METRICS):
            raise ValueError()
        counts = {key: value['records'] for key, value in metrics.items()}
        total = counts['binding_value_records']
        partitions = (
            ('binding_value_records', ('thread_process_linked_records', 'thread_process_unlinked_records')),
            ('binding_value_records', ('capture_envelope_matching_records', 'capture_envelope_mismatched_records')),
            ('capture_envelope_matching_records', ('recognized_api_records', 'unrecognized_api_records')),
            ('recognized_api_records', ('completion_compatible_records', 'completion_incompatible_records')),
        )
        for parent, children in partitions:
            if counts[parent] != sum(counts[key] for key in children):
                raise ValueError()
        if sum(row['records'] for row in groups['api'].values()) != counts['completion_compatible_records']:
            raise ValueError()
        def exact_extrema(parent, children):
            present = [row for row in children if row['records']]
            if present and (int(parent['first_ns']) != min(int(row['first_ns']) for row in present)
                    or int(parent['last_ns']) != max(int(row['last_ns']) for row in present)):
                raise ValueError()
        for parent, children in partitions:
            exact_extrema(metrics[parent], (metrics[key] for key in children))
        exact_extrema(metrics['completion_compatible_records'], groups['api'].values())
        linked=counts['thread_process_linked_records']
        compatible=counts['completion_compatible_records']
        queryable=counts['queryable_records']
        if (queryable > compatible or queryable > linked
                or queryable < max(0, linked+compatible-total)):
            raise ValueError()
        bounds = metrics['binding_value_records']
        for row in (*metrics.values(), *groups['api'].values()):
            if row['records'] > total or (row['records'] and not (
                int(bounds['first_ns']) <= int(row['first_ns']) <= int(row['last_ns']) <= int(bounds['last_ns'])
            )):
                raise ValueError()
        def within(child, parent):
            if child['records'] and (not parent['records'] or not (
                    int(parent['first_ns']) <= int(child['first_ns'])
                    <= int(child['last_ns']) <= int(parent['last_ns']))):
                raise ValueError()
        for child, parent in (
            ('thread_process_linked_records', 'binding_value_records'),
            ('thread_process_unlinked_records', 'binding_value_records'),
            ('capture_envelope_matching_records', 'binding_value_records'),
            ('capture_envelope_mismatched_records', 'binding_value_records'),
            ('recognized_api_records', 'capture_envelope_matching_records'),
            ('unrecognized_api_records', 'capture_envelope_matching_records'),
            ('completion_compatible_records', 'recognized_api_records'),
            ('completion_incompatible_records', 'recognized_api_records'),
            ('queryable_records', 'completion_compatible_records'),
            ('queryable_records', 'thread_process_linked_records'),
        ):
            within(metrics[child], metrics[parent])
        for row in groups['api'].values():
            within(row, metrics['completion_compatible_records'])
        return {'counts': counts,
                'timestamps': {'first_ns': bounds['first_ns'], 'last_ns': bounds['last_ns'],
                               'clock': 'recording-clock', 'encoding': 'decimal-string'},
                'apis': [{'api': api, **groups['api'].get(api, {'records': 0, 'first_ns': None, 'last_ns': None})}
                         for api in sorted(apis)]}
    except (ValueError, TypeError, KeyError, UnicodeError, csv.Error):
        raise ContractError('evidence summary violates its bounded contract') from None


def _health_summary(health):
    if health is None:
        return None
    known = EXPLICIT_ERROR_COUNTERS | EXPLICIT_LOSS_COUNTERS | {OBSERVER_OMISSION_COUNTER}
    # Arbitrary diagnostic names in imported evidence are not safe output text.
    return {**{key: health[key] for key in ('status', 'capture_stats_seen', 'counters_truncated',
                                           'proves_complete')},
            'sorter_dropped_events': str(health['sorter_dropped_events']),
            'counters': [{**({'name': row['name']} if row['name'] in known else
                            {'name_sha256': hashlib.sha256(row['name'].encode()).hexdigest()}),
                          'kind': row['kind'], 'value': str(row['value'])} for row in health['counters']]}


def evidence_summary(
    path: Path,
    root: Path,
    reader: Path,
    *,
    expected_sha256=None,
    include_queryability: bool = False,
) -> dict:
    """Verify and decode a fixed private copy; close each owned decoder and copy."""
    if type(include_queryability) is not bool:
        raise ContractError('evidence summary queryability mode is invalid')
    bundle = OpenEvidence(path, root, reader, expected_sha256=expected_sha256)
    try:
        location = bundle.source.resolve()
        capture = bundle.metadata['capture']
        processor = location.executable.with_name('trace_processor_shell.exe')
        def query(sql):
            result = run_with_bounded_stdout(
                [str(processor), 'query', str(bundle.path), sql],
                maximum_stdout=MAX_SUMMARY_BYTES, timeout_seconds=30, label='evidence summary')
            if result.returncode:
                raise ContractError('evidence summary decoder failed')
            return result.stdout
        inventory = decode_summary(query(summary_sql(capture)), capture)
        if not include_queryability:
            # This planner-only relational count was added after the public v1
            # contract. Keep ordinary evidence-summary/1 output compatible with
            # strict older validators rather than silently widening its shape.
            del inventory['counts']['queryable_records']
        health = decode_health(query(HEALTH_SQL))
        recording = bundle.metadata['recording']
        result = {'schema': SCHEMA, 'status': 'ok',
                'bundle': {'sha256': bundle.sha256, 'expected_digest_matched': expected_sha256 is not None,
                           'authenticity': 'unsigned-exporter-metadata'},
                'recording': {key: str(recording[key]) if type(recording[key]) is int else recording[key]
                              for key in ('sha256', 'bytes', 'packets', 'source_bytes', 'excluded_tail_bytes', 'source_phase')},
                'reader_runtime': location.reader_runtime,
                'capture': dict(capture), **inventory,
                'recording_health': _health_summary(health),
                'exporter_reported_health': _health_summary(bundle.metadata['health']),
                'semantics': {
                    'population': 'native-binding-value-records', 'unique_calls': False,
                    'api_counts': 'matching-envelope-and-compatible-completion',
                    'capability_basis': 'reader-known-capture-contract',
                    'zero_count': 'not-observed-in-this-recording',
                    'thread_process_link_is_context_attribution': False,
                    'private_payloads_validated': False, 'private_values_included': False,
                    'active_probes': False, 'browser_launched': False,
                    'source_snapshot': 'fixed-verified-copy',
                    'recording_metadata': 'unsigned-exporter-claims-except-verified-bytes-and-sha256',
                    'attribution_analysis': 'not-performed',
                    'decoder_read': 'end-of-file', 'live_freshness': 'not-applicable',
                    'proves_capture_complete': False, 'proves_server_behavior': False,
                }}
        # Health redaction and result assembly follow the decoder read. Bind
        # the published result after those steps as well as before decoding.
        bundle.source.resolve()
        return result
    finally:
        bundle.close()
