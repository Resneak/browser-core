"""Inventory-only discovery over the same fully validated metadata snapshot.

Separate commands and schema preserve the closed query v1/v2 contracts. No
event rows, cursor, private reader, browser authority or source writes exist.
"""
from __future__ import annotations

from pathlib import Path
import json
import re
import sys

from .contracts import ContractError, RUN_ID_RE
from .evidence_bundle import OpenEvidence
from .evidence_contract import MAX_RECORDING_BYTES, PHASES
from .evidence_query import _rendered_size
from .inspection_contract import CAPTURE_OFF
from .inspection_history import history_filters
from .metadata_inventory import analyst_activity as validate_activity
from .metadata_query import _metadata_query, MetadataQueryError, portable_context_selector
from .recording_source import RecordingSource

SCHEMA = 'browser-core.metadata-inventory-query/1'
MAX_INVENTORY_OUTPUT_BYTES = 16 * 1024


def _options(*, apis=(), script_id='', context_kind='', portable_context=None,
             start_ns='', end_ns='', analyst_activity=(), inventory_version=1):
    # Validate every option before opening a source, including bool-as-int.
    if type(inventory_version) is not int or inventory_version != 1:
        raise ContractError('inventory version must be 1')
    activities = validate_activity(analyst_activity)
    selector = portable_context_selector(portable_context)
    filters = history_filters(apis=apis, script=script_id, context=context_kind,
                              start_ns=start_ns, end_ns=end_ns)
    if selector is not None:
        filters['portable_context'] = selector
    return filters, activities


def _digest(value):
    if value is not None and (type(value) is not str or re.fullmatch(r'[0-9a-f]{64}', value) is None):
        raise ContractError('inventory digest is invalid')


def _absolute_path(value, label):
    if not isinstance(value, Path) or not value.is_absolute():
        raise ContractError(f'inventory {label} must be an absolute path')


def metadata_inventory_query(source, *, apis=(), script_id='', context_kind='',
                             portable_context=None, start_ns='', end_ns='',
                             analyst_activity=(), inventory_version=1,
                             expected_run_id=None, bundle_sha256=None,
                             expected_digest_matched=False):
    """Inventory an already-bound metadata source; never return event rows."""
    filters, activities = _options(apis=apis, script_id=script_id, context_kind=context_kind,
        portable_context=portable_context, start_ns=start_ns, end_ns=end_ns,
        analyst_activity=analyst_activity, inventory_version=inventory_version)
    if expected_run_id is not None and (type(expected_run_id) is not str or RUN_ID_RE.fullmatch(expected_run_id) is None):
        raise ContractError('inventory run binding is invalid')
    _digest(bundle_sha256)
    if type(expected_digest_matched) is not bool or (expected_digest_matched and bundle_sha256 is None):
        raise ContractError('inventory digest match declaration is invalid')
    if not callable(getattr(source, 'resolve', None)):
        raise ContractError('inventory requires a bound recording source')
    return _metadata_query(source, filters=filters, limit=1, metadata_version=2,
        analyst_activity=activities, expected_run_id=expected_run_id,
        bundle_sha256=bundle_sha256, expected_digest_matched=expected_digest_matched,
        _inventory_only=True)


def session_inventory(session_path: Path, root: Path, *, expected_run_id: str,
                      reader_executable: Path | None = None, apis=(), script_id='',
                      context_kind='', portable_context=None, start_ns='', end_ns='',
                      analyst_activity=(), inventory_version=1):
    """Read one fixed snapshot of the explicitly bound live or stopped run."""
    options = dict(apis=apis, script_id=script_id, context_kind=context_kind,
        portable_context=portable_context, start_ns=start_ns, end_ns=end_ns,
        analyst_activity=analyst_activity, inventory_version=inventory_version)
    _options(**options)
    _absolute_path(session_path, 'session')
    _absolute_path(root, 'repository root')
    if (type(expected_run_id) is not str or RUN_ID_RE.fullmatch(expected_run_id) is None
            or session_path.name != expected_run_id + '.json'):
        raise ContractError('inventory run binding is invalid')
    if reader_executable is not None:
        _absolute_path(reader_executable, 'reader')
    source = RecordingSource(session_path, root, reader_executable)
    try:
        return metadata_inventory_query(source, expected_run_id=expected_run_id, **options)
    except ContractError as error:
        if str(error) == 'session has no live recording':
            raise MetadataQueryError('session-recording-unavailable') from None
        if str(error) in {'unsupported recording capture contract',
                          'session value capture must be an object',
                          'session value capture requires the supported local allowlist'}:
            raise MetadataQueryError('capture-contract-unsupported') from None
        raise


def evidence_inventory(path: Path, root: Path, reader: Path, *, expected_sha256=None,
                       apis=(), script_id='', context_kind='', portable_context=None,
                       start_ns='', end_ns='', analyst_activity=(), inventory_version=1):
    """Inventory an immutable bundle verified by the existing bounded opener."""
    options = dict(apis=apis, script_id=script_id, context_kind=context_kind,
        portable_context=portable_context, start_ns=start_ns, end_ns=end_ns,
        analyst_activity=analyst_activity, inventory_version=inventory_version)
    _options(**options)
    for value, label in ((path, 'bundle'), (root, 'repository root'), (reader, 'reader')):
        _absolute_path(value, label)
    _digest(expected_sha256)
    bundle = OpenEvidence(path, root, reader, expected_sha256=expected_sha256)
    try:
        if bundle.metadata['capture'] != CAPTURE_OFF:
            raise ContractError('inventory requires a value-free capture')
        result = metadata_inventory_query(bundle.source, bundle_sha256=bundle.sha256,
            expected_digest_matched=expected_sha256 is not None, **options)
        result['source_recording'] = _source_recording(bundle.metadata.get('recording'), result)
        result = _bound_inventory_output(result)
        bundle.source.resolve()
        return result
    finally:
        bundle.close()


def _source_recording(recording, result):
    """Bind verified export-origin facts to the separately verified reopened copy."""
    fields = {'run_id', 'sha256', 'bytes', 'packets', 'source_bytes',
              'excluded_tail_bytes', 'source_phase'}
    if type(recording) is not dict or set(recording) != fields:
        raise ContractError('inventory source recording binding is invalid')
    for key in ('bytes', 'packets', 'source_bytes', 'excluded_tail_bytes'):
        maximum = 40_000_000 if key == 'packets' else MAX_RECORDING_BYTES
        if type(recording[key]) is not int or not 0 <= recording[key] <= maximum:
            raise ContractError('inventory source recording binding is invalid')
    snapshot = result['snapshot']
    if (recording['run_id'] != result['run_id']
            or recording['sha256'] != snapshot['sha256']
            or type(recording['source_phase']) is not str or recording['source_phase'] not in PHASES
            or recording['bytes'] + recording['excluded_tail_bytes'] != recording['source_bytes']
            or (recording['source_phase'] == 'finalized-recording' and recording['excluded_tail_bytes'] != 0)
            or str(recording['bytes']) != snapshot['bytes']
            or str(recording['packets']) != snapshot['packets']
            or snapshot['source_phase'] != 'finalized-recording'
            or snapshot['source_bytes'] != snapshot['bytes']
            or snapshot['excluded_tail_bytes'] != '0'):
        raise ContractError('inventory source recording binding is invalid')
    return {key: str(value) if type(value) is int else value for key, value in recording.items()}


def bounded_inventory_result(base, *, producer_revision):
    """Trim only summary rows; retain identity, health and exact population totals."""
    result = dict(base)
    result['producer_chromium_revision'] = producer_revision
    result['query'] = {key: value for key, value in base['query'].items()
                       if key not in ('requested_limit', 'ordering')}
    result['query']['returned_events'] = 0
    result['semantics'] = {key: value for key, value in base['semantics'].items()
                           if key not in ('parent_events_may_be_outside_page',
                                          'cursor_authenticated', 'cursor_authorizes_actions')}
    result['semantics'].update(continuation_supported=False, event_rows_included=False,
                               population_validated_before_filtering=True)
    result['output'] = {'max_rendered_json_bytes': MAX_INVENTORY_OUTPUT_BYTES,
        'rendered_json_bytes': 0, 'byte_limit_applied': False,
        'summaries_truncated': False, 'transport_delivery_verified': False,
        'transport_truncated': None}
    return _bound_inventory_output(result)


def _bound_inventory_output(result):
    # Can run again after evidence_inventory attaches source_recording. Keep
    # prior pruning flags and exact counts; include the origin in the byte cap.
    def groups():
        inventory = result['inventory']
        return [inventory['contexts'], inventory['apis'],
                *(row['apis'] for row in inventory['contexts']['groups'])]

    while True:
        result['output']['summaries_truncated'] = any(group['truncated'] for group in groups())
        # The count includes its own decimal encoding. The inventory-only CLI
        # writes these exact ASCII/LF bytes without an additional terminal newline.
        while True:
            size = _rendered_size(result)
            if result['output']['rendered_json_bytes'] == size:
                break
            result['output']['rendered_json_bytes'] = size
        if size <= MAX_INVENTORY_OUTPUT_BYTES:
            return result
        candidates = [group for group in groups() if group['groups']]
        if not candidates:
            raise ContractError('inventory metadata exceeds its output limit')
        # Deterministic pruning never abbreviates an exact selector or changes
        # total_groups/events. Prefer removing the most expensive remaining row.
        group = max(candidates, key=lambda item: _rendered_size(item['groups'][-1]))
        group['groups'].pop()
        group['reported_groups'] = len(group['groups'])
        group['truncated'] = group['reported_groups'] < group['total_groups']
        result['output']['byte_limit_applied'] = True


def _emit_inventory_json(result):
    """Emit exact counted ASCII/LF JSON; bypass Windows TextIO newline translation."""
    try:
        body = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True,
                          allow_nan=False).encode('ascii')
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError('inventory CLI output is invalid') from None
    if len(body) > MAX_INVENTORY_OUTPUT_BYTES:
        raise ContractError('inventory CLI output exceeds byte limit')
    if result.get('status') == 'ok' and result.get('output', {}).get('rendered_json_bytes') != len(body):
        raise ContractError('inventory CLI output byte count changed')
    # No text fallback: an unknown wrapper could translate internal newlines or
    # change encoding, invalidating both the count and cap. Normal CLI stdout,
    # pipes and pytest's captured stream all provide the binary interface.
    output = getattr(sys.stdout, 'buffer', None)
    if output is None:
        raise ContractError('inventory CLI requires binary stdout')
    try:
        written = output.write(body)
        if type(written) is not int or written != len(body):
            raise ContractError('inventory CLI output write was incomplete')
        output.flush()
    except OSError:
        raise ContractError('inventory CLI output transport failed') from None


INVENTORY_COMMANDS = ('session-inventory', 'evidence-inventory')


def inventory_command(argv):
    return len(argv) >= 2 and argv[0] == 'trace' and argv[1] in INVENTORY_COMMANDS


def emit_inventory_argument_error():
    try:
        _emit_inventory_json({'schema': SCHEMA, 'status': 'error', 'code': 'query-unavailable'})
    except (ContractError, OSError, KeyboardInterrupt):
        pass
    return 2


def add_inventory_commands(trace_sub, root):
    """Keep discovery separate from legacy queries and their closed options."""
    def run(args):
        try:
            selector = None
            if args.portable_pid is not None or args.portable_context_id is not None:
                selector = {'pid': args.portable_pid, 'context_id': args.portable_context_id}
            options = dict(apis=args.api, script_id=args.script_id,
                context_kind=args.context_kind, portable_context=selector,
                start_ns=args.start_ns, end_ns=args.end_ns,
                analyst_activity=args.analyst_activity, inventory_version=args.inventory_version)
            if args.inventory_source == 'session':
                result = session_inventory(args.session.absolute(), root,
                    expected_run_id=args.expected_run_id,
                    reader_executable=args.reader_executable.absolute() if args.reader_executable else None,
                    **options)
            else:
                result = evidence_inventory(args.bundle.resolve(), root,
                    args.reader_executable.absolute(), expected_sha256=args.expected_sha256, **options)
        except MetadataQueryError as error:
            _emit_inventory_json({'schema': SCHEMA, 'status': 'error', 'code': error.code})
            return 2
        except (ContractError, OSError):
            _emit_inventory_json({'schema': SCHEMA, 'status': 'error', 'code': 'query-unavailable'})
            return 2
        except KeyboardInterrupt:
            _emit_inventory_json({'schema': SCHEMA, 'status': 'error', 'code': 'interrupted'})
            return 130
        _emit_inventory_json(result)
        return 0

    for source in ('session', 'evidence'):
        parser = trace_sub.add_parser(source + '-inventory',
            help='inventory-only validated metadata; no event rows; 16 KiB JSON cap')
        if source == 'session':
            parser.add_argument('--session', type=Path, required=True)
            parser.add_argument('--expected-run-id', required=True)
            parser.add_argument('--reader-executable', type=Path)
        else:
            parser.add_argument('--bundle', type=Path, required=True)
            parser.add_argument('--reader-executable', type=Path, required=True)
            parser.add_argument('--expected-sha256')
        parser.add_argument('--api', action='append', default=[], help='exact portable event name; repeat up to 32')
        parser.add_argument('--script-id', default='')
        parser.add_argument('--context-kind', choices=('window', 'worker', 'other'), default='')
        parser.add_argument('--portable-pid', help='exact recorded PID; requires --portable-context-id')
        parser.add_argument('--portable-context-id', help='exact recorded context ID; requires --portable-pid')
        parser.add_argument('--start-ns', default='')
        parser.add_argument('--end-ns', default='')
        parser.add_argument('--analyst-activity', action='append', default=[],
            choices=('browser-control', 'page-evaluation', 'source-acquisition'))
        parser.add_argument('--inventory-version', type=int, choices=(1,), default=1)
        parser.set_defaults(func=run, inventory_source=source)
