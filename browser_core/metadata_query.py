"""Bounded queries of validated portable events from a value-free recording.

Use the existing exporter so context/causal validation is identical to collection.
This is a full bounded snapshot decode per call, not an incremental value reader.
"""
from __future__ import annotations

from collections import deque
from contextlib import closing
import csv
import hashlib
import io
import re
from pathlib import Path
from tempfile import TemporaryDirectory

from .bounded_process import run_with_bounded_stdout
from .contracts import ContractError
from .control_files import canonical_json_bytes
from .evidence_query import MAX_OUTPUT_BYTES, decode_cursor, encode_cursor, _cli_rendered_size
from .inspection_contract import CAPTURE_OFF, recording_capture
from .inspection_health import HEALTH_SQL, decode_health
from .inspection_history import history_filters
from .live_trace import snapshot_live_trace
from .perfetto import DynamicCallerAmbiguity, bind_perfetto_source_trace, export_perfetto
from .prepared_download import guarded_temporary_directory
from .metadata_inventory import MetadataInventory, analyst_activity as validate_activity
from .trace import iter_trace, scan_validated_trace

SCHEMA = 'browser-core.metadata-query/1'
INVENTORY_SCHEMA = 'browser-core.metadata-query/2'


def portable_context_selector(value):
    """Validate an exact recorded process/context pair, never a realm claim."""
    if value is None:
        return None
    if type(value) is not dict or set(value) != {'pid', 'context_id'}:
        raise ContractError('portable context selector requires exactly pid and context_id')
    pid, context_id = value['pid'], value['context_id']
    if (type(pid) is not str or re.fullmatch(r'[1-9][0-9]{0,18}', pid) is None
            or int(pid) > 2**63 - 1):
        raise ContractError('portable context selector pid must be an exact positive integer ID')
    if type(context_id) is not str or not 1 <= len(context_id) <= 256:
        raise ContractError('portable context selector context_id is invalid')
    try:
        if (len(context_id.encode('utf-8', errors='strict')) > 256
                or any(ord(char) < 32 or ord(char) == 127 for char in context_id)):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ContractError('portable context selector context_id is invalid') from None
    # Portable IDs include synthetic labels as well as native tokens. Do not
    # apply the private reader's hexadecimal grammar or case normalization.
    return {'pid': pid, 'context_id': context_id}


def metadata_options(metadata_version, analyst_activity):
    """Select a closed output contract before touching a recording."""
    if type(metadata_version) is not int or metadata_version not in (1, 2):
        raise ContractError('metadata version must be 1 or 2')
    activities = validate_activity(analyst_activity)
    if metadata_version == 1 and activities:
        raise ContractError('analyst activity declarations require metadata version 2')
    return (SCHEMA if metadata_version == 1 else INVENTORY_SCHEMA), activities


class MetadataQueryError(ContractError):
    """A closed code is safe to expose; exception details and paths are not."""
    def __init__(self, code, *, diagnostic=None):
        if code not in {'private-values-disabled', 'metadata-query-revision-unavailable',
                        'metadata-recording-contains-values', 'metadata-realm-filter-unavailable',
                        'metadata-attribution-ambiguous', 'session-recording-unavailable',
                        'capture-contract-unsupported'}:
            raise ValueError('unknown metadata diagnostic')
        self.code = code
        self.diagnostic = diagnostic
        super().__init__(code)


def _query(executable, path, sql, *, maximum=128*1024):
    result = run_with_bounded_stdout(
        [str(executable.with_name('trace_processor_shell.exe')), 'query', str(path), sql],
        maximum_stdout=maximum, timeout_seconds=30, label='metadata recording diagnostics')
    if result.returncode:
        raise ContractError('metadata recording diagnostics unavailable')
    return result.stdout


def require_value_free_recording(executable, path):
    """Count only; never select, decode or expose private payload fields."""
    body = _query(executable, path,
        "SELECT COUNT(*) AS private_records FROM slice WHERE name='BrowserCoreInspection.BindingValue'",
        maximum=4096)
    try:
        reader = csv.DictReader(io.StringIO(body.decode('utf-8', errors='strict')), strict=True)
        rows = list(reader)
        if (reader.fieldnames != ['private_records'] or len(rows)!=1
                or set(rows[0])!={'private_records'} or not rows[0]['private_records'].isdigit()):
            raise ValueError()
        if rows[0]['private_records']!='0':
            raise MetadataQueryError('metadata-recording-contains-values')
    except MetadataQueryError:
        raise
    except (ValueError, UnicodeError, csv.Error):
        raise ContractError('metadata recording value-count unavailable') from None


def export_metadata(*args, **kwargs):
    try:
        return export_perfetto(*args, **kwargs)
    except DynamicCallerAmbiguity as error:
        raise MetadataQueryError('metadata-attribution-ambiguous', diagnostic=error.diagnostic) from None
    except ContractError as error:
        if str(error)=='native dynamic code caller script is ambiguous':
            raise MetadataQueryError('metadata-attribution-ambiguous') from None
        raise


def _matches(event, filters):
    execution = event.get('execution') or {}
    if selector := filters.get('portable_context'):
        if (str(event['process']['pid']) != selector['pid']
                or execution.get('context_id') != selector['context_id']):
            return False
    if filters.get('apis') and event['event']['name'] not in filters['apis']:
        return False
    script = execution.get('script_id') or ''
    number = script.rsplit(':', 1)[-1] if script.startswith('v8:') else ''
    if filters['script'] and number != filters['script']:
        return False
    kind = 'worker' if execution.get('worker_id') else ('window' if execution.get('frame_id') else 'other')
    if filters['context'] and kind != filters['context']:
        return False
    if scope := filters.get('scope'):
        if (str(event['process']['pid']) != scope['pid']
                or str(execution.get('context_id', '')).upper() != scope['context_id']
                or str(execution.get('world_id', '')) != scope['realm_id']):
            return False
    timestamp = event['ts_monotonic_ns']
    return not (('start_ns' in filters and timestamp < int(filters['start_ns']))
                or ('end_ns' in filters and timestamp > int(filters['end_ns'])))


def metadata_query(source, *, filters, limit, include_values=False, expected_run_id=None,
                   cursor=None, bundle_sha256=None, expected_digest_matched=False,
                   analyst_activity=(), metadata_version=1, portable_context=None):
    return _metadata_query(source, filters=filters, limit=limit,
        include_values=include_values, expected_run_id=expected_run_id, cursor=cursor,
        bundle_sha256=bundle_sha256, expected_digest_matched=expected_digest_matched,
        analyst_activity=analyst_activity, metadata_version=metadata_version,
        portable_context=portable_context)


def _metadata_query(source, *, filters, limit, include_values=False, expected_run_id=None,
                    cursor=None, bundle_sha256=None, expected_digest_matched=False,
                    analyst_activity=(), metadata_version=1, portable_context=None,
                    _inventory_only=False, _focused_rows=False, _source_recording=None,
                    _compare=None):
    # Only the separate inventory API can select this private implementation
    # mode. Public query versions, limits and cursor bytes remain unchanged.
    schema, activities = metadata_options(metadata_version, () if _compare is not None else analyst_activity)
    if _compare is not None:
        activities = validate_activity(analyst_activity)
        schema = _compare.schema
    if _inventory_only:
        from .metadata_inventory_query import SCHEMA as schema
    if _focused_rows:
        from .metadata_rows import SCHEMA as schema, project_row
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ContractError('metadata query limit must be from 1 to 100')
    if type(filters) is not dict or any(type(key) is not str for key in filters):
        raise ContractError('metadata query filters are invalid')
    selector = portable_context_selector(portable_context)
    if 'portable_context' in filters:
        if selector is not None or filters['portable_context'] is None:
            raise ContractError('portable context selector is duplicated or invalid')
        selector = portable_context_selector(filters['portable_context'])
    if selector is not None:
        filters = {**filters, 'portable_context': selector}
    # Direct callers share this query path with the CLI. Reject selectors that
    # the portable matcher cannot apply, rather than reporting them as active.
    plain_filters = {key: value for key, value in filters.items() if key != 'portable_context'}
    try:
        canonical_filters = history_filters(
            search=plain_filters['search'], script=plain_filters['script'],
            context=plain_filters['context'], scope=plain_filters.get('scope'),
            start_ns=plain_filters.get('start_ns', ''), end_ns=plain_filters.get('end_ns', ''),
            apis=plain_filters.get('apis', ()))
    except (ContractError, KeyError, TypeError):
        raise ContractError('metadata query filters are invalid') from None
    if plain_filters != canonical_filters or canonical_filters['search']:
        raise ContractError('metadata query filters are invalid or unsupported')
    filters = canonical_filters
    if selector is not None:
        filters = {**filters, 'portable_context': selector}
    if bundle_sha256 is not None and (type(bundle_sha256) is not str
            or re.fullmatch(r'[0-9a-f]{64}', bundle_sha256) is None):
        raise ContractError('metadata bundle digest is invalid')
    if type(expected_digest_matched) is not bool or (expected_digest_matched and bundle_sha256 is None):
        raise ContractError('metadata digest match declaration is invalid')
    if type(include_values) is not bool:
        raise ContractError('metadata query value selection is invalid')
    if include_values:
        raise MetadataQueryError('private-values-disabled')
    if filters.get('scope'):
        # Portable metadata retains context IDs but does not record world IDs.
        # Refuse this private-reader selector instead of claiming zero matches.
        raise MetadataQueryError('metadata-realm-filter-unavailable')
    location = source.resolve()
    source_phase, source_path = location.phase, location.path
    def require_source_binding():
        after = source.resolve()
        if source_phase != 'live-prefix' and (after.phase != source_phase or after.path != source_path):
            raise ContractError('metadata query source phase or path changed')
        if after.session != location.session or after.reader_runtime != location.reader_runtime:
            # Lifecycle state may change in a live session while a fixed copy is read.
            old = {k:v for k,v in location.session.items() if k not in ('state','stopped_at')}
            new = {k:v for k,v in after.session.items() if k not in ('state','stopped_at')}
            if old != new or after.reader_runtime != location.reader_runtime:
                raise ContractError('metadata query source identity changed')
    if recording_capture(location.session) != CAPTURE_OFF:
        raise ContractError('metadata query requires a value-free capture')
    run_id = location.session['run_id']
    if expected_run_id is not None and expected_run_id != run_id:
        raise ContractError('metadata query run binding changed')
    revision = location.session.get('chromium_revision')
    if revision is None:
        raise MetadataQueryError('metadata-query-revision-unavailable')
    query_contract = {'schema':schema, 'filters':filters, 'limit':limit,
         **({'analyst_activity':activities} if activities else {}),
         'ordering':'timestamp-descending-then-sequence-descending'}
    if _inventory_only:
        query_contract = {'schema':schema, 'filters':filters, 'analyst_activity':activities}
    if _compare is not None:
        query_contract = {'schema':schema, 'filters':filters, 'compare':_compare.contract}
    query_sha256 = hashlib.sha256(canonical_json_bytes(query_contract)).hexdigest()
    if cursor is not None and bundle_sha256 is None:
        raise ContractError('mutable session snapshots have no continuation cursor')
    before = None
    if cursor is not None:
        before = decode_cursor(cursor, bundle_sha256=bundle_sha256, query_sha256=query_sha256)
    with snapshot_live_trace(location.path, parts=getattr(source, 'parts', None)) as snapshot:
        if source_phase == 'finalized-recording' and snapshot.incomplete_tail_bytes:
            raise ContractError('finalized recording has an incomplete packet')
        from . import __version__ as package_version
        from . import population_cache
        from .metadata_rows import project_row as validate_row
        cache_key = population_cache.cache_key(
            phase=source_phase, snapshot_sha256=snapshot.sha256, run_id=run_id,
            revision=revision, reader_runtime=location.reader_runtime,
            package_version=package_version)
        cached = population_cache.load(cache_key)

        def consume(events_for_scan, all_events):
            """Run the shared selection loop over one event source."""
            if _compare is not None:
                _compare.prepare(all_events)
            selected = deque(maxlen=0 if _inventory_only or _compare is not None else limit+1)
            inventory = MetadataInventory() if metadata_version == 2 else None
            total = highwater = 0
            with closing(all_events() if _compare is not None else events_for_scan()) as trace_events:
                for event in trace_events:
                    if event['run_id'] != run_id:
                        raise ContractError('metadata query event run binding changed')
                    highwater = event['seq']
                    # Validate the closed projection over the entire population too,
                    # never hide malformed identifiers behind a filter/page boundary.
                    # (A cache entry exists only after this held for every event.)
                    projected = project_row(event) if _focused_rows else event
                    if inventory is not None:
                        inventory.validate_identity(event)
                    if _compare is not None:
                        _compare.add(event)
                    if not _matches(event, filters):
                        continue
                    total += 1
                    if inventory is not None:
                        inventory.add(event)
                    if not _inventory_only and (before is None or (event['ts_monotonic_ns'], event['seq']) < before[1:]):
                        selected.append(projected)
            return selected, inventory, total, highwater

        if cached is not None:
            try:
                selected, inventory, total, _ = consume(
                    lambda: cached.events(filters), lambda: cached.events(None))
            except (OSError, ValueError, KeyError, TypeError):
                cached = None  # Corrupt entry: fall back to a fresh decode.
            else:
                highwater = cached.highwater
                health = cached.health
                if before is not None and before[0] != highwater:
                    raise ContractError('metadata query cursor snapshot changed')
        if cached is None:
            require_value_free_recording(location.executable, snapshot.path)
            with guarded_temporary_directory(
                    TemporaryDirectory(prefix='browser-core-metadata-query-'),
                    label='metadata query directory') as folder:
                path = Path(folder)/'events.jsonl'
                exported = export_metadata(location.executable.with_name('trace_processor_shell.exe'),
                    snapshot.path, path, run_id, revision)['report']
                if exported['source_trace']['sha256'] != snapshot.sha256:
                    raise ContractError('metadata query source digest changed')
                normalized_binding = bind_perfetto_source_trace(path)
                # Per-record decoding is not population validation. In particular,
                # late parent/context edges must fail even if filters/page bounds
                # would hide them. Match collected reports' full validator/limits.
                validation_digest = hashlib.sha256()
                scan_validated_trace(path, lambda _event: None,
                                     hash_update=validation_digest.update)
                if validation_digest.hexdigest() != normalized_binding['sha256']:
                    raise ContractError('metadata query normalized trace changed during validation')

                def bound_events():
                    observed_digest = hashlib.sha256()
                    with closing(iter_trace(path, hash_update=observed_digest.update)) as events:
                        yield from events
                    if observed_digest.hexdigest() != normalized_binding['sha256']:
                        raise ContractError('metadata query normalized trace changed during scan')

                selected, inventory, total, highwater = consume(bound_events, bound_events)
                if before is not None and before[0] != highwater:
                    raise ContractError('metadata query cursor snapshot changed')
                if bind_perfetto_source_trace(path) != normalized_binding:
                    raise ContractError('metadata query normalized trace changed between passes')
                health = decode_health(_query(location.executable, snapshot.path, HEALTH_SQL))

                def validate_for_cache(event):
                    if event['run_id'] != run_id:
                        raise ContractError('metadata query event run binding changed')
                    validate_row(event)
                    MetadataInventory.validate_identity(event)

                population_cache.store(cache_key, path, health=health, validate=validate_for_cache)
        events = list(reversed(selected))
        base = {'schema':schema, 'status':'ok', 'run_id':run_id, 'capture':dict(CAPTURE_OFF),
            'reader_runtime':location.reader_runtime,
            'snapshot':{'sha256':snapshot.sha256, 'bytes':str(snapshot.bytes),
                'source_bytes':str(snapshot.source_bytes), 'packets':str(snapshot.packets),
                'excluded_tail_bytes':str(snapshot.incomplete_tail_bytes), 'source_phase':source_phase},
            'recording_health':health,
            'query':{'filters':filters, 'query_sha256':query_sha256, 'requested_limit':limit,
                'matching_events':str(total), 'snapshot_max_seq':str(highwater),
                'ordering':'timestamp-descending-then-sequence-descending'},
            'semantics':{'private_values_included':False, 'private_value_records':0,
                'population':'validated-portable-native-events', 'full_snapshot_decode':True,
                'api_filter':'exact-portable-event-name', 'script_id':'native-v8-script-number',
                'context_kind':'frame-worker-marker-or-other',
                'parent_events_may_be_outside_page':True,
                'continuation_supported':bundle_sha256 is not None,
                'cursor_authenticated':False, 'cursor_authorizes_actions':False,
                'query_launched_browser':False, 'active_probe':False,
                'proves_capture_complete':False, 'server_side_architecture_observed':False}}
        if inventory is not None:
            base['inventory'] = inventory.result(activities)
        if bundle_sha256 is not None:
            base['bundle']={'sha256':bundle_sha256, 'expected_digest_matched':expected_digest_matched,
                            'authenticity':'unsigned-exporter-metadata'}
        if _compare is not None:
            result = _compare.result(base, producer_revision=revision)
            require_source_binding()
            return result
        if _inventory_only:
            from .metadata_inventory_query import bounded_inventory_result
            result = bounded_inventory_result(base, producer_revision=revision)
            require_source_binding()
            return result
        if _focused_rows:
            from .metadata_rows import bounded_rows_result
            result = bounded_rows_result(base, events, producer_revision=revision,
                                         source_recording=_source_recording)
            require_source_binding()
            return result
        if _source_recording is not None and metadata_version == 2:
            from .metadata_inventory_query import _source_recording as bind_source_recording
            base['source_recording'] = bind_source_recording(_source_recording, base)
        def page(count):
            output = dict(base, events=events[:count])
            more = len(events) > count
            next_cursor = None
            if more and count and bundle_sha256 is not None:
                last=events[count-1]
                next_cursor=encode_cursor(bundle_sha256, query_sha256, highwater,
                                          last['ts_monotonic_ns'], last['seq'])
            output['query']={**base['query'], 'returned_events':count, 'more_available':more,
                'output_limited':count<min(len(events),limit), 'next_cursor':next_cursor}
            return output
        count=min(len(events),limit)
        while count and _cli_rendered_size(page(count))>MAX_OUTPUT_BYTES:
            count-=1
        result=page(count)
        if (events and count==0) or _cli_rendered_size(result)>MAX_OUTPUT_BYTES:
            raise ContractError('metadata query result exceeds its output limit')
        require_source_binding()
        return result
