"""Opt-in, closed metadata rows with an exact 16 KiB CLI envelope.

Reuses the value-free exporter/population validator. This is a projection of
existing portable events, never a private/native-column reader or inferred join.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from .contracts import ContractError, RUN_ID_RE
from .evidence_bundle import OpenEvidence
from .evidence_query import MAX_CURSOR_BYTES, _rendered_size, encode_cursor
from .inspection_contract import CAPTURE_OFF
from .inspection_history import history_filters
from .metadata_inventory_query import _absolute_path, _digest, _source_recording
from .metadata_query import MetadataQueryError, _metadata_query, portable_context_selector
from .recording_source import RecordingSource

SCHEMA = 'browser-core.metadata-rows/1'
MAX_OUTPUT_BYTES = 16 * 1024
PARENTS = ('causal_parent_seq', 'callback_parent_seq', 'promise_parent_seq',
           'dynamic_code_parent_seq', 'message_dispatch_parent_seq')


class RowsArgumentError(Exception):
    """Closed parse rejection; never retain argparse's caller-derived text."""


class RowsArgumentParser(argparse.ArgumentParser):
    """Reject parse errors without retaining caller-derived argument text."""
    def error(self, message):
        raise RowsArgumentError() from None


def rows_command(argv):
    return len(argv) >= 2 and argv[0] == 'trace' and argv[1] in ('session-rows', 'evidence-rows')


def emit_argument_error():
    try:
        _emit_rows_json({'schema': SCHEMA, 'status': 'error', 'code': 'query-unavailable'})
    except (ContractError, OSError, KeyboardInterrupt):
        pass
    return 2


def _options(*, apis=(), script_id='', context_kind='', portable_context=None,
             start_ns='', end_ns='', limit=25, cursor=None, rows_version=1):
    if type(rows_version) is not int or rows_version != 1:
        raise ContractError('rows version must be 1')
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ContractError('rows limit must be from 1 to 100')
    if cursor is not None and (type(cursor) is not str or not 1 <= len(cursor) <= MAX_CURSOR_BYTES
            or re.fullmatch(r'[A-Za-z0-9_=-]+', cursor) is None):
        raise ContractError('rows cursor is invalid')
    selector = portable_context_selector(portable_context)
    filters = history_filters(apis=apis, script=script_id, context=context_kind,
                              start_ns=start_ns, end_ns=end_ns)
    if selector is not None:
        filters['portable_context'] = selector
    return filters


def _text(value, maximum, *, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise ContractError('rows identifier is invalid')
    try:
        if len(value.encode('utf-8', errors='strict')) > maximum or any(
                ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ContractError('rows identifier is invalid') from None
    return value


def _decimal(value, *, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not int or not 0 <= value <= 2**63-1:
        raise ContractError('rows integer is invalid')
    return str(value)


def project_row(event):
    """Explicit field copies only: no detail/value/provenance dictionaries."""
    execution = event.get('execution') or {}
    context_id = _text(execution.get('context_id'), 256, nullable=True)
    # Full portable IDs remain exact. They are recording-local, not authority.
    script_id = _text(execution.get('script_id'), 512, nullable=True)
    kind = 'worker' if execution.get('worker_id') else ('window' if execution.get('frame_id') else 'other')
    row = {'seq': _decimal(event['seq']),
        'timestamp_ns': _decimal(event['ts_monotonic_ns']),
        'pid': _decimal(event['process']['pid']),
        'api': _text(event['event']['name'], 256),
        'category': event['event']['category'],
        'context': {'id': context_id, 'kind': kind}, 'script_id': script_id,
        'parents': {key: _decimal(event[key]) for key in PARENTS if event.get(key) is not None},
        'request': None}
    request = event.get('request')
    if request is not None:
        # Even approved portable paths can contain secrets. Retain classification
        # only; never copy path/query/fragment/authority, body hashes or headers.
        url_class = re.fullmatch(
            r'((?:[a-z][a-z0-9+.-]{0,63}:)?(?:same-origin|cross-origin)):(?:/.*|<redacted>)',
            request['url_class'])
        if url_class is None:
            raise ContractError('rows URL classification is invalid')
        row['request'] = {key: request[key] for key in ('id', 'method')}
        row['request']['url_class'] = url_class[1] + ':<redacted>'
        row['request']['body_bytes'] = _decimal(request['body_bytes'])
        row['request']['target_scope'] = request.get('target_scope')
    return row


def metadata_rows(source, *, apis=(), script_id='', context_kind='', portable_context=None,
                  start_ns='', end_ns='', limit=25, cursor=None, rows_version=1,
                  expected_run_id=None, bundle_sha256=None, expected_digest_matched=False):
    """Query a bound value-free source; immutable bundles alone admit cursors."""
    options = dict(apis=apis, script_id=script_id, context_kind=context_kind,
        portable_context=portable_context, start_ns=start_ns, end_ns=end_ns,
        limit=limit, cursor=cursor, rows_version=rows_version)
    return _read_rows(source, options, expected_run_id=expected_run_id,
        bundle_sha256=bundle_sha256, expected_digest_matched=expected_digest_matched)


def _read_rows(source, options, *, expected_run_id=None, bundle_sha256=None,
               expected_digest_matched=False, source_recording=None):
    filters = _options(**options)
    if expected_run_id is not None and (type(expected_run_id) is not str
            or RUN_ID_RE.fullmatch(expected_run_id) is None):
        raise ContractError('rows run binding is invalid')
    _digest(bundle_sha256)
    if type(expected_digest_matched) is not bool or (expected_digest_matched and bundle_sha256 is None):
        raise ContractError('rows digest match declaration is invalid')
    if options.get('cursor') is not None and bundle_sha256 is None:
        raise ContractError('mutable session snapshots have no continuation cursor')
    if not callable(getattr(source, 'resolve', None)):
        raise ContractError('rows require a bound recording source')
    return _metadata_query(source, filters=filters, limit=options.get('limit', 25),
        cursor=options.get('cursor'), expected_run_id=expected_run_id,
        bundle_sha256=bundle_sha256, expected_digest_matched=expected_digest_matched,
        _focused_rows=True, _source_recording=source_recording)


def session_rows(session_path: Path, root: Path, *, expected_run_id: str,
                 reader_executable: Path | None = None, **options):
    _options(**options)
    if options.get('cursor') is not None:
        raise ContractError('mutable session snapshots have no continuation cursor')
    _absolute_path(session_path, 'session')
    _absolute_path(root, 'repository root')
    if (type(expected_run_id) is not str or RUN_ID_RE.fullmatch(expected_run_id) is None
            or session_path.name != expected_run_id + '.json'):
        raise ContractError('rows run binding is invalid')
    if reader_executable is not None:
        _absolute_path(reader_executable, 'reader')
    try:
        return _read_rows(RecordingSource(session_path, root, reader_executable), options,
                          expected_run_id=expected_run_id)
    except ContractError as error:
        if str(error) == 'session has no live recording':
            raise MetadataQueryError('session-recording-unavailable') from None
        if str(error) in {'unsupported recording capture contract',
                          'session value capture must be an object',
                          'session value capture requires the supported local allowlist'}:
            raise MetadataQueryError('capture-contract-unsupported') from None
        raise


def evidence_rows(path: Path, root: Path, reader: Path, *, expected_sha256=None, **options):
    _options(**options)
    for value, label in ((path, 'bundle'), (root, 'repository root'), (reader, 'reader')):
        _absolute_path(value, label)
    _digest(expected_sha256)
    bundle = OpenEvidence(path, root, reader, expected_sha256=expected_sha256)
    try:
        if bundle.metadata['capture'] != CAPTURE_OFF:
            raise ContractError('rows require a value-free capture')
        if type(bundle.metadata.get('recording')) is not dict:
            raise ContractError('rows source recording is unavailable')
        return _read_rows(bundle.source, options, bundle_sha256=bundle.sha256,
            expected_digest_matched=expected_sha256 is not None,
            source_recording=bundle.metadata['recording'])
    finally:
        bundle.close()


def bounded_rows_result(base, rows, *, producer_revision, source_recording=None):
    base = dict(base, producer_chromium_revision=producer_revision)
    if source_recording is not None:
        base['source_recording'] = _source_recording(source_recording, base)
    base['semantics'] = {**base['semantics'],
        'population_validated_before_filtering': True,
        'projection': 'portable-identifiers-parents-request-metadata',
        'request_metadata': 'same-event-only-no-inferred-join',
        'request_url_path': 'always-redacted',
        'unprojected_fields': 'omitted-not-observed-absent',
        'continuation': ('verified-immutable-bundle' if 'bundle' in base
                         else 'collect-immutable-bundle-for-continuation')}
    limit = base['query']['requested_limit']

    def page(count):
        more = len(rows) > count
        cursor = None
        if more and count and 'bundle' in base:
            last = rows[count-1]
            cursor = encode_cursor(base['bundle']['sha256'], base['query']['query_sha256'],
                int(base['query']['snapshot_max_seq']), int(last['timestamp_ns']), int(last['seq']))
        result = dict(base, rows=rows[:count])
        result['query'] = {**base['query'], 'returned_events': count, 'more_available': more,
            'output_limited': count < min(len(rows), limit), 'next_cursor': cursor}
        result['output'] = {'max_rendered_json_bytes': MAX_OUTPUT_BYTES, 'rendered_json_bytes': 0,
            'byte_limit_applied': result['query']['output_limited'],
            'transport_delivery_verified': False, 'transport_truncated': None}
        while True:
            size = _rendered_size(result)
            if size == result['output']['rendered_json_bytes']:
                return result, size
            result['output']['rendered_json_bytes'] = size

    # At most 101 rows are retained. Count the whole envelope including cursor,
    # health, producer/reader identity, bundle origin and the count itself.
    for count in range(min(len(rows), limit), -1, -1):
        result, size = page(count)
        if size <= MAX_OUTPUT_BYTES and (count or not rows):
            return result
    raise ContractError('rows metadata or one complete row exceeds its output limit')


def render_rows_json(result):
    """The exact existing CLI bytes, shared with opt-in artifact writers."""
    try:
        body = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True,
                          allow_nan=False).encode('ascii')
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError('rows CLI output is invalid') from None
    if len(body) > MAX_OUTPUT_BYTES:
        raise ContractError('rows CLI output exceeds byte limit')
    if result.get('status') == 'ok' and result.get('output', {}).get('rendered_json_bytes') != len(body):
        raise ContractError('rows CLI output byte count changed')
    return body


def _emit_rows_json(result):
    body = render_rows_json(result)
    output = getattr(sys.stdout, 'buffer', None)
    if output is None:
        raise ContractError('rows CLI requires binary stdout')
    try:
        written = output.write(body)
        if type(written) is not int or written != len(body):
            raise ContractError('rows CLI output write was incomplete')
        output.flush()
    except OSError:
        raise ContractError('rows CLI output transport failed') from None


def add_rows_commands(trace_sub, root):
    def run(args):
        try:
            selector = None
            if args.portable_pid is not None or args.portable_context_id is not None:
                selector = {'pid': args.portable_pid, 'context_id': args.portable_context_id}
            options = dict(apis=args.api, script_id=args.script_id,
                context_kind=args.context_kind, portable_context=selector,
                start_ns=args.start_ns, end_ns=args.end_ns, limit=args.limit,
                rows_version=args.rows_version)
            if args.rows_source == 'session':
                result = session_rows(args.session.absolute(), root,
                    expected_run_id=args.expected_run_id,
                    reader_executable=args.reader_executable.absolute() if args.reader_executable else None,
                    **options)
            else:
                result = evidence_rows(args.bundle.resolve(), root,
                    args.reader_executable.absolute(), expected_sha256=args.expected_sha256,
                    cursor=args.cursor, **options)
        except MetadataQueryError as error:
            _emit_rows_json({'schema': SCHEMA, 'status': 'error', 'code': error.code})
            return 2
        except (ContractError, OSError):
            _emit_rows_json({'schema': SCHEMA, 'status': 'error', 'code': 'query-unavailable'})
            return 2
        except KeyboardInterrupt:
            _emit_rows_json({'schema': SCHEMA, 'status': 'error', 'code': 'interrupted'})
            return 130
        _emit_rows_json(result)
        return 0

    for source in ('session', 'evidence'):
        parser = trace_sub.add_parser(source + '-rows',
            help='focused value-free portable rows; exact 16 KiB JSON cap')
        if source == 'session':
            parser.add_argument('--session', type=Path, required=True)
            parser.add_argument('--expected-run-id', required=True)
            parser.add_argument('--reader-executable', type=Path)
        else:
            parser.add_argument('--bundle', type=Path, required=True)
            parser.add_argument('--reader-executable', type=Path, required=True)
            parser.add_argument('--expected-sha256')
            parser.add_argument('--cursor', help='opaque continuation from this immutable bundle and exact query')
        parser.add_argument('--api', action='append', default=[],
            help='exact portable event name; repeat up to 32; fetch.request.start carries request metadata')
        parser.add_argument('--script-id', default='')
        parser.add_argument('--context-kind', choices=('window', 'worker', 'other'), default='')
        parser.add_argument('--portable-pid', help='exact recorded PID; requires --portable-context-id')
        parser.add_argument('--portable-context-id', help='exact recorded context ID; requires --portable-pid')
        parser.add_argument('--start-ns', default='')
        parser.add_argument('--end-ns', default='')
        parser.add_argument('--limit', type=int, default=25)
        parser.add_argument('--rows-version', type=int, choices=(1,), default=1)
        parser.set_defaults(func=run, rows_source=source)
