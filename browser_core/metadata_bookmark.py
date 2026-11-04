"""Bounded, opt-in bookmarks of existing immutable metadata-row responses.

No browser is launched. A trusted external manifest digest binds the citation;
local verification is integrity only, and replay additionally proves exact bytes
under the supplied immutable bundle and reader. Neither proves caller delivery.
"""
from __future__ import annotations

import hashlib
from itertools import islice
from pathlib import Path
import sys

from .contracts import ContractError
from .control_files import (
    canonical_json_bytes, decode_strict_json_bytes,
    publish_bytes_exclusive_result, read_bounded_control_snapshot_result,
    remove_control_conditionally,
)
from .evidence_query import decode_cursor, encode_cursor
from .metadata_inventory_query import _absolute_path, _digest
from . import metadata_rows as rows
from .owned_paths import directory_ancestry_binding, directory_identity

SCHEMA = 'browser-core.metadata-bookmark/1'
RECEIPT_SCHEMA = 'browser-core.metadata-bookmark-receipt/1'
MAX_MANIFEST_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 4096
RESPONSE_NAME = 'rows.json'
MANIFEST_NAME = 'manifest.json'
COMMANDS = ('evidence-bookmark', 'bookmark-verify', 'bookmark-replay')
LIMITATIONS = {
    'prose_claim_verified': False,
    'causality_inferred': False,
    'capture_completeness_verified': False,
    'source_authenticity_verified': False,
    'transport_delivery_verified': False,
    'transport_truncated': None,
}


def bookmark_command(argv):
    return len(argv) >= 2 and argv[0] == 'trace' and argv[1] in COMMANDS


def _required_digest(value):
    _digest(value)
    if value is None:
        raise ContractError('bookmark requires a trusted digest')


def _hash(body):
    return hashlib.sha256(body).hexdigest()


def _read(path, maximum):
    snapshot = read_bounded_control_snapshot_result(
        path, maximum=maximum, label='bookmark artifact', require_single_link=True)
    if snapshot.state != 'complete' or snapshot.body is None:
        raise ContractError('bookmark artifact is unavailable')
    return snapshot


def _validate_rows(root, document):
    # Only a fixed local schema is loaded; no external schema retrieval occurs.
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import ValidationError, SchemaError
    body = _read(root / 'schemas' / 'metadata-rows-v1.schema.json', 128 * 1024).body
    schema = decode_strict_json_bytes(body, label='rows schema')
    try:
        Draft202012Validator(schema).validate(document)
    except (ValidationError, SchemaError, RecursionError):
        raise ContractError('bookmark rows contract is invalid') from None
    if (document.get('status') != 'ok' or 'bundle' not in document
            or 'source_recording' not in document
            or document['bundle']['expected_digest_matched'] is not True
            or document['semantics']['continuation'] != 'verified-immutable-bundle'
            or document['semantics']['continuation_supported'] is not True):
        raise ContractError('bookmark requires verified immutable metadata rows')


def _replay_options(replay):
    if type(replay) is not dict or set(replay) != {
            'rows_version', 'expected_bundle_sha256', 'filters', 'limit', 'input_cursor'}:
        raise ContractError('bookmark replay fields are invalid')
    _required_digest(replay['expected_bundle_sha256'])
    filters = replay['filters']
    if type(filters) is not dict:
        raise ContractError('bookmark selectors are invalid')
    options = dict(apis=filters.get('apis', ()), script_id=filters.get('script', ''),
        context_kind=filters.get('context', ''), portable_context=filters.get('portable_context'),
        start_ns=filters.get('start_ns', ''), end_ns=filters.get('end_ns', ''),
        limit=replay['limit'], cursor=replay['input_cursor'], rows_version=replay['rows_version'])
    if rows._options(**options) != filters:
        raise ContractError('bookmark selectors are not canonical')
    return options


def _manifest(root, result, response_body, replay):
    _validate_rows(root, result)
    options = _replay_options(replay)
    if rows.render_rows_json(result) != response_body:
        raise ContractError('bookmark response bytes changed')
    query = result['query']
    if (result['bundle']['sha256'] != replay['expected_bundle_sha256']
            or query['filters'] != replay['filters']
            or query['requested_limit'] != options['limit']):
        raise ContractError('bookmark replay binding changed')
    contract = {'schema': rows.SCHEMA, 'filters': replay['filters'],
        'limit': replay['limit'], 'ordering': query['ordering']}
    if query['query_sha256'] != _hash(canonical_json_bytes(contract)):
        raise ContractError('bookmark query digest changed')
    cursor = replay['input_cursor']
    before = None
    if cursor is not None:
        before = decode_cursor(cursor, bundle_sha256=result['bundle']['sha256'],
                               query_sha256=query['query_sha256'])
        if before[0] != int(query['snapshot_max_seq']):
            raise ContractError('bookmark cursor snapshot changed')
    selected = result['rows']
    ids = [row['seq'] for row in selected]
    positions = [(int(row['timestamp_ns']), int(row['seq'])) for row in selected]
    if (len(set(ids)) != len(ids) or positions != sorted(positions, reverse=True)
            or any(int(seq) > int(query['snapshot_max_seq']) for seq in ids)
            or (before is not None and any(position >= before[1:] for position in positions))
            or query['returned_events'] != len(selected)
            or len(selected) > query['requested_limit']
            or int(query['matching_events']) < len(selected)
            or (query['more_available'] and int(query['matching_events']) <= len(selected))
            or query['output_limited'] != (query['more_available'] and len(selected) < query['requested_limit'])
            or query['output_limited'] != result['output']['byte_limit_applied']
            or query['more_available'] != (query['next_cursor'] is not None)):
        raise ContractError('bookmark page binding is invalid')
    if query['more_available']:
        if not selected or query['next_cursor'] != encode_cursor(
                result['bundle']['sha256'], query['query_sha256'],
                int(query['snapshot_max_seq']), *positions[-1]):
            raise ContractError('bookmark continuation changed')
    elif cursor is None and int(query['matching_events']) != len(selected):
        raise ContractError('bookmark complete page count changed')
    page = {'state': 'complete' if cursor is None and not query['more_available'] else 'partial',
        'input_cursor_present': cursor is not None, 'more_available': query['more_available'],
        'next_cursor': query['next_cursor']}
    return {'schema': SCHEMA,
        'response': {'name': RESPONSE_NAME, 'sha256': _hash(response_body), 'bytes': len(response_body)},
        'replay': replay,
        'citation': {key: value for key, value in result.items() if key not in {'schema', 'status', 'rows'}},
        'row_ids': ids, 'page': page, 'limitations': dict(LIMITATIONS)}


def _manifest_bytes(manifest):
    body = canonical_json_bytes(manifest)
    if len(body) > MAX_MANIFEST_BYTES:
        raise ContractError('bookmark manifest exceeds its byte limit')
    return body


def _receipt(manifest, manifest_body, operation):
    result = {'schema': RECEIPT_SCHEMA, 'status': 'ok', 'operation': operation,
        'manifest': {'name': MANIFEST_NAME, 'sha256': _hash(manifest_body), 'bytes': len(manifest_body)},
        'response': manifest['response'], 'page': manifest['page'],
        'returned_events': len(manifest['row_ids']),
        'matching_events': manifest['citation']['query']['matching_events'],
        'limitations': dict(LIMITATIONS)}
    _receipt_bytes(result)
    return result


def _receipt_bytes(result):
    body = canonical_json_bytes(result)
    if len(body) > MAX_RECEIPT_BYTES:
        raise ContractError('bookmark receipt exceeds its byte limit')
    return body


def _members(directory, expected_identity):
    if directory_identity(directory, label='bookmark directory') != expected_identity:
        raise ContractError('bookmark directory changed')
    if {path.name for path in islice(directory.iterdir(), 3)} != {RESPONSE_NAME, MANIFEST_NAME}:
        raise ContractError('bookmark directory is incomplete or has unexpected members')


def _load(directory, root, expected_manifest_sha256):
    for path, label in ((directory, 'directory'), (root, 'repository root')):
        _absolute_path(path, label)
    _required_digest(expected_manifest_sha256)
    identity = directory_identity(directory, label='bookmark directory')
    if identity is None:
        raise ContractError('bookmark directory is unavailable')
    _members(directory, identity)
    saved = _read(directory / MANIFEST_NAME, MAX_MANIFEST_BYTES)
    if _hash(saved.body) != expected_manifest_sha256:
        raise ContractError('bookmark manifest digest changed')
    manifest = decode_strict_json_bytes(saved.body, label='bookmark manifest')
    if type(manifest) is not dict or type(manifest.get('replay')) is not dict:
        raise ContractError('bookmark manifest is invalid')
    response = _read(directory / RESPONSE_NAME, rows.MAX_OUTPUT_BYTES)
    result = decode_strict_json_bytes(response.body, label='bookmark rows')
    expected = _manifest(root, result, response.body, manifest['replay'])
    # Exact reconstruction closes every manifest field, preserves the full
    # selectors and binds copied provenance/counts/health/limits to stored bytes.
    if _manifest_bytes(expected) != saved.body:
        raise ContractError('bookmark manifest binding changed')
    _members(directory, identity)
    for name, old, maximum in ((MANIFEST_NAME, saved, MAX_MANIFEST_BYTES),
                              (RESPONSE_NAME, response, rows.MAX_OUTPUT_BYTES)):
        current = _read(directory / name, maximum)
        if current != old:
            raise ContractError('bookmark artifacts changed during verification')
    return manifest, saved.body, response.body


def evidence_bookmark(path: Path, root: Path, reader: Path, directory: Path, *,
                      expected_sha256, **options):
    """Retain exactly one existing evidence-rows page in a fresh directory."""
    filters = rows._options(**options)
    _required_digest(expected_sha256)
    for value, label in ((path, 'bundle'), (root, 'repository root'),
                         (reader, 'reader'), (directory, 'directory')):
        _absolute_path(value, label)
    # Refuse all existing destinations, including empty directories and links,
    # before opening the input. The exclusive mkdir also closes the race.
    if directory.exists() or directory.is_symlink():
        raise ContractError('bookmark destination already exists')
    parent_ancestry = directory_ancestry_binding(directory.parent, label='bookmark parent')
    result = rows.evidence_rows(path, root, reader, expected_sha256=expected_sha256, **options)
    response_body = rows.render_rows_json(result)
    replay = {'rows_version': options.get('rows_version', 1),
        'expected_bundle_sha256': expected_sha256, 'filters': filters,
        'limit': options.get('limit', 25), 'input_cursor': options.get('cursor')}
    manifest = _manifest(root, result, response_body, replay)
    manifest_body = _manifest_bytes(manifest)
    receipt = _receipt(manifest, manifest_body, 'saved-local-artifacts')
    if directory_ancestry_binding(directory.parent, label='bookmark parent') != parent_ancestry:
        raise ContractError('bookmark parent changed')
    directory.mkdir(mode=0o700)
    directory_ancestry = None
    published_manifest = None
    try:
        directory_ancestry = directory_ancestry_binding(directory, label='bookmark directory')
        if directory_ancestry[:-1] != parent_ancestry:
            raise ContractError('bookmark directory changed')
        publish_bytes_exclusive_result(directory / RESPONSE_NAME, response_body,
            maximum=rows.MAX_OUTPUT_BYTES, label='bookmark rows', require_single_link=True)
        if directory_ancestry_binding(directory, label='bookmark directory') != directory_ancestry:
            raise ContractError('bookmark directory changed')
        published_manifest = publish_bytes_exclusive_result(directory / MANIFEST_NAME, manifest_body,
            maximum=MAX_MANIFEST_BYTES, label='bookmark manifest', require_single_link=True)
        _load(directory, root, _hash(manifest_body))
        if directory_ancestry_binding(directory, label='bookmark directory') != directory_ancestry:
            raise ContractError('bookmark directory changed')
    except (ContractError, OSError, KeyboardInterrupt):
        # A response-only directory is deliberately retained as incomplete.
        # Never remove a replacement owned by another writer during cleanup.
        if published_manifest is not None and directory_ancestry is not None:
            try:
                if (directory_ancestry_binding(directory, label='bookmark directory')
                        == directory_ancestry):
                    remove_control_conditionally(directory / MANIFEST_NAME,
                        expected_body=manifest_body, expected_identity=published_manifest.identity,
                        maximum=MAX_MANIFEST_BYTES, label='bookmark manifest',
                        require_handle_delete=True)
            except (ContractError, OSError):
                pass
        raise
    return receipt


def verify_bookmark(directory: Path, root: Path, *, expected_manifest_sha256):
    manifest, body, _ = _load(directory, root, expected_manifest_sha256)
    return _receipt(manifest, body, 'verified-local-artifacts')


def replay_bookmark(directory: Path, root: Path, path: Path, reader: Path, *,
                    expected_manifest_sha256, expected_sha256):
    _required_digest(expected_sha256)
    for value, label in ((path, 'bundle'), (reader, 'reader')):
        _absolute_path(value, label)
    manifest, body, response_body = _load(directory, root, expected_manifest_sha256)
    if expected_sha256 != manifest['replay']['expected_bundle_sha256']:
        raise ContractError('bookmark replay bundle changed')
    result = rows.evidence_rows(path, root, reader, expected_sha256=expected_sha256,
                               **_replay_options(manifest['replay']))
    if rows.render_rows_json(result) != response_body:
        raise ContractError('bookmark replay response changed')
    # Reject an artifact replacement that occurred during the full decode.
    if _load(directory, root, expected_manifest_sha256) != (manifest, body, response_body):
        raise ContractError('bookmark changed during replay')
    return _receipt(manifest, body, 'replayed-exact-response')


def emit_receipt(result):
    body = _receipt_bytes(result)
    output = getattr(sys.stdout, 'buffer', None)
    if output is None:
        raise ContractError('bookmark requires binary stdout')
    written = output.write(body)
    if type(written) is not int or written != len(body):
        raise ContractError('bookmark receipt write was incomplete')
    output.flush()


def emit_argument_error():
    try:
        emit_receipt({'schema': RECEIPT_SCHEMA, 'status': 'error', 'code': 'bookmark-unavailable'})
    except (ContractError, OSError, KeyboardInterrupt):
        pass
    return 2


def add_bookmark_commands(trace_sub, root):
    def run(args):
        try:
            if args.bookmark_operation == 'evidence-bookmark':
                selector = None
                if args.portable_pid is not None or args.portable_context_id is not None:
                    selector = {'pid': args.portable_pid, 'context_id': args.portable_context_id}
                result = evidence_bookmark(args.bundle.absolute(), root,
                    args.reader_executable.absolute(), args.out.absolute(),
                    expected_sha256=args.expected_sha256, apis=args.api, script_id=args.script_id,
                    context_kind=args.context_kind, portable_context=selector, start_ns=args.start_ns,
                    end_ns=args.end_ns, limit=args.limit, cursor=args.cursor, rows_version=args.rows_version)
            elif args.bookmark_operation == 'bookmark-verify':
                result = verify_bookmark(args.bookmark.absolute(), root,
                    expected_manifest_sha256=args.expected_manifest_sha256)
            else:
                result = replay_bookmark(args.bookmark.absolute(), root, args.bundle.absolute(),
                    args.reader_executable.absolute(), expected_sha256=args.expected_sha256,
                    expected_manifest_sha256=args.expected_manifest_sha256)
        except (ContractError, OSError):
            return emit_argument_error()
        except KeyboardInterrupt:
            try:
                emit_receipt({'schema': RECEIPT_SCHEMA, 'status': 'error', 'code': 'interrupted'})
            except (ContractError, OSError, KeyboardInterrupt):
                pass
            return 130
        # A broken transport must not be followed by a misleading second JSON
        # document. The durable artifacts remain independently verifiable.
        try:
            emit_receipt(result)
        except (ContractError, OSError, KeyboardInterrupt):
            return 2
        return 0

    for command in COMMANDS:
        parser = trace_sub.add_parser(command, help='bounded immutable metadata evidence bookmark')
        if command != 'evidence-bookmark':
            parser.add_argument('--bookmark', type=Path, required=True)
            parser.add_argument('--expected-manifest-sha256', required=True)
        if command != 'bookmark-verify':
            parser.add_argument('--bundle', type=Path, required=True)
            parser.add_argument('--reader-executable', type=Path, required=True)
            parser.add_argument('--expected-sha256', required=True)
        if command == 'evidence-bookmark':
            parser.add_argument('--out', type=Path, required=True)
            parser.add_argument('--api', action='append', default=[])
            parser.add_argument('--script-id', default='')
            parser.add_argument('--context-kind', choices=('window', 'worker', 'other'), default='')
            parser.add_argument('--portable-pid')
            parser.add_argument('--portable-context-id')
            parser.add_argument('--start-ns', default='')
            parser.add_argument('--end-ns', default='')
            parser.add_argument('--limit', type=int, default=25)
            parser.add_argument('--cursor')
            parser.add_argument('--rows-version', type=int, choices=(1,), default=1)
        parser.set_defaults(func=run, bookmark_operation=command)
