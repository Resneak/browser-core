"""Closed passive ownership metadata attached to an observed native API call.

Frame, document and V8-realm tokens are different identities. A context URL is
the browser's document/worker URL at binding entry, not a script-source receipt.
A borrowed native function can enter its owning realm, which need not be the
JavaScript realm that initiated the call.
"""
from __future__ import annotations

import copy
import re
from urllib.parse import urlsplit

from .contracts import ContractError
from .control_files import decode_strict_json_bytes

CONTEXT_SCHEMA = 'browser-core.inspection-context/1'
LIMITED_CONTEXT_SCHEMA = 'browser-core.inspection-context/2'
LIMITED_FIELDS = frozenset(('schema', 'context_id', 'v8_context_id', 'realm_id',
                            'context_kind', 'unavailable'))
MAX_CONTEXT_BYTES = 8192
KINDS = frozenset(('page', 'frame', 'detached-window', 'dedicated-worker',
                   'shared-worker', 'service-worker', 'worker', 'other'))
FIELDS = frozenset(('schema', 'context_id', 'v8_context_id', 'realm_id', 'kind',
                    'document_id', 'frame_id', 'parent_frame_id', 'worker_id',
                    'parent_context_id', 'document_url'))
TOKEN_FIELDS = ('context_id', 'v8_context_id', 'document_id', 'frame_id',
                'parent_frame_id', 'worker_id', 'parent_context_id')
OMITTED_LABELS = frozenset(('[URL exceeds display limit]', '[non-HTTP URL omitted]'))


def _require(condition):
    if not condition:
        raise ValueError('invalid passive context metadata')


def _token(value, *, nullable=False):
    if value is None and nullable:
        return
    _require(isinstance(value, str) and re.fullmatch('[0-9A-Fa-f]{32}', value)
             and int(value, 16) != 0)


def _url(value):
    _require(isinstance(value, dict) and value.get('not_fetch_provenance') is True)
    if value.get('status') == 'unavailable':
        _require(set(value) == {'status', 'reason', 'not_fetch_provenance'})
        _require(value['reason'] in ('length-limit', 'invalid-url', 'digest-unavailable'))
        return
    _require(set(value) == {'status', 'display', 'url_sha256', 'not_fetch_provenance'})
    _require(value['status'] == 'native-context-url')
    _require(isinstance(value['url_sha256'], str)
             and re.fullmatch('[0-9a-f]{64}', value['url_sha256']))
    display = value['display']
    _require(isinstance(display, str) and len(display.encode('utf-8')) <= 512
             and not any(ord(char) < 32 or ord(char) == 127 for char in display))
    if display in OMITTED_LABELS or display in ('about:blank', 'about:srcdoc'):
        return
    parsed = urlsplit(display)
    _require(parsed.scheme in ('http', 'https') and parsed.hostname
             and parsed.username is None and parsed.password is None
             and not parsed.query and not parsed.fragment and '\\' not in display)
    # Accessing .port rejects malformed and out-of-range ports too.
    _require(parsed.port is None or 1 <= parsed.port <= 65535)


def decode_context(encoded, *, context_id, context_kind, realm_id):
    """Admit the additive extension, with absent legacy metadata left absent."""
    if encoded == '':
        return None
    try:
        _require(isinstance(encoded, str) and len(encoded) <= MAX_CONTEXT_BYTES * 2
                 and len(encoded) % 2 == 0 and re.fullmatch('[0-9A-Fa-f]+', encoded))
        value = decode_strict_json_bytes(bytes.fromhex(encoded), label='native context metadata')
        if isinstance(value, dict) and value.get('schema') == LIMITED_CONTEXT_SCHEMA:
            _require(set(value) == LIMITED_FIELDS)
            _token(value['context_id'])
            _token(value['v8_context_id'])
            _require(type(value['realm_id']) is int and 0 <= value['realm_id'] <= 2**31 - 1)
            _require(value['context_id'] == context_id and value['realm_id'] == realm_id)
            _require(value['context_kind'] in ('window', 'worker', 'other')
                     and value['context_kind'] == context_kind)
            _require(value['unavailable'] == 'invalid-script-context')
            return value
        _require(isinstance(value, dict) and set(value) == FIELDS
                 and value['schema'] == CONTEXT_SCHEMA and value['kind'] in KINDS)
        for name in TOKEN_FIELDS:
            _token(value[name], nullable=name not in ('context_id', 'v8_context_id'))
        _require(type(value['realm_id']) is int and 0 <= value['realm_id'] <= 2**31 - 1)
        _require(value['context_id'] == context_id and value['realm_id'] == realm_id)
        kind = value['kind']
        if kind in ('page', 'frame', 'detached-window'):
            _require(context_kind == 'window' and value['worker_id'] is None
                     and value['parent_context_id'] is None)
            if kind == 'detached-window':
                _require(value['frame_id'] is None and value['parent_frame_id'] is None)
            else:
                _require(value['frame_id'] is not None)
                _require((kind == 'page') == (value['parent_frame_id'] is None))
                _require(value['frame_id'] != value['parent_frame_id'])
        elif kind.endswith('worker'):
            _require(context_kind == 'worker' and value['worker_id'] == context_id
                     and value['frame_id'] is None and value['parent_frame_id'] is None
                     and value['document_id'] is None
                     and value['parent_context_id'] != context_id)
            if kind != 'dedicated-worker':
                _require(value['parent_context_id'] is None)
        else:
            _require(context_kind == 'other' and all(value[name] is None for name in
                     ('frame_id', 'parent_frame_id', 'document_id', 'worker_id', 'parent_context_id')))
        _url(value['document_url'])
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, ContractError):
        raise ContractError('native context metadata violates its bounded contract') from None


def attribution(context):
    """Describe the native binding realm without inferring the initiating caller."""
    if context['schema'] == LIMITED_CONTEXT_SCHEMA:
        return {
            'status': 'native-limited',
            'method': 'passive-native-binding-entry',
            'reason': context['unavailable'],
            'kind': context['context_kind'],
            'v8_context_id': context['v8_context_id'],
            'document_id': None, 'frame_id': None, 'parent_frame_id': None,
            'worker_id': None, 'parent_context_id': None,
            'document': {'status': 'unavailable', 'reason': context['unavailable']},
            'source': {'status': 'unresolved', 'reason': 'script-source-not-recorded'},
        }
    return {
        'status': 'native-observed',
        'method': 'passive-native-binding-entry',
        'kind': context['kind'],
        'v8_context_id': context['v8_context_id'],
        'document_id': context['document_id'],
        'frame_id': context['frame_id'],
        'parent_frame_id': context['parent_frame_id'],
        'worker_id': context['worker_id'],
        'parent_context_id': context['parent_context_id'],
        'document': copy.deepcopy(context['document_url']),
        'source': {'status': 'unresolved', 'reason': 'script-source-not-recorded'},
    }


def view_summary(events):
    contexts = [(event['pid'], event['native_context']) for event in events
                if 'native_context' in event]
    complete = [(pid, context) for pid, context in contexts
                if context['schema'] == CONTEXT_SCHEMA]
    return {
        'schema': CONTEXT_SCHEMA,
        'observations_in_view': len(events),
        'attributed_observations_in_view': len(complete),
        'limited_observations_in_view': len(contexts) - len(complete),
        'binding_realms_in_view': len({(pid, context['v8_context_id']) for pid, context in complete}),
        'documents_in_view': len({(pid, context['document_id']) for pid, context in complete
                                  if context['document_id'] is not None}),
        'passive': True,
    }
