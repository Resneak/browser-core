"""Explicit, bounded CDP probe correlation; passive native recording stays separate.

No attribution is inferred from numeric script IDs alone. Page probes run in a
new isolated world, workers are never paused, and unmatched/ambiguous probes
remain unresolved. Debugger source labels are not fetched-source provenance.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import re
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

from . import cdp
from .contracts import ContractError
from .inspection import decode_rows, inspection_select
from .trace_rpc import DecoderInterrupted

MAX_TARGETS = 32
MAX_TARGET_INFOS = 1024
MAX_PROBES = 64
MAX_ATTEMPTS = 4
MAX_SCRIPTS = 2048
IDENTIFY_SECONDS = 20
MAX_MATCH_ROWS = 1000


def _merge_sources(first, second):
    result = dict(first)
    for key, value in second.items():
        result[key] = (value if key not in result or result[key] == value else
                       {'status': 'unresolved', 'reason': 'ambiguous-script-id-in-context'})
    return result


def source_label(value):
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return {'status': 'unavailable'}
    digest = hashlib.sha256(value.encode('utf-8', errors='surrogatepass')).hexdigest()
    try:
        url = urlsplit(value)
        if (url.scheme in ('http', 'https') and url.hostname
                and url.username is None and url.password is None and '\\' not in value
                and (url.port is None or 1 <= url.port <= 65535)):
            display = urlunsplit((url.scheme, url.netloc, url.path, '', ''))
            display = display.encode('utf-8', errors='replace')[:512].decode('utf-8', errors='ignore')
        elif value in ('', 'about:blank'):
            display = value or '(anonymous script)'
        else:
            display = '(non-network source label)'
    except ValueError:
        display = '(source label unavailable)'
    return {'status': 'debugger-reported', 'display': display,
            'url_sha256': digest, 'not_fetch_provenance': True}


class _Peer:
    def __init__(self, connection, reader, deadline):
        self.connection, self.reader, self.deadline = connection, reader, deadline
        self.command_id = 0
        self.contexts = defaultdict(dict)
        self.scripts = defaultdict(dict)
        self.versions = defaultdict(int)
        self.truncated = False
        self.messages = 0

    def _invalidate_contexts(self, sid):
        self.contexts[sid].clear()
        self.scripts[sid].clear()
        self.versions[sid] += 1
        self.truncated = True

    def _invalidate_scripts(self, sid):
        self.scripts[sid].clear()
        self.versions[sid] += 1
        self.truncated = True

    def event(self, event):
        sid = event.get('sessionId', '')
        if not isinstance(sid, str) or len(sid) > 256:
            raise ContractError('invalid attribution session')
        method, p = event.get('method'), event.get('params', {})
        if not isinstance(p, dict):
            if method in ('Runtime.executionContextCreated',
                          'Runtime.executionContextDestroyed',
                          'Runtime.executionContextsCleared',
                          'Page.frameNavigated', 'Page.frameDetached'):
                self._invalidate_contexts(sid)
            elif method == 'Debugger.scriptParsed':
                self._invalidate_scripts(sid)
            return
        if method == 'Runtime.executionContextCreated':
            context = p.get('context', {})
            aux_data = context.get('auxData', {}) if isinstance(context, dict) else None
            frame_id = aux_data.get('frameId') if isinstance(aux_data, dict) else None
            if (isinstance(context, dict) and type(context.get('id')) is int
                    and context['id'] > 0
                    and _bounded_metadata_id(context.get('uniqueId'))
                    and isinstance(aux_data, dict)
                    and (frame_id is None or _bounded_metadata_id(frame_id))):
                context_id = context['id']
                # Only these fields participate in probe identity. Retaining
                # the whole CDP context lets unused metadata accumulate across
                # attached sessions despite the per-message transport bound.
                context = {'id': context_id, 'uniqueId': context['uniqueId'],
                           'auxData': {'frameId': frame_id} if frame_id is not None else {}}
                if len(self.contexts[sid]) >= MAX_PROBES and context_id not in self.contexts[sid]:
                    self.truncated = True
                else:
                    prior = self.contexts[sid].get(context_id)
                    changed = prior is not None and prior != context
                    if prior is None or changed:
                        for key in tuple(self.scripts[sid]):
                            if key[0] == context_id:
                                del self.scripts[sid][key]
                                self.truncated = True
                        if changed:
                            # A repeated context ID with changed frame metadata
                            # cannot inherit its previous debugger source labels.
                            self.versions[sid] += 1
                            self.truncated = True
                    self.contexts[sid][context_id] = context
            else:
                self._invalidate_contexts(sid)
        elif method == 'Runtime.executionContextDestroyed':
            if type(p.get('executionContextId')) is int and p['executionContextId'] > 0:
                context_id = p['executionContextId']
                retired = self.contexts[sid].pop(context_id, None) is not None
                for key in tuple(self.scripts[sid]):
                    if key[0] == context_id:
                        del self.scripts[sid][key]
                        retired = True
                if retired:
                    self.versions[sid] += 1
            else:
                self._invalidate_contexts(sid)
        elif method == 'Runtime.executionContextsCleared':
            self.contexts[sid].clear()
            self.scripts[sid].clear()
            self.versions[sid] += 1
        elif method in ('Page.frameNavigated', 'Page.frameDetached'):
            # A frame transition can retire several contexts, including child
            # frames. Without every destruction notice, old debugger labels
            # cannot safely be assigned to a later document.
            self._invalidate_contexts(sid)
        elif method == 'Debugger.scriptParsed':
            key = p.get('scriptId')
            if (isinstance(key, str) and re.fullmatch(r'[0-9]{1,19}', key)
                    and int(key) <= 2**31-1
                    and type(p.get('executionContextId')) is int and p['executionContextId'] > 0
                    and isinstance(p.get('url', ''), str) and len(p.get('url', '')) <= 8192):
                slot = (p['executionContextId'], key)
                prior = self.scripts[sid].get(slot)
                if prior is not None:
                    if prior['url'] != p.get('url', ''):
                        # A reused debugger ID cannot identify either source.
                        # Keep the ambiguity until this context is retired.
                        prior['url'] = None
                elif sum(len(v) for v in self.scripts.values()) >= MAX_SCRIPTS:
                    self.truncated = True
                else:
                    self.scripts[sid][slot] = {
                        'scriptId': key, 'executionContextId': p.get('executionContextId'),
                        'url': p.get('url', ''),
                    }
            else:
                self._invalidate_scripts(sid)

    def call(self, method, params=None, sid=None):
        if time.monotonic() >= self.deadline:
            raise ContractError('context identification deadline expired')
        self.command_id += 1
        command = {'id': self.command_id, 'method': method, 'params': params or {}}
        if sid is not None:
            command['sessionId'] = sid
        payload = cdp._encode_cdp_command(command)
        cdp._send_websocket_bytes(self.connection, cdp._masked_text_frame(payload, cdp._websocket_random_bytes(4)))
        for _ in range(4096):
            self.messages += 1
            if self.messages > 16384:
                raise ContractError('context identification message limit reached')
            event = cdp._decode_strict_cdp_text(
                cdp._read_server_text_message(self.reader, self.connection), label='attribution CDP')
            if not isinstance(event, dict):
                raise ContractError('invalid attribution message')
            if cdp._response_matches_command_id(event, self.command_id):
                result = cdp._validated_command_response(event)['result']
                if not isinstance(result, dict):
                    raise ContractError('invalid attribution response')
                return result
            self.event(event)
        raise ContractError('context identification response limit reached')


def _bounded_metadata_id(value):
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and not any(ord(char) < 32 for char in value))


def _frames(tree, parent=None, *, truncated=None):
    if not isinstance(tree, dict):
        raise ContractError('invalid frame inventory')
    stack = [(tree, parent)]
    while stack:
        item, parent = stack.pop()
        frame = item.get('frame', {})
        declared_parent = frame.get('parentId') if isinstance(frame, dict) else None
        parent_id = parent if parent is not None else declared_parent
        if (not isinstance(frame, dict) or not _bounded_metadata_id(frame.get('id'))
                or (parent_id is not None and not _bounded_metadata_id(parent_id))
                or (declared_parent is not None and not _bounded_metadata_id(declared_parent))
                or (parent is not None and declared_parent is not None
                    and declared_parent != parent)
                or frame.get('id') == parent_id):
            if truncated is not None:
                truncated[0] = True
            continue
        yield frame, parent
        children = item.get('childFrames', [])
        if isinstance(children, list):
            if truncated is not None and len(children) > MAX_PROBES:
                truncated[0] = True
            if truncated is not None and any(not isinstance(child, dict) for child in children[:MAX_PROBES]):
                truncated[0] = True
            stack.extend((child, frame['id']) for child in children[:MAX_PROBES] if isinstance(child, dict))
        elif truncated is not None:
            truncated[0] = True


def collect_probes(endpoint):
    """Probe only currently attached contexts, with no navigation or API hooks."""
    deadline = time.monotonic()+IDENTIFY_SECONDS
    websocket = cdp._browser_websocket_url(endpoint, IDENTIFY_SECONDS)
    probes, errors = [], 0
    with cdp._websocket_connection(websocket, max(.01, deadline-time.monotonic()),
                                   os_error_label='context identification unavailable') as pair:
        peer = _Peer(*pair, deadline)
        targets = peer.call('Target.getTargets').get('targetInfos')
        if not isinstance(targets, list):
            raise ContractError('invalid context target inventory')
        eligible = []
        truncated = len(targets) > MAX_TARGET_INFOS
        for target in targets[:MAX_TARGET_INFOS]:
            if not isinstance(target, dict) or not isinstance(target.get('type'), str):
                truncated = True
                continue
            if target['type'] not in ('page', 'iframe', 'worker', 'shared_worker'):
                continue
            target_id = target.get('targetId')
            if not _bounded_metadata_id(target_id):
                truncated = True
                continue
            url = target.get('url', '')
            if not isinstance(url, str):
                truncated = True
                continue
            if not url.lower().startswith('chrome-extension:'):
                eligible.append(target)
                if len(eligible) > MAX_TARGETS:
                    truncated = True
                    break
        truncated = truncated or len(eligible) > MAX_TARGETS
        frame_attempts = 0
        for target in eligible[:MAX_TARGETS]:
            if len(probes) >= MAX_PROBES or frame_attempts >= MAX_PROBES or time.monotonic() >= deadline-1:
                truncated = True
                break
            sid = None
            try:
                sid = peer.call('Target.attachToTarget', {'targetId': target['targetId'], 'flatten': True})['sessionId']
                if not isinstance(sid, str) or not sid or len(sid) > 256:
                    sid = None
                    raise ContractError('invalid attached session')
                peer.call('Runtime.enable', sid=sid)
                # Configure this owned debugger agent before enabling it. Merely
                # attaching must not activate a page's `debugger` statements.
                peer.call('Debugger.setSkipAllPauses', {'skip': True}, sid=sid)
                peer.call('Debugger.enable', {'maxScriptsCacheSize': 0}, sid=sid)
                candidates = []
                if target['type'] in ('page', 'iframe'):
                    peer.call('Page.enable', sid=sid)
                    tree = peer.call('Page.getFrameTree', sid=sid)['frameTree']
                    tree_version = peer.versions[sid]
                    frame_truncated = [False]
                    for frame, parent in _frames(tree, truncated=frame_truncated):
                        if peer.versions[sid] != tree_version:
                            break
                        if frame_attempts >= MAX_PROBES or len(candidates)+len(probes) >= MAX_PROBES:
                            truncated = True
                            break
                        frame_attempts += 1
                        try:
                            created = peer.call('Page.createIsolatedWorld', {
                                'frameId': frame['id'], 'worldName': 'Browser Core context identification',
                                'grantUniveralAccess': False}, sid=sid)
                            context_id = created.get('executionContextId')
                            if type(context_id) is not int or context_id <= 0:
                                raise ContractError('invalid isolated world context')
                            ctx = peer.contexts[sid].get(context_id)
                            if ctx and ctx.get('auxData', {}).get('frameId') == frame['id']:
                                candidates.append((ctx, {'kind': 'frame' if parent or target['type']=='iframe' else 'page',
                                    'frame_id': frame['id'], 'parent_frame_id': parent or frame.get('parentId'),
                                    'document': source_label(frame.get('url', '')), 'isolated_probe': True}))
                            else:
                                # The numeric execution-context ID alone cannot
                                # bind a probe to the requested frame.
                                errors += 1
                        except (ContractError, KeyError):
                            errors += 1
                        if peer.versions[sid] != tree_version:
                            break
                    if peer.versions[sid] != tree_version:
                        # A navigation can reuse the frame ID with a new
                        # document. Every label from this tree is then stale.
                        candidates.clear()
                        errors += 1
                        truncated = True
                    truncated = truncated or frame_truncated[0]
                else:
                    candidates = [(ctx, {'kind': 'worker', 'target_type': target['type'],
                        'document': source_label(target.get('url', '')), 'isolated_probe': False})
                        for ctx in list(peer.contexts[sid].values())]
                version = peer.versions[sid]
                remaining = MAX_PROBES-len(probes)
                if len(candidates) > remaining:
                    truncated = True
                for ctx, metadata in candidates[:remaining]:
                    nonce = secrets.token_hex(16)
                    marker = (secrets.randbelow(900_000_000)+100_000_000,
                              secrets.randbelow(900_000_000)+100_000_000)
                    label = 'browser-core-context-probe/'+nonce
                    expression = ("(()=>{const c=new OffscreenCanvas(1,1);const x=c.getContext('2d');"
                                  f"x.getImageData({marker[0]},{marker[1]},1,1);return true;}})()\n//# sourceURL={label}")
                    probe = {'marker': marker, 'probe_script_id': None, 'sources': {},
                             'metadata': {**metadata, 'target_id': target['targetId'],
                                          'cdp_context_unique_id': ctx['uniqueId'],
                                          'identified_at_utc': datetime.now(timezone.utc).isoformat()}}
                    # Retain the marker even if evaluation times out or its caller
                    # cannot be verified: those extra reads must stay labeled.
                    probes.append(probe)
                    try:
                        result = peer.call('Runtime.evaluate', {'expression': expression,
                            'uniqueContextId': ctx['uniqueId'], 'returnByValue': True,
                            'silent': True, 'timeout': 750}, sid=sid)
                        matches = [s for s in peer.scripts[sid].values() if s['url']==label
                                   and s['executionContextId']==ctx['id']]
                        if ('exceptionDetails' in result or not isinstance(result.get('result'), dict)
                                or result['result'].get('value') is not True
                                or len(matches)!=1 or peer.contexts[sid].get(ctx['id'], {}).get('uniqueId') != ctx['uniqueId']
                                or peer.versions[sid] != version):
                            errors += 1
                            continue
                        sources = {}
                        for script in peer.scripts[sid].values():
                            other = peer.contexts[sid].get(script['executionContextId'], {})
                            same = (other.get('auxData', {}).get('frameId') == metadata.get('frame_id')
                                    if metadata.get('frame_id') else other.get('uniqueId')==ctx['uniqueId'])
                            if same and (script['url'] is None or
                                         not script['url'].startswith('browser-core-context-probe/')):
                                label_info = ({'status': 'unresolved',
                                               'reason': 'ambiguous-script-id-in-context'}
                                              if script['url'] is None else source_label(script['url']))
                                sources = _merge_sources(sources, {str(int(script['scriptId'])): label_info})
                        probe.update(probe_script_id=int(matches[0]['scriptId']), sources=sources)
                    except ContractError:
                        errors += 1
            except (ContractError, KeyError):
                errors += 1
            finally:
                if sid and time.monotonic() < deadline-0.1:
                    try:
                        peer.call('Target.detachFromTarget', {'sessionId': sid})
                    except ContractError:
                        pass  # Closing this owned connection detaches its own sessions.
        return probes, {'probes_requested': len(probes),
                        'probe_callers_verified': sum(p['probe_script_id'] is not None for p in probes),
                        'unavailable_contexts_or_commands': errors,
                        'truncated': truncated or peer.truncated}


class ContextAttribution:
    def __init__(self):
        self.probes = []
        self.attempts = 0
        self.last_attempt = None
        self.matches = {}
        self.conflicts = set()
        self.probe_events = set()
        self.probe_identities = defaultdict(set)
        self.probe_realms = defaultdict(set)
        self.generation = None
        self.match_limit_reached = False
        self.retained_conflicts = set()
        self.retained_match_limit = False

    def identify(self, endpoint):
        if self.attempts >= MAX_ATTEMPTS:
            raise ContractError('context identification attempt limit reached; reopen the inspector')
        self.attempts += 1
        self.last_attempt = {'status': 'unavailable'}
        probes, self.last_attempt = collect_probes(endpoint)
        self.probes.extend(probes)
        return deepcopy(self.last_attempt)

    def ingest(self, events):
        for index, probe in enumerate(self.probes):
            rows = []
            for event in events:
                values = event.get('parameters', {}).get('observed', [])
                if (event.get('api')=='OffscreenCanvasRenderingContext2D.getImageData'
                        and type(values) is list and len(values)==4
                        and all(type(value) is dict and value.get('type')=='number' for value in values)
                        and [v.get('value') for v in values]==[*probe['marker'], 1, 1]):
                    script_matches=(probe['probe_script_id'] is not None
                                    and event.get('script_id')==probe['probe_script_id'])
                    if script_matches or probe['probe_script_id'] is None:
                        self.probe_events.add(event['id'])
                    if script_matches:
                        rows.append(event)
            identities = self.probe_identities[index]
            identities.update((e['pid'], e['context_id']) for e in rows)
            if len(identities) > 1:
                self.conflicts.update(identities)
            for e in rows:
                self.probe_events.add(e['id'])
                if 'native_context' in e:
                    self.probe_realms[index].add((e['pid'], e['native_context']['v8_context_id'], e['script_id']))
                key = (e['pid'], e['context_id'])
                prior = self.matches.get(key)
                # Two labels for one native identity are not silently merged.
                def identity(p):
                    m = p['metadata']
                    return ('frame', m['frame_id']) if m.get('frame_id') else ('worker', m['target_id'], m['cdp_context_unique_id'])
                if prior:
                    if identity(prior) != identity(probe):
                        self.conflicts.add(key)
                    elif probe['metadata'].get('frame_id'):
                        old, new = prior['metadata'], probe['metadata']
                        old_parent, new_parent = old.get('parent_frame_id'), new.get('parent_frame_id')
                        old_document, new_document = old.get('document'), new.get('document')
                        old_digest = old_document.get('url_sha256') if isinstance(old_document, dict) else None
                        new_digest = new_document.get('url_sha256') if isinstance(new_document, dict) else None
                        if ((old_parent and new_parent and old_parent != new_parent)
                                or (old_digest and new_digest and old_digest != new_digest)):
                            # Two attached views may name one frame, but they
                            # cannot supply contradictory document claims.
                            self.conflicts.add(key)
                self.matches[key] = {**probe, 'sources': _merge_sources(prior['sources'] if prior else {}, probe['sources'])}

    def enrich(self, result):
        from .inspection_context import attribution, view_summary
        for event in result['events']:
            key = (event.get('pid'), event.get('context_id'))
            mapping = self.matches.get(key)
            if self.match_limit_reached:
                event['attribution'] = {'status': 'unresolved', 'reason': 'probe-match-limit-reached'}
            elif key in self.conflicts:
                event['attribution'] = {'status': 'unresolved', 'reason': 'ambiguous-probe'}
            elif mapping:
                event['attribution'] = deepcopy({'status': 'probe-correlated',
                    'method': 'explicit-cdp-probe-with-native-script-and-argument-match',
                    **mapping['metadata'], 'source': mapping['sources'].get(str(event['script_id']),
                        {'status': 'unresolved', 'reason': 'script-not-in-debugger-snapshot'})})
            else:
                event['attribution'] = {'status': 'unresolved', 'reason': 'no-matching-context-probe'}
            if 'native_context' in event:
                # A historical probe can share a frame token with a later document.
                # Direct native ownership wins; never borrow its script-source label.
                event['attribution'] = attribution(event['native_context'])
            if event.get('id') in self.probe_events or any(
                    ((event.get('pid'), event['native_context']['v8_context_id'], event.get('script_id'))
                     in self.probe_realms[i] if 'native_context' in event else
                     key in self.probe_identities[i] and event.get('script_id') == p['probe_script_id'])
                    for i, p in enumerate(self.probes)):
                event['observation_role'] = 'context-identification-probe'
        result['context_identification'] = {'attempts': self.attempts, 'attempt_limit': MAX_ATTEMPTS,
            'last_attempt': deepcopy(self.last_attempt), 'matched_native_contexts': 0 if self.match_limit_reached else len(set(self.matches)-self.conflicts),
            'ambiguous_native_contexts': len(self.conflicts), 'probe_events': len(self.probe_events),
            'retention': 'this-inspector-instance', 'active_probes': self.attempts > 0,
            'match_limit_reached': self.match_limit_reached}
        result['native_attribution'] = view_summary(result['events'])
        stack_states = [event.get('js_stack', {}).get('status', 'not-recorded') for event in result['events']]
        result['js_stack_attribution'] = {
            'schema':'browser-core.js-stack-view/1', 'observations_in_view':len(stack_states),
            'observed':stack_states.count('observed'), 'limited':stack_states.count('limited-context'),
            'unavailable':sum(status in {'no-isolate','no-visible-js-frame','non-blink-context'} for status in stack_states),
            'not_recorded':stack_states.count('not-recorded')}

    def reconcile(self, inspector):
        """Search probe markers beyond the latest 1,000 observations, bounded."""
        if not self.probes or inspector.decoder is None:
            return
        if self.generation != inspector.decoder_restarts:
            self.matches.clear()
            self.conflicts.clear()
            self.conflicts.update(self.retained_conflicts)
            self.probe_events.clear()
            self.probe_identities.clear()
            self.probe_realms.clear()
            self.match_limit_reached = self.retained_match_limit
            self.generation = inspector.decoder_restarts
        terms = ' OR '.join("INSTR(EXTRACT_ARG(s.arg_set_id, 'debug.parameters_json'), '"+
                            str(p['marker'][0])+"')>0" for p in self.probes)
        sql = inspection_select(incremental=True)+" AND EXTRACT_ARG(s.arg_set_id, 'debug.api')='OffscreenCanvasRenderingContext2D.getImageData' AND ("+terms+") ORDER BY s.id DESC LIMIT "+str(MAX_MATCH_ROWS)
        decoder = inspector.decoder
        previous_timeout = decoder.timeout
        decoder.timeout = 5
        try:
            events, total = decode_rows(decoder.query(sql, max_rows=MAX_MATCH_ROWS), limit=MAX_MATCH_ROWS)
        except DecoderInterrupted:
            inspector._recover_decoder()
        finally:
            decoder.timeout = previous_timeout
        if total > MAX_MATCH_ROWS:
            self.match_limit_reached = True
            return
        if total != len(events):
            raise ContractError('native probe match count disagrees with its short page')
        self.ingest(events)
