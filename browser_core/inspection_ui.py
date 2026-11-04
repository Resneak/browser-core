"""Loopback reader; active context probes require an enabled, explicit action."""
from __future__ import annotations
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler
import hashlib
import json
from pathlib import Path
import secrets
import socket
from tempfile import SpooledTemporaryFile
from threading import Lock
import time

from .contracts import ContractError
from .control_files import decode_strict_json_bytes
from .inspection import ALLOWLIST as ALLOWLIST, SCHEMA as SCHEMA
from .incremental_inspection import IncrementalInspection, InspectionRebuilding
from .recording_source import RecordingSource
from .inspection_contract import supported_capture
from .inspection_attribution import ContextAttribution
from .evidence_bundle import EvidenceExport, OpenEvidence
from .inspection_comparison import ComparisonExport, ComparisonCancelled
from .prepared_download import ExportCleanupPending
from .local_http import LocalPanelServer


def create_inspector(session_path: Path, repository_root: Path, *, reader_executable: Path | None = None,
                     allow_context_identification: bool = False):
    source=RecordingSource(session_path,repository_root,reader_executable)
    session=source.resolve().session
    if not supported_capture(session.get('value_capture')):
        raise ContractError('session was not launched with native value inspection')
    inspector=IncrementalInspection(session_path,repository_root,source)
    try:
        return _create_panel(source,inspector,ContextAttribution(),
                             allow_context_identification=allow_context_identification)
    except BaseException:
        inspector.close()
        raise


def create_evidence_inspector(bundle_path, repository_root, reader_executable, *, expected_sha256=None):
    bundle=OpenEvidence(bundle_path,repository_root,reader_executable,expected_sha256=expected_sha256)
    inspector=None
    try:
        if not supported_capture(bundle.metadata['capture']):
            raise ContractError('metadata-only evidence has no private value inspector; use evidence-summary')
        inspector=IncrementalInspection(bundle.path,repository_root,bundle.source)
        inspector.health=bundle.metadata['health']
        return _create_panel(bundle.source,inspector,bundle.attribution,bundle=bundle)
    except BaseException:
        with ExitStack() as closing:
            closing.callback(bundle.close)
            if inspector is not None:closing.callback(inspector.close)
        raise


def _create_panel(source,inspector,attribution,*,allow_context_identification=False,bundle=None):
    token=secrets.token_urlsafe(32)
    nonce=secrets.token_urlsafe(24)
    page=(Path(__file__).with_name('inspection_panel.html')).read_text(encoding='utf-8').replace('__NONCE__',nonce).encode('utf-8')
    reading=Lock()
    export=EvidenceExport()
    comparison=ComparisonExport()

    def decorate(data):
        attribution.reconcile(inspector)
        attribution.enrich(data)
        for event in data['events']:
            if 'ts' in event:
                event['timestamp_ns'] = str(event['ts'])
            if {'id', 'pid', 'tid', 'realm_id', 'script_id'} <= event.keys():
                event['native_ids'] = {key: str(event[key]) for key in
                                       ('id', 'pid', 'tid', 'realm_id', 'script_id')}
            if {'pid', 'context_id', 'realm_id'} <= event.keys():
                # Selection identifiers must not make a round trip through
                # JavaScript numbers, even for malformed/atypical large IDs.
                event['history_scope'] = {'pid': str(event['pid']),
                    'context_id': event['context_id'].upper(), 'realm_id': str(event['realm_id'])}
        data['context_identification']['available'] = bool(
            allow_context_identification and data.get('browser_running')
            and data.get('source_phase')=='live-prefix'
            and attribution.attempts < data['context_identification']['attempt_limit'])
        data['evidence_export']={'available':bundle is None,'private_values':True}
        if bundle is not None:
            data['evidence_bundle']=bundle.summary
            data['source_phase']=bundle.summary['source_phase']
            data['complete']=False  # End of imported bytes is not capture completeness.
            data['recovery_incomplete']=bundle.summary['source_phase']!='finalized-recording'
            data['context_identification']['retention']='evidence-bundle'
            # Enrichment can outlast the inspector's private-copy check.
            source.resolve()
        else:
            # Attribution may query the decoder after the inspector's own
            # source check. Do not publish stale live or completed data.
            after=source.resolve()
            if ((data.get('run_id') is not None
                    and after.session['run_id']!=data['run_id'])
                    or (data.get('source_phase') is not None
                        and after.phase!=data['source_phase'])
                    or (data.get('complete') and after.phase!='finalized-recording')):
                raise ContractError('recording source changed during panel enrichment')
        return data

    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            pass  # Capability URLs and captured values are not access logs.

        def send(self,status,body,kind):
            # A header write can fail after part of the response is on the wire.
            # Do not let an outer request handler start a second response then.
            self._response_started=True
            self.send_response(status)
            self.send_header('Content-Type',kind)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            try:
                self.wfile.write(body)
                if self.command=='POST' and status>=400 and self.close_connection:
                    # A rejected request can still have inbound body bytes.
                    # On Windows, immediately closing that socket can reset it
                    # before the caller reads our error. Send FIN first, then
                    # drain a small bounded remainder without interpreting it.
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_WR)
                    deadline=time.monotonic()+.05
                    remaining=8192
                    while remaining:
                        wait=deadline-time.monotonic()
                        if wait<=0:break
                        self.connection.settimeout(wait)
                        chunk=self.connection.recv(min(remaining,4096))
                        if not chunk:break
                        remaining-=len(chunk)
            except OSError:pass

        def allowed(self,*,panel_navigation=False):
            expected=f'127.0.0.1:{self.server.server_port}'
            if self.headers.get_all('Host') != [expected]:
                return False
            # The saved-profile picker has a different loopback port. Permit
            # its user-clicked top-level document navigation at the capability
            # page only. Data, downloads and actions retain the origin guard.
            navigation=(panel_navigation and self.command=='GET'
                        and self.path==f'/{token}/'
                        and self.headers.get_all('Sec-Fetch-Site')==['same-site']
                        and self.headers.get_all('Sec-Fetch-Mode')==['navigate']
                        and self.headers.get_all('Sec-Fetch-Dest')==['document']
                        and self.headers.get_all('Sec-Fetch-User')==['?1'])
            if self.headers.get('Sec-Fetch-Site') not in (None,'none','same-origin') and not navigation:
                return False
            origins=self.headers.get_all('Origin')
            if origins is not None and origins != ['http://'+expected]:
                return False
            return True

        def do_GET(self):
            if not self.allowed(panel_navigation=True):
                return self.send(403,b'Forbidden','text/plain; charset=utf-8')
            if self.path==f'/{token}/':
                return self.send(200,page,'text/html; charset=utf-8')
            if self.path==f'/{token}/comparison-progress':
                return self.send(200,json.dumps(comparison.progress(),allow_nan=False).encode(),'application/json')
            evidence_download=self.path.startswith(f'/{token}/download/') and bundle is None
            comparison_download=self.path.startswith(f'/{token}/comparison-download/')
            if evidence_download or comparison_download:
                artifact=comparison if comparison_download else export
                route='comparison-download' if comparison_download else 'download'
                if not reading.acquire(blocking=False):
                    return self.send(503,b'Download busy; try again','text/plain; charset=utf-8')
                try:
                    if artifact.path is None or self.path!=f'/{token}/{route}/{artifact.receipt["sha256"]}':
                        return self.send(404,b'No prepared export','text/plain; charset=utf-8')
                    # The capability URL names the prepared digest. Verify the
                    # opened file before promising that digest or byte length.
                    # Send the verified copy: the prepared path can change after
                    # validation but before or during the response body.
                    deadline=time.monotonic()+180
                    with SpooledTemporaryFile(max_size=1024*1024) as verified:
                        try:
                            actual=hashlib.sha256()
                            size=0
                            with artifact.path.open('rb') as stream:
                                for chunk in iter(lambda:stream.read(1024*1024),b''):
                                    size+=len(chunk)
                                    if size>artifact.receipt['bytes'] or time.monotonic()>deadline:
                                        raise OSError('prepared download changed or timed out')
                                    if verified.write(chunk)!=len(chunk):
                                        raise OSError('prepared download snapshot wrote incomplete bytes')
                                    actual.update(chunk)
                            if (size!=artifact.receipt['bytes'] or actual.hexdigest()!=artifact.receipt['sha256']
                                    or time.monotonic()>deadline):
                                raise OSError('prepared download changed')
                            verified.seek(0)
                        except OSError:
                            return self.send(409,b'Prepared download is no longer valid','text/plain; charset=utf-8')
                        self.send_response(200)
                        self.send_header('Content-Type','application/json' if comparison_download else 'application/octet-stream')
                        filename='browser-core-comparison.json' if comparison_download else 'browser-core-evidence.bcevidence'
                        self.send_header('Content-Disposition',f'attachment; filename="{filename}"')
                        self.send_header('Content-Length',str(artifact.receipt['bytes']))
                        self.send_header('Cache-Control','no-store')
                        self.send_header('X-Content-Type-Options','nosniff')
                        self.send_header('Referrer-Policy','no-referrer')
                        self.end_headers()
                        for chunk in iter(lambda:verified.read(1024*1024),b''):
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise OSError('download deadline')
                            self.connection.settimeout(min(30, remaining))
                            self.wfile.write(chunk)
                            if time.monotonic() > deadline:
                                raise OSError('download deadline')
                except OSError:
                    self.close_connection=True
                finally:
                    reading.release()
                return
            if self.path!=f'/{token}/data':
                return self.send(404,b'Not found','text/plain; charset=utf-8')
            if not reading.acquire(blocking=False):
                return self.send(503,b'{"error":"A refresh is already running"}','application/json')
            try:
                data=decorate(inspector.read(limit=1000))
                self.send(200,json.dumps(data,ensure_ascii=True,allow_nan=False).encode(),'application/json')
            except InspectionRebuilding:
                self.send(202,b'{"rebuilding":true,"error":"Rebuilding the inspector from the original recording"}','application/json')
            except ContractError:
                self.send(409,b'{"error":"The original recording is no longer readable"}','application/json')
            finally:
                reading.release()

        def do_POST(self):
            self._response_started=False
            if not self.allowed():
                return self.send(403,b'Forbidden','text/plain; charset=utf-8')
            identify=self.path==f'/{token}/identify' and allow_context_identification
            exporting=self.path==f'/{token}/export' and bundle is None
            comparing=self.path==f'/{token}/compare'
            cancelling=self.path==f'/{token}/comparison-cancel'
            if self.path!=f'/{token}/history' and not identify and not exporting and not comparing and not cancelling:
                return self.send(404,b'Not found','text/plain; charset=utf-8')
            try:
                lengths=self.headers.get_all('Content-Length')
                if (self.headers.get_all('Content-Type') != ['application/json'] or
                    self.headers.get_all('Transfer-Encoding') is not None or
                    lengths is None or len(lengths)!=1 or not lengths[0].isascii() or
                    not lengths[0].isdigit() or len(lengths[0])>5 or not 1<=int(lengths[0])<=8192):
                    raise ContractError('invalid history request')
                length=int(lengths[0])
                previous_timeout=self.connection.gettimeout()
                deadline=time.monotonic()+5.0
                try:
                    body=bytearray()
                    while len(body)<length:
                        remaining=deadline-time.monotonic()
                        if remaining<=0:
                            raise ContractError('history request body deadline exceeded')
                        self.connection.settimeout(remaining)
                        chunk=self.rfile.read1(length-len(body))
                        if time.monotonic()>=deadline:
                            raise ContractError('history request body deadline exceeded')
                        if type(chunk) is not bytes or len(chunk)>length-len(body):
                            raise ContractError('invalid history request body')
                        if not chunk:break
                        body.extend(chunk)
                finally:
                    self.connection.settimeout(previous_timeout)
                if len(body)!=length:
                    raise ContractError('incomplete history request body')
                data=decode_strict_json_bytes(bytes(body),label='history request')
                if not isinstance(data,dict):
                    raise ContractError('invalid history request')
                if identify:
                    if set(data) != {'confirm_active_probe'} or data['confirm_active_probe'] is not True:
                        raise ContractError('invalid context identification request')
                elif exporting:
                    if data != {'export_private_evidence':True} or data.get('export_private_evidence') is not True:
                        raise ContractError('invalid evidence export request')
                elif comparing:
                    if set(data)!={'a','b'}:
                        raise ContractError('invalid comparison request')
                elif cancelling:
                    if data!={}:
                        raise ContractError('invalid comparison cancellation request')
                elif set(data)-{'search','script','context','scope','start_ns','end_ns','cursor'}:
                    raise ContractError('invalid history request')
            except (OSError,ContractError):
                self.close_connection=True
                return self.send(400,b'{"error":"Invalid inspector request"}','application/json')
            if cancelling:
                # This affects only report preparation and must remain reachable
                # while its worker owns the normal recording read lock.
                return self.send(200,json.dumps({'cancel_requested':comparison.cancel()}).encode(),'application/json')
            if not reading.acquire(blocking=False):
                return self.send(503,b'{"error":"A refresh is already running"}','application/json')
            try:
                if exporting:
                    result=export.prepare(source,attribution,getattr(inspector,'health',None))
                elif comparing:
                    result=comparison.prepare(inspector,attribution,data,bundle=bundle.summary if bundle else None)
                elif identify:
                    location=source.resolve()
                    endpoint=location.session.get('automation',{}).get('cdp_endpoint')
                    if not location.browser_running or location.phase!='live-prefix' or not endpoint:
                        raise ContractError('context identification requires the live owned recording')
                    attribution.identify(endpoint)
                    result=decorate(inspector.read(limit=1000))
                else:
                    result=decorate(inspector.history(**data,limit=1000))
                self.send(200,json.dumps(result,ensure_ascii=True,allow_nan=False).encode(),'application/json')
            except InspectionRebuilding:
                self.send(202,b'{"rebuilding":true,"error":"Decoder restarted; previous search pages expired. Start a new search"}','application/json')
            except ComparisonCancelled:
                self.send(409,b'{"cancelled":true,"error":"Comparison canceled. The recording is retained."}','application/json')
            except ExportCleanupPending:
                self.send(400,b'{"error":"Previous export cleanup is still pending. The current download is retained; try preparation again shortly."}','application/json')
            except (ContractError,OSError):
                if getattr(self,'_response_started',False):
                    self.close_connection=True
                    return
                if inspector.closed:
                    self.send(409,b'{"error":"The original recording is no longer readable"}','application/json')
                elif identify:
                    self.send(400,b'{"error":"Context identification unavailable; recorded observations are retained. Reopen after four attempts."}','application/json')
                elif exporting:
                    self.send(400,b'{"error":"Evidence export failed; the original recording and any previous prepared download are retained"}','application/json')
                elif comparing:
                    self.send(400,b'{"error":"Comparison unavailable: reselect expired searches, or narrow a selection that exceeds report limits. Any earlier prepared download is retained."}','application/json')
                else:
                    self.send(400,b'{"error":"Invalid filters or expired history cursor; start a new search"}','application/json')
            finally:
                reading.release()

    class InspectorServer(LocalPanelServer):
        def server_close(self):
            try:
                super().server_close()
            finally:
                with reading, ExitStack() as closing:
                    if bundle is not None:closing.callback(bundle.close)
                    closing.callback(comparison.close)
                    closing.callback(export.close)
                    closing.callback(inspector.close)

    try:
        server=InspectorServer(('127.0.0.1',0),Handler)
    except BaseException:
        with ExitStack() as closing:
            closing.callback(comparison.close)
            closing.callback(export.close)
        raise
    server.daemon_threads=True
    return server,f'http://127.0.0.1:{server.server_port}/{token}/'


def serve_inspector(session_path: Path, repository_root: Path, *, open_browser=False, reader_executable: Path | None = None):
    server,url=create_inspector(session_path,repository_root,reader_executable=reader_executable)
    _serve_panel(server,url,open_browser=open_browser)


def serve_evidence(bundle_path,repository_root,reader_executable,*,open_browser=False,expected_sha256=None):
    server,url=create_evidence_inspector(bundle_path,repository_root,reader_executable,
                                       expected_sha256=expected_sha256)
    _serve_panel(server,url,open_browser=open_browser)


def _serve_panel(server,url,*,open_browser=False):
    try:
        print(json.dumps({'inspector_url':url,'read_only':True,'run_scope':'one-session'}),flush=True)
        if open_browser:
            import webbrowser
            webbrowser.open(url)
        server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
