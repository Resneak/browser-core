from contextlib import contextmanager
from http.client import HTTPConnection
from http.client import IncompleteRead
import json
from pathlib import Path
from threading import Thread, Event
from urllib.parse import urlsplit
from types import SimpleNamespace

import pytest

from browser_core.contracts import ContractError
from browser_core.inspection_contract import CAPTURE_OFF
import browser_core.inspection_ui as ui


@contextmanager
def panel(monkeypatch,enabled=False):
    location=SimpleNamespace(session={'value_capture':{'schema':ui.SCHEMA,'allowlist':ui.ALLOWLIST},
                                      'automation':{'cdp_endpoint':'http://127.0.0.1:12345'}},
                             phase='live-prefix',browser_running=True)
    monkeypatch.setattr(ui,'RecordingSource',lambda *args:SimpleNamespace(resolve=lambda:location))
    calls=[]
    def read(*args,**kwargs):
        calls.append(True)
        return {'events':[{'value':'<img src=x onerror=alert(1)>'}],
                'browser_running':True,'source_phase':'live-prefix'}
    fake=SimpleNamespace(read=read,history=read,close=lambda:None,closed=False)
    monkeypatch.setattr(ui,'IncrementalInspection',lambda *args:fake)
    server,url=ui.create_inspector(Path('/session'),Path('/repo'),allow_context_identification=enabled)
    thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield urlsplit(url),calls,fake
    finally:server.shutdown();server.server_close();thread.join(5)


def get(url,path,headers=None):
    connection=HTTPConnection(url.hostname,url.port,timeout=5)
    try:
        connection.request('GET',path,headers=headers or {})
        response=connection.getresponse()
        return response.status,dict(response.getheaders()),response.read()
    finally:connection.close()


def test_panel_returns_data_only_at_its_session_capability_and_does_not_log_values(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        status,headers,body=get(url,url.path)
        assert status==200 and headers['Cache-Control']=='no-store'
        assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
        assert b'__NONCE__' not in body
        assert b'.textContent=' in body and b'.innerHTML' not in body
        assert get(url,'/data')[0]==404 and not calls
        status,headers,body=get(url,url.path+'data')
        assert status==200 and len(calls)==1
        assert json.loads(body)['events'][0]['value'].startswith('<img')
        assert headers['Content-Type']=='application/json'


def test_live_panel_does_not_publish_stale_phase_after_enrichment(monkeypatch):
    location=SimpleNamespace(session={'run_id':'owned',
        'value_capture':{'schema':ui.SCHEMA,'allowlist':ui.ALLOWLIST}},
        phase='live-prefix',browser_running=True)
    source=SimpleNamespace(resolve=lambda:location)
    def read(**kwargs):
        source.resolve()
        return {'events':[],'run_id':'owned','source_phase':'live-prefix',
                'browser_running':True,'complete':False}
    fake=SimpleNamespace(read=read,history=read,close=lambda:None,closed=False)
    attribution=SimpleNamespace(attempts=0,
        reconcile=lambda inspector:setattr(location,'phase','recovered-prefix'),
        enrich=lambda data:data.update(context_identification={'attempt_limit':4}))
    monkeypatch.setattr(ui,'RecordingSource',lambda *args:source)
    monkeypatch.setattr(ui,'IncrementalInspection',lambda *args:fake)
    monkeypatch.setattr(ui,'ContextAttribution',lambda:attribution)
    server,address=ui.create_inspector(Path('/session'),Path('/repo'))
    thread=Thread(target=server.serve_forever,daemon=True);thread.start();url=urlsplit(address)
    try:
        assert get(url,url.path+'data')[0]==409
    finally:
        server.shutdown();server.server_close();thread.join(5)


@pytest.mark.parametrize('route,export_type,request_body',[
    ('compare',ui.ComparisonExport,b'{"a":{},"b":{}}'),
    ('export',ui.EvidenceExport,b'{"export_private_evidence":true}'),
])
def test_pending_export_cleanup_returns_bounded_message_and_keeps_reader_available(monkeypatch,route,export_type,request_body):
    def pending(*args,**kwargs):raise ui.ExportCleanupPending('private temporary path')
    monkeypatch.setattr(export_type,'prepare',pending)
    with panel(monkeypatch) as (url,calls,fake):
        status,body=post(url,url.path+route,request_body)
        assert status==400 and b'cleanup is still pending' in body
        assert b'current download is retained' in body and b'private temporary path' not in body
        assert not fake.closed and get(url,url.path+'data')[0]==200


@pytest.mark.parametrize('failure',['inspector','export','comparison'])
def test_panel_close_releases_all_other_owners_after_cleanup_failure(monkeypatch,failure):
    closed=[]
    def owner(name):
        def close():
            closed.append(name)
            if name==failure:raise ui.ExportCleanupPending('owned cleanup failure')
        return SimpleNamespace(close=close)
    monkeypatch.setattr(ui,'EvidenceExport',lambda:owner('export'))
    monkeypatch.setattr(ui,'ComparisonExport',lambda:owner('comparison'))
    server,_=ui._create_panel(None,owner('inspector'),None,bundle=owner('bundle'))
    with pytest.raises(ui.ExportCleanupPending):server.server_close()
    assert closed==['inspector','export','comparison','bundle']
    assert server.socket.fileno()==-1


def test_panel_close_releases_owners_after_server_close_failure(monkeypatch):
    closed=[]
    def owner(name):
        return SimpleNamespace(close=lambda:closed.append(name))
    monkeypatch.setattr(ui,'EvidenceExport',lambda:owner('export'))
    monkeypatch.setattr(ui,'ComparisonExport',lambda:owner('comparison'))
    original_close=ui.LocalPanelServer.server_close
    def failed_server_close(self):
        original_close(self)
        raise OSError('owned server-close failure')
    monkeypatch.setattr(ui.LocalPanelServer,'server_close',failed_server_close)
    server,_=ui._create_panel(None,owner('inspector'),None,bundle=owner('bundle'))
    with pytest.raises(OSError,match='owned server-close failure'):
        server.server_close()
    assert server.socket.fileno()==-1
    assert closed==['inspector','export','comparison','bundle']


def test_panel_url_emission_failure_closes_server(monkeypatch):
    closed=[]
    server=SimpleNamespace(
        serve_forever=lambda **_kwargs:pytest.fail('server started after URL emission failed'),
        server_close=lambda:closed.append(True))

    def failed_print(*_args,**_kwargs):
        raise BrokenPipeError('closed stdout')

    monkeypatch.setattr(ui,'print',failed_print,raising=False)
    with pytest.raises(BrokenPipeError,match='closed stdout'):
        ui._serve_panel(server,'http://127.0.0.1:1234/secret/')
    assert closed==[True]


def test_inspector_startup_failure_closes_reader_and_export_owners(monkeypatch):
    closed=[]
    location=SimpleNamespace(session={'value_capture':{'schema':ui.SCHEMA,'allowlist':ui.ALLOWLIST}})
    monkeypatch.setattr(ui,'RecordingSource',
                        lambda *args:SimpleNamespace(resolve=lambda:location))
    reader=SimpleNamespace(close=lambda:closed.append('inspector'))
    monkeypatch.setattr(ui,'IncrementalInspection',lambda *args:reader)
    monkeypatch.setattr(ui,'EvidenceExport',
                        lambda:SimpleNamespace(close=lambda:closed.append('export')))
    monkeypatch.setattr(ui,'ComparisonExport',
                        lambda:SimpleNamespace(close=lambda:closed.append('comparison')))
    def failed_bind(self,*args,**kwargs):
        raise OSError('owned loopback bind failure')
    monkeypatch.setattr(ui.LocalPanelServer,'__init__',failed_bind)
    with pytest.raises(OSError,match='owned loopback bind failure'):
        ui.create_inspector(Path('/session'),Path('/repo'))
    assert set(closed)=={'inspector','export','comparison'}


def test_evidence_inspector_startup_failure_closes_bundle_after_reader_cleanup_error(monkeypatch):
    closed=[]
    bundle=SimpleNamespace(metadata={'capture':{'schema':ui.SCHEMA,'allowlist':ui.ALLOWLIST},
                                     'health':None},
                           path=Path('/bundle-copy'),source=SimpleNamespace(),attribution=SimpleNamespace(),
                           close=lambda:closed.append('bundle'))
    monkeypatch.setattr(ui,'OpenEvidence',lambda *args,**kwargs:bundle)
    def close_reader():
        closed.append('inspector')
        raise OSError('owned reader cleanup failure')
    monkeypatch.setattr(ui,'IncrementalInspection',
                        lambda *args:SimpleNamespace(close=close_reader))
    def failed_panel(*args,**kwargs):
        raise ContractError('owned panel startup failure')
    monkeypatch.setattr(ui,'_create_panel',failed_panel)
    with pytest.raises(OSError,match='owned reader cleanup failure'):
        ui.create_evidence_inspector(Path('/bundle'),Path('/repo'),Path('/reader'))
    assert closed==['inspector','bundle']


@pytest.mark.parametrize('headers',[{'Host':'evil.example'}, {'Origin':'https://evil.example'}, {'Sec-Fetch-Site':'cross-site'}])
def test_panel_refuses_cross_site_or_rebound_requests(monkeypatch,headers):
    with panel(monkeypatch) as (url,calls,fake):
        assert get(url,url.path+'data',headers)[0]==403
        assert not calls


def picker_navigation_headers():
    return {'Sec-Fetch-Site':'same-site','Sec-Fetch-Mode':'navigate',
            'Sec-Fetch-Dest':'document','Sec-Fetch-User':'?1'}


def test_picker_link_can_open_only_the_panel_document_without_reading_data(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        headers=picker_navigation_headers()
        status,response_headers,body=get(url,url.path,headers)
        assert status==200 and response_headers['Content-Type']=='text/html; charset=utf-8'
        assert b'Recording inspection' in body and not calls
        for route in ('data','comparison-progress','download/abc','comparison-download/abc'):
            assert get(url,url.path+route,headers)[0]==403
        assert post(url,url.path+'history',b'{}',{'Content-Type':'application/json',**headers})[0]==403
        assert not calls


@pytest.mark.parametrize('replacement',[
    {'Sec-Fetch-Site':'cross-site'}, {'Sec-Fetch-Mode':'cors'},
    {'Sec-Fetch-Dest':'iframe'}, {'Sec-Fetch-Dest':'empty'},
    {'Sec-Fetch-User':'?0'}, {'Sec-Fetch-User':None},
    {'Origin':'http://127.0.0.1:1'}, {'Host':'unrelated.invalid'},
])
def test_panel_navigation_exception_requires_the_complete_user_navigation_shape(monkeypatch,replacement):
    headers=picker_navigation_headers()
    for key,value in replacement.items():
        if value is None:headers.pop(key,None)
        else:headers[key]=value
    with panel(monkeypatch) as (url,calls,fake):
        assert get(url,url.path,headers)[0]==403
        assert not calls


def test_panel_reports_stopped_recording_without_returning_old_data_as_live(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        def unavailable(*args,**kwargs):raise ContractError('private detail')
        fake.read=unavailable
        status,_,body=get(url,url.path+'data')
        assert status==409 and b'private detail' not in body


def test_panel_cannot_report_complete_after_source_changes_during_attribution():
    location=SimpleNamespace(phase='finalized-recording')
    source=SimpleNamespace(resolve=lambda:location)
    inspector=SimpleNamespace(read=lambda **kwargs:{'events':[], 'complete':True,
        'source_phase':'finalized-recording'},close=lambda:None)
    class Attribution:
        attempts=0
        def reconcile(self,inspector):location.phase='recovered-prefix'
        def enrich(self,data):data['context_identification']={'attempt_limit':4}
    server,url=ui._create_panel(source,inspector,Attribution())
    thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        address=urlsplit(url)
        status,_,body=get(address,address.path+'data')
        assert status==409 and b'"complete": true' not in body
    finally:server.shutdown();server.server_close();thread.join(5)


def test_rebuilding_is_not_reported_as_successful_empty_or_lost_recording(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        def pending(*args,**kwargs):raise ui.InspectionRebuilding('private detail')
        fake.read=fake.history=pending
        for status,body in [(lambda r:(r[0],r[2]))(get(url,url.path+'data')),
                            post(url,url.path+'history',b'{}')]:
            assert status==202 and json.loads(body)['rebuilding'] is True
            assert b'private detail' not in body and b'events' not in body


def post(url,path,body,headers=None):
    connection=HTTPConnection(url.hostname,url.port,timeout=5)
    try:
        connection.request('POST',path,body=body,headers=headers or {'Content-Type':'application/json'})
        response=connection.getresponse()
        return response.status,response.read()
    finally:connection.close()


def test_history_is_capability_scoped_and_passes_only_bounded_filters(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        observed=[]
        fake.history=lambda **kwargs:observed.append(kwargs) or {'events':[]}
        assert post(url,'/history',b'{}')[0]==404
        assert post(url,url.path+'history',b'{"search":"needle","script":"42"}')[0]==200
        assert observed==[{'search':'needle','script':'42','limit':1000}]
        assert not calls


def test_native_scope_and_timestamp_identifiers_are_lossless_text(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        fake.read=lambda **kwargs:{'events':[{'id':2**53+15,'pid':2**53+17,
            'tid':2**53+18,'context_id':'ab'*16,'realm_id':2**53+19,
            'script_id':2**53+21,'ts':2**53+23}]}
        status,_,body=get(url,url.path+'data')
        event=json.loads(body)['events'][0]
        assert status==200
        assert event['history_scope']=={'pid':str(2**53+17),'context_id':'AB'*16,'realm_id':str(2**53+19)}
        assert event['timestamp_ns']==str(2**53+23)
        assert event['native_ids']=={'id':str(2**53+15),'pid':str(2**53+17),
            'tid':str(2**53+18),'realm_id':str(2**53+19),'script_id':str(2**53+21)}


def test_history_accepts_exact_scope_and_time_bound_fields(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        observed=[]
        fake.history=lambda **kwargs:observed.append(kwargs) or {'events':[]}
        query={'scope':{'pid':'21','context_id':'AB'*16,'realm_id':'0'},
               'start_ns':str(2**53+1),'end_ns':str(2**53+3)}
        assert post(url,url.path+'history',json.dumps(query).encode())[0]==200
        assert observed==[{**query,'limit':1000}]


@pytest.mark.parametrize('body',[b'[]',b'{"limit":100000}',b'{"search":"x","search":"y"}',
                                 b'{"search":NaN}',b'x'*8193,b'{'])
def test_history_rejects_malformed_or_unbounded_bodies(monkeypatch,body):
    with panel(monkeypatch) as (url,calls,fake):
        assert post(url,url.path+'history',body)[0]==400 and not calls


@pytest.mark.parametrize('header',[{'Content-Type':'text/plain'},
    {'Content-Type':'application/json','Transfer-Encoding':'chunked'},
    {'Content-Type':'application/json','Content-Length':'-1'}])
def test_history_rejects_ambiguous_transport(monkeypatch,header):
    with panel(monkeypatch) as (url,calls,fake):
        assert post(url,url.path+'history',b'{}',header)[0]==400 and not calls


@pytest.mark.parametrize('header',[{'Host':'evil.example'}, {'Origin':'https://evil.example'}, {'Sec-Fetch-Site':'cross-site'}])
def test_history_preserves_cross_origin_protection(monkeypatch,header):
    with panel(monkeypatch) as (url,calls,fake):
        assert post(url,url.path+'history',b'{}',{'Content-Type':'application/json',**header})[0]==403
        assert not calls


def test_rejected_request_bodies_deliver_readable_errors_repeatedly(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        for _ in range(40):
            assert post(url,url.path+'history',b'x'*4096,
                        {'Content-Type':'application/json','Sec-Fetch-Site':'cross-site'})[0]==403
            assert post(url,url.path+'history',b'x'*4096,
                        {'Content-Type':'text/plain'})[0]==400
        assert not calls


def test_history_post_rejects_body_completed_after_total_read_deadline(monkeypatch):
    location=SimpleNamespace(session={'run_id':'owned'},phase='live-prefix')
    source=SimpleNamespace(resolve=lambda:location)
    history_calls=[]
    def history(**kwargs):
        history_calls.append(kwargs)
        return {'events':[],'context_identification':{'attempt_limit':4},
                'source_phase':'live-prefix','complete':False}
    inspector=SimpleNamespace(history=history,close=lambda:None,closed=False)
    attribution=SimpleNamespace(attempts=0,reconcile=lambda _inspector:None,
                                enrich=lambda _data:None)
    server,address=ui._create_panel(source,inspector,attribution)
    handler_type=server.RequestHandlerClass
    clock=[0.0]
    statuses=[]
    monkeypatch.setattr(ui,'time',SimpleNamespace(monotonic=lambda:clock[0]))
    monkeypatch.setattr(handler_type,'allowed',lambda _self,**_kwargs:True)
    monkeypatch.setattr(handler_type,'send',
                        lambda _self,status,_body,_kind:statuses.append(status))

    class Headers:
        def get_all(self,name):
            return {'Content-Type':['application/json'],
                    'Content-Length':['2']}.get(name)

    class Connection:
        timeout=None
        def gettimeout(self):return self.timeout
        def settimeout(self,value):self.timeout=value

    class Body:
        def read(self,_count):
            clock[0]=6.0
            return b'{}'
        def read1(self,_count):
            clock[0]=6.0
            return b'{}'

    handler=handler_type.__new__(handler_type)
    handler.path=urlsplit(address).path+'history'
    handler.headers=Headers()
    handler.connection=Connection()
    handler.rfile=Body()
    try:
        handler.do_POST()
        assert statuses==[400]
        assert history_calls==[]
        assert handler.close_connection is True
        assert handler.connection.timeout is None
    finally:
        server.server_close()


def test_rejected_post_drain_has_total_deadline(monkeypatch):
    server,_=ui._create_panel(None,SimpleNamespace(close=lambda:None),None)
    handler_type=server.RequestHandlerClass
    clock=[0.0]
    received=[]
    monkeypatch.setattr(ui,'time',SimpleNamespace(monotonic=lambda:clock[0]))
    monkeypatch.setattr(handler_type,'send_response',lambda _self,_status:None)
    monkeypatch.setattr(handler_type,'send_header',lambda _self,_name,_value:None)
    monkeypatch.setattr(handler_type,'end_headers',lambda _self:None)

    class Connection:
        def shutdown(self,_how):pass
        def settimeout(self,_value):pass
        def recv(self,_size):
            received.append(True)
            clock[0]+=0.03
            return b'x'

    handler=handler_type.__new__(handler_type)
    handler.connection=Connection()
    handler.wfile=SimpleNamespace(write=lambda _body:None,flush=lambda:None)
    handler.command='POST'
    handler.close_connection=True
    try:
        handler.send(400,b'error','text/plain')
        assert 1<=len(received)<=2
        assert clock[0]<=0.06
    finally:
        server.server_close()


@pytest.mark.parametrize('closed,expected',[(False,400),(True,409)])
def test_history_reports_invalid_requests_separately_from_unavailable_recording(monkeypatch,closed,expected):
    with panel(monkeypatch) as (url,calls,fake):
        def failed(**kwargs):raise ContractError('private captured value')
        fake.history=failed;fake.closed=closed
        status,body=post(url,url.path+'history',b'{}')
        assert status==expected and b'private captured value' not in body


def test_refresh_and_history_never_run_active_probes_and_standalone_is_read_only(monkeypatch):
    probes=[]
    monkeypatch.setattr(ui.ContextAttribution,'identify',lambda *args:probes.append(args))
    with panel(monkeypatch) as (url,calls,fake):
        assert get(url,url.path+'data')[0]==200
        assert post(url,url.path+'history',b'{}')[0]==200
        assert post(url,url.path+'identify',b'{"confirm_active_probe":true}')[0]==404
    with panel(monkeypatch,enabled=True) as (url,calls,fake):
        data=json.loads(get(url,url.path+'data')[2])
        assert data['context_identification']['available']
        assert post(url,url.path+'history',b'{}')[0]==200
        assert not probes
        assert post(url,url.path+'identify',b'{"confirm_active_probe":true}')[0]==200
        assert len(probes)==1 and probes[0][1]=='http://127.0.0.1:12345'


@pytest.mark.parametrize('body',[b'{}',b'[]',b'{"confirm_active_probe":false}',
    b'{"confirm_active_probe":1}',b'{"confirm_active_probe":true,"endpoint":"http://evil.invalid"}',
    b'{"confirm_active_probe":true,"confirm_active_probe":true}',b'x'*8193])
def test_identification_requires_the_exact_explicit_action_before_any_browser_access(monkeypatch,body):
    probes=[]
    monkeypatch.setattr(ui.ContextAttribution,'identify',lambda *args:probes.append(args))
    with panel(monkeypatch,enabled=True) as (url,calls,fake):
        assert post(url,url.path+'identify',body)[0]==400
        assert not calls and not probes


def test_identification_preserves_origin_guard_and_failed_probe_does_not_close_reader(monkeypatch):
    probes=[]
    def identify(*args):probes.append(True);raise ContractError('private CDP detail')
    monkeypatch.setattr(ui.ContextAttribution,'identify',identify)
    with panel(monkeypatch,enabled=True) as (url,calls,fake):
        body=b'{"confirm_active_probe":true}'
        assert post(url,url.path+'identify',body,{'Content-Type':'application/json','Origin':'https://evil.invalid'})[0]==403
        assert not probes
        status,content=post(url,url.path+'identify',body)
        assert status==400 and b'private' not in content and probes
        assert get(url,url.path+'data')[0]==200 and not fake.closed


def test_export_is_explicit_download_is_digest_bound_and_reads_do_not_export(monkeypatch,tmp_path):
    import hashlib
    exports=[]
    def prepare(self,source,attribution,health):
        exports.append(True);body=b'private native bytes '+str(len(exports)).encode()
        self.path=tmp_path/'prepared';self.path.write_bytes(body)
        self.receipt={'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)}
        return self.receipt
    monkeypatch.setattr(ui.EvidenceExport,'prepare',prepare)
    with panel(monkeypatch) as (url,calls,fake):
        assert get(url,url.path+'data')[0]==200 and not exports
        assert get(url,url.path+'download/'+'0'*64)[0]==404
        status,body=post(url,url.path+'export',b'{"export_private_evidence":true}')
        assert status==200 and len(exports)==1
        first=json.loads(body)['sha256']
        status,headers,body=get(url,url.path+'download/'+first)
        assert status==200 and body==b'private native bytes 1'
        assert 'attachment;' in headers['Content-Disposition']
        assert headers['Content-Type']=='application/octet-stream'
        assert get(url,url.path+'download/'+first,{'Origin':'https://evil.invalid'})[0]==403
        assert post(url,url.path+'export',b'{"export_private_evidence":true}')[0]==200
        assert get(url,url.path+'download/'+first)[0]==404
        assert not fake.closed


@pytest.mark.parametrize('body',[b'{}',b'[]',b'{"export_private_evidence":1}',b'{"export_private_evidence":false}',
    b'{"export_private_evidence":true,"output":"C:/unrelated"}',b'{"export_private_evidence":true,"export_private_evidence":true}'])
def test_export_rejects_nonexplicit_or_path_bearing_requests_before_source_access(monkeypatch,body):
    exports=[];monkeypatch.setattr(ui.EvidenceExport,'prepare',lambda *args:exports.append(True))
    with panel(monkeypatch) as (url,calls,fake):
        assert post(url,url.path+'export',body)[0]==400 and not exports and not calls


def test_export_error_does_not_close_healthy_reader(monkeypatch):
    def fail(*args):raise OSError('private path')
    monkeypatch.setattr(ui.EvidenceExport,'prepare',fail)
    with panel(monkeypatch) as (url,calls,fake):
        status,body=post(url,url.path+'export',b'{"export_private_evidence":true}')
        assert status==400 and b'private path' not in body
        assert get(url,url.path+'data')[0]==200 and not fake.closed


def test_post_header_failure_does_not_start_a_second_response(monkeypatch):
    statuses=[]
    failed=[]
    original_response=ui.BaseHTTPRequestHandler.send_response
    original_headers=ui.BaseHTTPRequestHandler.end_headers
    def record_response(self,status,*args,**kwargs):
        statuses.append(status)
        return original_response(self,status,*args,**kwargs)
    def fail_after_headers(self):
        original_headers(self)
        if self.command=='POST' and not failed:
            failed.append(True)
            raise OSError('owned header send failure')
    monkeypatch.setattr(ui.BaseHTTPRequestHandler,'send_response',record_response)
    monkeypatch.setattr(ui.BaseHTTPRequestHandler,'end_headers',fail_after_headers)
    with panel(monkeypatch) as (url,_,fake):
        try:
            post(url,url.path+'history',b'{}')
        except (IncompleteRead,OSError):
            pass
        assert failed
        assert statuses==[200]
        assert not fake.closed


def test_comparison_download_is_independent_digest_bound_and_origin_guarded(monkeypatch,tmp_path):
    import hashlib
    compared=[]
    def prepare(self,inspector,attribution,request,**kwargs):
        compared.append(request)
        body=json.dumps({'count':len(compared)}).encode()
        self.path=tmp_path/'comparison';self.path.write_bytes(body)
        self.receipt={'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),'summary':{}}
        return self.receipt
    monkeypatch.setattr(ui.ComparisonExport,'prepare',prepare)
    with panel(monkeypatch) as (url,calls,fake):
        request={'a':{'filters':{},'cursor':'a'},'b':{'filters':{},'cursor':'b'}}
        body=json.dumps(request).encode()
        assert post(url,'/compare',body)[0]==404
        assert post(url,url.path+'compare',body,{'Content-Type':'application/json','Origin':'https://evil.invalid'})[0]==403
        assert not compared
        status,content=post(url,url.path+'compare',body)
        assert status==200 and compared==[request]
        digest=json.loads(content)['sha256']
        status,headers,download=get(url,url.path+'comparison-download/'+digest)
        assert status==200 and json.loads(download)=={'count':1}
        assert headers['Content-Type']=='application/json'
        assert 'browser-core-comparison.json' in headers['Content-Disposition']
        assert get(url,url.path+'download/'+digest)[0]==404
        assert post(url,url.path+'compare',body)[0]==200
        assert get(url,url.path+'comparison-download/'+digest)[0]==404
        assert get(url,url.path+'data')[0]==200


@pytest.mark.parametrize('kind,route,download',[
    ('evidence','export','download'),
    ('comparison','compare','comparison-download'),
])
def test_prepared_download_rejects_changed_bytes_under_original_digest(monkeypatch,tmp_path,kind,route,download):
    import hashlib
    original=b'private prepared output'
    changed=b'altered prepared output'
    assert len(original)==len(changed)
    path=tmp_path/'prepared'
    def prepare(self,*args,**kwargs):
        path.write_bytes(original)
        self.path=path
        self.receipt={'sha256':hashlib.sha256(original).hexdigest(),'bytes':len(original)}
        return self.receipt
    owner=ui.EvidenceExport if kind=='evidence' else ui.ComparisonExport
    monkeypatch.setattr(owner,'prepare',prepare)
    request=(b'{"export_private_evidence":true}' if kind=='evidence'
             else b'{"a":{},"b":{}}')
    with panel(monkeypatch) as (url,calls,fake):
        status,body=post(url,url.path+route,request)
        assert status==200
        digest=json.loads(body)['sha256']
        path.write_bytes(changed)
        status,headers,body=get(url,url.path+download+'/'+digest)
        assert status==409
        assert 'Content-Disposition' not in headers
        assert changed not in body and original not in body
        assert get(url,url.path+'data')[0]==200 and not fake.closed


@pytest.mark.parametrize('kind,route,download',[
    ('evidence','export','download'),
    ('comparison','compare','comparison-download'),
])
def test_prepared_download_sends_the_verified_bytes_after_file_changes_at_headers(
        monkeypatch,tmp_path,kind,route,download):
    import hashlib
    original=(b'private native bytes A' if kind=='evidence' else b'{"count":1}')
    changed=(b'private native bytes B' if kind=='evidence' else b'{"count":2}')
    assert len(original)==len(changed)
    digest=hashlib.sha256(original).hexdigest()
    path=tmp_path/'prepared'
    def prepare(self,*args,**kwargs):
        path.write_bytes(original)
        self.path=path
        self.receipt={'sha256':digest,'bytes':len(original)}
        return self.receipt
    owner=ui.EvidenceExport if kind=='evidence' else ui.ComparisonExport
    monkeypatch.setattr(owner,'prepare',prepare)
    original_send=ui.BaseHTTPRequestHandler.send_response
    replaced=[]
    def change_at_headers(handler,status,*args,**kwargs):
        if (handler.command=='GET' and status==200
                and handler.path.endswith('/'+download+'/'+digest)):
            path.write_bytes(changed)
            replaced.append(True)
        return original_send(handler,status,*args,**kwargs)
    monkeypatch.setattr(ui.BaseHTTPRequestHandler,'send_response',change_at_headers)
    request=(b'{"export_private_evidence":true}' if kind=='evidence'
             else b'{"a":{},"b":{}}')
    with panel(monkeypatch) as (url,_,fake):
        assert post(url,url.path+route,request)[0]==200
        status,headers,body=get(url,url.path+download+'/'+digest)
        assert replaced==[True]
        assert status==200 and body==original
        assert hashlib.sha256(body).hexdigest()==digest
        assert get(url,url.path+download+'/'+digest)[0]==409
        assert not fake.closed


def test_comparison_failure_retains_healthy_reader_and_does_not_leak_paths(monkeypatch):
    def failed(*args,**kwargs):raise OSError('private path')
    monkeypatch.setattr(ui.ComparisonExport,'prepare',failed)
    with panel(monkeypatch) as (url,calls,fake):
        assert post(url,url.path+'compare',b'{}')[0]==400 and not calls
        status,body=post(url,url.path+'compare',b'{"a":{},"b":{}}')
        assert status==400 and b'private path' not in body
        assert get(url,url.path+'data')[0]==200 and not fake.closed


def test_comparison_progress_and_cancel_remain_available_during_owned_read(monkeypatch):
    from browser_core.inspection_history import encode_cursor,history_filters,query_digest
    entered=Event();release=Event();results=[]
    def preparing(export,*args,**kwargs):
        entered.set()
        assert release.wait(5)
        export._check_cancel()
        raise AssertionError('expected cancellation')
    monkeypatch.setattr(ui.ComparisonExport,'_prepare',preparing)
    with panel(monkeypatch) as (url,calls,fake):
        fake.history_key=b'controlled comparison key'
        cursor=encode_cursor(fake.history_key,query_digest(history_filters(),1000),1)
        selection={'filters':{},'cursor':cursor}
        worker=Thread(target=lambda:results.append(post(url,url.path+'compare',json.dumps({'a':selection,'b':selection}).encode())))
        worker.start()
        try:
            assert entered.wait(5)
            assert get(url,url.path+'data')[0]==503
            status,_,body=get(url,url.path+'comparison-progress')
            progress=json.loads(body)
            assert status==200 and progress['preparing'] and progress['phase']=='reading'
            assert progress['observations_checked']=='0' and not progress['cancel_requested']
            assert post(url,url.path+'comparison-cancel',b'{"extra":true}')[0]==400
            assert get(url,url.path+'comparison-progress',{'Origin':'https://evil.example'})[0]==403
            assert post(url,url.path+'comparison-cancel',b'{}',{'Content-Type':'application/json','Origin':'https://evil.example'})[0]==403
            status,body=post(url,url.path+'comparison-cancel',b'{}')
            assert status==200 and json.loads(body)=={'cancel_requested':True}
            assert json.loads(get(url,url.path+'comparison-progress')[2])['cancel_requested']
            release.set();worker.join(5)
            assert not worker.is_alive() and results[0][0]==409
            assert json.loads(results[0][1])['cancelled'] is True and not fake.closed
            assert json.loads(get(url,url.path+'comparison-progress')[2])=={'preparing':False}
            assert json.loads(post(url,url.path+'comparison-cancel',b'{}')[1])=={'cancel_requested':False}
        finally:
            release.set();worker.join(5)


def test_comparison_status_and_cancellation_require_the_owned_panel_route(monkeypatch):
    with panel(monkeypatch) as (url,calls,fake):
        assert get(url,'/comparison-progress')[0]==404
        assert post(url,'/comparison-cancel',b'{}')[0]==404
        assert json.loads(get(url,url.path+'comparison-progress')[2])=={'preparing':False}
        assert not calls


def test_bundle_panel_preserves_interruption_status_and_disables_all_capture_actions(monkeypatch):
    stopped=[]
    source=SimpleNamespace(resolve=lambda:None)
    bundle=SimpleNamespace(path=Path('/owned-copy'),source=source,attribution=ui.ContextAttribution(),
        metadata={'health':None,'capture':{'schema':ui.SCHEMA,'allowlist':ui.ALLOWLIST}},
        summary={'source_phase':'interrupted-recording'},close=lambda:stopped.append(True))
    fake=SimpleNamespace(read=lambda **kw:{'events':[],'source_phase':'finalized-recording','recording_settled':True,
        'browser_running':False,'complete':True},history=lambda **kw:{'events':[]},close=lambda:None)
    monkeypatch.setattr(ui,'OpenEvidence',lambda *a,**k:bundle)
    monkeypatch.setattr(ui,'IncrementalInspection',lambda *a:fake)
    server,address=ui.create_evidence_inspector(Path('/bundle'),Path('/repo'),Path('/reader'))
    thread=Thread(target=server.serve_forever,daemon=True);thread.start();url=urlsplit(address)
    try:
        status,_,body=get(url,url.path+'data');data=json.loads(body)
        assert status==200 and data['source_phase']=='interrupted-recording'
        assert not data['complete'] and data['recovery_incomplete']
        assert data['context_identification']['retention']=='evidence-bundle'
        for action in ('identify','export'):
            assert post(url,url.path+action,b'{}')[0]==404
        assert get(url,url.path+'download/'+'0'*64)[0]==404
    finally:server.shutdown();server.server_close();thread.join(5)
    assert stopped


def test_bundle_panel_does_not_publish_data_after_private_copy_changes(monkeypatch):
    changed=[False]
    def resolve():
        if changed[0]:
            raise ContractError('verified evidence recording copy changed')
        return SimpleNamespace()
    source=SimpleNamespace(resolve=resolve)
    attribution=SimpleNamespace(attempts=0,
        reconcile=lambda inspector:changed.__setitem__(0,True),
        enrich=lambda data:data.update(context_identification={'attempt_limit':4}))
    bundle=SimpleNamespace(path=Path('/owned-copy'),source=source,attribution=attribution,
        metadata={'health':None,'capture':{'schema':ui.SCHEMA,'allowlist':ui.ALLOWLIST}},
        summary={'source_phase':'recovered-prefix'},close=lambda:None)
    def read(**kwargs):
        source.resolve()
        return {'events':[],'source_phase':'finalized-recording',
                'browser_running':False,'complete':True}
    fake=SimpleNamespace(read=read,history=read,close=lambda:None,closed=False)
    monkeypatch.setattr(ui,'OpenEvidence',lambda *a,**kw:bundle)
    monkeypatch.setattr(ui,'IncrementalInspection',lambda *a:fake)
    server,address=ui.create_evidence_inspector(Path('/bundle'),Path('/repo'),Path('/reader'))
    thread=Thread(target=server.serve_forever,daemon=True);thread.start();url=urlsplit(address)
    try:
        assert get(url,url.path+'data')[0]==409
    finally:
        server.shutdown();server.server_close();thread.join(5)


def test_metadata_only_bundle_is_rejected_before_opening_private_value_panel(monkeypatch):
    closed=[]
    bundle=SimpleNamespace(path=Path('/owned-copy'),source=SimpleNamespace(),
                           metadata={'capture':CAPTURE_OFF},close=lambda:closed.append(True))
    monkeypatch.setattr(ui,'OpenEvidence',lambda *args,**kwargs:bundle)
    monkeypatch.setattr(ui,'IncrementalInspection',lambda *args:(_ for _ in ()).throw(
        AssertionError('private value reader must not be created')))
    with pytest.raises(ContractError,match='metadata-only'):
        ui.create_evidence_inspector(Path('/bundle'),Path('/repo'),Path('/reader'))
    assert closed==[True]


def test_evidence_panel_constructor_failure_releases_verified_copy(monkeypatch):
    closed=[]
    bundle=SimpleNamespace(path=Path('/owned-copy'),source=SimpleNamespace(),
                           metadata={'capture':{'schema':ui.SCHEMA,'allowlist':ui.ALLOWLIST}},
                           close=lambda:closed.append(True))
    monkeypatch.setattr(ui,'OpenEvidence',lambda *args,**kwargs:bundle)
    monkeypatch.setattr(ui,'IncrementalInspection',lambda *args:(_ for _ in ()).throw(
        ContractError('reader unavailable')))
    with pytest.raises(ContractError,match='reader unavailable'):
        ui.create_evidence_inspector(Path('/bundle'),Path('/repo'),Path('/reader'))
    assert closed==[True]
