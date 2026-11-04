from copy import deepcopy
import hashlib
from types import SimpleNamespace
from contextlib import contextmanager
import pytest

import browser_core.inspection_attribution as attribution
from browser_core.contracts import ContractError
from browser_core.trace_rpc import DecoderInterrupted


def probe(frame='frame-a', script=7, marker=(123456789,987654321)):
    return {'marker':marker,'probe_script_id':script,
            'metadata':{'frame_id':frame,'kind':'frame','target_id':'owned-target',
                        'cdp_context_unique_id':'cdp-world'},
            'sources':{'4':attribution.source_label('https://fixture.invalid/app.js?private=value')}}


def test_debugger_source_display_is_bounded_in_utf8_bytes():
    url='https://fixture.invalid/'+'é'*500
    label=attribution.source_label(url)
    assert label['status']=='debugger-reported'
    assert len(label['display'].encode('utf-8'))<=512
    assert url.startswith(label['display'])
    assert label['url_sha256']==hashlib.sha256(url.encode()).hexdigest()


def test_debugger_source_url_with_surrogate_has_serializable_display():
    label=attribution.source_label('https://fixture.invalid/\ud800')
    assert label['status']=='debugger-reported'
    assert label['display'].encode('utf-8')


def event(pid=10, context='aa', event_id=1, script=7, marker=(123456789,987654321)):
    return {'id':event_id,'pid':pid,'context_id':context,'script_id':script,
            'api':'OffscreenCanvasRenderingContext2D.getImageData',
            'parameters':{'observed':[{'type':'number','value':v} for v in (*marker,1,1)]}}


def enriched(index,events):
    result={'events':deepcopy(events)};index.enrich(result);return result


def test_identification_requires_both_native_script_and_random_arguments():
    index=attribution.ContextAttribution();index.probes=[probe()]
    wrong_script=event(script=8);wrong_marker=event(marker=(1,2),event_id=2)
    index.ingest([wrong_script,wrong_marker])
    assert not index.matches
    right=event();index.ingest([right])
    app=event(script=4,event_id=3)
    result=enriched(index,[right,app,event(pid=11,script=4,event_id=4)])
    assert result['events'][0]['observation_role']=='context-identification-probe'
    assert result['events'][1]['attribution']['source']['display']=='https://fixture.invalid/app.js'
    assert 'observation_role' not in result['events'][1]
    assert result['events'][2]['attribution']['status']=='unresolved'
    assert 'private' not in str(result)


def test_known_probe_script_mismatch_is_not_excluded_as_analyst_activity():
    index=attribution.ContextAttribution();index.probes=[probe()]
    copied_marker=event(script=8)
    index.ingest([copied_marker])
    assert copied_marker['id'] not in index.probe_events
    result=enriched(index,[copied_marker])['events'][0]
    assert 'observation_role' not in result
    assert result['attribution']['status']=='unresolved'


def test_boolean_argument_cannot_match_numeric_probe_marker():
    index=attribution.ContextAttribution();index.probes=[probe()]
    row=event()
    row['parameters']['observed'][-1]={'type':'boolean','value':True}
    index.ingest([row])
    assert row['id'] not in index.probe_events
    assert not index.matches


def test_enriched_attribution_does_not_expose_retained_probe_state():
    index=attribution.ContextAttribution();p=probe()
    p['metadata']['document']={'display':'https://fixture.invalid/page'}
    index.probes=[p]
    index.last_attempt={'status':'complete','details':{'count':1}}
    index.ingest([event()])

    first=enriched(index,[event(script=4)])
    first['events'][0]['attribution']['source']['display']='tampered source'
    first['events'][0]['attribution']['document']['display']='tampered document'
    first['context_identification']['last_attempt']['details']['count']=0

    second=enriched(index,[event(script=4)])
    observed=second['events'][0]['attribution']
    assert observed['source']['display']=='https://fixture.invalid/app.js'
    assert observed['document']['display']=='https://fixture.invalid/page'
    assert second['context_identification']['last_attempt']['details']['count']==1


def test_same_url_frames_and_reused_numeric_ids_do_not_merge_native_contexts():
    index=attribution.ContextAttribution();index.probes=[probe(),probe('frame-b',8,(333333333,444444444))]
    index.ingest([event(),event(context='bb',script=8,marker=(333333333,444444444),event_id=2)])
    rows=enriched(index,[event(script=4),event(context='bb',script=4,event_id=3),event(context='cc',script=4,event_id=4)])['events']
    assert [r['attribution'].get('frame_id') for r in rows]==['frame-a','frame-b',None]


def test_probe_replayed_in_another_context_is_ambiguous_even_across_ingestion_batches():
    index=attribution.ContextAttribution();index.probes=[probe()]
    index.ingest([event()]);index.ingest([event(context='bb',event_id=2)])
    assert index.conflicts=={(10,'aa'),(10,'bb')}
    assert all(e['attribution']['reason']=='ambiguous-probe' for e in enriched(index,[event(),event(context='bb')])['events'])


def test_conflicting_context_labels_and_conflicting_source_snapshots_fail_closed():
    index=attribution.ContextAttribution();index.probes=[probe(),probe('frame-b',8,(2,3))]
    index.ingest([event(),event(script=8,marker=(2,3),event_id=2)])
    assert enriched(index,[event(script=4)])['events'][0]['attribution']['reason']=='ambiguous-probe'
    first=probe()['sources'];second={'4':attribution.source_label('https://fixture.invalid/other.js')}
    merged=attribution._merge_sources(first,second)
    assert merged['4']['status']=='unresolved'
    assert attribution._merge_sources(merged,first)['4']['status']=='unresolved'


def test_distinct_debugger_labels_with_lone_surrogate_stay_ambiguous():
    surrogate=attribution.source_label('\ud800')
    question=attribution.source_label('?')
    assert surrogate['display']==question['display']
    assert surrogate['url_sha256']!=question['url_sha256']
    merged=attribution._merge_sources({'4':surrogate},{'4':question})
    assert merged['4']=={'status':'unresolved','reason':'ambiguous-script-id-in-context'}


def test_two_target_views_of_one_frame_agree_but_missing_scripts_stay_unresolved():
    index=attribution.ContextAttribution();a=probe();b=probe(script=8,marker=(2,3));b['metadata']['target_id']='oopif'
    index.probes=[a,b];index.ingest([event(),event(script=8,marker=(2,3),event_id=2)])
    result=enriched(index,[event(script=999)])
    assert not index.conflicts
    assert result['events'][0]['attribution']['status']=='probe-correlated'
    assert result['events'][0]['attribution']['source']['status']=='unresolved'


def test_two_target_views_of_one_frame_cannot_claim_conflicting_documents():
    index=attribution.ContextAttribution()
    first=probe()
    second=probe(script=8,marker=(2,3))
    second['metadata']['target_id']='oopif'
    first['metadata']['document']=attribution.source_label('https://old.invalid/page')
    second['metadata']['document']=attribution.source_label('https://new.invalid/page')
    index.probes=[first,second]

    index.ingest([event(),event(script=8,marker=(2,3),event_id=2)])

    result=enriched(index,[event(script=4,marker=(7,8))])
    assert result['events'][0]['attribution']=={
        'status':'unresolved','reason':'ambiguous-probe'}


def test_reconcile_rebuild_does_not_reuse_native_event_ids_and_detects_truncated_matches(monkeypatch):
    index=attribution.ContextAttribution();index.probes=[probe()]
    rows=[event()];total=[1]
    monkeypatch.setattr(attribution,'decode_rows',lambda *a,**kw:(rows,total[0]))
    queries=[]
    decoder=SimpleNamespace(timeout=30,query=lambda sql,**kw:queries.append((sql,kw)) or b'csv')
    reader=SimpleNamespace(decoder=decoder,decoder_restarts=0)
    index.reconcile(reader);assert index.probe_events=={1}
    rows[:]=[event(event_id=99)];reader.decoder_restarts=1
    index.reconcile(reader);assert index.probe_events=={99}
    assert queries[0][1]['max_rows']<=1001 and 'INSTR' in queries[0][0]
    total[0]=1001
    index.reconcile(reader)
    assert enriched(index,[event(script=4)])['events'][0]['attribution']['reason']=='probe-match-limit-reached'
    assert enriched(index,[])['context_identification']['matched_native_contexts']==0


def test_reconcile_rejects_short_probe_page_with_incomplete_count(monkeypatch):
    index=attribution.ContextAttribution();index.probes=[probe()]
    monkeypatch.setattr(attribution,'decode_rows',lambda *a,**kw:([event()],2))
    decoder=SimpleNamespace(timeout=30,query=lambda *a,**kw:b'csv')
    reader=SimpleNamespace(decoder=decoder,decoder_restarts=0)
    with pytest.raises(ContractError,match='probe match count'):
        index.reconcile(reader)
    assert not index.matches
    assert decoder.timeout==30


def test_reconcile_restores_decoder_timeout_after_probe_scan(monkeypatch):
    index=attribution.ContextAttribution();index.probes=[probe()]
    monkeypatch.setattr(attribution,'decode_rows',lambda *args,**kwargs:([],0))
    decoder=SimpleNamespace(timeout=30,query=lambda *args,**kwargs:b'csv')
    reader=SimpleNamespace(decoder=decoder,decoder_restarts=0)

    index.reconcile(reader)

    assert decoder.timeout==30


def test_query_interruption_enters_existing_verified_decoder_replay():
    index=attribution.ContextAttribution();index.probes=[probe()]
    def fail(*a,**k):raise DecoderInterrupted('helper exited')
    recovered=[]
    def recover():recovered.append(True);raise ContractError('rebuilding')
    decoder=SimpleNamespace(timeout=30,query=fail)
    reader=SimpleNamespace(decoder=decoder,decoder_restarts=0,_recover_decoder=recover)
    with pytest.raises(ContractError,match='rebuilding'):index.reconcile(reader)
    assert recovered
    assert decoder.timeout==30


def test_attempts_bounded_and_failures_do_not_masquerade_as_success(monkeypatch):
    index=attribution.ContextAttribution()
    def fail(endpoint):raise ContractError('unavailable')
    monkeypatch.setattr(attribution,'collect_probes',fail)
    for _ in range(attribution.MAX_ATTEMPTS):
        with pytest.raises(ContractError,match='unavailable'):index.identify('owned')
    with pytest.raises(ContractError,match='attempt limit'):index.identify('owned')
    assert index.last_attempt=={'status':'unavailable'} and not index.probes


def test_identification_result_cannot_change_retained_attempt(monkeypatch):
    index=attribution.ContextAttribution()
    summary={'probes_requested':1,'probe_callers_verified':1,
             'unavailable_contexts_or_commands':0,'truncated':False}
    monkeypatch.setattr(attribution,'collect_probes',lambda endpoint:([probe()],summary))
    returned=index.identify('owned')
    returned['probes_requested']=99
    assert index.last_attempt['probes_requested']==1


def test_failed_or_intercepted_probe_is_labeled_without_creating_context_attribution():
    index=attribution.ContextAttribution();p=probe();p['probe_script_id']=None;index.probes=[p]
    row=event(script=100);index.ingest([row])
    result=enriched(index,[row])['events'][0]
    assert result['observation_role']=='context-identification-probe'
    assert result['attribution']['status']=='unresolved' and not index.matches


def test_debugger_metadata_is_context_scoped_bounded_and_not_fetched_provenance(monkeypatch):
    peer=attribution._Peer(None,None,0)
    for ctx in (1,2):
        peer.event({'sessionId':'s','method':'Debugger.scriptParsed','params':{'scriptId':'4','executionContextId':ctx,'url':'https://fixture.invalid/a'}})
    assert len(peer.scripts['s'])==2
    monkeypatch.setattr(attribution,'MAX_SCRIPTS',2)
    peer.event({'sessionId':'s','method':'Debugger.scriptParsed','params':{'scriptId':'5','executionContextId':2,'url':'https://fixture.invalid/b'}})
    assert peer.truncated and len(peer.scripts['s'])==2
    for value in ('https://user:password@fixture.invalid/a?q=secret#value','data:text/javascript,private'):
        label=attribution.source_label(value)
        assert label['not_fetch_provenance'] is True and len(label['url_sha256'])==64
        assert not any(v in label['display'] for v in ('password','secret','private'))
    assert attribution.source_label('https://fixture.invalid/\nsecret')['status']=='unavailable'


def test_debugger_source_label_omits_terminal_delete_and_ambiguous_authority():
    assert attribution.source_label('https://fixture.invalid/a\x7fb')['status'] == 'unavailable'
    label = attribution.source_label('https://fixture.invalid\\private/path?token=secret')
    assert label['status'] == 'debugger-reported'
    assert label['display'] == '(non-network source label)'
    assert label['not_fetch_provenance'] is True
    for value in ('https://@fixture.invalid/a', 'https://:@fixture.invalid/a'):
        assert attribution.source_label(value)['display'] == '(non-network source label)'


def test_context_events_do_not_retain_unused_unbounded_cdp_metadata():
    peer=attribution._Peer(None,None,0)
    peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                'params':{'context':{'id':1,'uniqueId':'world-1',
                    'auxData':{'frameId':'frame-1','unused':'a'*100_000},
                    'origin':'b'*100_000}}})
    assert len(repr(peer.contexts['s'][1]))<1024
    assert peer.contexts['s'][1]['auxData']['frameId']=='frame-1'

    peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                'params':{'context':{'id':2,'uniqueId':'world-2',
                    'auxData':{'frameId':'x'*100_000}}}})
    assert not peer.contexts['s'] and peer.truncated


@pytest.mark.parametrize('script_id', ['2147483648', '9999999999999999999'])
def test_uncorrelatable_debugger_script_ids_do_not_enter_exportable_probe_state(script_id):
    peer=attribution._Peer(None,None,0)
    peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                'params':{'context':{'id':1,'uniqueId':'world-1','auxData':{}}}})
    peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                'params':{'scriptId':script_id,'executionContextId':1,
                          'url':'https://fixture.invalid/app.js'}})
    assert not peer.scripts['s']
    assert peer.truncated


@pytest.mark.parametrize('method,params', [
    ('Runtime.executionContextDestroyed', {'executionContextId': 1}),
    ('Runtime.executionContextsCleared', {}),
])
def test_destroyed_context_discards_stale_debugger_script_labels(method,params):
    peer=attribution._Peer(None,None,0)
    for context_id in (1,2):
        peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                    'params':{'context':{'id':context_id,'uniqueId':f'old-{context_id}',
                                         'auxData':{'frameId':'same-frame'}}}})
        peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                    'params':{'scriptId':str(context_id),'executionContextId':context_id,
                              'url':f'https://old.invalid/{context_id}.js'}})
    peer.event({'sessionId':'other','method':'Debugger.scriptParsed',
                'params':{'scriptId':'3','executionContextId':1,
                          'url':'https://other.invalid/app.js'}})

    peer.event({'sessionId':'s','method':method,'params':params})
    peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                'params':{'context':{'id':1,'uniqueId':'new-1',
                                     'auxData':{'frameId':'same-frame'}}}})

    assert (1,'1') not in peer.scripts['s']
    assert ((2,'2') in peer.scripts['s']) is (method == 'Runtime.executionContextDestroyed')
    assert (1,'3') in peer.scripts['other']


def test_destroyed_and_recreated_context_cannot_verify_an_inflight_probe():
    peer=attribution._Peer(None,None,0)
    created={'sessionId':'s','method':'Runtime.executionContextCreated',
        'params':{'context':{'id':1,'uniqueId':'same-world','auxData':{'frameId':'frame'}}}}
    peer.event(created)
    before=peer.versions['s']
    peer.event({'sessionId':'s','method':'Runtime.executionContextDestroyed',
                'params':{'executionContextId':1}})
    peer.event(created)
    assert peer.contexts['s'][1]['uniqueId']=='same-world'
    assert peer.versions['s']>before


@pytest.mark.parametrize('method,params',[
    ('Runtime.executionContextDestroyed', {'executionContextId':'1'}),
    ('Runtime.executionContextCreated', {'context':{'id':1,'uniqueId':None}}),
    ('Runtime.executionContextsCleared', []),
    ('Page.frameNavigated', []),
    ('Page.frameNavigated', {}),
    ('Page.frameNavigated', {'frame': {'id': []}}),
    ('Page.frameDetached', []),
    ('Page.frameDetached', {}),
    ('Page.frameDetached', {'frameId': []}),
])
def test_malformed_context_lifecycle_invalidates_session_labels(method,params):
    peer=attribution._Peer(None,None,0)
    peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                'params':{'context':{'id':1,'uniqueId':'old-world','auxData':{}}}})
    peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                'params':{'scriptId':'4','executionContextId':1,
                          'url':'https://old.invalid/app.js'}})
    peer.event({'sessionId':'s','method':method,'params':params})
    assert peer.truncated
    assert not peer.contexts['s'] and not peer.scripts['s']
    assert peer.versions['s']==1


@pytest.mark.parametrize('invalid_id',[0,-1])
@pytest.mark.parametrize('method,params',[
    ('Runtime.executionContextCreated',lambda value:{'context':{'id':value,
        'uniqueId':'invalid-world','auxData':{}}}),
    ('Runtime.executionContextDestroyed',lambda value:{'executionContextId':value}),
    ('Debugger.scriptParsed',lambda value:{'scriptId':'5','executionContextId':value,
        'url':'https://invalid.example/app.js'}),
])
def test_nonpositive_context_ids_cannot_leave_stale_debugger_labels(method,params,invalid_id):
    peer=attribution._Peer(None,None,0)
    peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                'params':{'context':{'id':1,'uniqueId':'real-world','auxData':{}}}})
    peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                'params':{'scriptId':'4','executionContextId':1,
                          'url':'https://real.example/app.js'}})
    peer.event({'sessionId':'s','method':method,'params':params(invalid_id)})
    assert peer.truncated and not peer.scripts['s']
    if method.startswith('Runtime.'):
        assert not peer.contexts['s']


@pytest.mark.parametrize('method,params',[
    ('Page.frameNavigated', {'frame': {'id': 'departed-frame'}}),
    ('Page.frameDetached', {'frameId': 'departed-frame'}),
])
def test_frame_lifecycle_retires_stale_debugger_labels(method,params):
    peer=attribution._Peer(None,None,0)
    for sid in ('departed','other'):
        peer.event({'sessionId':sid,'method':'Runtime.executionContextCreated',
                    'params':{'context':{'id':1,'uniqueId':sid,
                                         'auxData':{'frameId':'departed-frame'}}}})
        peer.event({'sessionId':sid,'method':'Debugger.scriptParsed',
                    'params':{'scriptId':'4','executionContextId':1,
                              'url':'https://old.invalid/app.js'}})
    peer.event({'sessionId':'departed','method':method,'params':params})
    assert peer.truncated
    assert not peer.contexts['departed'] and not peer.scripts['departed']
    assert (1,'4') in peer.scripts['other']
    assert peer.versions['departed']==1 and peer.versions['other']==0


def test_reused_numeric_context_id_discards_old_script_labels_without_destroy_notice():
    peer=attribution._Peer(None,None,0)
    def created(unique):
        peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                    'params':{'context':{'id':1,'uniqueId':unique,
                                         'auxData':{'frameId':'same-frame'}}}})
    created('old-unique')
    for context_id in (1,2):
        peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                    'params':{'scriptId':'4','executionContextId':context_id,
                              'url':f'https://old.invalid/{context_id}.js'}})
    created('old-unique')
    assert (1,'4') in peer.scripts['s']
    created('new-unique')
    assert (1,'4') not in peer.scripts['s']
    assert (2,'4') in peer.scripts['s']


def test_repeated_context_with_changed_frame_metadata_retires_old_script_labels():
    peer=attribution._Peer(None,None,0)
    def created(frame):
        peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                    'params':{'context':{'id':1,'uniqueId':'same-world',
                                         'auxData':{'frameId':frame}}}})
    created('first-frame')
    peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                'params':{'scriptId':'4','executionContextId':1,
                          'url':'https://first.invalid/app.js'}})
    created('second-frame')
    assert (1,'4') not in peer.scripts['s']
    assert peer.versions['s']==1 and peer.truncated


def test_script_label_before_first_context_creation_is_not_attributed_to_later_world():
    peer=attribution._Peer(None,None,0)
    peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                'params':{'scriptId':'4','executionContextId':1,
                          'url':'https://old.invalid/app.js'}})
    assert (1,'4') in peer.scripts['s']
    peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                'params':{'context':{'id':1,'uniqueId':'new-world',
                                     'auxData':{'frameId':'same-frame'}}}})
    assert (1,'4') not in peer.scripts['s']
    assert peer.truncated


def test_worker_probe_configures_skip_before_debugger_enable_and_never_pauses_or_resumes(monkeypatch):
    calls=[]
    class Peer:
        def __init__(self,*args):
            self.contexts={'s':{1:{'id':1,'uniqueId':'worker-context'}}}
            self.scripts={'s':{}}
            self.versions={'s':0};self.truncated=False
        def call(self,method,params=None,sid=None):
            calls.append((method,params))
            if method=='Target.getTargets':return {'targetInfos':[{'targetId':'w','type':'worker','url':'https://fixture.invalid/worker.js'}]}
            if method=='Target.attachToTarget':return {'sessionId':'s'}
            if method=='Runtime.evaluate':
                label=params['expression'].split('//# sourceURL=')[1]
                self.scripts['s'][(1,'5')]={'scriptId':'5','executionContextId':1,'url':label}
                return {'result':{'value':True}}
            return {}
    @contextmanager
    def connection(*args,**kwargs):yield (None,None)
    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    methods=[m for m,p in calls]
    assert methods.index('Debugger.setSkipAllPauses')<methods.index('Debugger.enable')
    assert not {'Debugger.pause','Debugger.resume','Runtime.runIfWaitingForDebugger'}&set(methods)
    assert calls[-1]==('Target.detachFromTarget',{'sessionId':'s'})
    assert receipt['probe_callers_verified']==1 and len(probes)==1
    params=next(p for m,p in calls if m=='Runtime.evaluate')
    assert params['uniqueContextId']=='worker-context' and params['timeout']==750


def test_worker_contexts_skipped_by_remaining_probe_budget_report_truncation(monkeypatch):
    monkeypatch.setattr(attribution,'MAX_PROBES',2)
    class Peer:
        def __init__(self,*args):
            self.contexts={sid:{index:{'id':index,'uniqueId':f'{sid}-{index}','auxData':{}}
                                for index in indices}
                           for sid,indices in (('first',(1,)),('last',(1,2)))}
            self.scripts={'first':{},'last':{}}
            self.versions={'first':0,'last':0}
            self.truncated=False
        def call(self,method,params=None,sid=None):
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':target,'type':'worker'}
                                       for target in ('first','last')]}
            if method=='Target.attachToTarget':return {'sessionId':params['targetId']}
            if method=='Runtime.evaluate':
                label=params['expression'].split('//# sourceURL=')[1]
                context=next(c for c in self.contexts[sid].values()
                             if c['uniqueId']==params['uniqueContextId'])
                self.scripts[sid][(context['id'],'5')]={
                    'scriptId':'5','executionContextId':context['id'],'url':label}
                return {'result':{'value':True}}
            return {}

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)
    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert len(probes)==2 and receipt['probe_callers_verified']==2
    assert receipt['truncated'] is True


@pytest.mark.parametrize('inventory',[{}, {'targetInfos':None}])
def test_missing_or_invalid_target_inventory_cannot_report_no_contexts(monkeypatch,inventory):
    class Peer:
        truncated=False
        def __init__(self,*args):pass
        def call(self,method,params=None,sid=None):
            assert method=='Target.getTargets'
            return inventory

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)
    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    with pytest.raises(ContractError,match='target inventory'):
        attribution.collect_probes('owned')


def test_malformed_eligible_target_is_reported_as_truncated(monkeypatch):
    class Peer:
        truncated=False
        def __init__(self,*args):pass
        def call(self,method,params=None,sid=None):
            assert method=='Target.getTargets'
            return {'targetInfos':[{'type':'worker'}]}

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)
    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert probes==[] and receipt['truncated'] is True


def test_oversized_target_inventory_stops_before_unneeded_entries(monkeypatch):
    monkeypatch.setattr(attribution,'MAX_TARGET_INFOS',2,raising=False)
    class UnneededTarget(dict):
        def get(self,*args):
            raise AssertionError('target beyond inventory scan limit was inspected')
    class Peer:
        truncated=False
        def __init__(self,*args):pass
        def call(self,method,params=None,sid=None):
            assert method=='Target.getTargets'
            return {'targetInfos':[{'type':'worker'}, {'type':'worker'}, UnneededTarget()]}

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)
    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert probes==[] and receipt['truncated'] is True


@pytest.mark.parametrize('url,truncated',[
    (['chrome-extension://private/worker.js'], True),
    ('CHROME-EXTENSION://private/worker.js', False),
])
def test_malformed_or_extension_target_url_is_not_eligible_for_active_probe(monkeypatch,url,truncated):
    calls=[]
    class Peer:
        truncated=False
        def __init__(self,*args):pass
        def call(self,method,params=None,sid=None):
            calls.append(method)
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'extension','type':'worker',
                                        'url':url}]}
            raise AssertionError('extension target reached an active probe')

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)
    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert calls==['Target.getTargets']
    assert probes==[] and receipt['truncated'] is truncated


def test_decimal_script_id_aliases_cannot_hide_conflicting_debugger_labels(monkeypatch):
    class Peer:
        def __init__(self,*args):
            self.contexts={'s':{1:{'id':1,'uniqueId':'worker-context'}}}
            self.scripts={'s':{
                (1,'04'):{'scriptId':'04','executionContextId':1,
                          'url':'https://fixture.invalid/first.js'},
                (1,'4'):{'scriptId':'4','executionContextId':1,
                         'url':'https://fixture.invalid/second.js'},
            }}
            self.versions={'s':0}
            self.truncated=False

        def call(self,method,params=None,sid=None):
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'w','type':'worker',
                                        'url':'https://fixture.invalid/worker.js'}]}
            if method=='Target.attachToTarget':return {'sessionId':'s'}
            if method=='Runtime.evaluate':
                label=params['expression'].split('//# sourceURL=')[1]
                self.scripts['s'][(1,'5')]={'scriptId':'5','executionContextId':1,'url':label}
                return {'result':{'value':True}}
            return {}

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')

    assert receipt['probe_callers_verified']==1
    assert probes[0]['sources']['4']=={
        'status':'unresolved','reason':'ambiguous-script-id-in-context'}
    assert '04' not in probes[0]['sources']


def test_repeated_script_id_with_conflicting_urls_has_no_resolved_source(monkeypatch):
    class Peer(attribution._Peer):
        def __init__(self, *args):
            super().__init__(*args)
            self.event({'sessionId':'s','method':'Runtime.executionContextCreated',
                        'params':{'context':{'id':1,'uniqueId':'worker-context','auxData':{}}}})
            for url in ('https://fixture.invalid/first.js',
                        'https://fixture.invalid/second.js'):
                self.event({'sessionId':'s','method':'Debugger.scriptParsed',
                            'params':{'scriptId':'4','executionContextId':1,'url':url}})

        def call(self, method, params=None, sid=None):
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'w','type':'worker',
                                        'url':'https://fixture.invalid/worker.js'}]}
            if method=='Target.attachToTarget':return {'sessionId':'s'}
            if method=='Runtime.evaluate':
                label=params['expression'].split('//# sourceURL=')[1]
                self.event({'sessionId':'s','method':'Debugger.scriptParsed',
                            'params':{'scriptId':'5','executionContextId':1,'url':label}})
                return {'result':{'value':True}}
            return {}

    @contextmanager
    def connection(*args, **kwargs):
        yield (None, None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')

    assert receipt['probe_callers_verified']==1
    assert probes[0]['sources']['4']=={
        'status':'unresolved','reason':'ambiguous-script-id-in-context'}


def test_repeated_script_id_remains_ambiguous_at_inventory_limit(monkeypatch):
    monkeypatch.setattr(attribution, 'MAX_SCRIPTS', 1)
    peer=attribution._Peer(None,None,0)
    def parsed(url):
        peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                    'params':{'scriptId':'4','executionContextId':1,'url':url}})

    parsed('https://fixture.invalid/first.js')
    parsed('https://fixture.invalid/first.js')
    assert peer.scripts['s'][(1,'4')]['url']=='https://fixture.invalid/first.js'
    parsed('https://fixture.invalid/second.js')
    assert peer.scripts['s'][(1,'4')]['url'] is None


def test_malformed_script_update_cannot_preserve_stale_source_label():
    peer=attribution._Peer(None,None,0)
    peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                'params':{'scriptId':'4','executionContextId':1,
                          'url':'https://old.invalid/app.js'}})
    peer.event({'sessionId':'s','method':'Debugger.scriptParsed',
                'params':{'scriptId':'4','executionContextId':1,'url':['malformed']}})
    assert peer.truncated
    assert not peer.scripts['s']
    assert peer.versions['s']==1


@pytest.mark.parametrize('invalid_children,has_skipped_child', [
    (attribution.MAX_PROBES, True), (1, False),
])
def test_skipped_frames_are_reported_as_truncated_even_when_children_are_invalid(
        monkeypatch, invalid_children, has_skipped_child):
    class Peer:
        def __init__(self,*args):
            self.contexts={'s':{1:{'id':1,'uniqueId':'frame-context','auxData':{'frameId':'root'}}}}
            self.scripts={'s':{}}
            self.versions={'s':0}
            self.truncated=False

        def call(self,method,params=None,sid=None):
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'p','type':'page'}]}
            if method=='Target.attachToTarget':return {'sessionId':'s'}
            if method=='Page.getFrameTree':
                return {'frameTree':{'frame':{'id':'root','url':'https://fixture.invalid/'},
                        'childFrames':[{'frame':{}} for _ in range(invalid_children)]
                                      +([{'frame':{'id':'hidden'}}] if has_skipped_child else [])}}
            if method=='Page.createIsolatedWorld':return {'executionContextId':1}
            if method=='Runtime.evaluate':
                label=params['expression'].split('//# sourceURL=')[1]
                self.scripts['s'][(1,'5')]={'scriptId':'5','executionContextId':1,'url':label}
                return {'result':{'value':True}}
            return {}

    @contextmanager
    def connection(*args,**kwargs):
        yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert len(probes)==1 and receipt['probe_callers_verified']==1
    assert receipt['truncated'] is True


def test_frame_tree_rejects_child_with_contradictory_parent_id():
    tree = {'frame': {'id': 'root'}, 'childFrames': [
        {'frame': {'id': 'child', 'parentId': 'other-parent'}},
    ]}
    truncated = [False]

    frames = list(attribution._frames(tree, truncated=truncated))

    assert [(frame['id'], parent) for frame, parent in frames] == [('root', None)]
    assert truncated == [True]


def test_frame_navigation_during_world_creation_cannot_keep_old_document_label(monkeypatch):
    class Peer:
        def __init__(self, *args):
            self.contexts = {'s': {}}
            self.scripts = {'s': {}}
            self.versions = {'s': 0}
            self.truncated = False

        def call(self, method, params=None, sid=None):
            if method == 'Target.getTargets':
                return {'targetInfos': [{'targetId': 'page', 'type': 'page'}]}
            if method == 'Target.attachToTarget':
                return {'sessionId': 's'}
            if method == 'Page.getFrameTree':
                return {'frameTree': {'frame': {
                    'id': 'frame', 'url': 'https://old.invalid/document'}}}
            if method == 'Page.createIsolatedWorld':
                # The frame ID survives navigation, but its document does not.
                self.versions['s'] += 1
                self.contexts['s'][1] = {
                    'id': 1, 'uniqueId': 'new-context',
                    'auxData': {'frameId': 'frame'},
                }
                return {'executionContextId': 1}
            if method == 'Runtime.evaluate':
                label = params['expression'].split('//# sourceURL=')[1]
                self.scripts['s'][(1, '5')] = {
                    'scriptId': '5', 'executionContextId': 1, 'url': label,
                }
                return {'result': {'value': True}}
            return {}

    @contextmanager
    def connection(*args, **kwargs):
        yield (None, None)

    monkeypatch.setattr(attribution, '_Peer', Peer)
    monkeypatch.setattr(attribution.cdp, '_browser_websocket_url', lambda *args: 'owned')
    monkeypatch.setattr(attribution.cdp, '_websocket_connection', connection)

    probes, receipt = attribution.collect_probes('owned')

    assert probes == []
    assert receipt['truncated'] is True


def test_failed_frame_world_attempts_are_bounded_and_report_truncation(monkeypatch):
    tree={'frame':{'id':'frame-64'}}
    for index in reversed(range(attribution.MAX_PROBES)):
        tree={'frame':{'id':f'frame-{index}'},'childFrames':[tree]}
    calls=[]

    class Peer:
        def __init__(self,*args):
            self.contexts={'s':{}}
            self.scripts={'s':{}}
            self.versions={'s':0}
            self.truncated=False

        def call(self,method,params=None,sid=None):
            if method=='Target.getTargets':return {'targetInfos':[{'targetId':'p','type':'page'}]}
            if method=='Target.attachToTarget':return {'sessionId':'s'}
            if method=='Page.getFrameTree':return {'frameTree':tree}
            if method=='Page.createIsolatedWorld':
                calls.append(params['frameId'])
                raise ContractError('world unavailable')
            return {}

    @contextmanager
    def connection(*args,**kwargs):
        yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert probes==[]
    assert len(calls)==attribution.MAX_PROBES
    assert receipt['truncated'] is True


def test_malformed_isolated_world_id_does_not_abort_other_frame_probes(monkeypatch):
    class Peer:
        def __init__(self,*args):
            self.contexts={'s':{1:{'id':1,'uniqueId':'child-context',
                                   'auxData':{'frameId':'child'}}}}
            self.scripts={'s':{}}
            self.versions={'s':0}
            self.truncated=False

        def call(self,method,params=None,sid=None):
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'p','type':'page'}]}
            if method=='Target.attachToTarget':
                return {'sessionId':'s'}
            if method=='Page.getFrameTree':
                return {'frameTree':{'frame':{'id':'root'},
                    'childFrames':[{'frame':{'id':'child'}}]}}
            if method=='Page.createIsolatedWorld':
                return {'executionContextId':[] if params['frameId']=='root' else 1}
            if method=='Runtime.evaluate':
                label=params['expression'].split('//# sourceURL=')[1]
                self.scripts['s'][(1,'5')]={'scriptId':'5',
                    'executionContextId':1,'url':label}
                return {'result':{'value':True}}
            return {}

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert len(probes)==1
    assert probes[0]['metadata']['frame_id']=='child'
    assert receipt['unavailable_contexts_or_commands']==1
    assert receipt['probe_callers_verified']==1


def test_isolated_world_context_cannot_claim_a_different_frame(monkeypatch):
    class Peer:
        def __init__(self,*args):
            self.contexts={'s':{1:{'id':1,'uniqueId':'other-world',
                                   'auxData':{'frameId':'other-frame'}}}}
            self.scripts={'s':{}}
            self.versions={'s':0}
            self.truncated=False

        def call(self,method,params=None,sid=None):
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'p','type':'page'}]}
            if method=='Target.attachToTarget':return {'sessionId':'s'}
            if method=='Page.getFrameTree':
                return {'frameTree':{'frame':{'id':'requested-frame'}}}
            if method=='Page.createIsolatedWorld':return {'executionContextId':1}
            if method=='Runtime.evaluate':
                label=params['expression'].split('//# sourceURL=')[1]
                self.scripts['s'][(1,'5')]={'scriptId':'5','executionContextId':1,'url':label}
                return {'result':{'value':True}}
            return {}

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert probes==[]
    assert receipt['probe_callers_verified']==0


def test_empty_attached_session_id_is_not_used_for_probe_commands(monkeypatch):
    calls=[]

    class Peer:
        truncated=False
        def __init__(self,*args):pass

        def call(self,method,params=None,sid=None):
            calls.append((method,sid))
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'worker','type':'worker'}]}
            if method=='Target.attachToTarget':
                return {'sessionId':''}
            raise AssertionError('probe command used an empty attached session')

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert probes==[]
    assert calls==[('Target.getTargets',None),('Target.attachToTarget',None)]
    assert receipt['unavailable_contexts_or_commands']==1


def test_evaluate_exception_field_cannot_verify_probe_caller(monkeypatch):
    class Peer:
        def __init__(self,*args):
            self.contexts={'s':{1:{'id':1,'uniqueId':'worker-context','auxData':{}}}}
            self.scripts={'s':{}}
            self.versions={'s':0}
            self.truncated=False

        def call(self,method,params=None,sid=None):
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'worker','type':'worker'}]}
            if method=='Target.attachToTarget':
                return {'sessionId':'s'}
            if method=='Runtime.evaluate':
                label=params['expression'].split('//# sourceURL=')[1]
                self.scripts['s'][(1,'5')]={'scriptId':'5',
                    'executionContextId':1,'url':label}
                return {'exceptionDetails':{},'result':{'value':True}}
            return {}

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert len(probes)==1
    assert probes[0]['probe_script_id'] is None
    assert probes[0]['sources']=={}
    assert receipt['probe_callers_verified']==0


def test_oversized_target_id_is_skipped_before_probe_and_export(monkeypatch):
    calls=[]

    class Peer:
        truncated=False
        def __init__(self,*args):pass

        def call(self,method,params=None,sid=None):
            calls.append(method)
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'t'*257,'type':'worker'}]}
            raise AssertionError('oversized target reached an active probe')

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert calls==['Target.getTargets']
    assert probes==[] and receipt['truncated'] is True


@pytest.mark.parametrize('frame', [
    {'id':'f'*257},
    {'id':'root','parentId':'p'*257},
])
def test_oversized_frame_identity_is_skipped_before_probe_and_export(monkeypatch,frame):
    calls=[]

    class Peer:
        def __init__(self,*args):
            self.contexts={'s':{}}
            self.scripts={'s':{}}
            self.versions={'s':0}
            self.truncated=False

        def call(self,method,params=None,sid=None):
            calls.append(method)
            if method=='Target.getTargets':
                return {'targetInfos':[{'targetId':'page','type':'page'}]}
            if method=='Target.attachToTarget':
                return {'sessionId':'s'}
            if method=='Page.getFrameTree':
                return {'frameTree':{'frame':frame}}
            if method=='Page.createIsolatedWorld':
                raise AssertionError('oversized frame identity reached an active probe')
            return {}

    @contextmanager
    def connection(*args,**kwargs):yield (None,None)

    monkeypatch.setattr(attribution,'_Peer',Peer)
    monkeypatch.setattr(attribution.cdp,'_browser_websocket_url',lambda *args:'owned')
    monkeypatch.setattr(attribution.cdp,'_websocket_connection',connection)
    probes,receipt=attribution.collect_probes('owned')
    assert probes==[] and receipt['truncated'] is True
    assert 'Page.createIsolatedWorld' not in calls


@pytest.mark.parametrize('unique_id', ['', 'context\nsecret'])
def test_context_unique_id_must_be_nonempty_printable_metadata(unique_id):
    peer=attribution._Peer(None,None,0)
    peer.event({'sessionId':'s','method':'Runtime.executionContextCreated',
        'params':{'context':{'id':1,'uniqueId':unique_id,'auxData':{}}}})
    assert not peer.contexts['s']
    assert peer.truncated is True
