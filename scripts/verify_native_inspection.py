"""Owned native observation fidelity gate: values, attribution and side effects."""
from __future__ import annotations
import argparse
import csv
import io
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.bounded_process import run_with_bounded_stdout
from browser_core.inspection import live_inspection, read_inspection
from browser_core.launcher import EvaluationLaunch, launch_evaluation
from browser_core.lifecycle import stop_session
from browser_core.live_trace import snapshot_live_trace
from browser_core.perfetto import export_perfetto
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright

MAIN = r'''
window.fixtureResult = (async () => {
  const hc = [];
  for (let i=0;i<64;i++) hc.push(navigator.hardwareConcurrency);
  const ua=navigator.userAgent, platform=navigator.platform, language=navigator.language;
  const screenSize=[screen.width,screen.height];
  const nativeText=Object.getOwnPropertyDescriptor(Navigator.prototype,'hardwareConcurrency').get.toString();
  const gl=document.createElement('canvas').getContext('webgl2');
  if(!gl) throw Error('owned WebGL fixture unavailable');
  const vector=Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS));
  const floatVector=Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE));
  const numeric=gl.getParameter(gl.MAX_TEXTURE_SIZE);
  const renderer=gl.getParameter(gl.RENDERER);
  let coercions=0, traps=0;
  const originalEnum={valueOf(){coercions++;return gl.MAX_TEXTURE_SIZE}};
  const objectResult=gl.getParameter(originalEnum);
  const proxied=new Proxy({}, {get(t,k){traps++; if(k===Symbol.toPrimitive)return ()=>gl.MAX_TEXTURE_SIZE; return undefined;}});
  const proxyResult=gl.getParameter(proxied);
  const sentinel=Object.freeze({sentinel:true});
  let exceptionIdentity=false;
  try {gl.getParameter({valueOf(){throw sentinel}})} catch(e) {exceptionIdentity=e===sentinel}
  let missingThrows=false;try {gl.getParameter()}catch(e){missingThrows=e instanceof TypeError}
  const invalid=gl.getParameter(-1);
  const invalidError=gl.getError();
  // These extras are ignored by the native API and must not become raw values.
  gl.getParameter(gl.MAX_TEXTURE_SIZE, 'UNRELATED-INPUT-MUST-NOT-BE-CAPTURED');
  const symbolBefore=Object.getOwnPropertySymbols(Navigator.prototype).length;
  const worker=await new Promise((resolve,reject)=>{
    const w=new Worker('/worker.js');w.onmessage=e=>{w.terminate();resolve(e.data)};w.onerror=reject;
  });
  const frame=await new Promise((resolve,reject)=>{
    const f=document.createElement('iframe');
    const handler=e=>{if(e.source===f.contentWindow&&e.data.kind==='fixture-frame'){window.removeEventListener('message',handler);resolve(e.data)}};
    window.addEventListener('message',handler);
    f.src=location.origin.replace('127.0.0.1','localhost')+'/frame.html';document.body.append(f);
    setTimeout(()=>reject(Error('frame timeout')),10000);
  });
  return {hc,ua,platform,language,screenSize,nativeText,vector,floatVector,numeric,renderer,
    objectResult,proxyResult,coercions,traps,exceptionIdentity,missingThrows,invalid,invalidError,
    symbolBefore,symbolAfter:Object.getOwnPropertySymbols(Navigator.prototype).length,worker,frame};
})();
'''
WORKER = "const values=[];for(let i=0;i<32;i++)values.push(navigator.hardwareConcurrency);postMessage({values,ua:navigator.userAgent});"
FRAME = "const values=[];for(let i=0;i<16;i++)values.push(navigator.hardwareConcurrency);parent.postMessage({kind:'fixture-frame',values,ua:navigator.userAgent},'*');"


def script_keys(processor, path):
    sql="""SELECT p.pid, EXTRACT_ARG(s.arg_set_id,'debug.context_id') AS context_id,
EXTRACT_ARG(s.arg_set_id,'debug.script_id') AS script_id FROM slice s
JOIN thread_track tt ON s.track_id=tt.id JOIN thread t ON tt.utid=t.utid
JOIN process p ON t.upid=p.upid WHERE s.name='BrowserCore.ScriptRun'"""
    result=run_with_bounded_stdout([str(processor),'query',str(path),sql],maximum_stdout=1024*1024,timeout_seconds=30,label='fixture attribution')
    if result.returncode: raise RuntimeError('attribution query failed')
    return {(int(r['pid']),r['context_id'],int(r['script_id'])) for r in csv.DictReader(io.StringIO(result.stdout.decode()))}


def verify(rows, fixture, keys):
    hc=[r for r in rows if r['api'] in ('Navigator.hardwareConcurrency.get','WorkerNavigator.hardwareConcurrency.get')]
    groups={}
    for row in hc:
        groups.setdefault((row['pid'],row['context_id'],row['script_id'],row['context_kind']),[]).append(row)
    known=[(key,values) for key,values in groups.items() if len(values) in (16,32,64)]
    assert sorted(len(values) for key,values in known)==[16,32,64], 'exact per-context read counts'
    assert len({key[1] for key,values in known})==3, 'distinct context IDs'
    assert len({key[0] for key,values in known})>=2, 'out-of-process frame'
    assert all(key[:3] in keys for key,values in known), 'script IDs correlate to native ScriptRun'
    assert any(key[3]=='worker' and len(values)==32 for key,values in known), 'worker attribution'
    assert all(r['result']=={'type':'number','value':fixture['hc'][0]} for _,values in known for r in values), 'actual returned hardware value'
    main_key=next(key for key,values in known if len(values)==64)
    main=[r for r in rows if (r['pid'],r['context_id'],r['script_id'])==main_key[:3]]
    for api,expected in [('Navigator.userAgent.get',fixture['ua']),('Navigator.platform.get',fixture['platform']),('Navigator.language.get',fixture['language'])]:
        assert any(r['api']==api and r['result'].get('value')==expected for r in main), api
    for api,expected in [('Screen.width.get',fixture['screenSize'][0]),('Screen.height.get',fixture['screenSize'][1])]:
        assert any(r['api']==api and r['result'].get('value')==expected for r in main), api
    gl=[r for r in main if r['api']=='WebGL2RenderingContext.getParameter']
    assert len(gl)==10, 'exact WebGL call count'
    assert sum(r['completion']=='exception' for r in gl)==2, 'exception classification'
    for expected in [fixture['vector'],fixture['floatVector']]:
        assert any([v.get('value') for v in r['result'].get('values',[])]==expected for r in gl), 'typed vector content'
    assert any(r['parameters']['observed']==[{'type':'number','value':3379}] and r['result'].get('value')==fixture['numeric'] for r in gl), 'input enum and returned scalar'
    assert any(r['result'].get('value')==fixture['renderer'] for r in gl), 'native renderer string'
    assert any(r['parameters']['observed']==[{'type':'proxy','omitted':'no-object-inspection'}] for r in gl), 'proxy not traversed'
    assert 'UNRELATED-INPUT-MUST-NOT-BE-CAPTURED' not in json.dumps(rows), 'unrelated argument omitted'
    return {'contexts':3,'native_script_correlations':3,'hardware_reads':112,'webgl_calls':10,'exception_calls':2,'cross_process':True}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--workspace',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--headless-only',action='store_true')
    p.add_argument('--executable', type=Path, help='Read an attested build while keeping profiles and recordings in --workspace')
    args=p.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    executable=args.executable or args.workspace/'chromium/src/out/BrowserCore/chrome.exe';processor=executable.with_name('trace_processor_shell.exe')
    routes={'/':(b'<!doctype html><body><script src="/main.js"></script>','text/html'),'/main.js':(MAIN.encode(),'text/javascript'),'/worker.js':(WORKER.encode(),'text/javascript'),'/frame.html':(b'<!doctype html><script src="/frame.js"></script>','text/html'),'/frame.js':(FRAME.encode(),'text/javascript')}
    runs=[]
    with _serve_fixtures(routes) as origin:
      for headless in ([True] if args.headless_only else [False,True]):
       for enabled in ([False,True] if not headless else [True,False]):
        label=f'{"headless" if headless else "headed"}-{"on" if enabled else "off"}'
        row={'label':label,'headless':headless,'inspection':enabled};session_path=None
        try:
          session_path,session=launch_evaluation(EvaluationLaunch(executable,args.workspace,headless=headless,live_trace=True,inspect_values=enabled,extra_args=('--site-per-process',)),ROOT)
          row['build']=session['build']
          row['session_path']=str(session_path)
          with sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint']);page=browser.contexts[0].new_page()
            crashes=[];page.on('crash',lambda _:crashes.append(True))
            response=page.goto(origin,wait_until='load',timeout=30000)
            assert response.status==200, 'fixture document did not load'
            page.wait_for_function('typeof window.fixtureResult !== "undefined"', timeout=10000)
            fixture=page.evaluate('window.fixtureResult', isolated_context=False);row['fixture']=fixture
            assert fixture['coercions']==1 and fixture['traps']==1 and fixture['exceptionIdentity'] and fixture['missingThrows']
            assert fixture['symbolBefore']==fixture['symbolAfter'] and '[native code]' in fixture['nativeText']
            if enabled:
              deadline=time.monotonic()+12
              while True:
                preview=live_inspection(session_path,ROOT,limit=1000)
                if any(r['api']=='WorkerNavigator.hardwareConcurrency.get' for r in preview['events']) and sum(r['api']=='Navigator.hardwareConcurrency.get' for r in preview['events'])>=80:break
                if time.monotonic()>deadline:raise RuntimeError('missing live fixture values')
                time.sleep(.25)
              (args.out/f'{label}-live.json').write_text(json.dumps(preview,indent=2),encoding='utf-8')
              with snapshot_live_trace(Path(session['live_trace']['path'])) as snap:
                keys=script_keys(processor,snap.path)
              row['coverage']=verify(preview['events'],fixture,keys)
              row['live_running']=preview['browser_running'];row['live_provisional']=not preview['complete']
            assert not crashes
            page.close()
          stop=stop_session(session_path,timeout_seconds=40);row['cleanup']=stop['state'];row['shutdown_mode']=stop.get('shutdown_mode')
          final=read_inspection(processor,Path(session['trace_path']),limit=1000)
          row['final_events']=final['total_events']
          (args.out/f'{label}-final.json').write_text(json.dumps(final,indent=2),encoding='utf-8')
          if enabled:
            verify(final['events'],fixture,script_keys(processor,Path(session['trace_path'])))
            portable=args.out/f'{label}-metadata.jsonl'
            exported=export_perfetto(processor,Path(session['trace_path']),portable,session['run_id'],session['chromium_revision'])
            row['metadata_export']=exported
            assert 'parameters_json' not in portable.read_text(encoding='utf-8') and 'browser-core.inspection/1' not in portable.read_text(encoding='utf-8')
          else:assert final['total_events']==0,'default must retain no raw values'
          row['passed']=row['cleanup']=='stopped' and row['shutdown_mode']=='graceful'
        except Exception as e:row.update(passed=False,error_type=type(e).__name__,error=str(e))
        finally:
          if session_path and row.get('cleanup')!='stopped':
            try:row['cleanup']=stop_session(session_path,timeout_seconds=40)['state']
            except Exception as e:row['cleanup_error']=type(e).__name__
        runs.append(row)
        print(json.dumps({k:row[k] for k in ('label','passed','error','coverage','cleanup') if k in row}),flush=True)
        (args.out/'summary.json').write_text(json.dumps({'schema':'browser-core.native-inspection-gate/1','runs':runs,'passed':all(r['passed'] for r in runs)},indent=2)+'\n',encoding='utf-8')
    comparisons={}
    for headless in {r['headless'] for r in runs}:
        pair=[r for r in runs if r['headless']==headless]
        comparisons['headless' if headless else 'headed']=(len(pair)==2 and pair[0].get('fixture') is not None and pair[0].get('fixture')==pair[1].get('fixture'))
    passed=all(r['passed'] for r in runs) and all(comparisons.values())
    (args.out/'summary.json').write_text(json.dumps({'schema':'browser-core.native-inspection-gate/1','runs':runs,'on_off_answers_equal':comparisons,'passed':passed},indent=2)+'\n',encoding='utf-8')
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
