"""Owned offline transfer/trace fidelity regression for Core and Kameleo.

Uses real browser primitives and verifies delivered values and ownership. Raw
native traces belong in an external workspace; the report contains no secrets.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path

CORE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(CORE),str(CORE/'scripts')]
from browser_core.launcher import EvaluationLaunch,launch_evaluation
from browser_core.lifecycle import stop_session
from browser_core.perfetto import export_perfetto
from browser_core.trace import load_validated_trace
from browser_core.smoke import _serve_fixtures
from run_alternating_kameleo import KameleoLocal
from patchright.sync_api import sync_playwright

EXPECTED_CASES={"structured-clone","transferred-port","transferred-large-buffer","copied-large-buffer","transferred-readable-stream","worker-transfer","cross-origin-frame-transfer"}|{f"repeated-port-{i}" for i in range(32)}

def verify_cases(document):
    if not isinstance(document,dict) or document.get('passed') is not True:
        raise RuntimeError('browser transfer fixture did not pass')
    rows=document.get('cases',[])
    if len(rows)!=len(EXPECTED_CASES) or {r.get('name') for r in rows}!=EXPECTED_CASES or not all(r.get('passed') is True for r in rows):
        raise RuntimeError('browser transfer coverage is incomplete')

def verify_message_trace(path):
    summary,events,index=load_validated_trace(path)
    posts=[e for e in events if e['event']=={'category':'message','name':'MessagePort.postMessage'}]
    dispatches=[e for e in events if e['event']=={'category':'message','name':'MessagePort.message.dispatch'}]
    cross_process=0;worker=False
    for e in dispatches:
        parent=index.get(e.get('causal_parent_seq'))
        if parent is None or parent['event']!={'category':'message','name':'MessagePort.postMessage'}:
            raise RuntimeError('native message dispatch lost its send correlation')
        cross_process+=e['process']['pid']!=parent['process']['pid']
        worker|=bool(e.get('execution',{}).get('worker_id'))
    if len(posts)<39 or len(dispatches)<39 or not cross_process or not worker or summary['dropped_events']:
        raise RuntimeError('native transfer trace coverage or fidelity failed')
    return {**summary,'message_posts':len(posts),'message_dispatches':len(dispatches),'cross_process_dispatches':cross_process,'worker_dispatch':worker}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--browser',choices=['core','kameleo'],default='core')
    p.add_argument('--executable',type=Path,default=Path('H:/bc/chromium/src/out/BrowserCore/chrome.exe'))
    p.add_argument('--workspace',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--trace',choices=['on','off'],default='on')
    p.add_argument('--scope',choices=['causal','broad','causal-stream','encoding'],default='broad')
    p.add_argument('--headless',action='store_true')
    p.add_argument('--live-trace',action='store_true')
    p.add_argument('--inspect-values',action='store_true')
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    fixtures=CORE/'fixtures'
    receiver=(fixtures/'native-message-transfer-receiver.js').read_bytes()
    routes={'/':((fixtures/'native-message-transfer-smoke.html').read_bytes(),'text/html'),'/transfer-receiver.js':(receiver,'text/javascript'),'/transfer-frame.html':(b'<!doctype html><script src="/transfer-receiver.js"></script>','text/html')}
    row={'schema':'browser-core.message-transfer-regression/1','browser':a.browser,'trace':a.trace if a.browser=='core' else None,'scope':a.scope,'headless':a.headless,'live_trace':a.live_trace,'status':'failed'}
    row['inspect_values']=a.inspect_values
    session_path=None;profile=None;client=KameleoLocal('http://127.0.0.1:5050')
    try:
        if a.browser=='core':
            session_path,session=launch_evaluation(EvaluationLaunch(a.executable,a.workspace,trace_mode=a.trace,trace_scope=a.scope,headless=a.headless,live_trace=a.live_trace,inspect_values=a.inspect_values,extra_args=('--site-per-process',),timeout_seconds=60),CORE)
            endpoint=session['automation']['cdp_endpoint'];row['build']=session['build'];row['session_file']=str(session_path)
        else:
            fp=client.fresh_fingerprint('152');name='Codex Browser Eval Alternating transfer '+a.out.name
            profile=client.create_disposable(fp['id'],name)
            if a.headless:client.request('POST',f"/profiles/{profile['id']}/start",{'arguments':['--headless']})
            endpoint=client.playwright_endpoint(profile['id']);row['fingerprint']={'browser':fp['browser'],'os':fp['os']}
        with _serve_fixtures(routes) as url, sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(endpoint,timeout=90000)
            page=browser.contexts[0].new_page();page.on('crash',lambda _:row.update(crashed=True))
            page.goto(url,timeout=30000)
            page.wait_for_function("document.title!=='browser-core-message-transfer-pending'",timeout=60000)
            result=json.loads(page.locator('#result').inner_text());row['result']=result;verify_cases(result)
            page.close()
        row['status']='passed'
    except Exception as e:row['error_class']=type(e).__name__
    finally:
        if session_path:
            try:
                stopped=stop_session(session_path,timeout_seconds=40)
                row['cleanup']=stopped['state'];row['shutdown_mode']=stopped.get('shutdown_mode')
            except Exception as e:row.update(status='failed',cleanup_error=type(e).__name__)
        if profile:
            try:client.cleanup_disposable(profile['id'],name);row['cleanup']='deleted'
            except Exception as e:row.update(status='failed',cleanup_error=type(e).__name__)
    if session_path and a.trace=='on':
        try:
            path=a.workspace/'traces'/f"{session['run_id']}.transfer.jsonl"
            row['export']=export_perfetto(a.executable.with_name('trace_processor_shell.exe'),Path(session['trace_path']),path,session['run_id'],session['chromium_revision'])
            row['native']=verify_message_trace(path)
        except Exception as e:row.update(status='failed',trace_error=type(e).__name__)
    (a.out/'summary.json').write_text(json.dumps(row,indent=2),encoding='utf-8')
    print(json.dumps(row,indent=2));return 0 if row['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
