"""Compare incremental native values with independent full-prefix reads on owned fixtures."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.inspection import live_inspection, read_inspection
from browser_core.launcher import EvaluationLaunch, launch_evaluation
from browser_core.lifecycle import stop_session
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright
from verify_native_inspection import MAIN, WORKER, FRAME, verify, script_keys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--headed',action='store_true')
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    executable=args.workspace/'chromium/src/out/BrowserCore/chrome.exe'
    processor=executable.with_name('trace_processor_shell.exe')
    routes={'/':(b'<!doctype html><body><script src="/main.js"></script>','text/html'),
        '/main.js':(MAIN.encode(),'text/javascript'),'/worker.js':(WORKER.encode(),'text/javascript'),
        '/frame.html':(b'<!doctype html><script src="/frame.js"></script>','text/html'),
        '/frame.js':(FRAME.encode(),'text/javascript')}
    report={'headless':not args.headed,'phases':[]};session_path=None;reader=None
    try:
        with _serve_fixtures(routes) as origin:
            session_path,session=launch_evaluation(EvaluationLaunch(executable,args.workspace,
                headless=not args.headed,live_trace=True,inspect_values=True,extra_args=('--site-per-process',)),ROOT)
            report.update(session_path=str(session_path),build=session['build'])
            reader=IncrementalInspection(session_path,ROOT)
            with sync_playwright() as pw:
                browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
                page=browser.contexts[0].new_page();crashes=[];page.on('crash',lambda _:crashes.append(True))
                page.goto(origin,wait_until='load',timeout=30000)
                fixture=page.evaluate('window.fixtureResult',isolated_context=False)
                def settle(expected):
                    deadline=time.monotonic()+25;steps=[]
                    while True:
                        started=time.monotonic();preview=reader.read(limit=1000)
                        steps.append({'seconds':round(time.monotonic()-started,4),
                                      'new_bytes':preview['new_bytes'],'events':preview['total_events']})
                        if preview['total_events']>=expected:return preview,steps
                        if time.monotonic()>deadline:raise RuntimeError('incremental visibility deadline')
                        time.sleep(.3)
                # The independent complete-prefix decoder determines the exact
                # initial population, then live intrinsic-table output must match.
                deadline=time.monotonic()+15
                while True:
                    baseline=live_inspection(session_path,ROOT,limit=1000)
                    if sum(r['api']=='WorkerNavigator.hardwareConcurrency.get' for r in baseline['events'])>=32:break
                    if time.monotonic()>deadline:raise RuntimeError('fixture data did not arrive')
                preview,steps=settle(baseline['total_events'])
                assert preview['events']==baseline['events'],'initial values or source identities differ'
                report['baseline']=baseline['total_events']
                report['initial_reads']=steps
                (args.out/'initial-private-values.json').write_text(json.dumps(preview,indent=2),encoding='utf-8')
                count=0
                for reads in [4096,12288,49152,196608]:
                    started=time.monotonic()
                    assert page.evaluate(f'(()=>{{let sum=0;for(let i=0;i<{reads};i++)sum+=navigator.hardwareConcurrency;return sum>0}})()',isolated_context=False)
                    count+=reads;execution=time.monotonic()-started;visibility=time.monotonic()
                    preview,steps=settle(report['baseline']+count)
                    visibility=time.monotonic()-visibility
                    started=time.monotonic();fresh=live_inspection(session_path,ROOT,limit=1000);full_seconds=time.monotonic()-started
                    assert preview['total_events']==fresh['total_events']==report['baseline']+count
                    assert preview['events']==fresh['events'],'incremental values or attribution differ'
                    started=time.monotonic();repeat=reader.read(limit=1000);repeat_seconds=time.monotonic()-started
                    assert repeat['events']==fresh['events']
                    phase={'deliberate_reads':count,'source_bytes':preview['source_bytes'],
                        'execution_seconds':round(execution,4),'visibility_seconds':round(visibility,4),
                        'read_steps':steps,'repeat_seconds':round(repeat_seconds,4),
                        'full_prefix_seconds':round(full_seconds,4),'events':fresh['total_events'],
                        'identical_latest_values_and_ids':True,'sorter_dropped_events':preview['sorter_dropped_events']}
                    report['phases'].append(phase);print(json.dumps(phase),flush=True)
                assert not crashes
                page.close()
            reader.close();report['decoder_reaped']=reader.decoder.process.poll() is not None
            stop=stop_session(session_path,timeout_seconds=40)
            report.update(cleanup=stop['state'],shutdown_mode=stop.get('shutdown_mode'))
            final=read_inspection(processor,Path(session['trace_path']),limit=1000)
            report['final_events']=final['total_events']
            initial=json.loads((args.out/'initial-private-values.json').read_text(encoding='utf-8'))
            report['coverage']=verify(initial['events'],fixture,script_keys(processor,Path(session['trace_path'])))
            report['passed']=report['decoder_reaped'] and report['shutdown_mode']=='graceful' and final['total_events']==count+report['baseline']
    except Exception as error:
        report.update(passed=False,error_type=type(error).__name__,error=str(error))
    finally:
        if reader is not None:reader.close()
        if session_path and report.get('cleanup')!='stopped':
            try:report['cleanup']=stop_session(session_path,timeout_seconds=40)['state']
            except Exception as error:report['cleanup_error']=type(error).__name__
        (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({k:report[k] for k in ('passed','error','cleanup','coverage','decoder_reaped') if k in report}),flush=True)
    return 0 if report.get('passed') else 1


if __name__=='__main__':raise SystemExit(main())
