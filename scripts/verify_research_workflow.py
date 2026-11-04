"""Owned local create/reopen/isolation and live-inspector research workflow."""
from pathlib import Path
import argparse,json,sys,time
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.research import start_research
from browser_core.profiles import delete_disposable_profile,load_profile
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--persona-id',required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    report={'runs':[]};owned=[]
    # One origin across reopens is essential to make storage persistence a
    # meaningful check. Values below are invented fixture markers only.
    routes={'/':(b'<!doctype html><title>Owned saved-profile fixture</title>','text/html')}
    try:
        with _serve_fixtures(routes) as origin, sync_playwright() as pw:
            for headless in [False,True]:
                first=f'ops-disp-research-{int(time.time())}-{int(headless)}'
                isolated=first+'-isolated'
                assert all(not (args.workspace/'profiles/registry'/f'{name}.json').exists() for name in (first,isolated)), 'test profile already exists'
                owned.extend([first,isolated])
                before=None
                for phase in ['create','reopen','isolation']:
                    profile=isolated if phase=='isolation' else first
                    row={'phase':phase,'headless':headless}
                    started=time.monotonic()
                    with start_research(args.workspace,ROOT,profile,headless=headless,
                                        persona_id=args.persona_id) as run:
                        row.update(startup_seconds=round(time.monotonic()-started,3),
                                   created_profile=run.created_profile,build=run.session['build'])
                        browser=pw.chromium.connect_over_cdp(run.session['automation']['cdp_endpoint'])
                        page=browser.contexts[0].new_page();page.goto(origin)
                        saved=page.evaluate("({stored:localStorage.getItem('research-fixture'),cookie:document.cookie})",isolated_context=False)
                        if phase=='reopen':
                            assert saved=={'stored':'saved','cookie':'research_fixture=saved'}
                            assert load_profile(args.workspace,profile)==before
                            assert not run.created_profile
                        else:
                            assert saved=={'stored':None,'cookie':''} and run.created_profile
                            page.evaluate("localStorage.setItem('research-fixture','saved');document.cookie='research_fixture=saved;SameSite=Lax;Path=/;Max-Age=3600'",isolated_context=False)
                        answer=page.evaluate('(()=>{let values=[];for(let i=0;i<32;i++)values.push(navigator.hardwareConcurrency);return {count:values.length,allEqual:values.every(v=>v===values[0])}})()',isolated_context=False)
                        assert answer=={'count':32,'allEqual':True}
                        deadline=time.monotonic()+20
                        while True:
                            with urlopen(run.url+'data',timeout=35) as response:
                                preview=json.loads(response.read(16*1024*1024))
                            hardware=[e for e in preview['events'] if e['api']=='Navigator.hardwareConcurrency.get']
                            if len(hardware)>=32:break
                            if time.monotonic()>deadline:raise RuntimeError('inspector visibility timed out')
                            time.sleep(.3)
                        assert preview['recording_health']['status']=='no-issues-reported'
                        row.update(storage_check=True,inspector_hardware_rows=len(hardware),
                                   recording_health=preview['recording_health'],browser_running=preview['browser_running'])
                        assert row['browser_running']
                        before=load_profile(args.workspace,profile) if phase=='create' else before
                        page.close()
                    row.update(shutdown_mode=run.stop_receipt.get('shutdown_mode'),
                               cleanup=run.stop_receipt['state'],inspector_thread_reaped=not run.thread.is_alive())
                    assert row['cleanup']=='stopped' and row['shutdown_mode']=='graceful' and row['inspector_thread_reaped']
                    report['runs'].append(row)
                    (args.out/'summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
                    print(json.dumps({k:v for k,v in row.items() if k!='build'}),flush=True)
        report['passed']=len(report['runs'])==6
    except Exception as error:
        report.update(passed=False,error_type=type(error).__name__,error=str(error)[:240])
    finally:
        report['profile_cleanup']=[]
        for profile in owned:
            try:report['profile_cleanup'].append(delete_disposable_profile(args.workspace,profile)['state'])
            except Exception as error:report['profile_cleanup'].append(type(error).__name__);report['passed']=False
        (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({k:report[k] for k in ['passed','error','profile_cleanup'] if k in report}),flush=True)
    return 0 if report.get('passed') else 1


if __name__=='__main__':raise SystemExit(main())
