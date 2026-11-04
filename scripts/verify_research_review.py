"""Actual piped research CLI keeps review alive, then cleans up on interruption."""
from pathlib import Path
import argparse,json,os,queue,subprocess,sys,time
from threading import Thread
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.contracts import load_session
from browser_core.cdp import request_browser_close
from browser_core.lifecycle import stop_session
from browser_core.profiles import delete_disposable_profile,load_profile
from patchright.sync_api import sync_playwright


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    report={'runs':[]}
    for exit_with_browser in (False,True):
        profile=f'ops-disp-research-review-{int(time.time())}-{int(exit_with_browser)}'
        assert not (args.workspace/'profiles/registry'/f'{profile}.json').exists()
        child=session_path=None;row={'exit_with_browser':exit_with_browser}
        bootstrap="""import threading,_thread,sys
from browser_core.cli import main
def stop():
 sys.stdin.readline()
 _thread.interrupt_main()
threading.Thread(target=stop,daemon=True).start()
raise SystemExit(main())
"""
        try:
            command=[sys.executable,'-c',bootstrap,'research',profile,'--workspace',str(args.workspace),'--headless','--no-open']
            if exit_with_browser:command.append('--exit-with-browser')
            child=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            messages=queue.Queue()
            def collect():
                for line in child.stdout:messages.put(line)
            thread=Thread(target=collect,daemon=True);thread.start()
            def receive(timeout):
                deadline=time.monotonic()+timeout;body=b''
                while time.monotonic()<deadline:
                    body+=messages.get(timeout=max(.1,deadline-time.monotonic()))
                    assert len(body)<1024*1024
                    try:return json.loads(body)
                    except json.JSONDecodeError:pass
                raise RuntimeError('CLI JSON readiness deadline')
            first=receive(30);session_path=Path(first['session_file'])
            session=load_session(session_path)
            with sync_playwright() as pw:
                browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
                page=browser.contexts[0].new_page();page.goto('about:blank')
                page.evaluate('for(let i=0;i<64;i++)navigator.hardwareConcurrency',isolated_context=False)
                request_browser_close(session['automation']['cdp_endpoint'],timeout_seconds=10)
            if not exit_with_browser:
                review=receive(45)
                assert review['recording_review_available'] and child.poll() is None
                with urlopen(first['inspector_url']+'data',timeout=40) as response:
                    result=json.loads(response.read(16*1024*1024))
                assert result['complete'] and result['source_phase']=='finalized-recording'
                assert sum(e['api']=='Navigator.hardwareConcurrency.get' for e in result['events'])>=64
                assert load_session(session_path)['state']=='stopped'
                row.update(viewer_alive_after_exit=True,recording_settled=result['recording_settled'],known_reads_retained=64)
                child.stdin.write(b'\n');child.stdin.flush()
            child.wait(timeout=45);thread.join(5)
            final=receive(5)
            assert child.returncode==0 and not thread.is_alive()
            assert final['shutdown']['state']=='stopped'
            assert final['reopen_recording_argv'][-1]=='--open'
            assert load_profile(args.workspace,profile)['id']==profile
            row.update(exit_code=child.returncode,shutdown=final['shutdown'],profile_retained=True,passed=True)
        except Exception as error:
            row.update(passed=False,error_type=type(error).__name__,error=str(error)[:240])
        finally:
            if child is not None:
                if child.poll() is None:
                    try:child.stdin.write(b'\n');child.stdin.flush();child.wait(timeout=45)
                    except Exception:child.kill();child.wait(timeout=5)
                for stream in (child.stdin,child.stdout,child.stderr):stream.close()
            if session_path:
                try:stop_session(session_path,timeout_seconds=40)
                except Exception as error:row['cleanup_error']=type(error).__name__
            try:row['profile_cleanup']=delete_disposable_profile(args.workspace,profile)['state']
            except Exception as error:row['profile_cleanup_error']=type(error).__name__
            report['runs'].append(row);(args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            print(json.dumps(row),flush=True)
    report['passed']=all(r.get('passed') and r.get('profile_cleanup')=='deleted' and not r.get('cleanup_error') for r in report['runs'])
    (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
