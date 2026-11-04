"""Owned native shutdown/crash, continuous viewing, reopening and CLI evidence."""
from pathlib import Path
import argparse,csv,hashlib,io,json,os,subprocess,sys,time
from threading import Thread
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.launcher import EvaluationLaunch,launch_evaluation
from browser_core.lifecycle import stop_session
from browser_core.process import terminate_verified
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.inspection import decode_rows,inspection_select
from browser_core.inspection_ui import create_inspector
from browser_core.live_trace import snapshot_live_trace
from browser_core.bounded_process import run_with_bounded_stdout
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright,expect


def all_rows(reader,search=''):
    first=reader.history(search=search);result=list(first['events']);cursor=first['next_cursor']
    while cursor:
        data=reader.history(search=search,cursor=cursor);result.extend(data['events']);cursor=data['next_cursor']
        assert len(result)<10000
    assert len(result)==first['total_events']
    return first,result


def cli_reopen(session_path,expected_phase):
    # Run the actual CLI. A stdin-controlled thread requests KeyboardInterrupt
    # in the main thread, exercising its normal serve/finally cleanup on Windows.
    bootstrap="""import sys,threading,_thread
from browser_core.cli import main
def stop():
 sys.stdin.readline()
 _thread.interrupt_main()
threading.Thread(target=stop,daemon=True).start()
raise SystemExit(main())
"""
    child=subprocess.Popen([sys.executable,'-c',bootstrap,'trace','inspect','--session',str(session_path)],
        cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    try:
        import queue
        ready=queue.Queue()
        thread=Thread(target=lambda:ready.put(child.stdout.readline()),daemon=True);thread.start()
        notice=json.loads(ready.get(timeout=20))
        with urlopen(notice['inspector_url']+'data',timeout=40) as response:
            result=json.loads(response.read(16*1024*1024))
        assert result['source_phase']==expected_phase and result['recording_settled']
        child.stdin.write(b'\n');child.stdin.flush()
        child.wait(timeout=20);thread.join(5)
        assert child.returncode==0 and not thread.is_alive()
        return {'exit_code':child.returncode,'source_phase':result['source_phase'],'read_only':notice['read_only'],
                'total_events':result['total_events'],'complete':result['complete']}
    finally:
        if child.poll() is None:
            try:child.stdin.write(b'\n');child.stdin.flush();child.wait(timeout=20)
            except Exception:child.kill();child.wait(timeout=5)
        for stream in (child.stdin,child.stdout,child.stderr):stream.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--executable',type=Path,help='Read an attested build without using its workspace for test output')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--headed',action='store_true')
    parser.add_argument('--mode',choices=['graceful','forced'],required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    exe=args.executable or args.workspace/'chromium/src/out/BrowserCore/chrome.exe'
    report={'mode':args.mode,'headless':not args.headed};path=reader=server=thread=None
    try:
        path,session=launch_evaluation(EvaluationLaunch(exe,args.workspace,
            headless=not args.headed,live_trace=True,inspect_values=True),ROOT)
        report.update(build=session['build'],session_path=str(path),persisted_file_binding=bool(session['live_trace'].get('file_binding')))
        assert report['persisted_file_binding']
        reader=IncrementalInspection(path,ROOT)
        routes={'/':(b'<!doctype html><title>Owned recovery fixture</title>','text/html')}
        with _serve_fixtures(routes) as origin,sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
            fixture=browser.contexts[0].new_page();fixture.goto(origin)
            fixture.evaluate('for(let i=0;i<2005;i++)navigator.hardwareConcurrency',isolated_context=False)
            deadline=time.monotonic()+30
            while True:
                before,known=all_rows(reader,search='hardwareConcurrency')
                if len(known)==2005:break
                if time.monotonic()>deadline:raise RuntimeError('known prefix did not arrive')
                time.sleep(.3)
            server,url=create_inspector(path,ROOT);thread=Thread(target=server.serve_forever,daemon=True);thread.start()
            viewer=pw.chromium.launch(headless=True);page=viewer.new_page(viewport={'width':1280,'height':900})
            errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(url);page.locator('#rows tr').nth(999).wait_for(timeout=25000)
            # These late reads need not have reached disk at an abrupt exit.
            fixture.evaluate('for(let i=0;i<17;i++)navigator.hardwareConcurrency',isolated_context=False)
            if args.mode=='forced':
                terminate_verified(session['process_identity'],timeout_seconds=15)
                report['termination_method']='verified-original-process-termination'
            else:
                stop=stop_session(path,timeout_seconds=40)
                report.update(cleanup=stop['state'],shutdown_mode=stop.get('shutdown_mode'))
                assert report['shutdown_mode']=='graceful'
            expected_phase='recovered-prefix' if args.mode=='forced' else 'finalized-recording'
            after,rows=all_rows(reader)
            assert after['source_phase']==expected_phase and after['recording_settled']
            assert after['complete']==(args.mode=='graceful')
            known_by_id={event['id']:event for event in rows}
            assert all(known_by_id[event['id']]==event for event in known)
            report.update(known_rows_retained=len(known),post_exit_events=len(rows),complete=after['complete'],
                          incomplete_tail_bytes=after['incomplete_tail_bytes'],recording_health=after['recording_health'])
            with snapshot_live_trace(reader.cursor.source) as snapshot:
                sql=inspection_select()+' ORDER BY s.ts DESC,s.id DESC'
                oracle=run_with_bounded_stdout([str(exe.with_name('trace_processor_shell.exe')),'query',str(snapshot.path),sql],
                    maximum_stdout=16*1024*1024,timeout_seconds=30,label='recovery independent oracle')
                assert oracle.returncode==0
                expected,total=decode_rows(oracle.stdout,limit=5000)
                assert rows==expected and total==len(rows)
                report.update(exact_independent_oracle=True,committed_prefix_bytes=snapshot.bytes,
                              committed_prefix_sha256=snapshot.sha256)
            label='Recovered · incomplete' if args.mode=='forced' else 'Saved recording'
            expect(page.locator('#state')).to_have_text(label,timeout=20000)
            assert page.locator('#rows tr').count()==1000
            if args.mode=='forced':assert 'Recent activity may be missing' in page.locator('#recording').inner_text()
            page.locator('#search').fill('hardwareConcurrency');page.locator('#historySearch').click()
            expect(page.locator('#state')).to_have_text('History · incomplete recovery' if args.mode=='forced' else 'History · saved recording',timeout=25000)
            page.locator('#older').click();expect(page.locator('#population')).to_contain_text('page 2',timeout=20000)
            assert page.locator('#rows tr').count()==1000
            report['widths']={}
            for width in (390,1280):
                page.set_viewport_size({'width':width,'height':900})
                overflow=page.evaluate('document.documentElement.scrollWidth>innerWidth');assert not overflow
                report['widths'][width]={'overflow':overflow}
                page.screenshot(path=str(args.out/f'panel-{width}.png'),full_page=True)
            report.update(panel_survives_exit=True,post_exit_history=True,page_errors=errors)
            assert not errors;viewer.close()
        reader.close();report['decoder_reaped']=reader.decoder.process.poll() is not None
        server.shutdown();server.server_close();server=None;thread.join(5)
        with IncrementalInspection(path,ROOT) as reopened:
            reopened_result,reopened_rows=all_rows(reopened)
            assert reopened_rows==rows and reopened_result['source_phase']==expected_phase
            report['fresh_reopen_exact']=True
        if report.get('cleanup')!='stopped':
            stop=stop_session(path,timeout_seconds=40)
            report.update(cleanup=stop['state'],shutdown_mode=stop.get('shutdown_mode'))
        report['cli_reopen']=cli_reopen(path,expected_phase)
        report['passed']=report['decoder_reaped'] and not thread.is_alive()
    except Exception as error:
        report.update(passed=False,error_type=type(error).__name__,error=str(error)[:400])
    finally:
        if reader:reader.close()
        if server:server.shutdown();server.server_close()
        if thread:thread.join(5)
        if path and report.get('cleanup')!='stopped':
            try:report['cleanup']=stop_session(path,timeout_seconds=40)['state']
            except Exception as error:report['cleanup_error']=type(error).__name__
        (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({k:v for k,v in report.items() if k not in ('build','session_path')}),flush=True)
    return 0 if report.get('passed') else 1


if __name__=='__main__':raise SystemExit(main())
