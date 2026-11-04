"""Owned native recording-budget gate; preserve earlier evidence and the browser."""
from pathlib import Path
import argparse,hashlib,json,sys,time,traceback
from threading import Thread

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.launcher import EvaluationLaunch,launch_evaluation
from browser_core.lifecycle import stop_session,session_status
from browser_core.recording_limits import MIB,limit_marker_path
from browser_core.recording_source import RecordingSource
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.inspection import decode_rows,inspection_select,live_inspection
from browser_core.inspection_ui import create_inspector
from browser_core.live_trace import snapshot_live_trace,live_trace_summary
from browser_core.bounded_process import run_with_bounded_stdout
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright,expect


def all_rows(reader,search=''):
    data=reader.history(search=search);first=data;events=list(data['events']);pages=1
    while data['next_cursor']:
        data=reader.history(search=search,cursor=data['next_cursor'])
        events.extend(data['events']);pages+=1
        assert pages<=150,'owned fixture exceeded page bound'
    assert len(events)==first['total_events']
    assert len({event['id'] for event in events})==len(events)
    return first,events


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(MIB),b''):value.update(block)
    return value.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--executable',type=Path,help='Read an attested build without using its workspace for test output')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--headed',action='store_true')
    parser.add_argument('--limit-mib',type=int,default=8,choices=(8,16))
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    exe=args.executable or args.workspace/'chromium/src/out/BrowserCore/chrome.exe'
    report={'headless':not args.headed,'limit_mib':args.limit_mib,'scope':'owned local byte-limit fixture; no rotation or memory-ceiling claim'}
    path=reader=server=thread=viewer=None
    try:
        path,session=launch_evaluation(EvaluationLaunch(exe,args.workspace,headless=not args.headed,
            live_trace=True,inspect_values=True,recording_limit_mib=args.limit_mib),ROOT)
        report.update(session_path=str(path),build=session['build'])
        assert session['live_trace']['byte_limit']==args.limit_mib*MIB
        source=Path(session['live_trace']['path']);marker=limit_marker_path(Path(session['trace_path']))
        reader=IncrementalInspection(path,ROOT)
        routes={'/':(b'<!doctype html><title>Owned recording limit fixture</title><button id="action">Still usable</button>','text/html')}
        with _serve_fixtures(routes) as origin,sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
            fixture=browser.contexts[0].new_page();fixture.goto(origin)
            fixture.evaluate('for(let i=0;i<2005;i++)navigator.hardwareConcurrency',isolated_context=False)
            deadline=time.monotonic()+35
            while True:
                before,known=all_rows(reader,'hardwareConcurrency')
                if len(known)==2005:break
                if time.monotonic()>deadline:raise RuntimeError('initial known evidence not visible')
                time.sleep(.3)
            assert not before['recording_settled'] and before['recording_budget']['byte_limit']==args.limit_mib*MIB
            server,url=create_inspector(path,ROOT);thread=Thread(target=server.serve_forever,daemon=True);thread.start()
            viewer=pw.chromium.launch(headless=True);page=viewer.new_page();errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(url);page.locator('#rows tr').nth(999).wait_for(timeout=30000)
            expect(page.locator('#recordingBudget')).to_contain_text(f'of {args.limit_mib} MiB')
            # Produce enough observed getter activity to exceed this small real
            # native budget. This changes no page return value or property.
            attempts=0
            while not marker.exists():
                fixture.evaluate('for(let i=0;i<32768;i++)navigator.hardwareConcurrency',isolated_context=False)
                attempts+=1
                if attempts>8:raise RuntimeError('native writer did not publish its limit')
                deadline=time.monotonic()+2
                while not marker.exists() and time.monotonic()<deadline:time.sleep(.15)
            assert marker.stat().st_size==0 and not Path(session['trace_path']).exists()
            at_limit=digest(source);bytes_at_limit=source.stat().st_size
            assert bytes_at_limit==args.limit_mib*MIB,'writer did not use exactly its bounded budget'
            print(json.dumps({'stage':'native-limit','bytes':bytes_at_limit,'headless':not args.headed}),flush=True)
            after,events=all_rows(reader)
            assert after['source_phase']=='limited-recording' and after['recording_settled'] and not after['complete']
            assert after['recording_limit']['written_bytes']==bytes_at_limit
            by_id={event['id']:event for event in events}
            assert all(by_id[event['id']]==event for event in known)
            with snapshot_live_trace(source) as snapshot:
                result=run_with_bounded_stdout([str(exe.with_name('trace_processor_shell.exe')),'query',str(snapshot.path),
                    inspection_select()+' ORDER BY s.ts DESC,s.id DESC'],maximum_stdout=64*MIB,
                    timeout_seconds=45,label='recording limit independent decode')
                assert result.returncode==0
                expected,total=decode_rows(result.stdout,limit=150000,capture=session['value_capture'])
                assert events==expected and total==len(events)
            (args.out/'events.json').write_text(json.dumps(events,indent=2)+'\n',encoding='utf-8')
            fixture.locator('#action').click()
            assert fixture.evaluate('for(let i=0;i<32768;i++)navigator.hardwareConcurrency; 2+2',isolated_context=False)==4
            fixture.goto(origin+'?after-limit')
            assert fixture.title()=='Owned recording limit fixture' and session_status(path)['running']
            # History/UI work above already spans many native flush periods;
            # verify explicitly that later browsing does not append new bytes.
            time.sleep(2.2)
            assert digest(source)==at_limit and source.stat().st_size==bytes_at_limit
            repeated=reader.read(limit=1000)
            assert repeated['total_events']==len(events) and repeated['events']==events[:1000]
            preview=live_inspection(path,ROOT,limit=1000);summary=live_trace_summary(path,ROOT,limit=1000)
            assert preview['source_phase']==summary['source_phase']=='limited-recording'
            assert not preview['complete'] and not summary['complete']
            expect(page.locator('#state')).to_have_text('Recording limit reached',timeout=30000)
            expect(page.locator('#recording')).to_contain_text('newer activity was not captured')
            expect(page.locator('#recording')).to_contain_text('browser is still open')
            page.locator('#search').fill('hardwareConcurrency');page.locator('#historySearch').click()
            expect(page.locator('#state')).to_have_text('History · recording limit reached',timeout=30000)
            page.locator('#rows tr').first.locator('button').click()
            chosen=json.loads(page.locator('#callerDetail').inner_text())
            assert by_id[chosen['eventId']]['result']==json.loads(page.locator('#resultDetail').inner_text())
            report['widths']={}
            for width in (390,1280):
                page.set_viewport_size({'width':width,'height':900})
                assert not page.evaluate('document.documentElement.scrollWidth>innerWidth',isolated_context=False)
                page.screenshot(path=str(args.out/f'panel-{width}.png'),full_page=True)
                report['widths'][str(width)]={'overflow':False}
            assert not errors
            report.update(known_reads_retained=len(known),recorded_events=len(events),attempted_batches=attempts,
                file_bytes=bytes_at_limit,file_sha256=at_limit,incomplete_tail_bytes=after['incomplete_tail_bytes'],
                exact_independent_oracle=True,browser_usable_after_limit=True,recording_stopped_growing=True,
                history_stays_available=True,live_commands_report_limit=True,page_errors=errors)
            print(json.dumps({'stage':'panel-and-history','events':len(events),'incomplete_tail_bytes':after['incomplete_tail_bytes']}),flush=True)
            viewer.close();viewer=None
        reader.close();assert reader.decoder.process.poll() is not None
        server.shutdown();server.server_close();server=None;thread.join(5)
        stop=stop_session(path,timeout_seconds=40)
        report.update(cleanup=stop['state'],shutdown_mode=stop.get('shutdown_mode'),decoder_reaped=True)
        assert report['cleanup']=='stopped'
        with IncrementalInspection(path,ROOT) as reopened:
            data,reopened_events=all_rows(reopened)
            assert reopened_events==events and data['source_phase']=='limited-recording' and not data['complete']
        assert digest(source)==at_limit and marker.stat().st_size==0 and not Path(session['trace_path']).exists()
        report.update(reopen_after_browser_exit=True,original_recording_preserved=True,passed=True)
    except Exception as error:
        report.update(passed=False,error_type=type(error).__name__,error=str(error)[:500])
        (args.out/'failure.txt').write_text(traceback.format_exc(),encoding='utf-8')
    finally:
        if viewer:viewer.close()
        if reader:reader.close()
        if server:server.shutdown();server.server_close()
        if thread:thread.join(5)
        if path and report.get('cleanup')!='stopped':
            try:report['cleanup']=stop_session(path,timeout_seconds=40)['state']
            except Exception as error:report['cleanup_error']=type(error).__name__
        (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({k:v for k,v in report.items() if k not in ('session_path','build')}),flush=True)
    return 0 if report.get('passed') else 1


if __name__=='__main__':raise SystemExit(main())
