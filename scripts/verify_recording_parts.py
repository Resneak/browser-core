"""Owned native gate for continuous recording across physical file boundaries."""
from pathlib import Path
import argparse,hashlib,json,sys,time,traceback
from threading import Thread

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.launcher import EvaluationLaunch,launch_evaluation
from browser_core.lifecycle import stop_session,session_status
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.recording_parts import part_path,done_marker_path
from browser_core.recording_limits import MIB,limit_marker_path
from browser_core.recording_interruption import interruption_marker_path
from browser_core.inspection import decode_rows,inspection_select,live_inspection
from browser_core.live_trace import live_trace_summary
from browser_core.inspection_ui import create_inspector
from browser_core.bounded_process import run_with_bounded_stdout
from browser_core.smoke import _serve_fixtures
from verify_recording_limit import all_rows
from recording_fixture_config import observed_buffers, require_buffer_mode
from recording_fixture_failure import require_supported_failure_mode
from patchright.sync_api import sync_playwright,expect


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--headed',action='store_true')
    parser.add_argument('--mode',choices=('finish','limit','forced','service-crash'),default='finish')
    args=parser.parse_args()
    require_supported_failure_mode(args.mode)
    args.out.mkdir(parents=True,exist_ok=False)
    exe=args.workspace/'chromium/src/out/BrowserCore/chrome.exe'
    report={'headless':not args.headed,'mode':args.mode,'part_mib':4,'max_parts':4,
            'scope':'owned continuous recording at small part sizes; no decoder RAM or full 4 GiB claim','passed':False}
    path=reader=server=thread=viewer=None
    def persist():
        (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    try:
        path,session=launch_evaluation(EvaluationLaunch(exe,args.workspace,headless=not args.headed,
            live_trace=True,inspect_values=True,recording_limit_mib=4,recording_parts=4),ROOT)
        report.update(session_path=str(path),build=session['build'],stage='initial')
        report['effective_buffer_config']=observed_buffers(Path(session['live_trace']['path']))
        persist()
        require_buffer_mode(report['effective_buffer_config'], 0)
        assert session['live_trace']['parts']['max_parts']==4
        source=Path(session['live_trace']['path']);limit=limit_marker_path(Path(session['trace_path']))
        reader=IncrementalInspection(path,ROOT)
        routes={'/':(b'<!doctype html><title>Owned segmented recording</title><button id="still-here">Continue research</button>','text/html')}
        with _serve_fixtures(routes) as origin,sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
            fixture=browser.contexts[0].new_page();fixture.goto(origin)
            fixture.evaluate("window.ownedMarker='same-page';localStorage.setItem('owned-parts','same-storage');document.cookie='owned_parts=same;SameSite=Lax;Path=/';for(let i=0;i<2005;i++)navigator.hardwareConcurrency",isolated_context=False)
            deadline=time.monotonic()+35
            while True:
                initial,known=all_rows(reader,'hardwareConcurrency')
                if len(known)==2005:break
                if time.monotonic()>deadline:raise RuntimeError('known initial rows not visible')
                time.sleep(.3)
            original_ids={event['id']:event for event in known}
            assert initial['recording_parts']['observed_parts']==1
            assert initial['recording_budget']['byte_limit']==16*MIB
            server,url=create_inspector(path,ROOT);thread=Thread(target=server.serve_forever,daemon=True);thread.start()
            viewer=pw.chromium.launch(headless=True);page=viewer.new_page();errors=[]
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(url);expect(page.locator('#recordingParts')).to_contain_text('1 of up to 4',timeout=30000)
            intended=2005;checkpoints=[]
            report['stage']='crossing-parts'
            while True:
                fixture.evaluate('for(let i=0;i<4096;i++)navigator.hardwareConcurrency',isolated_context=False)
                intended+=4096
                deadline=time.monotonic()+20
                while True:
                    current=reader.read(limit=1000)
                    if current['source_bytes']>initial['source_bytes'] and not current['catching_up']:break
                    if time.monotonic()>deadline:raise RuntimeError('recording did not advance')
                    time.sleep(.25)
                initial=current
                checkpoints.append({'bytes':current['source_bytes'],'parts':current['recording_parts']['observed_parts'],
                                    'intended_hardware_reads':intended,'browser_running':current['browser_running']})
                if args.mode=='limit' and limit.exists():break
                if args.mode!='limit' and current['recording_parts']['observed_parts']>=3:break
                if intended>100000:raise RuntimeError('part boundary was not reached')
            report['checkpoints']=checkpoints
            assert current['recording_parts']['observed_parts']>=3
            assert session_status(path)['running'] and fixture.title()=='Owned segmented recording'
            fixture.locator('#still-here').click()
            assert fixture.evaluate("({marker:window.ownedMarker,storage:localStorage.getItem('owned-parts'),cookie:document.cookie})",isolated_context=False)=={'marker':'same-page','storage':'same-storage','cookie':'owned_parts=same'}
            if args.mode!='limit':
                assert not limit.exists() and current['source_phase']=='live-prefix'
                live,events=all_rows(reader,'hardwareConcurrency')
                deadline=time.monotonic()+25
                while len(events)!=intended and time.monotonic()<deadline:
                    time.sleep(.3);live,events=all_rows(reader,'hardwareConcurrency')
                assert len(events)==intended
                assert all({e['id']:e for e in events}[k]==v for k,v in original_ids.items())
                report['all_live_deliberate_reads']=len(events)
            preview=live_inspection(path,ROOT,limit=1000)
            summary=live_trace_summary(path,ROOT,limit=1000)
            assert preview['source_bytes']>8*MIB and summary['bytes']>8*MIB
            assert preview['browser_running'] and summary['browser_running']
            report['one_shot_readers_cross_parts']=True
            expect(page.locator('#recordingParts')).to_contain_text('of up to 4 files',timeout=30000)
            print(json.dumps({'stage':'crossed','mode':args.mode,'headless':not args.headed,'parts':current['recording_parts']['observed_parts'],'intended_reads':intended}),flush=True)
            report['stage']='closing'
            if args.mode=='service-crash':
                from recording_fixture_failure import interrupt_owned_tracing_service
                report['interruption']=interrupt_owned_tracing_service(path,session)
                marker=interruption_marker_path(Path(session['trace_path']))
                deadline=time.monotonic()+25
                while not marker.exists() and time.monotonic()<deadline:time.sleep(.1)
                assert marker.exists(), 'service interruption marker missing'
                interrupted,retained=all_rows(reader,'hardwareConcurrency')
                assert interrupted['browser_running'] and interrupted['recording_settled']
                assert interrupted['source_phase']=='interrupted-recording' and not interrupted['complete']
                assert len(retained)==intended
                assert all({e['id']:e for e in retained}[k]==v for k,v in original_ids.items())
                fixture.locator('#still-here').click()
                expect(page.locator('#recording')).to_contain_text('capture has stopped',timeout=30000)
                report['interruption'].update(retained_hardware_reads=len(retained),warning_while_browser_open=True)
            if args.mode=='forced':
                from browser_core.process import terminate_verified
                terminate_verified(session['process_identity'],timeout_seconds=20)
            stopped=stop_session(path,timeout_seconds=40)
            report['stop']=stopped
            if args.mode!='forced':assert stopped['shutdown_mode']=='graceful'
            final,events=all_rows(reader)
            assert final['recording_settled'] and not final['browser_running']
            expected_phase={'finish':'finalized-recording','limit':'limited-recording','forced':'recovered-prefix','service-crash':'interrupted-recording'}[args.mode]
            assert final['source_phase']==expected_phase
            assert final['complete']==(args.mode=='finish')
            files=[];joined=bytearray()
            for number in range(1,5):
                part=part_path(source,number)
                if not part.exists():break
                body=part.read_bytes();joined.extend(body)
                files.append({'part':number,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
            assert len(files)>=3 and all(p['bytes']==4*MIB for p in files[:-1])
            assert not Path(session['trace_path']).exists()
            assert done_marker_path(Path(session['trace_path'])).exists()==(args.mode=='finish')
            if args.mode=='limit':assert len(joined)==16*MIB and limit.exists()
            assert final['source_sha256']==hashlib.sha256(joined[:final['snapshot_bytes']]).hexdigest()
            joined_path=args.out/'joined-prefix.pftrace';joined_path.write_bytes(joined[:final['snapshot_bytes']])
            result=run_with_bounded_stdout([str(exe.with_name('trace_processor_shell.exe')),'query',str(joined_path),
                inspection_select()+' ORDER BY s.ts DESC,s.id DESC'],maximum_stdout=64*MIB,timeout_seconds=45,label='independent joined recording decode')
            assert result.returncode==0
            expected,total=decode_rows(result.stdout,limit=150000,capture=session['value_capture'])
            assert events==expected and total==len(events)
            by_id={event['id']:event for event in events}
            assert all(by_id[k]==v for k,v in original_ids.items())
            hardware=[event for event in events if event['api']=='Navigator.hardwareConcurrency.get']
            if args.mode in ('finish','service-crash'):assert len(hardware)==intended
            if args.mode=='forced':assert len(hardware)>=report['all_live_deliberate_reads']
            report.update(parts=files,source_bytes=len(joined),snapshot_bytes=final['snapshot_bytes'],
                final_events=len(events),hardware_reads=len(hardware),incomplete_tail_bytes=final['incomplete_tail_bytes'],
                known_values_and_callers_preserved=2005,independent_decode_equal=True,
                source_sha256=final['source_sha256'],page_state_unchanged=True)
            with IncrementalInspection(path,ROOT) as reopened:
                fresh,fresh_events=all_rows(reopened)
                assert fresh_events==events and fresh['source_phase']==expected_phase
            report['fresh_reopen_equal']=True
            expected_label={'finish':'Saved recording','limit':'Recording limit reached','forced':'Recovered · incomplete','service-crash':'Recording interrupted'}[args.mode]
            expect(page.locator('#state')).to_have_text(expected_label,timeout=30000)
            page.locator('#search').fill('hardwareConcurrency');page.locator('#historySearch').click()
            expect(page.locator('#state')).to_contain_text('History',timeout=30000)
            page.locator('#rows tr').first.locator('button').click()
            selected=json.loads(page.locator('#callerDetail').inner_text())
            assert by_id[selected['eventId']]['result']==json.loads(page.locator('#resultDetail').inner_text())
            report['widths']={}
            for width in (390,1280):
                page.set_viewport_size({'width':width,'height':900})
                assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
                page.screenshot(path=str(args.out/f'panel-{width}.png'),full_page=True)
                report['widths'][str(width)]={'overflow':False}
            assert not errors;report['page_errors']=errors
            viewer.close();viewer=None
        report.update(passed=True,stage='complete')
    except Exception as error:
        report.update(passed=False,error_type=type(error).__name__,error=str(error)[:500])
        (args.out/'error.txt').write_text(traceback.format_exc(),encoding='utf-8')
    finally:
        if viewer:
            try:viewer.close()
            except Exception:pass
        if server:server.shutdown();server.server_close();thread.join(5)
        if reader:reader.close()
        if path:
            try:report['cleanup']=stop_session(path,timeout_seconds=40)
            except Exception as error:report.update(passed=False,cleanup_error=type(error).__name__)
        report['inspector_thread_reaped']=thread is None or not thread.is_alive()
        persist();print(json.dumps({k:report[k] for k in ('passed','mode','stage','error','source_bytes','hardware_reads') if k in report}),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
