"""Owned native recording beyond the old 1 GiB reader ceiling, with bounded output."""
from pathlib import Path
import argparse,csv,ctypes,hashlib,io,json,sys,time,traceback
from ctypes import wintypes

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.launcher import EvaluationLaunch,launch_evaluation
from browser_core.lifecycle import stop_session,session_status
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.inspection import inspection_select,decode_rows
from browser_core.recording_parts import part_path,done_marker_path
from browser_core.recording_limits import MIB
from browser_core.smoke import _serve_fixtures
from browser_core.bounded_process import run_with_bounded_stdout
from patchright.sync_api import sync_playwright
from recording_fixture_config import observed_buffers, require_buffer_mode

COUNT_SQL="""SELECT COUNT(*) AS total FROM __intrinsic_slice s
WHERE s.name='BrowserCoreInspection.BindingValue'
AND EXTRACT_ARG(s.arg_set_id, 'debug.api')='Navigator.hardwareConcurrency.get'"""


def memory(pid):
    class Global(ctypes.Structure):
        _fields_=[('length',wintypes.DWORD),('load',wintypes.DWORD)]+[(name,ctypes.c_ulonglong) for name in
            ('total','available','pagefile','available_pagefile','virtual','available_virtual','extended')]
    class Process(ctypes.Structure):
        _fields_=[('size',wintypes.DWORD),('faults',wintypes.DWORD)]+[(name,ctypes.c_size_t) for name in
            ('peak_working','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile','private')]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);psapi=ctypes.WinDLL('psapi',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE];kernel.CloseHandle.restype=wintypes.BOOL
    kernel.GlobalMemoryStatusEx.argtypes=[ctypes.POINTER(Global)];kernel.GlobalMemoryStatusEx.restype=wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Process),wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype=wintypes.BOOL
    status=Global();status.length=ctypes.sizeof(status)
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(status)):raise ctypes.WinError(ctypes.get_last_error())
    handle=kernel.OpenProcess(0x1000,False,pid)
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    try:
        info=Process();info.size=ctypes.sizeof(info)
        if not psapi.GetProcessMemoryInfo(handle,ctypes.byref(info),info.size):raise ctypes.WinError(ctypes.get_last_error())
        return {'decoder_working_mib':round(info.working/MIB,1),'decoder_private_mib':round(info.private/MIB,1),
                'system_free_mib':round(status.available/MIB,1)}
    finally:kernel.CloseHandle(handle)


def scalar(body):
    rows=list(csv.DictReader(io.StringIO(body.decode('utf-8'))))
    assert len(rows)==1 and set(rows[0])=={'total'}
    return int(rows[0]['total'])


def selected(reader,known,capture):
    ids=','.join(str(int(row['id'])) for row in known)
    body=reader.decoder.query(inspection_select(incremental=True)+f' AND s.id IN ({ids}) ORDER BY s.ts DESC,s.id DESC',max_rows=1000)
    values,total=decode_rows(body,limit=1000,capture=capture)
    assert values==known and total==len(known)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--target-mib',type=int,default=1100,choices=(1100,))
    parser.add_argument('--diagnose-rows',action='store_true',help='preserve the failed decoder response and its exact validation reason')
    parser.add_argument('--diagnose-native',action='store_true',help='save native startup/tracing logs for this owned fixture')
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    report={'scope':'owned headless capacity gate beyond 1 GiB; count plus sampled value/caller checks, not a long human task or Kameleo comparison',
            'passed':False,'target_mib':args.target_mib,'part_mib':128,'max_parts':12,'checkpoints':[]}
    path=reader=None;exe=args.workspace/'chromium/src/out/BrowserCore/chrome.exe';started=time.monotonic()
    if args.diagnose_rows:
        import browser_core.incremental_inspection as incremental_module
        original_decode=incremental_module.decode_rows
        def diagnostic_decode(body,*call_args,**kwargs):
            reasons=[]
            def observe(frame,event,arg):
                if frame.f_code is original_decode.__code__:
                    if event=='exception':
                        kind,value,_=arg
                        reasons.append({'type':kind.__name__,'reason':str(value),
                            'metadata':{k:v for k,v in (frame.f_locals.get('raw') or {}).items() if k not in ('parameters_json','result_json')}})
                    return observe
                return None
            prior=sys.gettrace();sys.settrace(observe)
            try:return original_decode(body,*call_args,**kwargs)
            except Exception:
                (args.out/'failed-query.csv').write_bytes(body)
                (args.out/'failed-row-reasons.json').write_text(json.dumps(reasons,indent=2)+'\n',encoding='utf-8')
                if reader and reader.cursor:
                    (args.out/'failed-reader-state.json').write_text(json.dumps({
                        'offset':reader.cursor.offset,'source_bytes':reader.cursor.source_bytes,
                        'packets':reader.cursor.packets,'digest':reader.cursor.digest.hexdigest()},indent=2)+'\n',encoding='utf-8')
                raise
            finally:sys.settrace(prior)
        incremental_module.decode_rows=diagnostic_decode
        report['diagnostic_row_validation']=True
    def persist():
        (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    try:
        native_args=('--enable-logging','--log-file='+str((args.out/'native.log').resolve()),
            '--vmodule=startup_tracing_controller=2,consumer_host=2,perfetto_service=2') if args.diagnose_native else ()
        report['diagnostic_native_logging']=args.diagnose_native
        path,session=launch_evaluation(EvaluationLaunch(exe,args.workspace,headless=True,
            live_trace=True,inspect_values=True,recording_limit_mib=128,recording_parts=12,extra_args=native_args),ROOT)
        report.update(session_path=str(path),build=session['build'],stage='starting');persist()
        report['effective_buffer_config']=observed_buffers(Path(session['live_trace']['path']))
        persist();require_buffer_mode(report['effective_buffer_config'], 0)
        reader=IncrementalInspection(path,ROOT)
        with _serve_fixtures({'/':(b'<!doctype html><title>Owned recording capacity fixture</title><button id="usable">Still usable</button>','text/html')}) as origin,sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
            page=browser.contexts[0].new_page();page.goto(origin)
            page.evaluate("window.ownedCapacity='same-page';for(let i=0;i<2005;i++)navigator.hardwareConcurrency",isolated_context=False)
            deadline=time.monotonic()+45
            while True:
                initial=reader.history(search='hardwareConcurrency',limit=1000)
                if initial['total_events']==2005:break
                assert time.monotonic()<deadline
                time.sleep(.3)
            known=initial['events'];assert len(known)==1000
            capture=session['value_capture'];intended=2005;cycles=0;previous_milestone=0
            report['stage']='growing';persist()
            while True:
                before=time.monotonic()
                page.evaluate('for(let i=0;i<65536;i++)navigator.hardwareConcurrency',isolated_context=False)
                intended+=65536;cycles+=1
                time.sleep(1.15)
                deadlines=time.monotonic()+90
                refreshes=[]
                while True:
                    report['pending_read']={'cycle':cycles,'intended_reads':intended,
                        'cursor_bytes':reader.cursor.offset if reader.cursor else 0}
                    persist()
                    tick=time.monotonic();data=reader.read(limit=1000);refreshes.append(round(time.monotonic()-tick,3))
                    report['last_read']={key:value for key,value in data.items() if key!='events'}
                    persist()
                    if not data['catching_up']:break
                    if time.monotonic()>deadlines:raise RuntimeError('reader failed to catch up within the fixture deadline')
                assert data['source_phase']=='live-prefix' and data['browser_running']
                assert data['recording_health']['status']=='no-issues-reported', 'recording health reports a problem; exact counters preserved in last_read'
                stats=memory(reader.decoder.process.pid)
                row={'cycle':cycles,'intended_reads':intended,'source_bytes':data['source_bytes'],
                     'snapshot_bytes':data['snapshot_bytes'],'parts':data['recording_parts']['observed_parts'],
                     'refresh_seconds':refreshes,'cycle_seconds':round(time.monotonic()-before,3),**stats}
                report['checkpoints'].append(row);persist()
                if stats['decoder_private_mib']>12288 or stats['system_free_mib']<8192:
                    raise RuntimeError('owned capacity test stopped at its host memory guard')
                milestone=data['source_bytes']//(100*MIB)
                if milestone>previous_milestone:
                    print(json.dumps({'stage':'growing','source_mib':round(data['source_bytes']/MIB,1),'intended_reads':intended,**stats}),flush=True)
                    previous_milestone=milestone
                if data['source_bytes']>args.target_mib*MIB:break
                if cycles>100 or time.monotonic()-started>2400:raise RuntimeError('owned capacity generation exceeded its bound')
            assert data['source_bytes']>1024*MIB and data['recording_parts']['observed_parts']>=9
            report['stage']='verifying-live';persist()
            deadline=time.monotonic()+90
            while True:
                data=reader.read(limit=1000)
                reader.decoder.timeout=45
                count=scalar(reader.decoder.query(COUNT_SQL,max_rows=1))
                if count==intended:break
                if time.monotonic()>deadline:raise RuntimeError('live count disagrees with deliberate reads')
                time.sleep(.3)
            selected(reader,known,capture)
            report['verified_live_health']=data['recording_health'];persist()
            assert data['recording_health']['status']=='no-issues-reported'
            page.locator('#usable').click()
            assert page.evaluate('window.ownedCapacity',isolated_context=False)=='same-page'
            assert session_status(path)['running']
            report.update(live_hardware_reads=count,known_live_values_and_callers=1000,
                          page_state_unchanged=True,stage='closing');persist()
            report['stop']=stop_session(path,timeout_seconds=60)
            assert report['stop']['shutdown_mode']=='graceful'
            deadline=time.monotonic()+120
            while True:
                data=reader.read(limit=1000)
                if data['recording_settled']:break
                if time.monotonic()>deadline:raise RuntimeError('final reader catch-up exceeded its bound')
            assert data['complete'] and data['source_phase']=='finalized-recording' and data['incomplete_tail_bytes']==0
            reader.decoder.timeout=45
            assert scalar(reader.decoder.query(COUNT_SQL,max_rows=1))==intended
            selected(reader,known,capture)
            report['final_recording_health']=data['recording_health'];persist()
            assert data['recording_health']['status']=='no-issues-reported'
            final_hash=data['source_sha256'];final_bytes=data['source_bytes'];final_packets=data['packets']
            report.update(final_hardware_reads=intended,final_source_bytes=final_bytes,final_packets=final_packets,
                          final_source_sha256=final_hash,stage='independent-decode');persist()
            reader.close();reader=None
            source=Path(session['live_trace']['path']);joined=args.out/'joined.pftrace';digest=hashlib.sha256();files=[]
            with joined.open('xb') as dest:
                for number in range(1,13):
                    part=part_path(source,number)
                    if not part.exists():break
                    files.append({'part':number,'bytes':part.stat().st_size})
                    with part.open('rb') as origin_file:
                        for body in iter(lambda:origin_file.read(MIB),b''):
                            dest.write(body);digest.update(body)
            assert joined.stat().st_size==final_bytes and digest.hexdigest()==final_hash
            assert done_marker_path(Path(session['trace_path'])).exists() and not Path(session['trace_path']).exists()
            # Independent process gets the complete joined file, not the live
            # cursor. Output is only one count, keeping the large gate bounded.
            result=run_with_bounded_stdout([str(exe.with_name('trace_processor_shell.exe')),'query',str(joined),COUNT_SQL],
                maximum_stdout=4096,timeout_seconds=180,label='independent capacity count')
            assert result.returncode==0 and scalar(result.stdout)==intended
            report.update(independent_count_equal=True,part_files=files,stage='fresh-reopen');persist()
            with IncrementalInspection(path,ROOT) as reopened:
                deadline=time.monotonic()+600
                while True:
                    fresh=reopened.read(limit=1000)
                    if fresh['recording_settled']:break
                    if time.monotonic()>deadline:raise RuntimeError('fresh large recording catch-up exceeded its bound')
                reopened.decoder.timeout=45
                assert fresh['complete'] and fresh['source_sha256']==final_hash
                assert scalar(reopened.decoder.query(COUNT_SQL,max_rows=1))==intended
                selected(reopened,known,capture)
                report['reopened_recording_health']=fresh['recording_health'];persist()
                assert fresh['recording_health']['status']=='no-issues-reported'
                report['reopened_memory']=memory(reopened.decoder.process.pid)
            report.update(fresh_reopen_equal=True,passed=True,stage='complete')
    except Exception as error:
        report.update(passed=False,error_type=type(error).__name__,error=str(error)[:500])
        if reader is not None:
            report['failure_health']=reader.health
            if reader.cursor is not None:
                report['failure_cursor']={
                    'offset':reader.cursor.offset,'source_bytes':reader.cursor.source_bytes,
                    'packets':reader.cursor.packets,'sha256':reader.cursor.digest.hexdigest()}
        (args.out/'error.txt').write_text(traceback.format_exc(),encoding='utf-8')
    finally:
        if reader:reader.close()
        if path:
            try:report['cleanup']=stop_session(path,timeout_seconds=60)
            except Exception as error:report.update(passed=False,cleanup_error=type(error).__name__)
        report['elapsed_seconds']=round(time.monotonic()-started,3);persist()
        print(json.dumps({k:report[k] for k in ('passed','stage','error','final_source_bytes','final_hardware_reads','elapsed_seconds') if k in report}),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
