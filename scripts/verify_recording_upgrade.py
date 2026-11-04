"""Reopen owned recordings after an upgrade without rewriting their evidence.

Each baseline is a completed verify_recording_recovery.py output directory.
Its saved prefix digest and event count are required; no new browser recording
is substituted. This verifies one installed reader against these exact inputs,
not compatibility with every historical or future Chromium/Perfetto build.
"""
from pathlib import Path
import argparse,hashlib,json,os,queue,subprocess,sys,traceback
from threading import Thread
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.bounded_process import run_with_bounded_stdout
from browser_core.contracts import load_session
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.inspection import decode_rows,inspection_select
from browser_core.inspection_ui import create_inspector
from browser_core.live_trace import snapshot_live_trace
from browser_core.recording_source import RecordingSource
from patchright.sync_api import sync_playwright,expect


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):value.update(block)
    return value.hexdigest()


def history(reader):
    first=reader.history();events=list(first['events']);cursor=first['next_cursor'];pages=1
    while cursor:
        data=reader.history(cursor=cursor)
        assert data['reader_runtime']==first['reader_runtime']
        assert data['source_phase']==first['source_phase']
        events.extend(data['events']);cursor=data['next_cursor'];pages+=1
        assert pages<=100,'fixture exceeds verification bound'
    assert len(events)==first['total_events']
    assert len({event['id'] for event in events})==len(events)
    return first,events,pages


def cli_reopen(session_path,reader_executable,expected):
    bootstrap="""import sys,threading,_thread
from browser_core.cli import main
def stop():
 sys.stdin.readline()
 _thread.interrupt_main()
threading.Thread(target=stop,daemon=True).start()
raise SystemExit(main())
"""
    argv=[sys.executable,'-c',bootstrap,'trace','inspect','--session',str(session_path)]
    if reader_executable:argv.extend(['--reader-executable',str(reader_executable)])
    child=subprocess.Popen(argv,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    try:
        ready=queue.Queue();thread=Thread(target=lambda:ready.put(child.stdout.readline()),daemon=True);thread.start()
        notice=json.loads(ready.get(timeout=30))
        with urlopen(notice['inspector_url']+'data',timeout=40) as response:
            result=json.loads(response.read(16*1024*1024))
        for key in ('source_phase','recording_settled','complete','recovery_incomplete','reader_runtime','total_events'):
            assert result[key]==expected[key],key
        assert notice['read_only'] is True
        child.stdin.write(b'\n');child.stdin.flush();child.wait(timeout=20);thread.join(5)
        assert child.returncode==0 and not thread.is_alive()
        return {'exit_code':child.returncode,'explicit_reader':reader_executable is not None,
                'read_only':True,'exact_summary':True}
    finally:
        if child.poll() is None:
            try:child.stdin.write(b'\n');child.stdin.flush();child.wait(timeout=20)
            except Exception:child.kill();child.wait(timeout=5)
        for stream in (child.stdin,child.stdout,child.stderr):stream.close()


def verify(baseline,exe,out,index,pw):
    previous=json.loads((baseline/'summary.json').read_text(encoding='utf-8'))
    assert previous['passed'] and previous['exact_independent_oracle']
    path=Path(previous['session_path']);session=load_session(path)
    source=RecordingSource(path,ROOT,exe if index%2 else None)
    location=source.resolve();original_hash=digest(location.path);session_hash=digest(path)
    assert location.reader_runtime['mode']=='compatible-reader'
    assert location.reader_runtime['producer_build']==previous['build']==session['build']
    result={'baseline':baseline.name,'session_path':str(path),'reader_runtime':location.reader_runtime}
    reader=server=thread=viewer=None
    try:
        reader=IncrementalInspection(path,ROOT,source)
        first,events,pages=history(reader)
        assert first['total_events']==previous['post_exit_events']
        assert first['complete']==previous['complete']
        assert first['recording_settled'] and first['browser_running'] is False
        assert first['recovery_incomplete']==(previous['mode']=='forced')
        with snapshot_live_trace(location.path) as snapshot:
            assert snapshot.sha256==previous['committed_prefix_sha256']
            assert snapshot.bytes==previous['committed_prefix_bytes']
            oracle=run_with_bounded_stdout([str(exe.with_name('trace_processor_shell.exe')),'query',str(snapshot.path),
                inspection_select()+' ORDER BY s.ts DESC,s.id DESC'],maximum_stdout=16*1024*1024,
                timeout_seconds=30,label='upgraded recording independent full decode')
            assert oracle.returncode==0
            expected,total=decode_rows(oracle.stdout,limit=10000,capture=session['value_capture'])
            assert events==expected and total==len(events)
        (out/f'{baseline.name}-events.json').write_text(json.dumps(events,indent=2)+'\n',encoding='utf-8')
        observed=sum(event['api']=='Navigator.hardwareConcurrency.get' for event in events)
        assert observed>=previous['known_rows_retained'],'known hardware read count decreased'
        result.update(total_events=len(events),history_pages=pages,hardware_reads=observed,
            unchanged_historical_prefix=True,exact_independent_oracle=True,complete=first['complete'],
            source_phase=first['source_phase'],recording_health=first['recording_health'])
        server,url=create_inspector(path,ROOT,reader_executable=exe if index%2 else None)
        thread=Thread(target=server.serve_forever,daemon=True);thread.start()
        viewer=pw.chromium.launch(headless=True);page=viewer.new_page();errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(url);page.locator('#rows tr').nth(999).wait_for(timeout=30000)
        expect(page.locator('#readerRuntime')).to_be_visible()
        expect(page.locator('#readerRuntime')).to_contain_text('different browser build')
        expected_state='Recovered · incomplete' if previous['mode']=='forced' else 'Saved recording'
        expect(page.locator('#state')).to_have_text(expected_state,timeout=10000)
        if previous['mode']=='forced':expect(page.locator('#recording')).to_contain_text('Recent activity may be missing')
        page.locator('#search').fill('hardwareConcurrency');page.locator('#historySearch').click()
        expect(page.locator('#state')).to_have_text('History · incomplete recovery' if previous['mode']=='forced' else 'History · saved recording',timeout=30000)
        page.locator('#older').click();expect(page.locator('#population')).to_contain_text('page 2',timeout=30000)
        page.locator('#rows tr').first.locator('button').click()
        expected_event=[event for event in events if event['api']=='Navigator.hardwareConcurrency.get'][1000]
        assert json.loads(page.locator('#resultDetail').inner_text())==expected_event['result']
        caller=json.loads(page.locator('#callerDetail').inner_text())
        assert caller['eventId']==expected_event['id'] and caller['scriptId']==expected_event['script_id']
        assert caller['contextId']==expected_event['context_id'] and caller['timestampNs']==expected_event['ts']
        result['widths']={}
        for width in (390,1280):
            page.set_viewport_size({'width':width,'height':900})
            overflow=page.evaluate('document.documentElement.scrollWidth>innerWidth',isolated_context=False)
            assert not overflow;result['widths'][str(width)]={'overflow':False}
            page.screenshot(path=str(out/f'{baseline.name}-{width}.png'),full_page=True)
        assert not errors
        result.update(page_errors=errors,upgrade_banner_visible=True,old_history_caller_and_value_exact=True)
        viewer.close();viewer=None
        server.shutdown();server.server_close();server=None;thread.join(5)
        reader.close();assert reader.decoder.process.poll() is not None
        result['decoder_reaped']=True
        result['cli']=cli_reopen(path,exe if index%2 else None,first)
        assert digest(location.path)==original_hash and digest(path)==session_hash
        result.update(recording_sha256=original_hash,session_sha256=session_hash,original_files_unchanged=True,passed=True)
    finally:
        if viewer:viewer.close()
        if server:server.shutdown();server.server_close()
        if thread:thread.join(5)
        if reader:reader.close()
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reader-executable',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,action='append',required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    report={'runs':[],'scope':'exact owned stopped recordings; no live website or future decoder compatibility claim'}
    with sync_playwright() as pw:
        for index,baseline in enumerate(args.baseline):
            try:row=verify(baseline,args.reader_executable.resolve(),args.out,index,pw)
            except Exception as error:
                row={'baseline':baseline.name,'passed':False,'error_type':type(error).__name__,'error':str(error)[:500]}
                (args.out/f'{baseline.name}-failure.txt').write_text(traceback.format_exc(),encoding='utf-8')
            report['runs'].append(row);report['passed']=all(item['passed'] for item in report['runs'])
            (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            print(json.dumps(row),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
