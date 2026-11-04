"""Kill only owned decoder helpers; prove live/history/saved viewer recovery."""
from pathlib import Path
import argparse,json,sys,time
from threading import Thread
from urllib.request import Request,urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(Path(__file__).resolve().parent))
from browser_core.launcher import EvaluationLaunch,launch_evaluation
from browser_core.lifecycle import stop_session
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.smoke import _serve_fixtures
from browser_core.inspection import inspection_select,decode_rows
from browser_core.live_trace import snapshot_live_trace
from browser_core.bounded_process import run_with_bounded_stdout
import browser_core.inspection_ui as ui
from patchright.sync_api import sync_playwright,expect

def request(url,body=None):
    req=Request(url,data=json.dumps(body).encode() if body is not None else None,
                headers={'Content-Type':'application/json'} if body is not None else {})
    with urlopen(req,timeout=40) as response:
        result=json.loads(response.read(16*1024*1024))
        assert response.status==200,result
        return result

def history(url):
    first=request(url+'history',{});rows=list(first['events']);cursor=first['next_cursor']
    while cursor:
        data=request(url+'history',{'cursor':cursor});rows.extend(data['events']);cursor=data['next_cursor']
        assert len(rows)<10000
    assert len(rows)==first['total_events']
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--headed',action='store_true')
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    exe=args.workspace/'chromium/src/out/BrowserCore/chrome.exe'
    report={'headless':not args.headed,'cases':[]};path=server=thread=None
    captured=[];original=ui.IncrementalInspection
    def capture(*a,**k):
        reader=original(*a,**k);captured.append(reader);return reader
    ui.IncrementalInspection=capture
    try:
        path,session=launch_evaluation(EvaluationLaunch(exe,args.workspace,headless=not args.headed,
                                        live_trace=True,inspect_values=True),ROOT)
        report.update(build=session['build'],session_path=str(path))
        with _serve_fixtures({'/':(b'<!doctype html><title>Owned decoder recovery fixture</title>','text/html')}) as origin,sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
            fixture=browser.contexts[0].new_page();fixture.goto(origin)
            fixture.evaluate('for(let i=0;i<2005;i++)navigator.hardwareConcurrency',isolated_context=False)
            with IncrementalInspection(path,ROOT) as warm:
                deadline=time.monotonic()+30
                while warm.read()['total_events']<2017:
                    assert time.monotonic()<deadline
                    time.sleep(.3)
            viewer=pw.chromium.launch(headless=True)
            for phase in ('live','history','saved'):
                row={'phase':phase};report['cases'].append(row)
                if phase=='saved':
                    stop=stop_session(path,timeout_seconds=40)
                    report.update(cleanup=stop['state'],shutdown_mode=stop.get('shutdown_mode'))
                    assert stop.get('shutdown_mode')=='graceful'
                server,url=ui.create_inspector(path,ROOT);thread=Thread(target=server.serve_forever,daemon=True);thread.start()
                page=viewer.new_page(viewport={'width':1280,'height':900});errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(url);page.locator('#rows tr').nth(999).wait_for(timeout=25000)
                if phase!='saved':page.locator('#pause').click()
                time.sleep(3)
                before=history(url);row['before_events']=len(before)
                if phase in ('history','saved'):
                    page.locator('#historySearch').click()
                    expect(page.locator('#state')).to_have_text('History · saved recording' if phase=='saved' else 'History · fixed search',timeout=20000)
                page.locator('#rows tr button').first.click()
                selected=page.locator('#callerDetail').inner_text()
                reader=captured[-1];old_decoder=reader.decoder
                old_decoder.process.kill();old_decoder.process.wait(timeout=5)
                with page.expect_response(lambda r:r.status==202 and r.url.startswith(url),timeout=20000):
                    if phase=='live':page.locator('#pause').click()
                    else:page.locator('#older').click()
                row['replay_prefix_bytes']=reader.replay_guard[0]
                row['replay_prefix_sha256']=reader.replay_guard[1]
                assert page.locator('#rows tr').count()==1000 and page.locator('#callerDetail').inner_text()==selected
                row['display_retained_during_rebuild']=True
                if phase!='live':
                    expect(page.locator('#message')).to_contain_text('start a new search',timeout=10000)
                    assert page.locator('#older').is_disabled()
                    row['old_pages_expired_explicitly']=True
                    page.locator('#historySearch').click()
                expect(page.locator('#decoderRecovery')).to_be_visible(timeout=25000)
                if phase=='live':page.locator('#pause').click()
                time.sleep(3)
                after=history(url)
                assert after==before
                assert reader.decoder is not old_decoder and old_decoder.process.poll() is not None
                assert reader.decoder_restarts==1 and reader.replay_guard is None
                row.update(exact_rows_after_restart=True,old_decoder_reaped=True,restarts=1)
                if phase!='saved':
                    fixture.evaluate('for(let i=0;i<17;i++)navigator.hardwareConcurrency',isolated_context=False)
                    deadline=time.monotonic()+30
                    while True:
                        after=history(url)
                        if len(after)==len(before)+17:break
                        assert time.monotonic()<deadline
                        time.sleep(.4)
                    row['new_reads_after_restart']=17
                with snapshot_live_trace(reader.cursor.source) as snapshot:
                    oracle=run_with_bounded_stdout([str(exe.with_name('trace_processor_shell.exe')),'query',str(snapshot.path),inspection_select()+' ORDER BY s.ts DESC,s.id DESC'],maximum_stdout=16*1024*1024,timeout_seconds=30,label='decoder recovery oracle')
                    assert oracle.returncode==0
                    rows,total=decode_rows(oracle.stdout,limit=5000)
                    assert rows==after and total==len(after)
                    row['independent_oracle_exact']=True
                row['widths']={}
                for width in (390,1280):
                    page.set_viewport_size({'width':width,'height':900})
                    overflow=page.evaluate('document.documentElement.scrollWidth>innerWidth')
                    assert not overflow
                    row['widths'][width]={'overflow':overflow}
                    page.screenshot(path=str(args.out/f'{phase}-{width}.png'),full_page=True)
                assert not errors;row['page_errors']=errors
                page.close();server.shutdown();server.server_close();thread.join(5)
                assert not thread.is_alive() and reader.decoder.process.poll() is not None
                row['cleanup']=True;server=thread=None
                print(json.dumps(row),flush=True)
            viewer.close()
        report['passed']=True
    except Exception as error:
        report.update(passed=False,error_type=type(error).__name__,error=str(error)[:1000])
    finally:
        if server:server.shutdown();server.server_close()
        if thread:thread.join(5)
        if path and report.get('cleanup')!='stopped':
            try:report['cleanup']=stop_session(path,timeout_seconds=40)['state']
            except Exception as error:report['cleanup_error']=type(error).__name__
        ui.IncrementalInspection=original
        (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('session_path','build','cases')}),flush=True)
    return 0 if report.get('passed') else 1

if __name__=='__main__':raise SystemExit(main())
