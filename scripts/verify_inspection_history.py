"""Real native history pagination, independent prefix oracle and panel checks."""
from pathlib import Path
import argparse,json,sys,time
from threading import Thread

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from browser_core.launcher import EvaluationLaunch,launch_evaluation
from browser_core.lifecycle import stop_session
from browser_core.incremental_inspection import IncrementalInspection
from browser_core.inspection import inspection_select,decode_rows
from browser_core.inspection_ui import create_inspector
from browser_core.bounded_process import run_with_bounded_stdout
from browser_core.live_trace import snapshot_live_trace
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright,expect


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--headed',action='store_true')
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    exe=args.workspace/'chromium/src/out/BrowserCore/chrome.exe'
    report={'headless':not args.headed};path=reader=server=thread=None
    try:
        path,session=launch_evaluation(EvaluationLaunch(exe,args.workspace,
            headless=not args.headed,live_trace=True,inspect_values=True),ROOT)
        report.update(build=session['build'],session_path=str(path))
        reader=IncrementalInspection(path,ROOT)
        routes={'/':(b'<!doctype html><title>Owned full-history fixture</title>','text/html')}
        with _serve_fixtures(routes) as origin,sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
            fixture=browser.contexts[0].new_page();fixture.goto(origin)
            vendor=fixture.evaluate('navigator.vendor',isolated_context=False)
            assert isinstance(vendor,str)
            fixture.evaluate('for(let i=0;i<2505;i++)navigator.hardwareConcurrency',isolated_context=False)
            deadline=time.monotonic()+30
            while True:
                first=reader.history(search='hardwareConcurrency')
                if first['total_events']==2505:break
                if time.monotonic()>deadline:raise RuntimeError('deliberate events did not arrive')
                time.sleep(.3)
            assert len(first['events'])==1000
            with snapshot_live_trace(reader.cursor.source) as snapshot:
                sql=inspection_select()+" AND EXTRACT_ARG(s.arg_set_id,'debug.api')='Navigator.hardwareConcurrency.get' ORDER BY s.ts DESC,s.id DESC"
                oracle=run_with_bounded_stdout([str(exe.with_name('trace_processor_shell.exe')),'query',str(snapshot.path),sql],
                    maximum_stdout=16*1024*1024,timeout_seconds=30,label='history independent oracle')
                assert oracle.returncode==0
                expected,total=decode_rows(oracle.stdout,limit=5000)
                assert total==2505
            # Add new events between pages. None may enter the existing search.
            fixture.evaluate('for(let i=0;i<17;i++)navigator.hardwareConcurrency',isolated_context=False)
            pages=[first];cursor=first['next_cursor']
            while cursor:
                data=reader.history(search='hardwareConcurrency',cursor=cursor)
                assert data['total_events']==2505
                pages.append(data);cursor=data['next_cursor']
                assert len(pages)<=4
            assert [e for page in pages for e in page['events']]==expected
            again=reader.history(search='hardwareConcurrency',cursor=first['page_cursor'])
            assert again['events']==first['events']
            deadline=time.monotonic()+20
            while True:
                newer=reader.history(search='hardwareConcurrency')
                if newer['total_events']==2522:break
                if time.monotonic()>deadline:raise RuntimeError('new search did not include new events')
                time.sleep(.3)
            old=reader.history(search='Navigator.vendor.get')
            assert len(old['events'])==1 and old['events'][0]['result']['value']==vendor
            filtered=reader.history(search='Navigator.vendor.get',script=str(old['events'][0]['script_id']),context='window')
            assert filtered['events']==old['events']
            report.update(exact_oracle_events=2505,page_lengths=[len(p['events']) for p in pages],
                          preserved_snapshot_after_append=True,new_search_events=2522,early_value_and_caller_found=True)
            server,url=create_inspector(path,ROOT)
            thread=Thread(target=server.serve_forever,daemon=True);thread.start()
            viewer=pw.chromium.launch(headless=True)
            page=viewer.new_page(viewport={'width':1280,'height':900});errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(url);page.locator('#rows tr').nth(999).wait_for(timeout=25000)
            page.locator('#pause').click();page.locator('#search').fill('Navigator.vendor.get')
            assert page.locator('#rows tr').count()==0
            page.locator('#historySearch').click()
            expect(page.locator('#state')).to_have_text('History · fixed search',timeout=25000)
            assert page.locator('#rows tr').count()==1
            page.locator('#rows button').first.click()
            assert vendor in page.locator('#resultDetail').inner_text()
            page.locator('#search').fill('hardwareConcurrency');page.locator('#historySearch').click()
            expect(page.locator('#state')).to_have_text('History · fixed search',timeout=25000)
            assert page.locator('#rows tr').count()==1000
            first_ids=page.evaluate('events.map(e=>e.id)',isolated_context=False)
            page.locator('#older').click()
            expect(page.locator('#population')).to_contain_text('page 2',timeout=25000)
            second_ids=page.evaluate('events.map(e=>e.id)',isolated_context=False)
            assert not set(first_ids)&set(second_ids)
            page.locator('#older').click()
            expect(page.locator('#population')).to_contain_text('page 3',timeout=25000)
            assert page.locator('#rows tr').count()==522 and page.locator('#older').is_disabled()
            page.locator('#newer').click()
            expect(page.locator('#population')).to_contain_text('page 2',timeout=25000)
            assert page.evaluate('events.map(e=>e.id)',isolated_context=False)==second_ids
            page.locator('#newer').click()
            expect(page.locator('#population')).to_contain_text('page 1',timeout=25000)
            assert page.evaluate('events.map(e=>e.id)',isolated_context=False)==first_ids
            report['widths']={}
            for width in (390,1280):
                page.set_viewport_size({'width':width,'height':900})
                overflow=page.evaluate('document.documentElement.scrollWidth>innerWidth')
                assert not overflow;report['widths'][width]={'overflow':overflow}
                page.screenshot(path=str(args.out/f'panel-{width}.png'),full_page=True)
            page.locator('#live').click()
            expect(page.locator('#state')).to_have_text('Live · provisional',timeout=15000)
            assert page.locator('#rows tr').count()==1000
            report.update(panel_early_value_found=True,panel_paging_return_exact=True,return_to_live=True,page_errors=errors)
            assert not errors
            viewer.close();fixture.close()
        server.shutdown();server.server_close();thread.join(5);server=None
        reader.close();report['decoder_reaped']=reader.decoder.process.poll() is not None
        stop=stop_session(path,timeout_seconds=40)
        report.update(cleanup=stop['state'],shutdown_mode=stop.get('shutdown_mode'),inspector_thread_reaped=not thread.is_alive())
        report['passed']=report['decoder_reaped'] and report['inspector_thread_reaped'] and report['shutdown_mode']=='graceful'
    except Exception as error:
        report.update(passed=False,error_type=type(error).__name__,error=str(error)[:400])
    finally:
        if server:server.shutdown();server.server_close()
        if thread:thread.join(5)
        if reader:reader.close()
        if path and report.get('cleanup')!='stopped':
            try:report['cleanup']=stop_session(path,timeout_seconds=40)['state']
            except Exception as error:report['cleanup_error']=type(error).__name__
        (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({k:v for k,v in report.items() if k!='build'}),flush=True)
    return 0 if report.get('passed') else 1


if __name__=='__main__':raise SystemExit(main())
