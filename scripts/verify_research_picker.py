"""Exercise the actual saved-browser page against owned native browser sessions."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
from threading import Thread
import time
import uuid
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from browser_core.research_picker import create_research_picker
from browser_core.profiles import delete_disposable_profile, load_profile
from browser_core.lifecycle import session_status
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright, expect


def wait_for(condition, seconds=60):
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() > deadline:
            raise RuntimeError('owned picker gate timed out')
        time.sleep(.2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--headed', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'owned local picker UI create/reopen/isolation; no Kameleo speed comparison',
              'headless': not args.headed, 'runs': [], 'passed': False}
    prefix = 'ops-disp-picker-' + uuid.uuid4().hex[:12]
    names = [prefix + '-saved', prefix + '-isolated']
    registry = args.workspace / 'profiles/registry'
    before_registry = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in registry.glob('*.json')}
    owned = []
    server = thread = viewer = None
    try:
        server, url = create_research_picker(args.workspace, ROOT, headless=not args.headed,
                                             recording_limit_mib=16)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        routes = {'/': (b'<!doctype html><title>Owned picker storage fixture</title>', 'text/html')}
        with _serve_fixtures(routes) as origin, sync_playwright() as pw:
            viewer = pw.chromium.launch(headless=True)
            panel = viewer.new_page(viewport={'width': 1280, 'height': 900})
            page_errors = []
            panel.on('pageerror', lambda error: page_errors.append(str(error)))
            panel.goto(url)
            expect(panel.locator('#statusTitle')).to_have_text('Choose a research browser', timeout=15000)
            expect(panel.locator('#listError')).to_be_hidden()
            original = None
            for phase in ('create', 'reopen', 'isolation'):
                name = names[1] if phase == 'isolation' else names[0]
                row = {'phase': phase}
                if phase != 'reopen':
                    owned.append(name)
                    panel.locator('#newName').fill(name)
                    started = time.monotonic()
                    panel.locator('#create').click()
                else:
                    panel.locator('#search').fill(name)
                    button = panel.locator(f'button[data-profile="{name}"]')
                    expect(button).to_be_enabled(timeout=10000)
                    # A routine status poll must not replace the keyboard's
                    # focused Open button while a researcher is choosing.
                    button.focus()
                    panel.wait_for_timeout(1600)
                    expect(button).to_be_focused()
                    started = time.monotonic()
                    button.press('Enter')
                expect(panel.locator('#statusTitle')).to_have_text('Research browser is open', timeout=90000)
                row['click_to_ready_seconds'] = round(time.monotonic() - started, 3)
                run = server.picker.active
                assert run and run.session['profile']['id'] == name
                row.update(build=run.session['build'], created_profile=run.created_profile,
                           session_path=str(run.session_path))
                assert run.created_profile == (phase != 'reopen')
                assert run.session['live_trace']['byte_limit'] == 16 * 1024 * 1024
                browser = pw.chromium.connect_over_cdp(run.session['automation']['cdp_endpoint'])
                page = browser.contexts[0].new_page()
                page.goto(origin)
                stored = page.evaluate("({stored:localStorage.getItem('picker-fixture'),cookie:document.cookie})", isolated_context=False)
                if phase == 'reopen':
                    assert stored == {'stored': 'saved', 'cookie': 'picker_fixture=saved'}
                    assert load_profile(args.workspace, name) == original
                else:
                    assert stored == {'stored': None, 'cookie': ''}
                    page.evaluate("localStorage.setItem('picker-fixture','saved');document.cookie='picker_fixture=saved;SameSite=Lax;Path=/;Max-Age=3600'", isolated_context=False)
                page.evaluate('for(let i=0;i<32;i++)navigator.hardwareConcurrency', isolated_context=False)
                def seen():
                    with urlopen(run.url + 'data', timeout=45) as response:
                        data = json.loads(response.read(16 * 1024 * 1024))
                    row['hardware_rows'] = len([e for e in data['events'] if e['api'] == 'Navigator.hardwareConcurrency.get'])
                    row['recording_health'] = data['recording_health']
                    return row['hardware_rows'] == 32
                wait_for(seen, 40)
                assert row['recording_health']['status'] == 'no-issues-reported'
                assert panel.locator('#inspector').get_attribute('href') == run.url
                row['storage_check'] = True
                if phase == 'create':
                    original = load_profile(args.workspace, name)
                    row['widths'] = {}
                    for width in (390, 1280):
                        panel.set_viewport_size({'width': width, 'height': 900})
                        assert not panel.evaluate('document.documentElement.scrollWidth>innerWidth')
                        panel.screenshot(path=str(args.out / f'picker-running-{width}.png'), full_page=True)
                        row['widths'][str(width)] = {'overflow': False}
                if phase == 'reopen':
                    try:
                        browser.new_browser_cdp_session().send('Browser.close')
                    except Exception:
                        pass
                else:
                    panel.locator('#stop').click()
                expect(panel.locator('#statusTitle')).to_have_text('Choose a research browser', timeout=70000)
                wait_for(lambda: not server.picker.worker.is_alive())
                assert run.stop_receipt['state'] == 'stopped'
                row['shutdown_mode'] = run.stop_receipt['shutdown_mode']
                assert row['shutdown_mode'] in (('graceful', 'exited-before-force') if phase == 'reopen' else ('graceful',))
                assert not session_status(run.session_path)['running']
                assert run.thread.is_alive() and not run.inspector_closed
                with urlopen(run.url + 'data', timeout=45) as response:
                    reviewed = json.loads(response.read(16 * 1024 * 1024))
                assert reviewed['source_phase'] == 'finalized-recording'
                assert len([e for e in reviewed['events'] if e['api'] == 'Navigator.hardwareConcurrency.get']) == 32
                row.update(recording_review=True, known_reads_retained=32)
                report['runs'].append(row)
                (args.out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
                print(json.dumps({'phase': phase, 'passed': True, 'click_to_ready_seconds': row['click_to_ready_seconds']}), flush=True)
            panel.locator('#search').fill(prefix)
            expect(panel.locator('#profiles .profile')).to_have_count(2)
            expect(panel.locator('#recent a')).to_have_count(3)
            expect(panel.locator('#recent small')).to_have_count(3)
            assert len({item['opened_at'] for item in server.picker.snapshot()['recent']}) == 3
            for width in (390, 1280):
                panel.set_viewport_size({'width': width, 'height': 900})
                assert not panel.evaluate('document.documentElement.scrollWidth>innerWidth')
                panel.screenshot(path=str(args.out / f'picker-review-{width}.png'), full_page=True)
            assert not page_errors
            report['page_errors'] = page_errors
            viewer.close()
            viewer = None
        retained = [run for _, run in server.picker.reviews]
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive() and all(not run.thread.is_alive() for run in retained)
        report['helpers_reaped'] = True
        report['passed'] = len(report['runs']) == 3
    except Exception as error:
        import traceback
        report.update(passed=False, error_type=type(error).__name__, error=str(error)[:500])
        (args.out / 'error.txt').write_text(traceback.format_exc(), encoding='utf-8')
    finally:
        if viewer:
            try: viewer.close()
            except Exception: pass
        if server:
            server.shutdown()
            server.server_close()
        if thread:
            thread.join(5)
        report['profile_cleanup'] = []
        for name in owned:
            try:
                result = delete_disposable_profile(args.workspace, name)
                report['profile_cleanup'].append(result['state'])
            except Exception as error:
                report['profile_cleanup'].append(type(error).__name__)
                report['passed'] = False
        after_registry = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in registry.glob('*.json')}
        report['unrelated_registry_unchanged'] = before_registry == after_registry
        report['passed'] = report['passed'] and report['unrelated_registry_unchanged']
        (args.out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({k: report[k] for k in ('passed', 'error', 'profile_cleanup', 'unrelated_registry_unchanged') if k in report}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
