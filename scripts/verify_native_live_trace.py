"""Measure live native trace visibility, exact fixture reads and final retention."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from browser_core.bounded_process import run_with_bounded_stdout
from browser_core.cdp import evaluate_page_expression
from browser_core.launcher import EvaluationLaunch, launch_evaluation
from browser_core.lifecycle import session_status, stop_session
from browser_core.live_trace import live_trace_summary, snapshot_live_trace

SQL = """SELECT name, count(*) AS events FROM slice
WHERE name IN ('Navigator.hardwareConcurrency.get', 'WorkerNavigator.hardwareConcurrency.get')
GROUP BY name ORDER BY name"""
READS = 4096


def counts(processor: Path, trace: Path) -> dict[str, int]:
    result = run_with_bounded_stdout([str(processor), 'query', str(trace), SQL],
        maximum_stdout=4096, timeout_seconds=30, label='live fixture trace query')
    if result.returncode:
        raise RuntimeError('trace processor rejected the native snapshot')
    return {row['name']: int(row['events']) for row in
            csv.DictReader(io.StringIO(result.stdout.decode('utf-8')))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--headless-only', action='store_true')
    args = parser.parse_args()
    if args.out.exists():
        parser.error('use a fresh output directory')
    args.out.mkdir(parents=True)
    executable = args.workspace / 'chromium/src/out/BrowserCore/chrome.exe'
    processor = executable.with_name('trace_processor_shell.exe')
    runs = []
    for headless in ([True] if args.headless_only else [False, True]):
        row = {'headless': headless, 'phases': []}
        session_path = None
        label = 'headless' if headless else 'headed'
        try:
            session_path, session = launch_evaluation(EvaluationLaunch(
                executable, args.workspace, headless=headless,
                live_trace=True, trace_scope='broad'), ROOT)
            row['build'] = session['build']
            final = Path(session['trace_path'])
            live = Path(session['live_trace']['path'])
            endpoint = session['automation']['cdp_endpoint']
            target = session['automation']['managed_target_url']

            def wait_snapshot(minimum: int, name: str):
                deadline = time.monotonic() + 10
                previous_bytes = -1
                while time.monotonic() < deadline:
                    if session_status(session_path)['running'] is not True:
                        raise RuntimeError('browser exited before live observations arrived')
                    if live.exists() and live.stat().st_size != previous_bytes:
                        previous_bytes = live.stat().st_size
                        if previous_bytes:
                            with snapshot_live_trace(live) as snapshot:
                                observed = counts(processor, snapshot.path)
                                if observed.get('Navigator.hardwareConcurrency.get', 0) >= minimum:
                                    saved = args.out / f'{label}-{name}.pftrace'
                                    saved.write_bytes(snapshot.path.read_bytes())
                                    return {'events': observed, 'bytes': snapshot.bytes,
                                            'packets': snapshot.packets, 'sha256': snapshot.sha256,
                                            'incomplete_tail_bytes': snapshot.incomplete_tail_bytes}
                    time.sleep(0.2)
                raise RuntimeError('live observations did not reach the known fixture count')

            baseline = wait_snapshot(0, 'baseline')
            base_count = baseline['events'].get('Navigator.hardwareConcurrency.get', 0)
            row['baseline'] = baseline
            for phase in range(1, 4):
                started = time.monotonic()
                result = evaluate_page_expression(endpoint,
                    f'(() => {{let total=0; for(let i=0;i<{READS};i++) total+=navigator.hardwareConcurrency; return total>0;}})()',
                    target_url=target)
                if result is not True:
                    raise RuntimeError('owned fixture did not complete')
                snapshot = wait_snapshot(base_count + phase * READS, f'phase-{phase}')
                snapshot.update(phase=phase, visible_seconds=round(time.monotonic()-started, 3),
                    browser_running=session_status(session_path)['running'], final_exists=final.exists())
                snapshot['exact_count'] = (snapshot['events'].get('Navigator.hardwareConcurrency.get', 0)
                                           == base_count + phase * READS)
                if phase == 3:
                    preview = live_trace_summary(session_path, ROOT, limit=1000)
                    snapshot['managed_summary_events'] = next(
                        g['events'] for g in preview['groups'] if g['name'] == 'Navigator.hardwareConcurrency.get')
                    snapshot['managed_summary_running'] = preview['browser_running']
                    snapshot['managed_summary_provisional'] = preview['complete'] is False
                row['phases'].append(snapshot)
                print(json.dumps({'mode': label, **snapshot}), flush=True)

            # Keep a reader open through the actual native final publication.
            with snapshot_live_trace(live) as last:
                prefix = last.path.read_bytes()
                stopped = stop_session(session_path, timeout_seconds=40)
                row['cleanup'] = stopped['state']
                row['shutdown_mode'] = stopped.get('shutdown_mode')
                row['final_exists'] = final.is_file()
                row['live_removed'] = not live.exists()
                if final.is_file():
                    with final.open('rb') as stream:
                        row['final_preserves_live_prefix'] = stream.read(len(prefix)) == prefix
                    row['final_counts'] = counts(processor, final)
                    row['final_sha256'] = hashlib.sha256(final.read_bytes()).hexdigest()
                    (args.out / f'{label}-final.pftrace').write_bytes(final.read_bytes())
            row['passed'] = (
                len(row['phases']) == 3 and all(p['exact_count'] and p['browser_running']
                    and not p['final_exists'] for p in row['phases'])
                and row.get('final_preserves_live_prefix') is True
                and row.get('live_removed') is True
                and row.get('shutdown_mode') == 'graceful'
                and row['phases'][-1].get('managed_summary_events') == base_count + 3 * READS
                and row['phases'][-1].get('managed_summary_running') is True
                and row['phases'][-1].get('managed_summary_provisional') is True
                and row.get('final_counts', {}).get('Navigator.hardwareConcurrency.get', 0)
                    == base_count + 3 * READS)
        except Exception as error:
            row.update(passed=False, error_type=type(error).__name__, error=str(error))
        finally:
            if session_path and row.get('cleanup') != 'stopped':
                try:
                    cleanup = stop_session(session_path, timeout_seconds=40)
                    row['cleanup'] = cleanup['state']
                    row['shutdown_mode'] = cleanup.get('shutdown_mode')
                except Exception as error:
                    row['cleanup_error'] = type(error).__name__
        runs.append(row)
        print(json.dumps({'mode': label, 'passed': row['passed'], 'cleanup': row.get('cleanup'),
                          'error': row.get('error')}), flush=True)
        (args.out / 'summary.json').write_text(json.dumps({'schema': 'browser-core.live-native-gate/1',
            'runs': runs, 'passed': all(r['passed'] for r in runs)}, indent=2)+'\n', encoding='utf-8')
    return 0 if all(r['passed'] for r in runs) else 1


if __name__ == '__main__':
    raise SystemExit(main())
