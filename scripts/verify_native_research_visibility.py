"""Check research-window scheduling without changing background-tab semantics."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from browser_core.cdp import evaluate_page_expression, temporary_startup_page
from browser_core.launcher import EvaluationLaunch, launch_evaluation
from browser_core.lifecycle import stop_session


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--persona', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error('use a fresh output path')
    rows = []
    expression = '({hidden:document.hidden,visibility:document.visibilityState})'
    for headless in (False, True):
        path = None
        row = {'headless': headless}
        try:
            path, session = launch_evaluation(EvaluationLaunch(
                args.workspace/'chromium/src/out/BrowserCore/chrome.exe', args.workspace,
                persona_id=args.persona, headless=headless, trace_mode='off', timeout_seconds=30,
            ), ROOT)
            endpoint = session['automation']['cdp_endpoint']
            startup = session['automation']['managed_target_url']
            with TemporaryDirectory(prefix='browser-core-startup-') as folder:
                fixture = Path(folder).resolve()/'profile.html'
                fixture.write_text('<!doctype html><title>Owned background tab</title>', encoding='utf-8')
                with temporary_startup_page(endpoint, fixture) as background:
                    row['foreground'] = evaluate_page_expression(endpoint, expression, target_url=startup)
                    row['background'] = evaluate_page_expression(endpoint, expression, target_url=background)
            row['after_close'] = evaluate_page_expression(endpoint, expression, target_url=startup)
            row['passed'] = (
                row['foreground'] == row['after_close'] == {'hidden': False, 'visibility': 'visible'}
                and row['background'] == {'hidden': True, 'visibility': 'hidden'}
            )
        except Exception as error:
            row.update(passed=False, error_type=type(error).__name__)
        finally:
            if path:
                row['cleanup'] = stop_session(path, timeout_seconds=40)['state']
        rows.append(row)
        print(json.dumps(row), flush=True)
    report = {'schema': 'browser-core.research-visibility/1', 'runs': rows,
              'passed': all(row['passed'] for row in rows)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
