"""Run the observable-surface diff against branded Google Chrome, by hand.

The grading logic lives in ``browser_core.surface_diff`` so that the allowlist is
locked by tests that run without a browser, and so this script and the pytest
gate cannot drift apart. This is the operator entry point; the gate is
``tests/test_surface_diff.py``.

    python scripts/diff_against_branded_chrome.py \
        --core H:/bc/chromium/src/out/BrowserCore/chrome.exe \
        --branded "C:/Program Files/Google/Chrome/Application/chrome.exe"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from browser_core.errors import ContractError, safe_failure_receipt
from browser_core.surface_diff import diff_against_branded_chrome, render_surface_diff

DEFAULT_BRANDED = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")


def _default_core() -> Path | None:
    workspace = os.environ.get("BROWSER_CORE_WORKSPACE")
    if not workspace:
        return None
    return Path(workspace) / "chromium" / "src" / "out" / "BrowserCore" / "chrome.exe"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, default=_default_core())
    parser.add_argument("--branded", type=Path, default=DEFAULT_BRANDED)
    parser.add_argument("--json", action="store_true", help="emit the report instead of a summary")
    args = parser.parse_args(argv)

    if args.core is None:
        parser.error("pass --core or set BROWSER_CORE_WORKSPACE")

    try:
        report = diff_against_branded_chrome(args.core, args.branded)
    except ContractError as exc:
        print(f"surface diff refused: {safe_failure_receipt(exc)}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2) if args.json else render_surface_diff(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
