"""Record a Core lifecycle cohort without discarding attempts or stop receipts.

This is a Core-only workflow measurement, not an equal-work competitor test.
It launches disposable profiles only when explicitly invoked with a workspace
and executable. Each invocation requires a new output directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from browser_core.contracts import reject_sensitive_keys
from browser_core.errors import safe_failure_receipt
from browser_core.multi_identity_ops import run_profile_velocity_batch


def implementation_receipt() -> dict:
    """Bind measurements to controller bytes as well as this harness."""
    paths = [Path(__file__).resolve(), ROOT / "upstream.json"]
    paths.extend((ROOT / "browser_core").rglob("*.py"))
    paths.extend((ROOT / "patches").glob("*.patch"))
    paths.append(ROOT / "patches" / "series.json")
    digests = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sorted(paths)}
    body = json.dumps(digests, sort_keys=True, separators=(",", ":")).encode()
    return {"files": len(digests), "sha256": hashlib.sha256(body).hexdigest(), "digests": digests}


def evidence_document(result: dict, *, batch_seconds: float, source_sha256: str) -> dict:
    """Keep the complete redacted producer receipt, including unsuccessful work."""
    reject_sensitive_keys(result)
    batch = result["ops_batch"]
    timing = batch["timing"]
    measured = (
        timing["all_attempts_ms"] + timing["substitution_cleanup_ms"]
        + timing.get("substitution_selection_ms", 0)
        + timing.get("failed_identity_cleanup_ms", 0)
        + timing.get("teardown_attempts_ms", sum(timing["stop_to_dispose_samples_ms"]))
    )
    return {
        "schema": "browser-core.profile-velocity-measurement/1",
        "source_sha256": source_sha256,
        "browser": "core",
        "mode": "headless",
        "workload": {
            "ready_boundary": "managed launch and persona readiness",
            "trace_mode": "off",
            "lifecycle": "sequential launch; concurrent residency; separate teardown",
            "competitor_comparison": False,
        },
        "batch_seconds": batch_seconds,
        # Includes catalog selection and unmeasured failure cleanup; do not
        # assign the residual to verification without separate phase evidence.
        "outside_recorded_phases_ms": batch_seconds * 1000 - measured,
        "result": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--count", type=int, default=4)
    parser.add_argument("--persona", action="append", default=None)
    args = parser.parse_args()
    # Never overwrite a previous run, including a failed run.
    args.out.mkdir(parents=True, exist_ok=False)
    source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    implementation_before = implementation_receipt()
    started = time.perf_counter()
    try:
        result = run_profile_velocity_batch(
            args.workspace, count=args.count, persona_ids=args.persona,
            ready_mode="launch", executable=args.executable, repository_root=ROOT,
        )
        document = evidence_document(
            result, batch_seconds=time.perf_counter() - started, source_sha256=source_sha256,
        )
        passed = result["functional_batch_passed"]
    except Exception as error:
        document = {
            "schema": "browser-core.profile-velocity-measurement/1",
            "source_sha256": source_sha256, "completed": False,
            "batch_seconds": time.perf_counter() - started,
            "error": safe_failure_receipt(error),
        }
        passed = False
    implementation_after = implementation_receipt()
    document["implementation"] = implementation_before
    document["implementation_unchanged"] = implementation_before == implementation_after
    passed = passed and document["implementation_unchanged"]
    reject_sensitive_keys(document)
    with (args.out / "summary.json").open("x", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"passed": bool(passed), "batch_seconds": document["batch_seconds"]}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
