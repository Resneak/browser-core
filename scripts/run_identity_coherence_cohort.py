#!/usr/bin/env python3
"""Multi-persona identity evaluation + optional primary Browser Core coherence."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from browser_core.kernels import (  # noqa: E402
    device_from_playwright,
    discover_kernels,
    probe_playwright_kernel,
)
from browser_core.contracts import ContractError, RUN_ID_RE  # noqa: E402
from browser_core.control_files import (  # noqa: E402
    decode_strict_json_bytes,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
)
from browser_core.launcher import EvaluationLaunch, launch_evaluation  # noqa: E402
from browser_core.lifecycle import (  # noqa: E402
    stop_session,
    validate_stopped_session_receipt,
)
from browser_core.owned_paths import directory_identity  # noqa: E402
from browser_core.personas import list_personas  # noqa: E402
from browser_core.profiles import PROFILE_ID_RE  # noqa: E402

from browser_eval.identity import evaluate_expected_against_observed  # noqa: E402
from browser_eval.models import collector_check_counts_consistent  # noqa: E402
from browser_eval.redact import redact_obj  # noqa: E402
from browser_eval.registry import load_registry, select_specs  # noqa: E402
from browser_eval.runner import RunConfig, execute_run  # noqa: E402


EVAL_ROOT = ROOT.parent / "browser-eval"
MAX_COHORT_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_COHORT_PERSONAS = 256
_DIGEST_16_RE = re.compile(r"^[0-9a-f]{16}$")


def _strict_json_file(path: Path, *, label: str) -> dict[str, Any]:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_COHORT_DOCUMENT_BYTES,
        label=label,
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")

    try:
        document = decode_strict_json_bytes(snapshot.body, label=label)
    except ContractError:
        raise ContractError(f"{label} is not strict JSON") from None
    if not isinstance(document, dict):
        raise ContractError(f"{label} must be a JSON object")
    return document


def _run_controlled_evaluation(output: Path) -> tuple[Path, dict[str, Any]]:
    specs = select_specs(
        load_registry(EVAL_ROOT / "browser_eval" / "data" / "evaluators.json"),
        "controlled_coherence",
    )
    return execute_run(
        specs,
        RunConfig(
            backend="external-cdp",
            channel="chromium",
            headless=False,
            profile=None,
            screenshots=False,
            out=output,
            timeout_ms=90_000,
        ),
    )


def _metric_count(metrics: dict[str, Any], key: str) -> int:
    value = metrics.get(key)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 1_000_000
    ):
        raise ContractError("identity cohort evaluator metrics are invalid")
    return value


def _metric_digest(metrics: dict[str, Any], key: str) -> str:
    value = metrics.get(key)
    if not isinstance(value, str) or _DIGEST_16_RE.fullmatch(value) is None:
        raise ContractError("identity cohort evaluator metrics are invalid")
    return value


def _cohort_count(item: dict[str, Any], key: str) -> int:
    value = item.get(key)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 1_000_000
    ):
        raise ContractError("identity cohort persona result is invalid")
    return value


def _controlled_summary_receipt(
    summary: dict[str, Any],
    *,
    expected_vector: dict[str, Any],
) -> dict[str, Any]:
    run_id = summary.get("run_id")
    evaluators = summary.get("evaluators")
    if (
        summary.get("schema_version") != 1
        or summary.get("kind") != "browser_eval_summary"
        or not isinstance(run_id, str)
        or RUN_ID_RE.fullmatch(run_id) is None
        or not isinstance(evaluators, list)
        or len(evaluators) != 1
        or not isinstance(evaluators[0], dict)
    ):
        raise ContractError("identity cohort evaluator summary is invalid")
    evaluator = evaluators[0]
    signals = evaluator.get("signals")
    if (
        evaluator.get("id") != "controlled_coherence"
        or evaluator.get("status") != "ok"
        or evaluator.get("verdict") not in {"pass", "fail"}
        or not isinstance(signals, dict)
    ):
        raise ContractError("identity cohort controlled summary is invalid")
    counts: dict[str, int] = {}
    for key in ("completed", "failed", "total"):
        value = summary.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1:
            raise ContractError("identity cohort evaluator summary counts are invalid")
        counts[key] = value
    if counts != {"completed": 1, "failed": 0, "total": 1}:
        raise ContractError("identity cohort evaluator summary counts are inconsistent")
    if any(signals.get(key) != value for key, value in expected_vector.items()):
        raise ContractError("identity cohort summary and evaluator result disagree")
    if evaluator["verdict"] == "pass" and any(
        expected_vector[key] != 0
        for key in ("failed_checks", "identity_failed_claims", "identity_unavailable_claims")
    ):
        raise ContractError("identity cohort pass verdict contradicts evaluator signals")
    return {
        "schema_version": 1,
        "kind": "browser_eval_summary",
        "run_id": run_id,
        "status": "ok",
        "verdict": evaluator["verdict"],
        **counts,
    }


def _probe_flat(observed: dict[str, Any]) -> dict[str, Any]:
    flat: dict[str, Any] = {
        "window.locale": observed["language"],
        "window.languages": observed["languages"],
        "window.platform": observed["platform"],
        "window.maxTouchPoints": observed["maxTouchPoints"],
        "window.hardwareConcurrency": observed["hardwareConcurrency"],
        "window.pluginsLength": observed["pluginsLength"],
        "window.mimeTypesLength": observed["mimeTypesLength"],
        "window.screen.width": observed["screenWidth"],
        "window.screen.height": observed["screenHeight"],
        "window.screen.colorDepth": observed["colorDepth"],
        "window.screen.pixelDepth": observed["pixelDepth"],
        "window.screen.devicePixelRatio": observed["devicePixelRatio"],
        "window.timezone": observed["timezone"],
        "rendering.webgl.vendor": observed["webglVendor"],
        "rendering.webgl.renderer": observed["webglRenderer"],
        "rendering.webgl.version": observed["webglVersion"],
    }
    optional = {
        "window.deviceMemory": observed.get("deviceMemory"),
        "window.pdfViewerEnabled": observed.get("pdfViewerEnabled"),
        "userAgentData.mobile": observed.get("userAgentDataMobile"),
        "userAgentData.platform": observed.get("userAgentDataPlatform"),
    }
    for key, value in optional.items():
        if value is not None:
            flat[key] = value
    return flat


def _source_meta(source: str) -> dict[str, str] | None:
    # kernel-probe:playwright-chromium:pw-desktop-chrome
    if not source.startswith("kernel-probe:"):
        return None
    parts = source.split(":", 2)
    if len(parts) != 3:
        return None
    return {"kernel_id": parts[1], "device_id": parts[2]}


def evaluate_kernel_persona(
    repository_root: Path, persona: dict[str, Any]
) -> dict[str, Any]:
    meta = _source_meta(persona["provenance"]["source"])
    if meta is None:
        return {
            "id": persona["id"],
            "arm": "skip",
            "reason": "not-a-kernel-probe-persona",
            "identity_failed_claims": None,
        }
    kernels = {item["id"]: item for item in discover_kernels(repository_root)}
    kernel = kernels.get(meta["kernel_id"])
    if kernel is None or not kernel.get("available"):
        return {
            "id": persona["id"],
            "arm": "skip",
            "reason": f"kernel-unavailable:{meta['kernel_id']}",
            "identity_failed_claims": None,
        }
    # device id is pw-<safe-name>; recover preset from stored evidence is preferred,
    # but device_from_playwright needs the Playwright name. Parse from device id.
    device_id = meta["device_id"]
    # Evidence includes full device; load from workspace later if needed.
    # For re-probe we use geography + known mapping via evidence file sha.
    return {
        "id": persona["id"],
        "arm": "kernel-pending-evidence",
        "device_id": device_id,
        "kernel_id": meta["kernel_id"],
    }


def evaluate_from_evidence(
    workspace: Path,
    repository_root: Path,
    persona: dict[str, Any],
) -> dict[str, Any]:
    from browser_core.personas import load_persona_evidence

    digest = persona["provenance"]["source_sha256"]
    try:
        evidence = load_persona_evidence(workspace, digest)
    except Exception as exc:  # noqa: BLE001
        return {
            "id": persona["id"],
            "arm": "skip",
            "reason": f"evidence-missing:{type(exc).__name__}",
            "identity_failed_claims": None,
        }

    # Physical android probe shape
    if persona["provenance"]["source"] == "physical-android-owned-probe":
        observed = evidence.get("observed") or {}
        flat = {
            "window.locale": (observed.get("languages") or [None])[0],
            "window.languages": observed.get("languages"),
            "window.platform": observed.get("platform"),
            "window.maxTouchPoints": observed.get("maxTouchPoints"),
            "window.hardwareConcurrency": observed.get("hardwareConcurrency"),
            "window.screen.width": observed.get("screenWidth"),
            "window.screen.height": observed.get("screenHeight"),
            "window.screen.devicePixelRatio": observed.get("devicePixelRatio"),
            "window.timezone": observed.get("timezone"),
            "rendering.webgl.vendor": observed.get("webglVendor"),
            "rendering.webgl.renderer": observed.get("webglRenderer"),
            "rendering.webgl.version": observed.get("webglVersion"),
        }
        flat = {k: v for k, v in flat.items() if v is not None}
        # Historical capture: evaluate stored observation against contract (self-consistency).
        result, findings = evaluate_expected_against_observed(
            persona["identity_contract"]["expected"],
            flat,
        )
        return {
            "id": persona["id"],
            "arm": "physical-android-evidence",
            "realization": "historical-evidence",
            "identity_passed_claims": result["passed_claims"],
            "identity_failed_claims": result["failed_claims"],
            "identity_unavailable_claims": result["unavailable_claims"],
            "findings": findings,
        }

    # Kernel probe evidence: re-run live probe with same device/locale/timezone.
    device = evidence.get("device")
    kernel_doc = evidence.get("kernel")
    if not isinstance(device, dict) or not isinstance(kernel_doc, dict):
        return {
            "id": persona["id"],
            "arm": "skip",
            "reason": "evidence-shape-unexpected",
            "identity_failed_claims": None,
        }
    kernels = {item["id"]: item for item in discover_kernels(repository_root)}
    kernel = kernels.get(kernel_doc["id"])
    if kernel is None or not kernel.get("available"):
        return {
            "id": persona["id"],
            "arm": "skip",
            "reason": f"kernel-unavailable:{kernel_doc.get('id')}",
            "identity_failed_claims": None,
        }
    # Re-bind locale/timezone from persona geography for exact realization.
    live_device = device_from_playwright(
        device["name"],
        locale=persona["geography"]["locale"],
        timezone=persona["geography"]["timezone"],
    )
    probe = probe_playwright_kernel(kernel, live_device)
    if probe.get("passed") is not True:
        return {
            "id": persona["id"],
            "arm": "kernel-live",
            "realization": live_device.get("realization"),
            "probe_passed": False,
            "probe_checks": probe.get("checks"),
            "identity_failed_claims": None,
            "error": "probe-failed",
        }
    flat = _probe_flat(probe["observed"])
    expected = persona["identity_contract"]["expected"]
    # Only evaluate claims present in both expected and live flat (optional UA data may differ).
    # Still require zero failures on overlapping required paths.
    result, findings = evaluate_expected_against_observed(expected, flat)
    return {
        "id": persona["id"],
        "arm": "kernel-live",
        "realization": live_device.get("realization"),
        "probe_passed": True,
        "identity_passed_claims": result["passed_claims"],
        "identity_failed_claims": result["failed_claims"],
        "identity_unavailable_claims": result["unavailable_claims"],
        "findings": findings,
        "claim_fields": result["fields"],
    }


def run_primary_browser_core(
    *,
    workspace: Path,
    executable: Path,
    profile_id: str,
    out_dir: Path,
    repository_root: Path = ROOT,
) -> dict[str, Any]:
    """Launch Browser Core eval session and run controlled_coherence + identity."""
    if not all(
        isinstance(path, Path)
        for path in (workspace, executable, out_dir, repository_root)
    ):
        raise ContractError("identity cohort primary paths must be Paths")
    if not isinstance(profile_id, str) or PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise ContractError("identity cohort profile ID is invalid")
    session_path, session = launch_evaluation(
        EvaluationLaunch(
            executable=executable,
            workspace=workspace,
            profile_id=profile_id,
            trace_mode="off",
            timeout_seconds=180,
        ),
        repository_root,
    )
    eval_out = out_dir / "browser-eval-primary"
    previous_endpoint = os.environ.pop("BROWSER_EVAL_CDP_ENDPOINT", None)
    previous_session = os.environ.get("BROWSER_CORE_SESSION_FILE")
    os.environ["BROWSER_CORE_SESSION_FILE"] = str(session_path)
    try:
        run_dir, returned_summary = _run_controlled_evaluation(eval_out)
        if not isinstance(run_dir, Path):
            raise ContractError("identity cohort evaluator run directory is invalid")
        resolved_run_dir = run_dir.resolve()
        try:
            resolved_run_dir.relative_to(eval_out.resolve())
        except ValueError:
            raise ContractError(
                "identity cohort evaluator run directory escaped its output"
            ) from None
        summary = _strict_json_file(
            resolved_run_dir / "summary.json",
            label="identity cohort evaluator summary",
        )
        if not isinstance(returned_summary, dict):
            raise ContractError("identity cohort evaluator summary changed after evaluation")
        try:
            returned_json = json.dumps(
                redact_obj(returned_summary), sort_keys=True, separators=(",", ":"), allow_nan=False
            )
            saved_json = json.dumps(summary, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            raise ContractError("identity cohort evaluator summary changed after evaluation") from None
        if returned_json != saved_json:
            raise ContractError("identity cohort evaluator summary changed after evaluation")
        evaluator = _strict_json_file(
            resolved_run_dir / "evaluators" / "controlled_coherence.json",
            label="identity cohort evaluator result",
        )
    finally:
        try:
            validate_stopped_session_receipt(
                stop_session(session_path, timeout_seconds=60),
                expected_run_id=session.get("run_id"),
            )
        finally:
            if previous_session is None:
                os.environ.pop("BROWSER_CORE_SESSION_FILE", None)
            else:
                os.environ["BROWSER_CORE_SESSION_FILE"] = previous_session
            if previous_endpoint is not None:
                os.environ["BROWSER_EVAL_CDP_ENDPOINT"] = previous_endpoint

    result: dict[str, Any] = {
        "arm": "browser-core-primary",
        "session_file": str(session_path),
        "eval_exit": 0,
        "run_dir": str(resolved_run_dir),
    }
    metrics = evaluator.get("metrics") or {}
    if not isinstance(metrics, dict):
        raise ContractError("identity cohort evaluator metrics are invalid")
    result["coherence"] = {
        "passed_checks": _metric_count(metrics, "passed_checks"),
        "failed_checks": _metric_count(metrics, "failed_checks"),
        "unavailable_checks": _metric_count(metrics, "unavailable_checks"),
        "collector_checkset_sha256_16": _metric_digest(
            metrics, "collector_checkset_sha256_16"
        ),
    }
    result["identity"] = {
        "identity_passed_claims": _metric_count(metrics, "identity_passed_claims"),
        "identity_failed_claims": _metric_count(metrics, "identity_failed_claims"),
        "identity_unavailable_claims": _metric_count(
            metrics, "identity_unavailable_claims"
        ),
        "identity_contract_sha256_16": _metric_digest(
            metrics, "identity_contract_sha256_16"
        ),
    }
    expected_summary_vector = {
        **result["coherence"],
        **result["identity"],
        "render_fingerprint": _metric_digest(metrics, "render_fingerprint"),
        "surface_fingerprint": _metric_digest(metrics, "surface_fingerprint"),
        "automation_fingerprint": _metric_digest(metrics, "automation_fingerprint"),
    }
    result["summary_receipt"] = _controlled_summary_receipt(
        summary,
        expected_vector=expected_summary_vector,
    )
    checks = metrics.get("checks")
    if (
        not isinstance(checks, dict)
        or not checks
        or len(checks) > 1024
        or any(
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not (value is True or value is False or value is None)
            for key, value in checks.items()
        )
    ):
        raise ContractError("identity cohort evaluator checks are invalid")
    if not collector_check_counts_consistent(metrics):
        raise ContractError("identity cohort evaluator checks are inconsistent")
    result["unavailable_check_ids"] = sorted(
        key for key, value in checks.items() if value is None
    )
    result["failed_check_ids"] = sorted(
        key for key, value in checks.items() if value is False
    )
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--executable", type=Path, default=None)
    parser.add_argument("--profile-id", default="eval-windows-native")
    parser.add_argument("--skip-primary", action="store_true")
    parser.add_argument(
        "--max-personas",
        type=int,
        default=0,
        help="if >0, evaluate at most this many non-primary personas (spread sample)",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if (
        not all(
            isinstance(path, Path)
            for path in (args.workspace, args.repository_root, args.out)
        )
        or (args.executable is not None and not isinstance(args.executable, Path))
        or not isinstance(args.profile_id, str)
        or PROFILE_ID_RE.fullmatch(args.profile_id) is None
        or not isinstance(args.skip_primary, bool)
        or isinstance(args.max_personas, bool)
        or not isinstance(args.max_personas, int)
        or not 0 <= args.max_personas <= MAX_COHORT_PERSONAS
    ):
        raise ContractError("identity cohort controls are invalid")
    workspace = args.workspace.resolve()
    repo = args.repository_root.resolve()
    out = args.out.absolute()
    if directory_identity(out, label="identity cohort output") is not None:
        raise ContractError("identity cohort output directory already exists")
    out.mkdir(parents=True, exist_ok=False)
    out_identity = directory_identity(out, label="identity cohort output")
    if out_identity is None:
        raise ContractError("identity cohort output directory was not created")

    personas = list_personas(workspace)
    if args.max_personas and args.max_personas > 0:
        non_primary = [p for p in personas if p["id"] != "owned-win11-core153"]
        if len(non_primary) > args.max_personas:
            step = max(len(non_primary) // args.max_personas, 1)
            sampled = non_primary[::step][: args.max_personas]
            primary = [p for p in personas if p["id"] == "owned-win11-core153"]
            personas = sampled + primary
    multi = []
    for persona in personas:
        if persona["id"] == "owned-win11-core153":
            multi.append(
                {
                    "id": persona["id"],
                    "arm": "primary-deferred",
                    "identity_failed_claims": None,
                    "note": "evaluated via live Browser Core arm",
                }
            )
            continue
        multi.append(evaluate_from_evidence(workspace, repo, persona))

    report: dict[str, Any] = {
        "schema": "browser-core.identity-coherence-cohort/1",
        "workspace": str(workspace),
        "persona_count": len(personas),
        "multi_persona": multi,
    }

    if not args.skip_primary and args.executable is not None:
        report["primary"] = run_primary_browser_core(
            workspace=workspace,
            executable=args.executable.resolve(),
            profile_id=args.profile_id,
            out_dir=out,
            repository_root=repo,
        )
    else:
        report["primary"] = {
            "arm": "browser-core-primary",
            "skipped": True,
            "reason": "no-executable-or-skip-flag",
        }

    # Aggregate gates
    realized = [
        item for item in multi if item.get("identity_failed_claims") is not None
    ]
    identity_failures = sum(
        _cohort_count(item, "identity_failed_claims") for item in realized
    )
    identity_unavail = sum(
        _cohort_count(item, "identity_unavailable_claims") for item in realized
    )
    primary = report.get("primary") or {}
    coherence = primary.get("coherence") or {}
    primary_identity = primary.get("identity") or {}
    report["gates"] = {
        "multi_persona_realized": len(realized),
        "multi_persona_identity_failures": identity_failures,
        "multi_persona_identity_unavailables": identity_unavail,
        "multi_persona_zero_identity_failures": identity_failures == 0
        and len(realized) >= 4,
        "primary_coherence_failed": coherence.get("failed_checks"),
        "primary_coherence_passed": coherence.get("passed_checks"),
        "primary_coherence_unavailable": coherence.get("unavailable_checks"),
        "primary_identity_failed": primary_identity.get("identity_failed_claims"),
        "primary_identity_passed": primary_identity.get("identity_passed_claims"),
        "primary_coherence_non_regress": (
            coherence.get("failed_checks") == 0
            and isinstance(coherence.get("passed_checks"), int)
            and coherence.get("passed_checks") >= 60
        ),
        "primary_identity_zero_failures": primary_identity.get("identity_failed_claims")
        == 0,
    }
    report["gates"]["cohort_passed"] = bool(
        report["gates"]["multi_persona_zero_identity_failures"]
        and (
            primary.get("skipped")
            or (
                report["gates"]["primary_coherence_non_regress"]
                and report["gates"]["primary_identity_zero_failures"]
            )
        )
    )

    out_path = out / "identity-coherence-cohort.json"
    publication = publish_json_exclusive_result(
        out_path,
        report,
        maximum=MAX_COHORT_DOCUMENT_BYTES,
        label="identity coherence cohort report",
    )
    if directory_identity(out, label="identity cohort output") != out_identity:
        raise ContractError("identity cohort output directory changed")
    sys.stdout.buffer.write(publication.body)
    return 0 if report["gates"]["cohort_passed"] else 2


if __name__ == "__main__":
    try:
        exit_code = main()
    except (ContractError, OSError, RuntimeError, ValueError) as exc:
        print(
            f"identity coherence cohort failed ({type(exc).__name__})",
            file=sys.stderr,
        )
        exit_code = 2
    raise SystemExit(exit_code)
