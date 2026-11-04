"""Run a control-subtracted offline observation of saved product scripts.

Drives the full lab flow in one command: an empty-script control arm, one arm per
saved script, control subtraction for each, and a pairwise surface comparison.

The comparison is the point. One arm tells you what a script touched; repeated arms
tell you whether that surface is *stable*, and arms across rolls tell you whether the
collector changed or only its encoding did.

    python scripts/run_product_script_observation.py `
      --script <pin.js> --label pin `
      --script <prev-roll.js> --label prev `
      --executable H:\\bc\\chromium\\src\\out\\BrowserCore\\chrome.exe `
      --trace-processor H:\\bc\\chromium\\src\\out\\BrowserCore\\trace_processor_shell.exe `
      --workspace H:\\bc --out H:\\bc\\observations\\run-001

Offline replay of stored artifacts. Not a live product session, and not an
acceptance, bypass, or bot-score claim.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from browser_core.contracts import ContractError  # noqa: E402
from browser_core.control_files import publish_bytes_exclusive  # noqa: E402
from browser_core.owned_paths import directory_identity  # noqa: E402
from browser_core.product_observation import (  # noqa: E402
    DOM_PROFILES,
    HOOK_MODES,
    INPUT_PROFILES,
    MAX_METHOD_SOURCE_BYTES,
    MAX_PRODUCT_SCRIPT_BYTES,
    ProductScriptObservation,
    _read_stable_regular_bytes,
    _sanitize_script_execution_summary,
    _sanitize_source_provenance,
    _sanitize_startup_document,
    build_ready_probe,
    classify_product_script,
    compare_surfaces,
    grade_script_source_provenance,
    run_product_script_observation,
    validate_product_script_observation_config,
    build_repeated_surface_baseline,
    subtract_control,
    suggest_driver,
    write_observation,
)
from browser_core.trace_scopes import TRACE_SCOPES  # noqa: E402

CONTROL_SOURCE = b"/* browser-core control arm: no behaviour */\n"


def _source_provenance_summary(subtractions: list[dict]) -> dict[str, dict]:
    """Project source pins into a path-free run-level reviewer index."""
    result: dict[str, dict] = {}
    for subtraction in subtractions:
        label = subtraction.get("arm_label")
        if not isinstance(label, str):
            continue
        source = _sanitize_source_provenance(
            subtraction.get("source_provenance")
        )
        if source.get("status") != "not_supplied":
            result[label] = source
    return result


def _trace_health_summary(documents: list[dict]) -> dict[str, object]:
    """Aggregate path-free shutdown/flush receipts across every attempted arm."""
    shutdown_modes: Counter[str] = Counter()
    flush_statuses: Counter[str] = Counter()
    budget_statuses: Counter[str] = Counter()
    budget_overruns: Counter[str] = Counter()
    for document in documents:
        shutdown = document.get("browser_shutdown")
        if isinstance(shutdown, dict) and shutdown.get("mode") in {
            "graceful",
            "forced",
            "exited-before-force",
        }:
            shutdown_modes[shutdown["mode"]] += 1
        flush = document.get("trace_flush")
        if isinstance(flush, dict) and flush.get("status") in {
            "settled",
            "missing",
            "present-unsettled",
        }:
            flush_statuses[flush["status"]] += 1
        budget = document.get("trace_export_budget")
        if isinstance(budget, dict) and isinstance(budget.get("within_budget"), bool):
            budget_statuses[
                "within" if budget["within_budget"] else "over"
            ] += 1
            if budget.get("bytes_within_budget") is False:
                budget_overruns["source_bytes"] += 1
            if budget.get("events_within_budget") is False:
                budget_overruns["exportable_events"] += 1
    total = len(documents)
    return {
        "attempted_arms_including_control": total,
        "shutdown_modes": dict(sorted(shutdown_modes.items())),
        "trace_flush_statuses": dict(sorted(flush_statuses.items())),
        "trace_export_budget_statuses": dict(sorted(budget_statuses.items())),
        "trace_export_budget_overruns": dict(sorted(budget_overruns.items())),
        "missing_shutdown_receipts": total - sum(shutdown_modes.values()),
        "missing_trace_flush_receipts": total - sum(flush_statuses.values()),
        "missing_trace_export_budget_receipts": total - sum(budget_statuses.values()),
    }


def _diagnostic_script_execution(document: dict) -> dict[str, object] | None:
    """Project only the closed native execution receipt from a failed arm."""
    analysis = document.get("diagnostic_trace_analysis")
    value = analysis.get("script_execution") if isinstance(analysis, dict) else None
    return _sanitize_script_execution_summary(
        value, label="failed-arm diagnostic"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", type=Path, action="append", required=True)
    parser.add_argument("--label", action="append", required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--trace-processor", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--captures-root",
        type=Path,
        default=None,
        help="capture tree used to resolve each sample's real origin; binds a "
        "provenance verdict into every arm so a free-text --label cannot travel "
        "downstream unchecked",
    )
    parser.add_argument(
        "--source-url",
        help=(
            "public URL the saved bytes were fetched from; use with "
            "--source-retrieved-at and --source-sha256 to bind a non-capture pin"
        ),
    )
    parser.add_argument(
        "--source-retrieved-at",
        help="timezone-aware ISO 8601 retrieval time for --source-url",
    )
    parser.add_argument(
        "--source-sha256",
        help=(
            "full expected artifact SHA-256 for either public-URL or Git-input "
            "provenance; verified before launch"
        ),
    )
    parser.add_argument(
        "--source-git-checkout",
        type=Path,
        help="clean local checkout containing a generated or tracked public artifact",
    )
    parser.add_argument(
        "--source-git-repository-url",
        help="public HTTP(S) origin URL expected for --source-git-checkout",
    )
    parser.add_argument(
        "--source-git-revision",
        help="full 40-character HEAD commit expected for --source-git-checkout",
    )
    parser.add_argument(
        "--source-build-recipe",
        type=Path,
        help=(
            "tracked build recipe inside --source-git-checkout; the grade binds "
            "its digest but does not claim an independent rebuild"
        ),
    )
    parser.add_argument(
        "--source-rebuild-checkout",
        type=Path,
        help=(
            "optional distinct clean checkout at the same origin/revision used "
            "for a byte-for-byte artifact match; this does not prove build execution"
        ),
    )
    parser.add_argument(
        "--source-rebuild-artifact",
        type=Path,
        help=(
            "artifact inside --source-rebuild-checkout; must occupy the same "
            "repository-relative path and match the observed bytes"
        ),
    )
    parser.add_argument("--dwell-seconds", type=float, default=20.0)
    parser.add_argument(
        "--trace-scope",
        choices=tuple(TRACE_SCOPES),
        default="broad",
        help=(
            "broad records generated binding/API surface; causal records the "
            "much smaller native execution/network plane; causal-stream adds "
            "native stream boundaries; encoding records debug plus only the "
            "generated TextEncoder/TextDecoder family. Measured on Anubis pure-JS: broad "
            "retained 25 arm-only + 4 elevated names and normalized to 117.7 MB; "
            "causal retained only two fetch names and normalized to 5.7 KB"
        ),
    )
    parser.add_argument("--headless", action="store_true")
    parser.add_argument(
        "--dom-profile",
        choices=tuple(sorted(DOM_PROFILES)),
        default="minimal",
        help="host document richness; run both to separate script behaviour from page effects",
    )
    parser.add_argument(
        "--script-path",
        default="/product-script.js",
        help=(
            "path each sample is served from; the collector reads its own script src, "
            "so this can mirror a real deployment's path"
        ),
    )
    parser.add_argument(
        "--declared-script-url",
        help=(
            "original HTTPS script URL represented by a non-executing data-block "
            "element. Use for loaders that validate their source hostname; the "
            "saved bytes still load from loopback and the URL is never fetched"
        ),
    )
    prelude_group = parser.add_mutually_exclusive_group()
    prelude_group.add_argument(
        "--prelude",
        help=(
            "JavaScript run after the synthetic DOM exists and before the sample "
            "loads, on both control and sample pages. Use for documented globals "
            "such as ddoptions; artifacts retain only its byte count and digest"
        ),
    )
    prelude_group.add_argument(
        "--prelude-file",
        type=Path,
        help=(
            "read the pre-load JavaScript from a UTF-8 file instead of exposing "
            "it in the process command line; artifacts still retain only bytes "
            "and digest"
        ),
    )
    parser.add_argument(
        "--hook-mode",
        choices=HOOK_MODES,
        default="off",
        help=(
            "active argument instrumentation: off is passive; inert adds the "
            "same hook tag with no wrappers; on wraps selected built-ins. Compare "
            "on against inert before trusting captured arguments"
        ),
    )
    parser.add_argument(
        "--hook-target",
        action="append",
        default=[],
        metavar="NAME",
        help="instrument only this named hook target; repeatable, empty means all",
    )
    parser.add_argument(
        "--input-profile",
        choices=INPUT_PROFILES,
        default="none",
        help="none leaves input untouched; probe delivers a bounded trusted-input control",
    )
    parser.add_argument(
        "--no-resource-intents",
        action="store_false",
        dest="capture_resource_intents",
        help=(
            "disable the passive redacted CDP DOM resource inventory; intended "
            "only for an observer-effect control run"
        ),
    )
    parser.add_argument(
        "--reloads",
        type=int,
        default=0,
        help="extra page loads per arm, giving warm self-set cookie/storage state",
    )
    parser.add_argument(
        "--allow-unrecognised-script",
        action="store_true",
        help="run even if a --script does not look like a built anti-bot script",
    )
    parser.add_argument(
        "--stage",
        action="append",
        default=[],
        metavar="PATH_PREFIX=FILE",
        help=(
            "serve a saved second-stage script at the path the client fetches it "
            "from, e.g. /tenant-guid/=ips.js. A collector that arrives in more "
            "than one piece cannot start without this, and reports a surface "
            "anyway"
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=60.0,
        help=(
            "per-CDP-command budget in (0, 300]. Raise it for a collector that blocks the main "
            "thread: Kasada's interrogation stage holds it for about 102 seconds on "
            "this host, so a readback on the 60 second default queues behind the "
            "solve and times out, and the arm reports a failed probe rather than a "
            "surface"
        ),
    )
    parser.add_argument(
        "--browser-arg",
        action="append",
        default=[],
        metavar="FLAG",
        help=(
            "extra Chromium flag, repeatable, recorded in every arm. The module "
            "has carried this field for method controls since headed/headless "
            "surface differences turned up, and the runner could not set it. "
            "Measured 2026-08-08: retained driven Kasada arms complete headless "
            "in 110.8-113.4 seconds; a headed GPU-enabled arm did not complete "
            "while headed --disable-gpu reported ready in 99.7 seconds, so the "
            "GPU choice must be explicit and this option is how to test it"
        ),
    )
    parser.add_argument(
        "--await-ready-seconds",
        type=float,
        default=0.0,
        help=(
            "poll for the collector to report ready instead of sleeping the dwell, "
            "up to this cap, and record why the arm stopped. A dwell cannot tell "
            "you whether what it waited for happened: 20 and 150 second dwells "
            "produced byte-identical counts on a driven Kasada arm"
        ),
    )
    ready_group = parser.add_mutually_exclusive_group()
    ready_group.add_argument(
        "--ready-expression",
        help=(
            "vendor-specific boolean expression polled after the driver, e.g. "
            "window.__collector_done === true. Only readiness is retained; the "
            "expression must not return a token"
        ),
    )
    ready_group.add_argument(
        "--ready-expression-file",
        type=Path,
        help=(
            "read the readiness expression from a bounded UTF-8 file; prefer "
            "this when shell quoting could alter quotes or operators"
        ),
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        metavar="N",
        help=(
            "run each script N times with suffixed labels and report the measured "
            "noise floor. Rerun stability is vendor-specific -- Akamai, Kasada and "
            "PerimeterX drift 0 while Shape drifts 9-11 -- so a single arm cannot "
            "tell a real change from that vendor's own jitter"
        ),
    )
    parser.add_argument(
        "--inline-script",
        action="store_true",
        help=(
            "embed the sample in the page instead of linking it. A collector that "
            "shipped inline never had a script URL, and several read "
            "document.currentScript; Shape's Nordstrom deployment is one 247,795 "
            "byte inline script that reads it six times"
        ),
    )
    driver_group = parser.add_mutually_exclusive_group()
    driver_group.add_argument(
        "--driver",
        help=(
            "JavaScript evaluated once after load to perform the host page's "
            "role, e.g. the client's documented entry point. A collector that "
            "waits to be driven cannot be observed by a page that never drives it"
        ),
    )
    parser.add_argument(
        "--retry-failed",
        type=int,
        default=0,
        metavar="N",
        help=(
            "retry a planned arm up to N times when trace export fails. Each retry "
            "uses a distinct label and artifact; failed attempts remain auditable. "
            "This is opt-in because a retry spends another browser launch"
        ),
    )
    driver_group.add_argument(
        "--driver-file",
        type=Path,
        help=(
            "read host-driver JavaScript from a bounded UTF-8 file instead of "
            "placing it in the process command line"
        ),
    )
    args = parser.parse_args(argv)

    def method_source(inline: str | None, path: Path | None, role: str) -> str | None:
        if path is None:
            return inline
        try:
            payload = _read_stable_regular_bytes(
                path,
                maximum=MAX_METHOD_SOURCE_BYTES,
                label=f"{role} source",
            )
        except ContractError as exc:
            parser.error(str(exc))
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            parser.error(f"--{role}-file must be valid UTF-8")
        raise AssertionError("argparse.error did not exit")  # pragma: no cover

    prelude_source = method_source(args.prelude, args.prelude_file, "prelude")
    driver_source = method_source(args.driver, args.driver_file, "driver")
    ready_expression_source = method_source(
        args.ready_expression, args.ready_expression_file, "ready-expression"
    )
    if ready_expression_source is not None:
        # Validate syntax-wrapper bounds before creating output or launching the
        # control. Shell-mutated expressions still become a measured no-signal at
        # runtime, but oversized/empty files are configuration errors.
        build_ready_probe(ready_expression_source)

    stage_routes = []
    for item in args.stage:
        prefix, _, filename = item.partition("=")
        if not prefix.startswith("/") or not filename:
            parser.error(f"--stage must look like /path/prefix=file.js: {item!r}")
        stage = Path(filename)
        if not stage.is_file():
            parser.error(f"--stage file does not exist: {stage}")
        stage_routes.append((prefix, stage))
    stage_routes_tuple = tuple(stage_routes)

    if len(args.script) != len(args.label):
        parser.error("--script and --label must be given the same number of times")
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if args.retry_failed < 0:
        parser.error("--retry-failed must be non-negative")
    if any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", label)
        for label in args.label
    ):
        parser.error(
            "--label must be a 1-128 character identifier using only letters, "
            "digits, dot, underscore, or hyphen"
        )
    if "control" in args.label:
        parser.error("--label control is reserved for the matched control arm")
    if len(set(args.label)) != len(args.label):
        parser.error("--label values must be unique")

    # Expand and validate the entire artifact namespace before creating output or
    # spending a browser launch. Retry labels share the same directory as planned
    # arms, so a user label such as ``pin-retry1`` must not be allowed to collide
    # with the retry of ``pin``.
    plan: list[tuple[Path, str, str]] = []
    for script, label in zip(args.script, args.label):
        if args.repeat == 1:
            plan.append((script, label, label))
        else:
            for index in range(1, args.repeat + 1):
                plan.append((script, f"{label}-r{index}", label))
    artifact_labels = ["control"]
    for _script, label, _group in plan:
        artifact_labels.extend(
            label if attempt == 0 else f"{label}-retry{attempt}"
            for attempt in range(args.retry_failed + 1)
        )
    if any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", label)
        for label in artifact_labels
    ):
        parser.error("expanded repeat/retry labels exceed the safe label contract")
    if len(set(artifact_labels)) != len(artifact_labels):
        parser.error("expanded repeat/retry labels must be unique")
    public_source_fields = (
        args.source_url,
        args.source_retrieved_at,
        args.source_sha256,
    )
    git_source_fields = (
        args.source_git_checkout,
        args.source_git_repository_url,
        args.source_git_revision,
        args.source_build_recipe,
        args.source_sha256,
    )
    public_source_selected = bool(args.source_url or args.source_retrieved_at)
    git_source_selected = bool(
        args.source_git_checkout
        or args.source_git_repository_url
        or args.source_git_revision
        or args.source_build_recipe
        or args.source_rebuild_checkout
        or args.source_rebuild_artifact
    )
    if public_source_selected and git_source_selected:
        parser.error("public URL and Git-input source provenance are mutually exclusive")
    if public_source_selected and not all(public_source_fields):
        parser.error(
            "--source-url, --source-retrieved-at, and --source-sha256 must be given together"
        )
    if git_source_selected and not all(git_source_fields):
        parser.error(
            "--source-git-checkout, --source-git-repository-url, "
            "--source-git-revision, --source-build-recipe, and --source-sha256 "
            "must be given together"
        )
    if bool(args.source_rebuild_checkout) != bool(args.source_rebuild_artifact):
        parser.error(
            "--source-rebuild-checkout and --source-rebuild-artifact must be "
            "given together"
        )
    if args.source_sha256 and not (public_source_selected or git_source_selected):
        parser.error("--source-sha256 requires a public URL or Git-input source")
    if (public_source_selected or git_source_selected) and len(args.script) != 1:
        parser.error("source provenance currently requires exactly one --script")
    if ready_expression_source and args.await_ready_seconds <= 0:
        parser.error("a readiness expression requires --await-ready-seconds")
    if args.hook_target and args.hook_mode == "off":
        parser.error("--hook-target requires --hook-mode on or inert")
    if directory_identity(args.out, label="product observation output") is not None:
        raise ContractError("product observation output directory already exists")

    def observation_config(
        script: Path, label: str, *, bind_source: bool = True
    ) -> ProductScriptObservation:
        return ProductScriptObservation(
            script=script,
            label=label,
            executable=args.executable,
            trace_processor=args.trace_processor,
            workspace=args.workspace,
            dwell_seconds=args.dwell_seconds,
            trace_scope=args.trace_scope,
            headed=not args.headless,
            dom_profile=args.dom_profile,
            script_path=args.script_path,
            declared_script_url=args.declared_script_url,
            prelude_js=prelude_source,
            reloads=args.reloads,
            captures_root=args.captures_root,
            source_url=args.source_url if bind_source else None,
            source_retrieved_at=args.source_retrieved_at if bind_source else None,
            source_sha256=args.source_sha256 if bind_source else None,
            source_git_checkout=args.source_git_checkout if bind_source else None,
            source_git_repository_url=(
                args.source_git_repository_url if bind_source else None
            ),
            source_git_revision=args.source_git_revision if bind_source else None,
            source_build_recipe=args.source_build_recipe if bind_source else None,
            source_rebuild_checkout=(
                args.source_rebuild_checkout if bind_source else None
            ),
            source_rebuild_artifact=(
                args.source_rebuild_artifact if bind_source else None
            ),
            timeout_seconds=args.timeout_seconds,
            extra_browser_args=tuple(args.browser_arg),
            hook_mode=args.hook_mode,
            hook_target_names=tuple(args.hook_target),
            input_profile=args.input_profile,
            capture_resource_intents=args.capture_resource_intents,
            stage_routes=stage_routes_tuple,
            driver_js=driver_source,
            await_ready_seconds=args.await_ready_seconds,
            ready_expression=ready_expression_source if bind_source else None,
            inline_script=args.inline_script,
        )

    # Fail before creating output or spending browser launches on a mislabelled
    # capture, malformed timestamp, or mismatched public digest.
    for script, label in zip(args.script, args.label):
        config = observation_config(script, label)
        validate_product_script_observation_config(config)
        payload = _read_stable_regular_bytes(
            script,
            maximum=MAX_PRODUCT_SCRIPT_BYTES,
            label="product script",
        )
        verdict = classify_product_script(payload)
        if not verdict["looks_like_built_antibot_script"]:
            message = (
                f"{label}: {script.name} does not look like a built anti-bot script "
                f"({'; '.join(verdict['reasons'])})"
            )
            if not args.allow_unrecognised_script:
                raise ContractError(message + " -- pass --allow-unrecognised-script to override")
            print(f"WARNING {message}", file=sys.stderr)
        if public_source_selected or git_source_selected:
            grade_script_source_provenance(config, payload)

    args.out.mkdir(parents=True, exist_ok=False)
    output_identity = directory_identity(
        args.out, label="product observation output"
    )
    if output_identity is None:
        raise ContractError("product observation output directory was not created")

    def observe(
        script: Path, label: str, *, bind_source: bool = True
    ) -> tuple[Path, dict]:
        document = run_product_script_observation(
            observation_config(script, label, bind_source=bind_source),
            ROOT,
        )
        path = write_observation(args.out / f"arm-{label}.json", document)
        return path, document

    control_path = args.out / "control-source.js"
    publish_bytes_exclusive(
        control_path,
        CONTROL_SOURCE,
        maximum=len(CONTROL_SOURCE),
        label="product observation control source",
    )
    print("running control arm ...", file=sys.stderr)
    _, control = observe(control_path, "control", bind_source=False)
    if control.get("error"):
        raise ContractError(f"control arm failed: {control['error']}")
    trace_health_documents = [control]

    subtractions = []
    by_group: dict[str, list[dict]] = {}
    failed_arms: list[dict[str, object]] = []
    failed_attempts: list[dict[str, object]] = []
    recovered_arms: dict[str, str] = {}
    for script, label, group in plan:
        arm = None
        successful_label = label
        last_error_kind = "unknown"
        last_diagnostic_script_execution = None
        attempts = 0
        for attempt in range(args.retry_failed + 1):
            attempt_label = label if attempt == 0 else f"{label}-retry{attempt}"
            print(f"running arm {attempt_label} ...", file=sys.stderr)
            _, candidate = observe(script, attempt_label)
            trace_health_documents.append(candidate)
            attempts += 1
            if not candidate.get("error"):
                arm = candidate
                successful_label = attempt_label
                if attempt:
                    recovered_arms[label] = attempt_label
                break
            last_error_kind = str(candidate["error"]).split(":", 1)[0][:120]
            last_diagnostic_script_execution = _diagnostic_script_execution(candidate)
            failed_attempt = {
                "planned_label": label,
                "attempt_label": attempt_label,
                "group": group,
                "attempt": attempt + 1,
                "error_kind": last_error_kind,
            }
            if last_diagnostic_script_execution is not None:
                failed_attempt["diagnostic_script_execution"] = (
                    last_diagnostic_script_execution
                )
            failed_attempts.append(failed_attempt)
            diagnostic_flag = ""
            if (
                last_diagnostic_script_execution is not None
                and last_diagnostic_script_execution["open"] > 0
            ):
                diagnostic_flag = (
                    " [SCRIPT EXECUTION OPEN: "
                    f"{last_diagnostic_script_execution['open']}]"
                )
            print(
                f"WARNING arm {attempt_label} failed{diagnostic_flag}: "
                f"{candidate['error']}",
                file=sys.stderr,
            )
            retryable = last_error_kind == "trace export failed"
            if attempt < args.retry_failed and retryable:
                print(
                    f"retrying planned arm {label} after trace-export failure ...",
                    file=sys.stderr,
                )
                continue
            break
        if arm is None:
            failed = {
                "label": label,
                "group": group,
                "error_kind": last_error_kind,
            }
            if attempts > 1:
                failed["attempts"] = attempts
            if last_diagnostic_script_execution is not None:
                failed["diagnostic_script_execution"] = (
                    last_diagnostic_script_execution
                )
            failed_arms.append(failed)
            continue
        # Say it here, not only in the JSON. A collector fetching its own next
        # stage gets an empty 200 and fails quietly further on, and these paths
        # are the --stage arguments a fuller observation needs.
        unserved = arm.get("unserved_requests") or {}
        if unserved.get("count"):
            print(
                f"NOTE  arm {label} requested {unserved['count']} path(s) this "
                f"rehost had no bytes for:",
                file=sys.stderr,
            )
            for path in unserved["paths"]:
                print(f"        --stage {path}=<saved-file.js>", file=sys.stderr)
        started = (arm.get("collector_startup") or {}).get("started")
        if started is False:
            reasons = "; ".join((arm.get("collector_startup") or {}).get("reasons", []))
            print(f"NOTE  arm {label} collector did not start: {reasons}", file=sys.stderr)
            entry = suggest_driver(arm.get("startup"))
            if entry and not driver_source:
                print(
                    "        this vendor is host-driven; its measured entry point is:",
                    file=sys.stderr,
                )
                print(
                    f"        --driver \"(() => {{ {entry}; return 'ok'; }})()\"",
                    file=sys.stderr,
                )
        subtraction = subtract_control(arm, control)
        write_observation(
            args.out / f"subtraction-{successful_label}.json", subtraction
        )
        subtractions.append(subtraction)
        by_group.setdefault(group, []).append(subtraction)
        flag = "" if subtraction["clean_subtraction"] else "  [DIRTY CONTROL]"
        if not subtraction.get(
            "ready_probe_comparable", True
        ):
            flag += "  [READINESS PROBE MISMATCH]"
        if subtraction.get("collector_started") is not True:
            flag += "  [COLLECTOR NOT STARTED]"
        if subtraction.get("rehost_dependencies_complete") is not True:
            flag += "  [REHOST DEPENDENCY INCOMPLETE]"
        script_execution = subtraction.get("arm_script_execution") or {}
        open_script_executions = script_execution.get("open")
        if isinstance(open_script_executions, int) and open_script_executions > 0:
            flag += f"  [SCRIPT EXECUTION OPEN: {open_script_executions}]"
        elevated_names = len(subtraction.get("elevated_in_arm") or {})
        generated_workers = (
            ((subtraction.get("arm_execution_context_counts") or {}).get(
                "generated_binding"
            ) or {}).get("worker")
        )
        worker_suffix = (
            f", {generated_workers} generated-binding worker context(s)"
            if isinstance(generated_workers, int)
            else ""
        )
        print(
            f"  {label}: {subtraction['attributed_api_names']} arm-only API names, "
            f"{elevated_names} elevated control-shared names"
            f"{worker_suffix}"
            f"{flag}",
            file=sys.stderr,
        )

    # A repeated group can measure its own noise floor, which is the only honest
    # bar for a later drift check: same script, same settings, arms back to back.
    baselines = {}
    for group, group_subs in by_group.items():
        if len(group_subs) < 2:
            continue
        if not all(
            item.get(
                "surface_claim_ready", item.get("clean_subtraction", False)
            )
            is True
            for item in group_subs
        ):
            baselines[group] = {
                "status": "skipped",
                "reason": "control_readiness_startup_or_dependencies_not_claim_ready",
                "arms": len(group_subs),
            }
            print(
                f"  {group}: baseline skipped because the control, readiness "
                "probe, collector startup, or rehost dependency set is not "
                "claim-ready",
                file=sys.stderr,
            )
            continue
        baseline = build_repeated_surface_baseline(group_subs, label=group)
        write_observation(args.out / f"baseline-{group}.json", baseline)
        baselines[group] = {
            "arms": baseline["arms"],
            "stable_core": baseline["api_name_count"],
            "volatile": len(baseline["volatile_api_names"]),
            "measured_noise_floor": baseline["measured_noise_floor"],
            "pairwise_differences": baseline["pairwise_differences"],
            "request_activity_baseline": baseline["request_activity_baseline"],
        }
        print(
            f"  {group}: stable core {baseline['api_name_count']}, "
            f"{len(baseline['volatile_api_names'])} volatile, "
            f"measured noise floor {baseline['measured_noise_floor']} "
            f"(pairwise {baseline['pairwise_differences']})",
            file=sys.stderr,
        )
        request_floor = baseline["request_activity_baseline"]
        if request_floor.get("status") == "ok" and request_floor.get(
            "variable_shapes"
        ):
            print(
                f"  {group}: request metrics vary on "
                f"{request_floor['variable_shapes']} of "
                f"{request_floor['union_shapes']} redacted shape(s); inspect the "
                "repeat floor before interpreting a cross-method byte delta",
                file=sys.stderr,
            )

    planned_by_group = Counter(group for _script, _label, group in plan)
    failed_by_group: dict[str, list[str]] = {}
    for failed in failed_arms:
        failed_by_group.setdefault(failed["group"], []).append(failed["label"])
    claim_ready_by_group = {
        group: sum(
            item.get("surface_claim_ready", item["clean_subtraction"]) is True
            for item in group_subtractions
        )
        for group, group_subtractions in by_group.items()
    }
    groups = {
        group: {
            "requested": requested,
            "successful": len(by_group.get(group, [])),
            "claim_ready": claim_ready_by_group.get(group, 0),
            "failed": sorted(failed_by_group.get(group, [])),
            # Compatibility: `complete` means every requested process arm ran.
            "complete": len(by_group.get(group, [])) == requested,
            "all_surface_claim_ready": (
                claim_ready_by_group.get(group, 0) == requested
                and len(by_group.get(group, [])) == requested
            ),
        }
        for group, requested in sorted(planned_by_group.items())
    }
    execution_complete = not failed_arms and len(subtractions) == len(plan)
    claim_ready_arms = [
        item["arm_label"]
        for item in subtractions
        if item.get("surface_claim_ready", item["clean_subtraction"]) is True
    ]
    not_claim_ready_arms = [
        item["arm_label"]
        for item in subtractions
        if item.get("surface_claim_ready", item["clean_subtraction"]) is not True
    ]
    summary = {
        "schema": "browser-core.product-script-observation-run/1",
        "repeat": args.repeat,
        "retry_failed": args.retry_failed,
        # Compatibility: `complete` is process-execution completion, not evidence
        # readiness. The explicit fields below keep those contracts distinct.
        "complete": execution_complete,
        "execution_complete": execution_complete,
        "all_surface_claim_ready": (
            execution_complete and len(claim_ready_arms) == len(plan)
        ),
        "claim_ready_arms": claim_ready_arms,
        "not_claim_ready_arms": not_claim_ready_arms,
        "planned_arms": [label for _script, label, _group in plan],
        "successful_arms": len(subtractions),
        "failed_arms": failed_arms,
        "failed_attempts": failed_attempts,
        "recovered_arms": recovered_arms,
        "trace_health": _trace_health_summary(trace_health_documents),
        "groups": groups,
        "baselines": baselines,
        "control_label": control["label"],
        "arms": [s["arm_label"] for s in subtractions],
        "attributed_api_names": {
            s["arm_label"]: s["attributed_api_names"] for s in subtractions
        },
        # `attributed_api_names` is the historical arm-only count. High-rate
        # collectors can also amplify names already present in the empty control;
        # surface-only summaries hid those. Keep the compatibility field and make
        # both parts explicit rather than silently changing its meaning.
        "arm_only_api_names": {
            s["arm_label"]: s["attributed_api_names"] for s in subtractions
        },
        "elevated_api_names": {
            s["arm_label"]: len(s.get("elevated_in_arm") or {})
            for s in subtractions
        },
        "total_distinguishing_api_names": {
            s["arm_label"]: (
                s["attributed_api_names"] + len(s.get("elevated_in_arm") or {})
            )
            for s in subtractions
        },
        "execution_context_counts": {
            s["arm_label"]: s["arm_execution_context_counts"]
            for s in subtractions
            if isinstance(s.get("arm_execution_context_counts"), dict)
        },
        "script_execution": {
            s["arm_label"]: s["arm_script_execution"]
            for s in subtractions
            if isinstance(s.get("arm_script_execution"), dict)
        },
        "collector_startup": {
            s["arm_label"]: _sanitize_startup_document(s["collector_startup"])
            for s in subtractions
            if isinstance(s.get("collector_startup"), dict)
        },
        "clean_subtraction": {
            s["arm_label"]: s["clean_subtraction"] for s in subtractions
        },
        "rehost_dependencies_complete": {
            s["arm_label"]: s.get("rehost_dependencies_complete")
            for s in subtractions
        },
        "surface_claim_ready": {
            s["arm_label"]: (
                s.get("surface_claim_ready", s["clean_subtraction"]) is True
            )
            for s in subtractions
        },
        "non_claims": [
            "offline replay of stored artifacts; not a live product session",
            "no acceptance, bypass, evasion, or bot-score claim",
        ],
    }
    source_provenance = _source_provenance_summary(subtractions)
    if source_provenance:
        summary["source_provenance"] = source_provenance
    if len(subtractions) >= 2:
        summary["comparison"] = compare_surfaces(subtractions)
        write_observation(args.out / "comparison.json", summary["comparison"])

    write_observation(args.out / "summary.json", summary)
    if directory_identity(
        args.out, label="product observation output"
    ) != output_identity:
        raise ContractError("product observation output directory changed during the run")
    print(json.dumps(summary, indent=2, sort_keys=True))
    # A partial batch is still useful evidence and is therefore written, but it
    # cannot satisfy a requested repeat gate. Non-zero prevents shell pipelines
    # and overnight jobs from silently treating one surviving arm as completion.
    return 2 if failed_arms else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as exc:
        print(f"run_product_script_observation: {exc}", file=sys.stderr)
        raise SystemExit(2)
