from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


REPOSITORY = Path(__file__).resolve().parents[3]
CORE_ROOT = REPOSITORY / "general" / "browser-core"
EVAL_ROOT = REPOSITORY / "general" / "browser-eval"
sys.path[:0] = [str(CORE_ROOT), str(EVAL_ROOT)]

from browser_core.build import executable_evidence  # noqa: E402
from browser_core.contracts import ContractError  # noqa: E402
from browser_core.control_files import (  # noqa: E402
    JsonPublicationCursor,
    decode_strict_json_bytes,
    read_bounded_control_snapshot_result,
)
from browser_core.launcher import EvaluationLaunch, launch_evaluation  # noqa: E402
from browser_core.lifecycle import (  # noqa: E402
    stop_session,
    validate_stopped_session_receipt,
)
from browser_core.numeric import is_finite_number  # noqa: E402
from browser_core.owned_paths import directory_identity  # noqa: E402
from browser_core.profiles import PROFILE_ID_RE, load_profile  # noqa: E402
from browser_eval.registry import load_registry, select_specs  # noqa: E402
from browser_eval.redact import redact_obj  # noqa: E402
from browser_eval.runner import RunConfig, execute_run  # noqa: E402


KAMELEO_NAME_PREFIX = "Codex Browser Eval Alternating"
MAX_KAMELEO_REQUEST_BYTES = 1024 * 1024
MAX_KAMELEO_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_KAMELEO_RESPONSE_READ_CALLS = 65_536
MAX_KAMELEO_PATH_CHARACTERS = 4096
MAX_KAMELEO_PROFILE_ID_CHARACTERS = 128
MAX_KAMELEO_COHORT_REPORT_BYTES = 64 * 1024 * 1024
MAX_KAMELEO_TRIALS_PER_ARM = 64
_REMOTE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST_16_RE = re.compile(r"^[0-9a-f]{16}$")
_VERSION_RE = re.compile(r"^[0-9]{1,4}(?:\.[0-9]{1,8}){0,3}$")


class _NoKameleoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _open_kameleo_request(request: urllib.request.Request, *, timeout: float):
    try:
        parsed = urllib.parse.urlparse(request.full_url)
        host = parsed.hostname
        port = parsed.port
    except (AttributeError, ValueError):
        raise ContractError("Kameleo HTTP request requires literal loopback") from None
    if (
        parsed.scheme != "http"
        or host not in {"127.0.0.1", "::1"}
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ContractError("Kameleo HTTP request requires literal loopback")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoKameleoRedirect()
    )
    return opener.open(request, timeout=timeout)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _strict_json_bytes(raw: bytes, *, label: str) -> Any:
    try:
        return decode_strict_json_bytes(raw, label=label)
    except ContractError:
        raise ContractError(f"{label} is not strict JSON") from None


def _remote_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _REMOTE_ID_RE.fullmatch(value) is None:
        raise ContractError(f"Kameleo {label} is invalid")
    return value


def _fingerprint_vector(fingerprint: object, *, expected_major: str) -> dict[str, Any]:
    if not isinstance(fingerprint, dict) or not isinstance(expected_major, str):
        raise ContractError("Kameleo fingerprint evidence is invalid")
    browser = fingerprint.get("browser")
    operating_system = fingerprint.get("os")
    if not isinstance(browser, dict) or not isinstance(operating_system, dict):
        raise ContractError("Kameleo fingerprint evidence is invalid")
    major = browser.get("major")
    product = browser.get("product")
    version = browser.get("version")
    family = operating_system.get("family")
    platform = operating_system.get("platform")
    os_version = operating_system.get("version")
    if (
        isinstance(major, bool)
        or not isinstance(major, int)
        or str(major) != expected_major
        or product != "chrome"
        or not isinstance(version, str)
        or _VERSION_RE.fullmatch(version) is None
        or family != "windows"
        or not isinstance(platform, str)
        or not 1 <= len(platform) <= 64
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in platform
        )
        or not isinstance(os_version, str)
        or _VERSION_RE.fullmatch(os_version) is None
    ):
        raise ContractError("Kameleo fingerprint evidence is invalid")
    return {
        "browser": {"major": major, "product": product, "version": version},
        "os": {"family": family, "platform": platform, "version": os_version},
    }


def _bounded_timeout(value: object) -> float:
    if (
        not is_finite_number(value)
        or not 0 < value <= 60
    ):
        raise ContractError("Kameleo request timeout is invalid")
    return float(value)


def _strict_json_file(path: Path, *, label: str) -> dict[str, Any]:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_KAMELEO_COHORT_REPORT_BYTES,
        label=label,
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")
    document = _strict_json_bytes(snapshot.body, label=label)
    if not isinstance(document, dict):
        raise ContractError(f"{label} must be a JSON object")
    return document


def _evaluator_selection(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ContractError("Kameleo cohort evaluator selection is invalid")
    return value


def _owned_evaluator_summary(
    output: Path,
    run_dir: object,
) -> tuple[Path, dict[str, Any]]:
    if not isinstance(run_dir, Path):
        raise ContractError("Kameleo cohort evaluator run directory is invalid")
    resolved = run_dir.resolve()
    try:
        resolved.relative_to(output.resolve())
    except ValueError:
        raise ContractError(
            "Kameleo cohort evaluator run directory escaped its output"
        ) from None
    return resolved, _strict_json_file(
        resolved / "summary.json",
        label="Kameleo cohort evaluator summary",
    )


def _bind_saved_evaluator_summary(returned: object, saved: dict[str, Any]) -> None:
    if not isinstance(returned, dict):
        raise ContractError("Kameleo cohort evaluator summary changed after evaluation")
    try:
        expected = json.dumps(
            redact_obj(returned), sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        actual = json.dumps(
            saved, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("Kameleo cohort evaluator summary changed after evaluation") from None
    if expected != actual:
        raise ContractError("Kameleo cohort evaluator summary changed after evaluation")


class KameleoLocal:
    def __init__(self, base_url: str) -> None:
        if (
            not isinstance(base_url, str)
            or not 1 <= len(base_url) <= 256
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in base_url
            )
        ):
            raise ContractError("Kameleo API must be a loopback HTTP endpoint")
        try:
            parsed = urllib.parse.urlparse(base_url)
            port = parsed.port
        except ValueError:
            raise ContractError("Kameleo API must be a loopback HTTP endpoint") from None
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or port is None
            or not 1 <= port <= 65535
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ContractError("Kameleo API must be a loopback HTTP endpoint")
        host = (
            "[::1]" if parsed.hostname == "::1"
            else "127.0.0.1" if parsed.hostname == "localhost"
            else parsed.hostname
        )
        self.base_url = f"http://{host}:{port}"

    def request(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        *,
        timeout_seconds: float = 60.0,
    ) -> Any:
        if method not in {"GET", "POST", "DELETE"}:
            raise ContractError("Kameleo request method is invalid")
        if (
            not isinstance(path, str)
            or not 1 <= len(path) <= MAX_KAMELEO_PATH_CHARACTERS
            or not path.startswith("/")
            or path.startswith("//")
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in path
            )
        ):
            raise ContractError("Kameleo request path is invalid")
        parsed_path = urllib.parse.urlparse(path)
        if parsed_path.scheme or parsed_path.netloc or parsed_path.fragment:
            raise ContractError("Kameleo request path is invalid")
        timeout = _bounded_timeout(timeout_seconds)
        if payload is not None and method == "GET":
            raise ContractError("Kameleo GET request cannot contain a body")
        if payload is None:
            body = None
        else:
            try:
                body = json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("ascii")
            except (OverflowError, RecursionError, TypeError, ValueError):
                raise ContractError(
                    "Kameleo request payload is not strict JSON"
                ) from None
            if len(body) > MAX_KAMELEO_REQUEST_BYTES:
                raise ContractError("Kameleo request payload is too large")
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json"} if body is not None else {},
        )
        response: Any | None = None
        status: Any = None
        raw: Any = None
        primary_error: BaseException | None = None
        try:
            deadline = time.monotonic() + timeout
            response = _open_kameleo_request(request, timeout=timeout)
            status = response.getcode()
            reader = getattr(response, "read1", None)
            if callable(reader):
                parts = bytearray()
                for _ in range(MAX_KAMELEO_RESPONSE_READ_CALLS):
                    if time.monotonic() > deadline:
                        raise ContractError("Kameleo response deadline exceeded")
                    remaining = MAX_KAMELEO_RESPONSE_BYTES + 1 - len(parts)
                    chunk = reader(remaining)
                    if time.monotonic() > deadline:
                        raise ContractError("Kameleo response deadline exceeded")
                    if type(chunk) is not bytes:
                        raise ContractError("Kameleo response body is invalid")
                    if len(chunk) > remaining:
                        raise ContractError("Kameleo response is too large")
                    parts.extend(chunk)
                    if not chunk or len(parts) > MAX_KAMELEO_RESPONSE_BYTES:
                        break
                else:
                    raise ContractError("Kameleo response has too many fragments")
                raw = bytes(parts)
            else:
                raw = response.read(MAX_KAMELEO_RESPONSE_BYTES + 1)
                if time.monotonic() > deadline:
                    raise ContractError("Kameleo response deadline exceeded")
        except urllib.error.HTTPError as exc:
            response = exc
            primary_error = exc
        except BaseException as exc:
            primary_error = exc

        safe_primary: BaseException | None = None
        if isinstance(primary_error, urllib.error.HTTPError):
            safe_primary = RuntimeError(
                f"Kameleo {method} {path.split('?')[0]} returned HTTP {primary_error.code}"
            )
        elif isinstance(primary_error, ContractError):
            safe_primary = primary_error
        elif isinstance(
            primary_error,
            (AttributeError, OSError, RuntimeError, TypeError, ValueError),
        ):
            safe_primary = RuntimeError(
                f"Kameleo {method} request failed ({type(primary_error).__name__})"
            )
        elif primary_error is not None:
            safe_primary = primary_error

        cleanup_error: ContractError | None = None
        if response is not None:
            try:
                response.close()
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                cleanup_error = ContractError(
                    "Kameleo response cleanup failed (response-close)"
                )
        if cleanup_error is not None:
            if safe_primary is not None:
                raise cleanup_error from safe_primary
            raise cleanup_error from None
        if safe_primary is not None:
            raise safe_primary from None
        if (
            isinstance(status, bool)
            or not isinstance(status, int)
            or not 200 <= status <= 299
        ):
            raise RuntimeError(
                f"Kameleo {method} request returned an unexpected status"
            )
        if type(raw) is not bytes:
            raise ContractError("Kameleo response body is invalid")
        if len(raw) > MAX_KAMELEO_RESPONSE_BYTES:
            raise ContractError("Kameleo response is too large")
        return _strict_json_bytes(raw, label="Kameleo response") if raw else None

    def fresh_fingerprint(self, browser_version: str) -> dict[str, Any]:
        if (
            not isinstance(browser_version, str)
            or re.fullmatch(r"[0-9]{1,4}", browser_version) is None
        ):
            raise ContractError("Kameleo browser version is invalid")
        query = urllib.parse.urlencode(
            {
                "deviceType": "desktop",
                "osFamily": "windows",
                "browserProduct": "chrome",
                "browserVersion": browser_version,
            }
        )
        fingerprints = self.request("GET", f"/fingerprints?{query}")
        if not isinstance(fingerprints, list) or not fingerprints:
            raise RuntimeError("Kameleo returned no matching fingerprints")
        fingerprint = fingerprints[0]
        if not isinstance(fingerprint, dict):
            raise ContractError("Kameleo returned an invalid fingerprint document")
        _remote_id(fingerprint.get("id"), label="fingerprint ID")
        return fingerprint

    def playwright_endpoint(self, profile_id: str) -> str:
        profile_id = _remote_id(profile_id, label="profile ID")
        parsed = urllib.parse.urlparse(self.base_url)
        host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
        return f"ws://{host}:{parsed.port or 80}/playwright/{profile_id}"

    def create_disposable(self, fingerprint_id: str, name: str) -> dict[str, Any]:
        fingerprint_id = _remote_id(fingerprint_id, label="fingerprint ID")
        if (
            not isinstance(name, str)
            or not name.startswith(KAMELEO_NAME_PREFIX + " ")
            or not 1 <= len(name) <= 128
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in name
            )
        ):
            raise ContractError(
                "refusing to create a profile outside the disposable name prefix"
            )
        profile = self.request(
            "POST",
            "/profiles/new",
            {
                "fingerprintId": fingerprint_id,
                "name": name,
                "screen": {"value": "off"},
                "proxy": {"value": "none"},
                "storage": "local",
            },
        )
        if not isinstance(profile, dict) or profile.get("name") != name:
            raise RuntimeError("Kameleo returned an invalid profile document")
        _remote_id(profile.get("id"), label="profile ID")
        return profile

    def cleanup_disposable(self, profile_id: str, expected_name: str) -> None:
        profile_id = _remote_id(profile_id, label="profile ID")
        if (
            not isinstance(expected_name, str)
            or not expected_name.startswith(KAMELEO_NAME_PREFIX + " ")
            or not 1 <= len(expected_name) <= 128
        ):
            raise ContractError("Kameleo disposable expected name is invalid")
        profile = self.request("GET", f"/profiles/{profile_id}")
        if not isinstance(profile, dict) or profile.get("name") != expected_name:
            raise RuntimeError(
                "refusing to clean up a Kameleo profile whose exact name changed"
            )
        state = profile.get("status", {}).get("lifetimeState")
        if state in {"running", "starting", "terminating"}:
            if state != "terminating":
                self.request("POST", f"/profiles/{profile_id}/stop")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                status = self.request(
                    "GET",
                    f"/profiles/{profile_id}/status",
                    timeout_seconds=min(10.0, max(0.001, remaining)),
                )
                if isinstance(status, dict) and status.get("lifetimeState") in {
                    "terminated",
                    "created",
                }:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("Kameleo disposable profile did not stop")
        self.request("DELETE", f"/profiles/{profile_id}")


def result_vector(summary: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(summary, dict) or not isinstance(summary.get("evaluators"), list):
        raise ContractError("Kameleo cohort evaluator summary is invalid")
    matches = [
        item
        for item in summary["evaluators"]
        if isinstance(item, dict) and item.get("id") == "controlled_coherence"
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("signals"), dict):
        raise ContractError("Kameleo cohort controlled evaluator result is invalid")
    evaluator = matches[0]
    signals = evaluator["signals"]
    keys = (
        "collector_checkset_sha256_16",
        "passed_checks",
        "failed_checks",
        "unavailable_checks",
        "identity_contract_sha256_16",
        "identity_passed_claims",
        "identity_failed_claims",
        "identity_unavailable_claims",
        "render_fingerprint",
        "surface_fingerprint",
        "automation_fingerprint",
    )
    if evaluator.get("verdict") not in {"pass", "fail"}:
        raise ContractError("Kameleo cohort controlled evaluator verdict is invalid")
    if evaluator.get("status") != "ok" or evaluator.get("error") is not None:
        raise ContractError("Kameleo cohort controlled evaluator status is invalid")
    required = {
        "collector_checkset_sha256_16",
        "passed_checks",
        "failed_checks",
        "unavailable_checks",
        "render_fingerprint",
        "surface_fingerprint",
        "automation_fingerprint",
    }
    identity = {
        "identity_contract_sha256_16",
        "identity_passed_claims",
        "identity_failed_claims",
        "identity_unavailable_claims",
    }
    if any(signals.get(key) is None for key in required) or (
        any(signals.get(key) is not None for key in identity)
        and any(signals.get(key) is None for key in identity)
    ):
        raise ContractError(
            "Kameleo cohort controlled evaluator signals are incomplete"
        )
    for key in (
        "passed_checks",
        "failed_checks",
        "unavailable_checks",
        "identity_passed_claims",
        "identity_failed_claims",
        "identity_unavailable_claims",
    ):
        value = signals.get(key)
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 1_000_000
        ):
            raise ContractError(
                "Kameleo cohort controlled evaluator signals are invalid"
            )
    for key in (
        "collector_checkset_sha256_16",
        "identity_contract_sha256_16",
        "render_fingerprint",
        "surface_fingerprint",
        "automation_fingerprint",
    ):
        value = signals.get(key)
        if value is not None and (
            not isinstance(value, str) or _DIGEST_16_RE.fullmatch(value) is None
        ):
            raise ContractError(
                "Kameleo cohort controlled evaluator signals are invalid"
            )
    if evaluator["verdict"] == "pass" and (
        signals["passed_checks"] == 0
        or signals["failed_checks"] != 0
        or signals.get("identity_failed_claims", 0) != 0
        or signals.get("identity_unavailable_claims", 0) != 0
    ):
        raise ContractError("Kameleo cohort controlled evaluator pass is inconsistent")
    return {
        "verdict": evaluator["verdict"],
        **{key: signals.get(key) for key in keys if signals.get(key) is not None},
    }


def evaluator_run(output: Path, selection: str) -> tuple[Path, dict[str, Any]]:
    selection = _evaluator_selection(selection)
    specs = select_specs(
        load_registry(EVAL_ROOT / "browser_eval" / "data" / "evaluators.json"),
        selection,
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


def run_core_trial(
    executable: Path,
    workspace: Path,
    profile_id: str,
    output: Path,
    evaluator_selection: str,
) -> dict[str, Any]:
    if not all(isinstance(path, Path) for path in (executable, workspace, output)):
        raise ContractError("Kameleo cohort core trial paths must be Paths")
    if not isinstance(profile_id, str) or PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise ContractError("Kameleo cohort profile ID is invalid")
    evaluator_selection = _evaluator_selection(evaluator_selection)
    session_path, session = launch_evaluation(
        EvaluationLaunch(
            executable=executable,
            workspace=workspace,
            profile_id=profile_id,
            timeout_seconds=60,
        ),
        CORE_ROOT,
    )
    previous = os.environ.pop("BROWSER_EVAL_CDP_ENDPOINT", None)
    old_session = os.environ.get("BROWSER_CORE_SESSION_FILE")
    os.environ["BROWSER_CORE_SESSION_FILE"] = str(session_path)
    try:
        returned_run_dir, returned_summary = evaluator_run(output, evaluator_selection)
        run_dir, summary = _owned_evaluator_summary(output, returned_run_dir)
        _bind_saved_evaluator_summary(returned_summary, summary)
    finally:
        try:
            validate_stopped_session_receipt(
                stop_session(session_path, timeout_seconds=30),
                expected_run_id=session.get("run_id"),
            )
        finally:
            if old_session is None:
                os.environ.pop("BROWSER_CORE_SESSION_FILE", None)
            else:
                os.environ["BROWSER_CORE_SESSION_FILE"] = old_session
            if previous is None:
                os.environ.pop("BROWSER_EVAL_CDP_ENDPOINT", None)
            else:
                os.environ["BROWSER_EVAL_CDP_ENDPOINT"] = previous
    return {
        "arm": "browser-core",
        "run_dir": str(run_dir),
        "session": str(session_path),
        "trace": session["trace_path"],
        "build": session["build"],
        "vector": result_vector(summary),
    }


def run_kameleo_trial(
    client: KameleoLocal,
    browser_version: str,
    cohort_id: str,
    trial: int,
    output: Path,
    evaluator_selection: str,
) -> dict[str, Any]:
    if not isinstance(client, KameleoLocal) or not isinstance(output, Path):
        raise ContractError("Kameleo cohort external trial input is invalid")
    if (
        not isinstance(cohort_id, str)
        or _REMOTE_ID_RE.fullmatch(cohort_id) is None
        or isinstance(trial, bool)
        or not isinstance(trial, int)
        or not 1 <= trial <= MAX_KAMELEO_TRIALS_PER_ARM
    ):
        raise ContractError("Kameleo cohort external trial controls are invalid")
    evaluator_selection = _evaluator_selection(evaluator_selection)
    fingerprint = client.fresh_fingerprint(browser_version)
    fingerprint_evidence = _fingerprint_vector(
        fingerprint, expected_major=browser_version
    )
    expected_name = f"{KAMELEO_NAME_PREFIX} {cohort_id} {trial:02d}"
    profile = client.create_disposable(str(fingerprint["id"]), expected_name)
    profile_id = str(profile["id"])
    recovery_record = output.parent / "disposables" / f"{profile_id}.json"
    recovery_started = False
    recovery_cursor: JsonPublicationCursor | None = None
    try:
        recovery_record.parent.mkdir(parents=True, exist_ok=True)
        recovery_cursor = JsonPublicationCursor(
            recovery_record,
            maximum=64 * 1024,
            label="Kameleo disposable recovery record",
        )
        recovery_cursor.publish(
            {
                "profile_id": profile_id,
                "expected_name": expected_name,
                "created_by": "run_alternating_kameleo.py",
                "cleaned": False,
            }
        )
        recovery_started = True
        playwright_endpoint = client.playwright_endpoint(profile_id)
        previous = os.environ.get("BROWSER_EVAL_CDP_ENDPOINT")
        old_session = os.environ.pop("BROWSER_CORE_SESSION_FILE", None)
        os.environ["BROWSER_EVAL_CDP_ENDPOINT"] = playwright_endpoint
        try:
            returned_run_dir, returned_summary = evaluator_run(
                output, evaluator_selection
            )
            run_dir, summary = _owned_evaluator_summary(output, returned_run_dir)
            _bind_saved_evaluator_summary(returned_summary, summary)
        finally:
            if previous is None:
                os.environ.pop("BROWSER_EVAL_CDP_ENDPOINT", None)
            else:
                os.environ["BROWSER_EVAL_CDP_ENDPOINT"] = previous
            if old_session is None:
                os.environ.pop("BROWSER_CORE_SESSION_FILE", None)
            else:
                os.environ["BROWSER_CORE_SESSION_FILE"] = old_session
    finally:
        client.cleanup_disposable(profile_id, expected_name)
        if recovery_started and recovery_cursor is not None:
            recovery_cursor.publish(
                {
                    "profile_id": profile_id,
                    "expected_name": expected_name,
                    "created_by": "run_alternating_kameleo.py",
                    "cleaned": True,
                }
            )
    return {
        "arm": "kameleo",
        "run_dir": str(run_dir),
        "profile_id": profile_id,
        "fingerprint": fingerprint_evidence,
        "vector": result_vector(summary),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Alternate attested Browser Core and disposable Kameleo trials"
    )
    result.add_argument("--executable", type=Path, required=True)
    result.add_argument("--workspace", type=Path, required=True)
    result.add_argument("--profile-id", required=True)
    result.add_argument("--out", type=Path, required=True)
    result.add_argument("--core-trials", type=int, default=10)
    result.add_argument("--kameleo-trials", type=int, default=5)
    result.add_argument("--kameleo-browser-version", default="151")
    result.add_argument("--kameleo-api", default="http://127.0.0.1:5050")
    result.add_argument("--evaluators", default="controlled_coherence")
    return result


def main() -> int:
    args = parser().parse_args()
    if not all(
        isinstance(path, Path) for path in (args.executable, args.workspace, args.out)
    ):
        raise ContractError("Kameleo cohort paths must be Paths")
    if (
        not isinstance(args.profile_id, str)
        or PROFILE_ID_RE.fullmatch(args.profile_id) is None
    ):
        raise ContractError("Kameleo cohort profile ID is invalid")
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_KAMELEO_TRIALS_PER_ARM
        for value in (args.core_trials, args.kameleo_trials)
    ):
        raise ContractError("Kameleo cohort trial counts are invalid")
    evaluator_selection = _evaluator_selection(args.evaluators)
    client = KameleoLocal(args.kameleo_api)
    if (
        not isinstance(args.kameleo_browser_version, str)
        or re.fullmatch(r"[0-9]{1,4}", args.kameleo_browser_version) is None
    ):
        raise ContractError("Kameleo browser version is invalid")
    executable = args.executable.absolute()
    workspace = args.workspace.absolute()
    output = args.out.absolute()
    if directory_identity(output, label="Kameleo cohort output") is not None:
        raise ContractError("Kameleo cohort output directory already exists")
    build = executable_evidence(CORE_ROOT, executable, allow_unverified=False)
    load_profile(workspace, args.profile_id)
    output.mkdir(parents=True, exist_ok=False)
    output_identity = directory_identity(output, label="Kameleo cohort output")
    if output_identity is None:
        raise ContractError("Kameleo cohort output directory was not created")
    report_cursor = JsonPublicationCursor(
        output / "cohort.json",
        maximum=MAX_KAMELEO_COHORT_REPORT_BYTES,
        label="Kameleo alternating cohort report",
    )
    cohort_id = utc_stamp()
    runs: list[dict[str, Any]] = []
    core_done = 0
    kameleo_done = 0

    def core() -> None:
        nonlocal core_done
        core_done += 1
        runs.append(
            run_core_trial(
                executable,
                workspace,
                args.profile_id,
                output / f"{len(runs) + 1:02d}-browser-core-{core_done:02d}",
                evaluator_selection,
            )
        )
        report_cursor.publish({"cohort_id": cohort_id, "runs": runs})

    def kameleo() -> None:
        nonlocal kameleo_done
        kameleo_done += 1
        runs.append(
            run_kameleo_trial(
                client,
                args.kameleo_browser_version,
                cohort_id,
                kameleo_done,
                output / f"{len(runs) + 1:02d}-kameleo-{kameleo_done:02d}",
                evaluator_selection,
            )
        )
        report_cursor.publish({"cohort_id": cohort_id, "runs": runs})

    while core_done < args.core_trials or kameleo_done < args.kameleo_trials:
        pair = min(core_done, kameleo_done)
        scheduled: list[Callable[[], None]] = (
            [kameleo, core] if pair % 2 == 0 else [core, kameleo]
        )
        for action in scheduled:
            if action is core and core_done >= args.core_trials:
                continue
            if action is kameleo and kameleo_done >= args.kameleo_trials:
                continue
            action()

    final = {"cohort_id": cohort_id, "build": build, "runs": runs}
    final_body = report_cursor.publish(final)
    if directory_identity(output, label="Kameleo cohort output") != output_identity:
        raise ContractError("Kameleo cohort output directory changed")
    sys.stdout.buffer.write(final_body)
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except (ContractError, OSError, RuntimeError, ValueError) as exc:
        print(f"browser-core cohort failed ({type(exc).__name__})", file=sys.stderr)
        exit_code = 2
    raise SystemExit(exit_code)
