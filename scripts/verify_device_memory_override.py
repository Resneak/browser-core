"""Live gate for native patch 0005 -- the device-memory override.

Run this after any rebuild of the attested binary. It is a live check rather than
a unit test because the thing under test is a C++ change: the Python mirror in
``kernels.approximate_device_memory`` can only be trusted if a real browser keeps
agreeing with it, and a unit test that compares the mirror to itself would pass
forever while the build silently regressed.

Four properties, in the order they would hurt if they broke:

1. **The worker realm agrees with the main thread.** ``WorkerNavigator`` is a
   different object on a different thread. A main-thread-only override is worse
   than no override -- it replaces a dull value with a self-contradiction, and it
   is the first thing a collector that builds a worker would notice.
2. **The clamp is not a bypass.** A request under the desktop floor or over its
   ceiling must come back clamped. If a caller could ask for 1 GB on a desktop
   build and get 1, the patch would be minting values Chromium never emits.
3. **The request header tracks the property.** ``Device-Memory`` is derived from
   the same accessor, so a script comparing the JavaScript value against the HTTP
   header gets a free cross-surface test. They must not disagree.
4. **Absent the switch, nothing moves.**

Usage::

    python scripts/verify_device_memory_override.py \
        --executable H:\\bc\\chromium\\src\\out\\BrowserCore\\chrome.exe

Exits non-zero on the first property that fails, and prints every case either
way, because a gate that only speaks up on failure teaches nobody what it covers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from browser_core.build import load_build_attestation  # noqa: E402
from browser_core.errors import ContractError, safe_failure_receipt  # noqa: E402
from browser_core.kernels import approximate_device_memory  # noqa: E402
from browser_core.numeric import is_finite_number  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DEVICE_MEMORY_GATE_SCHEMA = "browser-core.device-memory-live-gate/1"
MAX_DEVICE_MEMORY_CASES = 128

PROBE_ORIGIN = "https://device-memory-gate.invalid"
PROBE_URL = f"{PROBE_ORIGIN}/"
PROBE_PATTERN = f"{PROBE_ORIGIN}/**"

# Fetches a subresource so there is a second request to carry the client hint.
PAGE = (
    b"<!doctype html><title>device-memory-gate</title><body>"
    b"<script>fetch('/hint-probe.txt').catch(() => {});</script></body>"
)

# Reads the same expression on both threads, so a difference is a real
# difference and not an artefact of asking two different questions.
READ_BOTH_REALMS = """async () => {
  const main = navigator.deviceMemory;
  const source = 'onmessage = () => postMessage(navigator.deviceMemory)';
  const url = URL.createObjectURL(new Blob([source], {type: 'text/javascript'}));
  const worker = new Worker(url);
  const worker_value = await new Promise((resolve) => {
    worker.onmessage = (event) => resolve(event.data);
    worker.onerror = () => resolve('worker-error');
    worker.postMessage(0);
    setTimeout(() => resolve('worker-timeout'), 4000);
  });
  worker.terminate();
  URL.revokeObjectURL(url);
  return {main, worker: worker_value};
}"""

# (label, switch value or None, expected reported value). A non-integer value is
# included deliberately: the patch parses the switch and falls back to the host
# size when parsing fails, and "malformed input is ignored" is exactly the kind of
# behaviour that rots silently into a crash or a zero.
CASES: list[tuple[str, int | str | None, float]] = [
    ("no switch, host value", None, 32),
    ("non-numeric value, ignored", "banana", 32),
    ("empty value, ignored", "", 32),
    ("negative value, ignored", "-4096", 32),
    ("2048 MiB", 2048, 2),
    ("4096 MiB", 4096, 4),
    ("8192 MiB", 8192, 8),
    ("5000 MiB, nearer 4096", 5000, 4),
    ("7000 MiB, nearer 8192", 7000, 8),
    ("6144 MiB, tie rounds down", 6144, 4),
    ("12288 MiB, tie rounds down", 12288, 8),
    ("1024 MiB, under the floor", 1024, 2),
    ("131072 MiB, over the ceiling", 131072, 32),
]


def _args_for(megabytes: int | str | None) -> list[str]:
    if megabytes is None:
        return []
    if isinstance(megabytes, bool) or not isinstance(megabytes, (int, str)):
        raise ContractError("device-memory override must be an integer, text, or null")
    if isinstance(megabytes, int):
        if not -1_000_000_000 <= megabytes <= 1_000_000_000:
            raise ContractError("device-memory override integer is outside the test bound")
    elif len(megabytes) > 32 or re.fullmatch(r"[A-Za-z0-9+-]*", megabytes) is None:
        raise ContractError("device-memory override text is outside the test contract")
    return [f"--browser-core-device-memory-mb={megabytes}"]


def _validate_observation(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"header", "main", "worker"}:
        raise ContractError("device-memory observation fields are invalid")

    def reading(item: object, *, worker: bool = False) -> object:
        if worker and isinstance(item, str) and item in {
            "worker-error",
            "worker-timeout",
        }:
            return item
        if (
            not is_finite_number(item)
            or not 0 <= item <= 1024
        ):
            raise ContractError("device-memory observation reading is invalid")
        return item

    header = value.get("header")
    if header is not None and (
        not isinstance(header, str)
        or len(header) > 32
        or re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", header) is None
    ):
        raise ContractError("device-memory observation header is invalid")
    return {
        "header": header,
        "main": reading(value.get("main")),
        "worker": reading(value.get("worker"), worker=True),
    }


def _validate_cases(
    cases: object,
) -> list[tuple[str, int | str | None, float]]:
    if type(cases) is not list or not 1 <= len(cases) <= MAX_DEVICE_MEMORY_CASES:
        raise ContractError("device-memory case population is invalid")
    checked: list[tuple[str, int | str | None, float]] = []
    seen_labels: set[str] = set()
    for item in cases:
        if not isinstance(item, tuple) or len(item) != 3:
            raise ContractError("device-memory case entry is invalid")
        label, megabytes, want = item
        try:
            label_bytes = label.encode("utf-8", errors="strict") if isinstance(label, str) else b""
        except UnicodeEncodeError:
            label_bytes = b""
        if (
            not label_bytes
            or len(label_bytes) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in label)
            or label in seen_labels
        ):
            raise ContractError("device-memory case label is invalid or duplicated")
        _args_for(megabytes)
        if (
            not is_finite_number(want)
            or not 0 < want <= 1024
        ):
            raise ContractError("device-memory expected value is invalid")
        seen_labels.add(label)
        checked.append((label, megabytes, float(want)))
    return checked


def observe(
    executable: Path,
    megabytes: int | str | None,
    *,
    expected_attestation: dict[str, object],
) -> dict[str, object]:
    if not isinstance(executable, Path):
        raise ContractError("device-memory executable must be a Path")
    before = load_build_attestation(ROOT, executable)
    if before != expected_attestation:
        raise ContractError("device-memory build attestation changed before the case")
    from playwright.sync_api import sync_playwright

    seen: dict[str, object] = {"header": None}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(executable), args=_args_for(megabytes)
        )
        try:
            context = browser.new_context()

            def handle(route):
                if route.request.url.endswith("/hint-probe.txt"):
                    seen["header"] = route.request.headers.get("device-memory")
                    route.fulfill(status=200, content_type="text/plain", body=b"ok")
                    return
                route.fulfill(
                    status=200,
                    content_type="text/html; charset=utf-8",
                    headers={"Accept-CH": "Device-Memory", "Critical-CH": "Device-Memory"},
                    body=PAGE,
                )

            context.route(PROBE_PATTERN, handle)
            page = context.new_page()
            # Twice: Accept-CH applies to requests after the response that set it.
            page.goto(PROBE_URL, wait_until="load")
            page.goto(PROBE_URL, wait_until="load")
            page.wait_for_timeout(1000)
            evaluated = page.evaluate(READ_BOTH_REALMS)
            if not isinstance(evaluated, dict):
                raise ContractError("device-memory realm probe returned an invalid result")
            seen.update(evaluated)
            context.close()
        finally:
            browser.close()
    after = load_build_attestation(ROOT, executable)
    if after != expected_attestation:
        raise ContractError("device-memory build attestation changed during the case")
    return _validate_observation(seen)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--executable",
        type=Path,
        required=True,
        help="attested Browser Core chrome.exe carrying native patch 0005",
    )
    parsed = parser.parse_args()

    try:
        cases = _validate_cases(CASES)
        attestation = load_build_attestation(ROOT, parsed.executable)
    except ContractError as exc:
        print(f"device-memory gate refused: {safe_failure_receipt(exc)}", file=sys.stderr)
        return 2

    failures: list[str] = []
    print(f"{'case':<32} {'main':>6} {'worker':>7} {'header':>7} {'want':>6}  result")
    for label, megabytes, want in cases:
        try:
            seen = observe(
                parsed.executable,
                megabytes,
                expected_attestation=attestation,
            )
        except Exception as exc:
            receipt = safe_failure_receipt(exc)
            failures.append(f"{label}: {receipt}")
            print(f"{label:<32} {'-':>6} {'-':>7} {'-':>7} {want:>6g}  FAIL {receipt}")
            continue
        main_value = seen.get("main")
        worker_value = seen.get("worker")
        header = seen.get("header")

        problems = []
        if main_value != want:
            problems.append(f"property {main_value} != {want}")
        if worker_value != main_value:
            problems.append(f"worker {worker_value} != main {main_value}")
        if header is not None and str(header) != f"{want:g}":
            problems.append(f"header {header} != {want:g}")
        # The mirror only claims to model well-formed sizes; a rejected switch is
        # the patch's own fallback path, not arithmetic, so it is not checked here.
        if isinstance(megabytes, int) and approximate_device_memory(megabytes) != want:
            problems.append("python mirror disagrees with the case table")
        if problems:
            failures.append(f"{label}: {'; '.join(problems)}")

        print(
            f"{label:<32} {main_value!s:>6} {worker_value!s:>7} {header!s:>7} "
            f"{want:>6g}  {'ok' if not problems else 'FAIL ' + '; '.join(problems)}"
        )

    print(
        json.dumps(
            {
                "schema": DEVICE_MEMORY_GATE_SCHEMA,
                "cases": len(cases),
                "failures": len(failures),
                "chromium_revision": attestation["chromium_revision"],
                "executable_sha256_16": attestation["executable_sha256"][:16],
                "runtime_bundle_sha256_16": attestation["runtime_bundle_sha256"][:16],
            },
            sort_keys=True,
        )
    )
    for failure in failures:
        print(f"  {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
