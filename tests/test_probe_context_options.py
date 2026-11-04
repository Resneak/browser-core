"""The probe must hand the browser every option the device contract specifies.

Written after a real regression: an edit that added user-agent alignment dropped
``has_touch`` from the context options, and every mobile capture would have
produced a touchless phone. A live probe caught it on the next run -- the
realization check is not decorative -- but a browser should not be required to
notice that a dictionary lost a key.

So this exercises ``_probe_with_browser`` against a fake browser that records
what it was asked for. No Playwright, no process, no socket, in the same spirit
as ``test_hook_script_semantics``: the riskiest part of a capture is the part
that decides what the browser is told, and that part is plain Python.
"""

from __future__ import annotations

import ast
import itertools
from pathlib import Path
from typing import Any

import pytest

from browser_core.kernels import (
    KERNEL_SCHEMA,
    _probe_with_browser,
    align_user_agent_version,
    device_from_playwright,
)
from browser_core.personas import persona_from_kernel_probe

ROOT = Path(__file__).resolve().parents[1]


class _FakePage:
    def __init__(self, observed: dict[str, Any]) -> None:
        self._observed = observed
        self.goto_urls: list[str] = []

    def set_default_timeout(self, _timeout: int) -> None:
        return None

    def goto(self, url: str) -> None:
        self.goto_urls.append(url)

    def evaluate(self, _script: str) -> dict[str, Any]:
        return self._observed

    @property
    def context(self) -> "_FakeContext":  # pragma: no cover - only if code reaches for it
        raise AssertionError("the probe should not need the page's context")


class _FakeContext:
    def __init__(self, observed: dict[str, Any]) -> None:
        self._observed = observed
        self.routed: list[str] = []
        self.closed = False
        self.page = _FakePage(observed)

    def route(self, pattern: str, _handler: Any) -> None:
        self.routed.append(pattern)

    def new_page(self) -> _FakePage:
        return self.page

    def new_cdp_session(self, _page: Any) -> Any:  # pragma: no cover - override path only
        raise RuntimeError("no CDP in the fake browser")

    def close(self) -> None:
        self.closed = True


class _FakeBrowser:
    """Records the context options it was asked for, then replays an observation."""

    def __init__(self, observed: dict[str, Any]) -> None:
        self._observed = observed
        self.options: dict[str, Any] = {}
        self.context: _FakeContext | None = None

    def new_context(self, **options: Any) -> _FakeContext:
        self.options = options
        self.context = _FakeContext(self._observed)
        return self.context


def _kernel(engine: str = "chromium") -> dict[str, Any]:
    return {
        "schema": KERNEL_SCHEMA,
        "id": "k-1",
        "engine": engine,
        "product": "chromium" if engine == "chromium" else engine,
        "available": True,
        "executable": __file__,
        "executable_sha256_16": "0123456789abcdef",
        "capabilities": ["mobile-emulation"],
        "source": {"kind": "playwright-managed", "playwright_version": "1.0"},
    }


def _observation(device: dict[str, Any], user_agent: str) -> dict[str, Any]:
    """What a browser that honoured every option would report back."""
    return {
        "title": "owned-kernel-probe",
        "secureContext": True,
        "userAgent": user_agent,
        "userAgentDataMobile": device["is_mobile"],
        "userAgentDataPlatform": "Android" if device["is_mobile"] else "Windows",
        "userAgentDataBrands": ["Chromium/153", "Not_A Brand/8"],
        "platform": "Linux armv81" if device["is_mobile"] else "Win32",
        "languages": [device["locale"], device["locale"].split("-", 1)[0]],
        "maxTouchPoints": 5 if device["has_touch"] else 0,
        "hardwareConcurrency": 8,
        "deviceMemory": 8,
        "pluginsLength": 0,
        "mimeTypesLength": 0,
        "pdfViewerEnabled": False,
        "innerWidth": device["viewport"]["width"],
        "innerHeight": device["viewport"]["height"],
        "screenWidth": device["screen"]["width"],
        "screenHeight": device["screen"]["height"],
        # Emulation reserves no area, so these equal the screen. An unfaithful
        # shim produces a confident, wrong verdict about the subject, so the
        # fixture reports what the real probe measured rather than what would be
        # convenient.
        "availWidth": device["screen"]["width"],
        "availHeight": device["screen"]["height"],
        "colorDepth": 24,
        "pixelDepth": 24,
        "devicePixelRatio": device["device_scale_factor"],
        "language": device["locale"],
        "intlLocale": device["locale"],
        "timezone": device["timezone"],
        "coarsePointer": device["has_touch"],
        "touchEventSurface": device["has_touch"],
        "chromeObject": True,
        "webglIdentitySchema": "webgl2-preferred-unmasked-v1",
        "webglVendor": "WebKit",
        "webglRenderer": "WebKit WebGL",
        "webglVersion": "WebGL 2.0 (OpenGL ES 3.0 Chromium)",
        "webglUnmaskedVendor": "Google Inc. (NVIDIA)",
        "webglUnmaskedRenderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11)",
    }


REQUIRED_OPTIONS = {
    "viewport",
    "screen",
    "device_scale_factor",
    "has_touch",
    "user_agent",
    "locale",
    "timezone_id",
}


@pytest.mark.parametrize("preset", ["Pixel 7", "Desktop Chrome"])
def test_every_option_the_device_contract_specifies_reaches_the_browser(preset: str) -> None:
    """The regression this file exists for: a dropped key is a silent defect."""
    device = device_from_playwright(preset, locale="en-US", timezone="America/Chicago")
    browser = _FakeBrowser(_observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Safari/537.36"))
    _probe_with_browser(browser, "153.0.7988.0", _kernel(), device)

    missing = REQUIRED_OPTIONS - set(browser.options)
    assert not missing, f"context options dropped: {sorted(missing)}"


def test_touch_reaches_the_browser_with_the_value_the_device_declares() -> None:
    """A phone whose has_touch never arrives reports zero touch points.

    That is the single most-read mobile emulation tell, so it gets its own test
    rather than relying on the set-membership check above.
    """
    phone = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    assert phone["has_touch"] is True
    browser = _FakeBrowser(_observation(phone, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36"))
    _probe_with_browser(browser, "153.0.7988.0", _kernel(), phone)
    assert browser.options["has_touch"] is True
    assert browser.options["is_mobile"] is True


def test_the_user_agent_handed_over_carries_the_running_browsers_version() -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    browser = _FakeBrowser(_observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36"))
    _probe_with_browser(browser, "153.0.7988.0", _kernel(), device)
    assert "Chrome/153.0.7988.0" in browser.options["user_agent"]


def test_probe_rejects_a_browser_that_ignored_the_requested_user_agent() -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(
        device,
        "Mozilla/5.0 (Windows NT 10.0) Chrome/153.0.7988.0 Safari/537.36",
    )
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert probe["checks"]["user_agent"] is False
    assert probe["passed"] is False


def test_a_firefox_kernel_is_not_told_about_mobile_emulation() -> None:
    """`is_mobile` is a Chromium and WebKit option; Firefox rejects it."""
    device = device_from_playwright("Desktop Firefox", locale="en-US", timezone="America/Chicago")
    browser = _FakeBrowser(_observation(device, "Mozilla/5.0 Firefox/148.0"))
    _probe_with_browser(browser, "148.0", _kernel("firefox"), device)
    assert "is_mobile" not in browser.options


def test_the_probe_closes_the_context_it_opened() -> None:
    device = device_from_playwright("Desktop Chrome", locale="en-US", timezone="America/Chicago")
    browser = _FakeBrowser(_observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Safari/537.36"))
    _probe_with_browser(browser, "153.0.7988.0", _kernel(), device)
    assert browser.context is not None and browser.context.closed


def test_the_probe_page_is_served_from_the_reserved_origin_not_the_network() -> None:
    """`.invalid` cannot resolve, so interception is the only way it is answered."""
    device = device_from_playwright("Desktop Chrome", locale="en-US", timezone="America/Chicago")
    browser = _FakeBrowser(_observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Safari/537.36"))
    _probe_with_browser(browser, "153.0.7988.0", _kernel(), device)
    assert browser.context is not None
    assert all(".invalid" in pattern for pattern in browser.context.routed)
    assert all(url.endswith(".invalid/") for url in browser.context.page.goto_urls)


# -- every rule must judge a field a capture can actually produce ---------------


def _render_claim_key(node: ast.AST, values: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_render_claim_key(part, values) for part in node.values)
    if (
        isinstance(node, ast.FormattedValue)
        and node.conversion == -1
        and node.format_spec is None
    ):
        return _render_claim_key(node.value, values)
    if isinstance(node, ast.Name) and node.id in values:
        return values[node.id]
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "capitalize"
        and not node.args
        and not node.keywords
    ):
        return _render_claim_key(node.func.value, values).capitalize()
    raise AssertionError(f"unsupported claim-key expression: {ast.dump(node)}")


def _expand_claim_key(
    node: ast.AST, domains: dict[str, tuple[str, ...]]
) -> set[str]:
    names = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
    if not names:
        return {_render_claim_key(node, {})}
    if not names.issubset(domains):
        raise AssertionError(f"unsupported claim-key expression: {ast.dump(node)}")
    ordered = sorted(names)
    populations = [domains[name] for name in ordered]
    combinations = 1
    for population in populations:
        combinations *= len(population)
    if combinations > 256:
        raise AssertionError(f"unsupported claim-key expression: {ast.dump(node)}")
    return {
        _render_claim_key(node, dict(zip(ordered, values, strict=True)))
        for values in itertools.product(*populations)
    }


def _static_string_domains(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    domains: dict[str, tuple[str, ...]] = {}
    for node in tree.body:
        if not (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.AST)
        ):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            continue
        try:
            literal = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            continue
        values = tuple(literal) if isinstance(literal, dict) else literal
        if isinstance(values, (list, tuple, set, frozenset)) and all(
            isinstance(value, str) for value in values
        ):
            domains[targets[0].id] = tuple(sorted(values))
    return domains


def _string_domain(
    node: ast.AST, constants: dict[str, tuple[str, ...]]
) -> tuple[str, ...] | None:
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "items"
        and isinstance(node.func.value, ast.Name)
        and not node.args
        and not node.keywords
    ):
        return constants.get(node.func.value.id)
    try:
        literal = ast.literal_eval(node)
    except (ValueError, TypeError):
        return None
    if isinstance(literal, (list, tuple, set, frozenset)) and all(
        isinstance(value, str) for value in literal
    ):
        return tuple(sorted(literal))
    return None


def _loop_key_domains(
    scope: ast.AST, constants: dict[str, tuple[str, ...]]
) -> dict[str, tuple[str, ...]]:
    collected: dict[str, set[str]] = {"axis": {"width", "height"}}
    for node in ast.walk(scope):
        if not isinstance(node, (ast.For, ast.comprehension)):
            continue
        domain = _string_domain(node.iter, constants)
        if domain is None:
            continue
        target = node.target
        if isinstance(target, ast.Name):
            collected.setdefault(target.id, set()).update(domain)
        elif (
            isinstance(target, (ast.Tuple, ast.List))
            and target.elts
            and isinstance(target.elts[0], ast.Name)
        ):
            collected.setdefault(target.elts[0].id, set()).update(domain)
    return {key: tuple(sorted(values)) for key, values in collected.items()}


class _ExpectedClaimAccesses(ast.NodeVisitor):
    def __init__(self, domains: dict[str, tuple[str, ...]]) -> None:
        self.domains = domains
        self.keys: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # The local claim() helper reads expected by a dynamic parameter whose
        # finite values are established at its call sites.
        return None

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "expected"
            and node.func.attr == "get"
            and len(node.args) == 1
            and not node.keywords
        ):
            self.keys.update(_expand_claim_key(node.args[0], self.domains))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == "expected":
            self.keys.update(_expand_claim_key(node.slice, self.domains))
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        left = node.left
        for operator, comparator in zip(node.ops, node.comparators, strict=True):
            if (
                isinstance(operator, (ast.In, ast.NotIn))
                and isinstance(comparator, ast.Name)
                and comparator.id == "expected"
            ):
                self.keys.update(_expand_claim_key(left, self.domains))
            left = comparator
        self.generic_visit(node)


def _claim_keys_rules_read(source: str | None = None) -> set[str]:
    """Claim keys `persona_quality` inspects, including f-string families.

    Parse syntax instead of quote-sensitive text. Every call must have one
    statically enumerable string argument; an unfamiliar expression fails the
    census rather than becoming an invisible rule dependency. The current
    geometry family is expanded over its measured width/height axes.
    """
    if source is None:
        source = (ROOT / "browser_core" / "persona_quality.py").read_text(
            encoding="utf-8"
        )
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    scope: ast.AST = next(
        (node for node in functions if node.name == "coherence_findings"),
        functions[0] if len(functions) == 1 else tree,
    )
    domains = _loop_key_domains(scope, _static_string_domains(tree))
    keys: set[str] = set()
    for node in ast.walk(scope):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "claim"
        ):
            continue
        if len(node.args) != 1 or node.keywords:
            raise AssertionError(
                f"unsupported claim-key expression: {ast.dump(node)}"
            )
        keys.update(_expand_claim_key(node.args[0], domains))
    accesses = _ExpectedClaimAccesses(domains)
    body = scope.body if isinstance(scope, ast.FunctionDef) else [scope]
    for node in body:
        accesses.visit(node)
    keys.update(accesses.keys)
    return keys


def test_rule_claim_census_is_syntax_aware_and_fail_closed() -> None:
    source = """
def synthetic_rule(axis):
    claim('window.singleQuoted')
    claim(f"window.screen.{axis}")
"""

    assert _claim_keys_rules_read(source) == {
        "window.singleQuoted",
        "window.screen.width",
        "window.screen.height",
    }
    with pytest.raises(AssertionError, match="unsupported claim-key expression"):
        _claim_keys_rules_read("claim(dynamic_key)")


def test_rule_claim_census_includes_direct_expected_access_paths() -> None:
    source = """
_MEMBERSHIP = ("window.membership",)
_FAMILIES = {"window.subscript": "number"}

def coherence_findings(persona):
    expected = persona["identity_contract"]["expected"]
    claim("window.helper")
    expected.get("window.get")
    if "window.literalMembership" in expected:
        pass
    for key in _MEMBERSHIP:
        if key in expected:
            pass
    for claim_name, family in _FAMILIES.items():
        if claim_name in expected:
            expected[claim_name]
"""

    assert _claim_keys_rules_read(source) == {
        "window.helper",
        "window.get",
        "window.literalMembership",
        "window.membership",
        "window.subscript",
    }


def _claim_keys_a_capture_produces() -> set[str]:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, align_user_agent_version(device["user_agent"], "153.0.7988.0"))
    browser = _FakeBrowser(observed)
    probe = _probe_with_browser(browser, "153.0.7988.0", _kernel(), device)
    persona, _ = persona_from_kernel_probe(
        _kernel(),
        device,
        probe,
        persona_id="census",
        name="census",
        kernel_id="k-1",
        os_family="android",
        os_version="14",
        architecture="arm64",
        country="US",
        locale="en-US",
        timezone_name="America/Chicago",
    )
    return set(persona["identity_contract"]["expected"])


def test_kernel_persona_retains_the_measured_user_agent_claim() -> None:
    device = device_from_playwright(
        "Pixel 7", locale="en-US", timezone="America/Chicago"
    )
    user_agent = align_user_agent_version(device["user_agent"], "153.0.7988.0")
    probe = _probe_with_browser(
        _FakeBrowser(_observation(device, user_agent)),
        "153.0.7988.0",
        _kernel(),
        device,
    )
    persona, _ = persona_from_kernel_probe(
        _kernel(),
        device,
        probe,
        persona_id="user-agent-custody",
        name="user-agent-custody",
        kernel_id="k-1",
        os_family="android",
        os_version="14",
        architecture="arm64",
        country="US",
        locale="en-US",
        timezone_name="America/Chicago",
    )

    assert persona["identity_contract"]["expected"]["window.userAgent"] == user_agent


def test_no_rule_judges_a_field_that_no_capture_produces() -> None:
    """A rule over an unpopulated field is indistinguishable from one that works.

    `available-screen-exceeds-screen` guarded `screen.availWidth` for the life of
    the catalog and could never fire: of 6,228 personas exactly one carried the
    field, and it was a hand-written fixture. The rule looked healthy because
    silence and correctness are the same output.
    """
    unproducible = _claim_keys_rules_read() - _claim_keys_a_capture_produces()
    assert not unproducible, (
        "these claims are judged by a rule but no capture emits them: "
        f"{sorted(unproducible)}"
    )


def test_no_capture_produces_a_field_that_every_rule_ignores() -> None:
    """The mirror of the test above, and the structural one of the pair.

    Four of the six identity defects found on 2026-08-07 were introduced by
    fixing something else: closing the processor axis handed phones a desktop
    core table, moving capture onto the attested build left user agents claiming
    one major while their client hints claimed another, touch emulation reported
    the protocol's default of one point on every handset. Each was a field that
    capture recorded, that looked fine read on its own, and that no rule joined
    to anything.

    That is what an open-loop rule list does to a combinatorial matrix: a value
    nothing judges is indistinguishable from a value that is right. This test
    closes the loop in the only place it can be closed cheaply -- a field enters
    the contract and the suite fails until some rule has an opinion about it.

    Failing here does not mean the field is wrong. It means nobody has said yet
    what wrong would look like.
    """
    unjudged = _claim_keys_a_capture_produces() - _claim_keys_rules_read()
    assert not unjudged, (
        "these claims are recorded on every persona and no rule reads them, so a "
        "wrong value in any of them would be invisible: " + str(sorted(unjudged))
    )


# -- the realization checks must be able to fail -------------------------------
#
# Each of these is the safety net for an override, and a net that cannot fail is
# not a net. They are asserted here against a fake browser that reports something
# other than what was asked for, which is precisely the case a real browser
# produces when it does not understand a switch.


def test_the_user_agent_check_fails_when_the_client_hints_disagree() -> None:
    """The defect B38 fixed: preset says 147, the browser's hints say 153."""
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/147.0.7727.15 Mobile Safari/537.36")
    observed["userAgentDataBrands"] = ["Chromium/153", "Not_A Brand/8"]
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert probe["checks"]["user_agent_matches_client_hints"] is False
    assert probe["passed"] is False


def test_the_user_agent_check_passes_when_they_name_one_browser() -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36")
    observed["userAgentDataBrands"] = ["Chromium/153", "Not_A Brand/8"]
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert probe["checks"]["user_agent_matches_client_hints"] is True


def test_the_grease_brand_does_not_decide_the_user_agent_check() -> None:
    """`Not_A Brand/8` is deliberate noise and carries no real version."""
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36")
    observed["userAgentDataBrands"] = ["Not_A Brand/8"]
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert probe["checks"]["user_agent_matches_client_hints"] is False


@pytest.mark.parametrize("brands", [None, []])
def test_chromium_probe_cannot_pass_with_missing_client_hints(brands: object) -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36")
    observed["userAgentDataBrands"] = brands
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert probe["checks"]["user_agent_matches_client_hints"] is False
    assert probe["passed"] is False


def test_chromium_probe_cannot_pass_when_user_agent_lacks_a_version() -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Mobile Safari/537.36")
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert probe["checks"]["user_agent_matches_client_hints"] is False
    assert probe["passed"] is False


@pytest.mark.parametrize("mobile", [None, False])
def test_chromium_probe_requires_matching_client_hints_mobile(mobile: object) -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36")
    observed["userAgentDataMobile"] = mobile
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert probe["checks"]["client_hints_mobile"] is False
    assert probe["passed"] is False


def test_the_memory_check_fails_when_a_binary_ignored_the_switch() -> None:
    """A stock binary ignores --browser-core-device-memory-mb silently.

    Without this check the capture would mint a persona carrying the capture
    host's own RAM while believing it had applied an override.
    """
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36")
    observed["deviceMemory"] = 32  # the host's value: the switch did nothing
    probe = _probe_with_browser(
        _FakeBrowser(observed), "153.0.7988.0", _kernel(), device, device_memory_mb=4096
    )
    assert probe["checks"]["device_memory"] is False
    assert probe["passed"] is False


def test_the_memory_check_passes_when_the_browser_honoured_the_switch() -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36")
    observed["deviceMemory"] = 4
    probe = _probe_with_browser(
        _FakeBrowser(observed), "153.0.7988.0", _kernel(), device, device_memory_mb=4096
    )
    assert probe["checks"]["device_memory"] is True


def test_no_memory_check_is_recorded_when_no_override_was_asked_for() -> None:
    """A check that always runs would judge captures that made no claim."""
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36")
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert "device_memory" not in probe["checks"]


class _PartialCdpContext(_FakeContext):
    """A CDP session where the touch override fails and the processor one works.

    Exactly the case that motivated splitting the handlers: sharing one
    try/except meant a failed touch send also cleared the processor override, so
    a persona recorded a core count nothing had verified.
    """

    def new_cdp_session(self, _page: Any) -> Any:
        class _Session:
            def send(self, method: str, _params: dict[str, Any]) -> None:
                if method == "Emulation.setTouchEmulationEnabled":
                    raise RuntimeError("touch emulation unavailable")

        return _Session()


class _PartialCdpBrowser(_FakeBrowser):
    def new_context(self, **options: Any) -> _FakeContext:
        self.options = options
        self.context = _PartialCdpContext(self._observed)
        return self.context


def test_a_failed_touch_override_does_not_cost_the_processor_check() -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Mobile Safari/537.36")
    observed["hardwareConcurrency"] = 8
    probe = _probe_with_browser(
        _PartialCdpBrowser(observed), "153.0.7988.0", _kernel(), device, 8
    )
    # The processor override applied, so its check must still be recorded.
    assert probe["checks"]["hardware_concurrency"] is True
    # The touch override did not, so it claims nothing rather than claiming five.
    assert "max_touch_points" not in probe["checks"]


def test_mobile_probe_cannot_pass_with_one_touch_point_after_override_failure() -> None:
    device = device_from_playwright("Pixel 7", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, align_user_agent_version(device["user_agent"], "153.0.7988.0"))
    observed["maxTouchPoints"] = 1
    probe = _probe_with_browser(_PartialCdpBrowser(observed), "153.0.7988.0", _kernel(), device)
    assert probe["checks"]["multi_touch"] is False
    assert probe["passed"] is False


def test_failed_processor_override_cannot_pass_with_a_different_observed_core_count() -> None:
    device = device_from_playwright("Desktop Chrome", locale="en-US", timezone="America/Chicago")
    observed = _observation(device, "Mozilla/5.0 Chrome/153.0.7988.0 Safari/537.36")
    observed["hardwareConcurrency"] = 8
    probe = _probe_with_browser(_FakeBrowser(observed), "153.0.7988.0", _kernel(), device, 4)
    assert probe["checks"]["hardware_concurrency"] is False
    assert probe["passed"] is False
