"""Gate the observable-surface diff against branded Google Chrome.

The live comparison needs two real binaries and is skipped without them. The
grading logic does not, and that is deliberate: the allowlist is the contract,
so it is locked by tests that run on every host, and a future change that widens
it has to change a test that says why.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import browser_core.surface_diff as surface_diff
from browser_core.errors import ContractError
from browser_core.surface_diff import (
    ALLOWED_DIFFERENCES,
    READ_SURFACE_JS,
    SURFACE_DIFF_SCHEMA,
    compare_surfaces,
    diff_against_branded_chrome,
    render_surface_diff,
)

BRANDED_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")


def _core_executable() -> Path | None:
    workspace = os.environ.get("BROWSER_CORE_WORKSPACE")
    if not workspace:
        return None
    candidate = Path(workspace) / "chromium" / "src" / "out" / "BrowserCore" / "chrome.exe"
    return candidate if candidate.exists() else None


def _surface(**overrides):
    base = {field: "value" for field in surface_diff._SURFACE_TEXT_FIELDS}
    base.update({field: False for field in surface_diff._SURFACE_BOOLEAN_FIELDS})
    base.update({
        field: minimum
        for field, (minimum, _maximum) in surface_diff._SURFACE_INTEGER_RANGES.items()
    })
    base.update({
        field: minimum
        for field, (minimum, _maximum) in surface_diff._SURFACE_REAL_RANGES.items()
    })
    base.update({
        "userAgent": "Mozilla/5.0 HeadlessChrome/153.0.0.0",
        "brands": "Chromium/153, Not_A Brand/8",
        "platform": "Win32",
        "webdriver": False,
        "plugins": 5,
        "pluginNames": "A | B | C | D | E",
        "screen": "1280x720x1280x720",
        "fontsViaMetrics": "",
        "fontWidths": ",".join("1" for _ in surface_diff.PROBE_FONTS),
        "glUnmaskedRenderer": "ANGLE (NVIDIA)",
    })
    base.update(overrides)
    return base


def test_a_diff_between_a_build_and_itself_is_refused_not_passed() -> None:
    """The failure this check was rewritten to prevent.

    The first version reported zero differences because both launches used
    Playwright's bundled Chromium -- the probe helper only honours an executable
    path for attested kernels. A comparison that cannot fail is worse than none,
    so identical versions raise rather than pass.
    """
    with pytest.raises(ContractError, match="same build"):
        compare_surfaces(
            _surface(), _surface(), core_version="153.0.7988.0", branded_version="153.0.7988.0"
        )


def test_the_two_known_differences_are_allowed_and_nothing_else_is() -> None:
    report = compare_surfaces(
        _surface(),
        _surface(userAgent="Mozilla/5.0 HeadlessChrome/150.0.0.0", brands="Not;A=Brand/8, Chromium/150, Google Chrome/150"),
        core_version="153.0.7988.0",
        branded_version="150.0.7871.187",
    )
    assert report["differing"] == ["brands", "userAgent"]
    assert report["unexpected"] == []
    assert report["passed"] is True


def test_a_reopened_automation_tell_fails_the_gate() -> None:
    """The regression this exists to catch: a rebuild that puts webdriver back."""
    report = compare_surfaces(
        _surface(webdriver=True),
        _surface(userAgent="Mozilla/5.0 HeadlessChrome/150.0.0.0",
                 brands="Chromium/150, Google Chrome/150"),
        core_version="153.0.7988.0",
        branded_version="150.0.7871.187",
    )
    assert report["unexpected"] == ["webdriver"]
    assert report["passed"] is False
    assert "UNEXPECTED" in render_surface_diff(report)


@pytest.mark.parametrize(
    ("core_brands", "branded_brands"),
    [
        ("Chromium/153, Not_A Brand/8", "Chromium/151, Not_A Brand/8"),
        ("Chromium/153, Not_A Brand/8", "Chromium/151, Not Google Chrome/151"),
        ("Chromium/153, Not_A Brand/8", "Chromium/151, Google Chrome/150"),
        ("Chromium/153, Google Chrome/153", "Chromium/151, Google Chrome/151"),
        ("Chromium/152, Not_A Brand/8", "Chromium/151, Google Chrome/151"),
        ("Chromium/153, Chromium/153", "Chromium/151, Google Chrome/151"),
        ("Chromium/153, Chromium/152", "Chromium/151, Google Chrome/151"),
        ("Chromium/153,  Google Chrome/153", "Chromium/151, Google Chrome/151"),
        ("Chromium/153, Not_A Brand/8", "Google Chrome/151"),
        ("Chromium/153, Not_A Brand/8", "Chromium/150, Google Chrome/151"),
        ("Chromium/153, Not_A Brand/8", "Chromium/151, Google Chrome/151, Google Chrome/150"),
        ("Chromium/153, Not_A Brand/8", "Chromium/151, Google Chrome/151, Google Chrome/151"),
    ],
)
def test_comparison_refuses_a_misidentified_browser_reference(
    core_brands: str, branded_brands: str
) -> None:
    with pytest.raises(ContractError, match="brands|brand"):
        compare_surfaces(
            _surface(brands=core_brands),
            _surface(brands=branded_brands),
            core_version="153.0.7988.0",
            branded_version="151.0.7871.187",
        )


@pytest.mark.parametrize(
    ("core_agent", "branded_agent"),
    [
        ("Mozilla/5.0 HeadlessChrome/147.0.0.0", "Mozilla/5.0 HeadlessChrome/151.0.0.0"),
        ("Mozilla/5.0 HeadlessChrome/153.0.0.0", "Mozilla/5.0 Chrome/149.0.0.0"),
        ("Mozilla/5.0 NotChrome/153.0.0.0", "Mozilla/5.0 HeadlessChrome/151.0.0.0"),
    ],
)
def test_comparison_refuses_user_agent_major_disagreement(
    core_agent: str, branded_agent: str
) -> None:
    with pytest.raises(ContractError, match="user agent"):
        compare_surfaces(
            _surface(userAgent=core_agent),
            _surface(userAgent=branded_agent,
                     brands="Chromium/151, Google Chrome/151"),
            core_version="153.0.7988.0",
            branded_version="151.0.7871.187",
        )


def test_surface_renderer_rejects_sparse_and_private_foreign_artifacts() -> None:
    private = "private-surface-schema-marker"
    for document in (
        {"schema": SURFACE_DIFF_SCHEMA},
        {"schema": private},
        "not-an-object",
    ):
        with pytest.raises(ContractError) as failure:
            render_surface_diff(document)
        assert private not in str(failure.value)


def test_surface_renderer_requires_a_coherent_closed_report() -> None:
    private = "private-surface-report-marker"
    report = compare_surfaces(
        _surface(),
        _surface(userAgent="Chrome/151", brands="Chromium/151, Google Chrome/151"),
        core_version="153.0",
        branded_version="151.0",
    )
    assert render_surface_diff(report).endswith("PASS")

    mutations = (
        {**report, "differing": [private]},
        {**report, "unexpected": [private]},
        {**report, "fields": len(surface_diff._SURFACE_FIELDS) + 1},
        {**report, "passed": False},
        {**report, "private": private},
        {
            **report,
            "core_build": {
                "chromium_revision": private,
                "executable_sha256_16": "2" * 16,
                "runtime_bundle_sha256_16": "3" * 16,
            },
        },
    )
    for mutation in mutations:
        with pytest.raises(ContractError) as failure:
            render_surface_diff(mutation)
        assert private not in str(failure.value)


def test_surface_renderer_does_not_assert_unsaved_binary_provenance() -> None:
    report = compare_surfaces(
        _surface(),
        _surface(userAgent="Mozilla/5.0 HeadlessChrome/151.0.0.0",
                 brands="Chromium/151, Google Chrome/151"),
        core_version="153.0",
        branded_version="151.0",
    )
    rendered = render_surface_diff(report)
    assert "Browser Core side (reported)" in rendered
    assert "Chrome reference (reported)" in rendered
    assert "attested Browser Core" not in rendered
    assert "branded Google Chrome" not in rendered


def test_compare_surface_boundary_rejects_extra_fields_and_invalid_versions() -> None:
    with pytest.raises(ContractError, match="fields"):
        compare_surfaces(
            {**_surface(), "private": "secret"},
            _surface(),
            core_version="153.0",
            branded_version="151.0",
        )
    with pytest.raises(ContractError, match="bounded ASCII"):
        compare_surfaces(
            _surface(),
            _surface(),
            core_version=True,  # type: ignore[arg-type]
            branded_version="151.0",
        )


@pytest.mark.parametrize("core_version", ["153", "153.foo", "153.00", "153.0.0.0.1"])
def test_comparison_refuses_noncanonical_browser_versions(core_version: str) -> None:
    with pytest.raises(ContractError, match="reference version"):
        compare_surfaces(
            _surface(),
            _surface(userAgent="Chrome/151", brands="Chromium/151, Google Chrome/151"),
            core_version=core_version,
            branded_version="151.0",
        )


def test_surface_renderer_refuses_noncanonical_report_versions() -> None:
    report = compare_surfaces(
        _surface(),
        _surface(userAgent="Chrome/151", brands="Chromium/151, Google Chrome/151"),
        core_version="153.0",
        branded_version="151.0",
    )
    with pytest.raises(ContractError, match="structure"):
        render_surface_diff({**report, "core_version": "153.foo"})


def test_whole_surface_diff_binds_the_core_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import browser_core.surface_diff as surface_diff

    attestation = {
        "chromium_revision": "1" * 40,
        "executable_sha256": "2" * 64,
        "runtime_bundle_sha256": "3" * 64,
    }
    monkeypatch.setattr(surface_diff, "load_build_attestation", lambda *_args: attestation)
    readings = iter([("153.0", _surface()),
                     ("151.0", _surface(
                         userAgent="Mozilla/5.0 HeadlessChrome/151.0.0.0",
                         brands="Chromium/151, Google Chrome/151"))])
    monkeypatch.setattr(surface_diff, "read_surface", lambda _path: next(readings))
    report = surface_diff.diff_against_branded_chrome(
        Path("core.exe"), Path("branded.exe")
    )
    assert report["core_build"] == {
        "chromium_revision": "1" * 40,
        "executable_sha256_16": "2" * 16,
        "runtime_bundle_sha256_16": "3" * 16,
    }
    assert render_surface_diff(report).endswith("PASS")


def test_the_allowlist_is_exactly_these_three_fields() -> None:
    """A lock, not a tautology.

    Every entry is a field a detector can read to separate our build from retail
    Chrome. Widening the set means accepting another such field, so it requires
    editing this assertion and saying why in the same commit -- which is what
    happened when audioSum was added: measured on three builds, deterministic on
    each, and the two stock builds agree with each other while ours does not.

    userAgent and brands cannot be closed here. audioSum is the one entry that is
    an open defect rather than a fact of life, and it should leave this set once
    a build with is_official_build = true has been measured.
    """
    assert ALLOWED_DIFFERENCES == frozenset({"userAgent", "brands", "audioSum"})


def test_the_probe_reads_the_fields_the_gate_claims_to_protect() -> None:
    """Guards against the read script and the claim drifting apart.

    A field silently dropped from the probe would be reported as identical
    forever, because both sides would be missing it.
    """
    for field in (
        "webdriver",
        "plugins",
        "pluginNames",
        "pdfViewerEnabled",
        "glUnmaskedVendor",
        "glUnmaskedRenderer",
        "deviceMemory",
        "hardwareConcurrency",
        "maxTouchPoints",
        "screen",
        "jsHeapLimit",
        "chromeObject",
        "fontsViaApi",
        "fontsViaMetrics",
        "fontWidths",
    ):
        assert f"{field}:" in READ_SURFACE_JS


def test_live_surface_projection_is_closed_finite_and_bounded() -> None:
    observed = _surface()
    observed.update(userAgent="Browser", webdriver=False, plugins=5, audioSum=1.0)
    assert surface_diff._validated_observed_surface(observed)["plugins"] == 5

    with pytest.raises(ContractError, match="invalid value type"):
        surface_diff._validated_observed_surface(
            {field: None for field in surface_diff._SURFACE_FIELDS}
        )
    with pytest.raises(ContractError, match="fields"):
        surface_diff._validated_observed_surface({**observed, "private_path": "secret"})
    with pytest.raises(ContractError, match="number"):
        surface_diff._validated_observed_surface({**observed, "audioSum": float("nan")})
    invalid_numbers = {
        "plugins": 1.5,
        "maxTouchPoints": -1,
        "hardwareConcurrency": 0,
        "fontsViaApi": len(surface_diff.PROBE_FONTS) + 1,
        "devicePixelRatio": 0,
        "audioSum": -0.1,
        "jsHeapLimit": 2**60,
    }
    for field, value in invalid_numbers.items():
        with pytest.raises(ContractError):
            surface_diff._validated_observed_surface({**observed, field: value})
    invalid_text = (
        {**observed, "userAgent": ""},
        {**observed, "language": "en-US\tprivate"},
        {**observed, "screen": "1280x720x1400x720"},
        {**observed, "pluginNames": "A | B"},
        {**observed, "fontsViaMetrics": "private-font"},
        {**observed, "fontWidths": "1,2"},
        {
            **observed,
            "fontWidths": ",".join("NaN" for _ in surface_diff.PROBE_FONTS),
        },
    )
    for mutation in invalid_text:
        with pytest.raises(ContractError, match="text"):
            surface_diff._validated_observed_surface(mutation)
    with pytest.raises(ContractError, match="text"):
        surface_diff._validated_observed_surface(
            {
                **observed,
                "userAgent": "x" * (surface_diff.MAX_SURFACE_TEXT_BYTES + 1),
            }
        )


def _install_surface_reader_fakes(
    monkeypatch: pytest.MonkeyPatch,
    page: object,
    *,
    context_close,
    browser_close,
) -> None:
    import playwright.sync_api as sync_api

    class Context:
        def route(self, *_args, **_kwargs) -> None:
            return None

        def new_page(self):
            return page

        def close(self) -> None:
            context_close()

    class Browser:
        version = "153.0.0.0"

        def new_context(self, **_kwargs):
            return Context()

        def close(self) -> None:
            browser_close()

    class Chromium:
        def launch(self, **_kwargs):
            return Browser()

    class Manager:
        def __enter__(self):
            return type("Playwright", (), {"chromium": Chromium()})()

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(sync_api, "sync_playwright", Manager)


def test_surface_reader_closes_context_and_browser_after_primary_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"browser")
    events: list[str] = []
    private = "private-page-evaluation-diagnostic"

    class Page:
        def goto(self, *_args, **_kwargs) -> None:
            return None

        def evaluate(self, *_args, **_kwargs):
            raise RuntimeError(private)

    _install_surface_reader_fakes(
        monkeypatch,
        Page(),
        context_close=lambda: events.append("context-close"),
        browser_close=lambda: events.append("browser-close"),
    )
    with pytest.raises(ContractError) as raised:
        surface_diff.read_surface(executable)
    assert str(raised.value) == "browser surface observation failed (RuntimeError)"
    assert private not in str(raised.value)
    assert events == ["context-close", "browser-close"]


def test_surface_reader_cleanup_failure_is_phase_labeled_and_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"browser")
    events: list[str] = []

    class Page:
        def goto(self, *_args, **_kwargs) -> None:
            return None

        def evaluate(self, expression, *_args, **_kwargs):  # noqa: ANN001
            return _surface() if expression == READ_SURFACE_JS else 0.5

    def fail(phase: str) -> None:
        events.append(phase)
        raise RuntimeError(f"private-{phase}")

    _install_surface_reader_fakes(
        monkeypatch,
        Page(),
        context_close=lambda: fail("context-close"),
        browser_close=lambda: fail("browser-close"),
    )
    with pytest.raises(ContractError) as raised:
        surface_diff.read_surface(executable)
    assert str(raised.value) == (
        "browser surface observation cleanup failed (context-close,browser-close)"
    )
    assert "private" not in str(raised.value)
    assert events == ["context-close", "browser-close"]


def test_surface_reader_rejects_coerced_and_hard_linked_executables(
    tmp_path: Path,
) -> None:
    import browser_core.surface_diff as surface_diff

    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"fixture")
    with pytest.raises(ContractError, match="path must be a Path"):
        surface_diff.read_surface(str(executable))  # type: ignore[arg-type]

    (tmp_path / "chrome-alias.exe").hardlink_to(executable)
    with pytest.raises(ContractError, match="hard links"):
        surface_diff.read_surface(executable)


@pytest.mark.skipif(
    _core_executable() is None or not BRANDED_CHROME.exists(),
    reason="needs both the attested build (BROWSER_CORE_WORKSPACE) and branded Chrome",
)
def test_live_surface_matches_branded_chrome_except_version_and_brand() -> None:
    core = _core_executable()
    assert core is not None
    report = diff_against_branded_chrome(core, BRANDED_CHROME)
    assert report["unexpected"] == [], render_surface_diff(report)
    assert len(report["identical"]) >= 34
    # The font surface is indistinguishable from retail Chrome on this host by
    # every method measured, including the full per-face width vector.
    for field in ("fontsViaApi", "fontsViaMetrics", "fontWidths"):
        assert field in report["identical"]
