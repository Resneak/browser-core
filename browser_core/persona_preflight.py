"""Verify selected native profile settings before publishing a ready session.

This is a startup settings check, not Browser Eval's independent regression
matrix. It reads a fresh owned secure local document, never a research page.
No page properties, device metrics or CDP domains are overridden/enabled.
"""
from __future__ import annotations

import math
import time
from tempfile import TemporaryDirectory

from .cdp import (
    _positive_finite_seconds, _remaining_deadline_seconds,
    evaluate_page_expression, temporary_startup_page,
)
from .contracts import ContractError
from .prepared_download import guarded_temporary_directory


SUPPORTED_CLAIMS = frozenset({
    "rendering.webgl.renderer", "rendering.webgl.vendor", "rendering.webgl.version",
    "userAgentData.mobile", "userAgentData.platform", "userAgentData.brands",
    "window.userAgent", "window.deviceMemory", "window.hardwareConcurrency",
    "window.languages", "window.locale", "window.maxTouchPoints",
    "window.mimeTypesLength", "window.pdfViewerEnabled", "window.platform",
    "window.pluginsLength", "window.screen.colorDepth", "window.screen.devicePixelRatio",
    "window.screen.height", "window.screen.pixelDepth", "window.screen.width",
    "window.screen.availHeight", "window.screen.availWidth", "window.timezone",
})

# Fixed code; contract keys/values are never interpolated into JavaScript.
_READ_NATIVE_SETTINGS = """(() => {
 const canvas=document.createElement('canvas');
 const gl=canvas.getContext('webgl2')||canvas.getContext('webgl');
 const debug=gl && gl.getExtension('WEBGL_debug_renderer_info');
 try {
  return {url:location.href,secure:isSecureContext,claims:{
   'rendering.webgl.renderer':gl ? gl.getParameter(debug?debug.UNMASKED_RENDERER_WEBGL:gl.RENDERER):null,
   'rendering.webgl.vendor':gl ? gl.getParameter(debug?debug.UNMASKED_VENDOR_WEBGL:gl.VENDOR):null,
   'rendering.webgl.version':gl ? gl.getParameter(gl.VERSION):null,
   'userAgentData.mobile':navigator.userAgentData?.mobile ?? null,
   'userAgentData.platform':navigator.userAgentData?.platform ?? null,
   'userAgentData.brands':navigator.userAgentData?.brands.map(b=>b.brand+'/'+b.version) ?? null,
   'window.userAgent':navigator.userAgent,
   'window.deviceMemory':navigator.deviceMemory ?? null,
   'window.hardwareConcurrency':navigator.hardwareConcurrency,
   'window.languages':Array.from(navigator.languages),
   'window.locale':Intl.DateTimeFormat().resolvedOptions().locale,
   'window.maxTouchPoints':navigator.maxTouchPoints,
   'window.mimeTypesLength':navigator.mimeTypes.length,
   'window.pdfViewerEnabled':navigator.pdfViewerEnabled,
   'window.platform':navigator.platform,'window.pluginsLength':navigator.plugins.length,
   'window.screen.colorDepth':screen.colorDepth,'window.screen.devicePixelRatio':devicePixelRatio,
   'window.screen.height':screen.height,'window.screen.pixelDepth':screen.pixelDepth,
   'window.screen.width':screen.width,'window.screen.availHeight':screen.availHeight,
   'window.screen.availWidth':screen.availWidth,
   'window.timezone':Intl.DateTimeFormat().resolvedOptions().timeZone
  }};
 } finally {gl?.getExtension('WEBGL_lose_context')?.loseContext();}
})()"""


def require_supported_native_claims(persona: dict) -> None:
    """Do not silently omit custom contract claims from a ready-session check."""
    expected = persona['identity_contract']['expected']
    if not expected or set(expected) - SUPPORTED_CLAIMS:
        raise ContractError(
            'selected persona contains claims this native startup check cannot verify; '
            'use a profile captured from this browser'
        )


def _same_value(expected: object, observed: object) -> bool:
    # JSON numbers may be decoded as int or float; booleans are not numbers.
    if type(expected) in (int, float) and type(observed) in (int, float):
        return (all(type(value) is int or math.isfinite(value) for value in (expected, observed))
                and expected == observed)
    if type(expected) is not type(observed):
        return False
    if isinstance(expected, list):
        return len(expected) == len(observed) and all(
            _same_value(a, b) for a, b in zip(expected, observed)
        )
    return expected == observed


def require_native_claims(persona: dict, observed: dict) -> None:
    require_supported_native_claims(persona)
    if not isinstance(observed, dict) or set(observed) != SUPPORTED_CLAIMS:
        raise ContractError('native startup settings observation is incomplete')
    mismatches = sorted(
        key for key, value in persona['identity_contract']['expected'].items()
        if not _same_value(value, observed[key])
    )
    if mismatches:
        # Only our fixed field names are reported, never actual/claimed values.
        from .errors import PersonaRealizationError

        raise PersonaRealizationError(
            'selected persona was not realized: ' + ', '.join(mismatches)
            + '; capture a new profile from this browser or choose a compatible one'
        )


def verify_native_persona(
    persona: dict, cdp_endpoint: str, *, timeout_seconds: float = 10.0,
) -> None:
    require_supported_native_claims(persona)
    timeout_seconds = _positive_finite_seconds(timeout_seconds, label='native startup settings')
    deadline = time.monotonic() + timeout_seconds
    # File documents are secure contexts without opening a new network route.
    # This also works with the offline runner's exact-origin proxy containment.
    # Guard the directory identity while the owned page may observe its path.
    body = b'<!doctype html><meta http-equiv="Content-Security-Policy" content="default-src \'none\'"><title>Browser Core profile check</title>'
    with guarded_temporary_directory(
            TemporaryDirectory(prefix='browser-core-startup-'),
            label='native startup fixture directory',
    ) as directory:
        fixture = directory / 'profile.html'
        with fixture.open('xb') as stream:
            if stream.write(body) != len(body):
                raise ContractError('native startup fixture write was incomplete')
        remaining = _remaining_deadline_seconds(deadline, label='native startup settings')
        with temporary_startup_page(cdp_endpoint, fixture, timeout_seconds=remaining) as url:
            observed = evaluate_page_expression(
                cdp_endpoint, _READ_NATIVE_SETTINGS, target_url=url,
                timeout_seconds=_remaining_deadline_seconds(deadline, label='native startup settings'),
                command_id=962,
            )
            if (not isinstance(observed, dict) or set(observed) != {'url', 'secure', 'claims'}
                    or observed['url'] != url or observed['secure'] is not True):
                raise ContractError('native startup settings require the owned secure document')
            require_native_claims(persona, observed['claims'])
