"""Native hardware settings for an explicitly selected desktop persona."""
from __future__ import annotations

from .contracts import ContractError
from .chromium_arguments import classify_arguments
from .personas import reject_incoherent_persona, validate_persona
from .kernels import timezones_equivalent

HARDWARE_SWITCHES = frozenset({
    "--browser-core-hardware-concurrency", "--browser-core-device-memory-mb",
})


def native_hardware_arguments(persona: dict, extra_args: tuple[str, ...]) -> tuple[str, ...]:
    persona = validate_persona(persona)
    if not isinstance(extra_args, tuple) or not all(isinstance(arg, str) for arg in extra_args):
        raise ContractError("persona extra arguments are invalid")
    expected = persona["identity_contract"]["expected"]
    arguments = []
    concurrency = expected.get("window.hardwareConcurrency")
    memory = expected.get("window.deviceMemory")
    if concurrency is not None:
        if type(concurrency) is not int or not 1 <= concurrency <= 1024:
            raise ContractError("persona hardware concurrency cannot be realized")
        arguments.append(f"--browser-core-hardware-concurrency={concurrency}")
    if memory is not None:
        if type(memory) not in (int, float) or memory not in (2, 4, 8, 16, 32):
            raise ContractError("persona memory cannot be realized by this desktop build")
        arguments.append(f"--browser-core-device-memory-mb={int(memory * 1024)}")
    managed = set(classify_arguments(tuple(arguments)).switches)
    if managed.intersection(classify_arguments(extra_args).switches):
        raise ContractError("extra arguments cannot override selected persona hardware")
    return tuple(arguments)


def native_persona_arguments(persona: dict, extra_args: tuple[str, ...]) -> tuple[str, ...]:
    """Translate the selected desktop profile into process-native settings.

    ScreenInfo supplies the same virtual display to headed and headless frames;
    Chromium's scale-factor setting keeps native rendering and CSS aligned.
    """
    persona = reject_incoherent_persona(validate_persona(persona))
    from .persona_preflight import require_supported_native_claims

    require_supported_native_claims(persona)
    arguments = list(native_hardware_arguments(persona, extra_args))
    device = persona['device']
    screen = device['screen']
    viewport = device['viewport']
    geography = persona['geography']
    expected = persona['identity_contract']['expected']
    available = [expected.get('window.screen.availWidth', screen['width']),
                 expected.get('window.screen.availHeight', screen['height'])]
    if any(type(value) is not int or not 200 <= value <= screen[dimension]
           for value, dimension in zip(available, ('width', 'height'))):
        raise ContractError('persona screen work area cannot be realized')
    arguments += [
        f"--browser-core-screen-size={screen['width']},{screen['height']}",
        f"--browser-core-screen-work-area={available[0]},{available[1]}",
        f"--force-device-scale-factor={viewport['device_scale_factor']:g}",
        f"--window-size={viewport['width']},{viewport['height']}",
        '--window-position=0,0',
        '--lang=' + geography['locale'],
        '--browser-core-locale=' + geography['locale'],
        '--accept-lang=' + ','.join(geography['languages']),
        '--browser-core-timezone=' + geography['timezone'],
    ]
    managed = set(classify_arguments(tuple(arguments)).switches)
    managed.add('screen-info')
    if managed.intersection(classify_arguments(extra_args).switches):
        raise ContractError('extra arguments cannot override selected persona settings')
    return tuple(arguments)


def require_native_geography(persona: dict, observed: dict) -> None:
    """Do not publish a usable session when the native geo setting failed."""
    geography = persona['geography']
    if (observed.get('locale') != geography['locale']
            or observed.get('languages') != geography['languages']
            or not timezones_equivalent(observed.get('timezone'), geography['timezone'])):
        raise ContractError('selected persona geography was not realized by the browser')
