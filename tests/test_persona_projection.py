import copy
import pytest
from browser_core.contracts import ContractError
from browser_core.personas import persona_digest
from browser_core.persona_projection import native_hardware_arguments
from browser_core.persona_projection import native_persona_arguments, require_native_geography
from test_personas import fixture_persona


def hardware_persona(cores=10, memory=32):
    persona = copy.deepcopy(fixture_persona())
    persona["identity_contract"]["expected"].update({
        "window.hardwareConcurrency": cores, "window.deviceMemory": memory,
    })
    persona["integrity_sha256"] = persona_digest(persona)
    return persona


def test_selected_hardware_is_realized_by_native_arguments():
    assert native_hardware_arguments(hardware_persona(), ()) == (
        "--browser-core-hardware-concurrency=10", "--browser-core-device-memory-mb=32768",
    )
    assert native_hardware_arguments(fixture_persona(), ()) == ()


@pytest.mark.parametrize("cores,memory", [(0,32),(1025,32),(True,32),(10,1),(10,12),(10,True)])
def test_unrealizable_hardware_fails_explicitly(cores,memory):
    with pytest.raises(ContractError):
        native_hardware_arguments(hardware_persona(cores,memory), ())


@pytest.mark.parametrize("argument", ["--browser-core-hardware-concurrency=32","--browser-core-device-memory-mb=8192"])
def test_extra_arguments_cannot_silently_replace_persona_claims(argument):
    with pytest.raises(ContractError, match="override"):
        native_hardware_arguments(hardware_persona(), (argument,))


def test_display_and_geography_use_one_native_selection():
    arguments = native_persona_arguments(hardware_persona(), ())
    assert '--browser-core-screen-size=2560,1440' in arguments
    assert '--browser-core-screen-work-area=2560,1440' in arguments
    assert '--force-device-scale-factor=1' in arguments
    assert '--lang=en-US' in arguments
    assert '--browser-core-locale=en-US' in arguments
    assert '--accept-lang=en-US' in arguments
    assert '--browser-core-timezone=America/Chicago' in arguments
    assert '--browser-core-hardware-concurrency=10' in arguments


@pytest.mark.parametrize('argument', [
    '--screen-info={800x600}', '--force-device-scale-factor=2',
    '--browser-core-screen-size=800,600', '--browser-core-screen-work-area=800,600',
    '--window-size=800,600', '--window-position=100,100',
    '--lang=fr-FR', '--accept-lang=fr-FR', '--browser-core-timezone=Europe/Paris',
    '--browser-core-locale=fr-FR',
])
def test_persona_selection_rejects_conflicting_overrides(argument):
    with pytest.raises(ContractError, match='override'):
        native_persona_arguments(fixture_persona(), (argument,))


def test_contradictory_screen_claim_is_not_silently_replaced():
    persona = hardware_persona()
    persona['identity_contract']['expected']['window.screen.width'] = 800
    persona['integrity_sha256'] = persona_digest(persona)
    with pytest.raises(ContractError, match='contradicts'):
        native_persona_arguments(persona, ())


@pytest.mark.parametrize('field,value', [('locale','en-GB'),('languages',['en-US','en']),('timezone','Europe/Paris')])
def test_observed_geography_must_match_before_session_publication(field,value):
    persona = fixture_persona()
    observed = {k:persona['geography'][k] for k in ('locale','languages','timezone')}
    require_native_geography(persona, observed)
    observed[field] = value
    with pytest.raises(ContractError, match='not realized'):
        require_native_geography(persona, observed)
