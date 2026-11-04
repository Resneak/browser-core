from types import SimpleNamespace
from contextlib import nullcontext
import pytest
import browser_core.kernels as kernels
from browser_core.contracts import ContractError
from browser_core.personas import persona_from_kernel_probe
from test_probe_context_options import _FakeBrowser, _kernel, _observation


def captured(marker=True):
    device=kernels.device_from_playwright('Desktop Chrome',locale='en-US',timezone='America/Chicago')
    observed=_observation(device,kernels.align_user_agent_version(device['user_agent'],'153.0.7988.0'))
    observed.update(webglVendor='Google Inc. (NVIDIA)',webglRenderer='ANGLE (NVIDIA GPU)',
                    webglVersion='WebGL 2.0 (OpenGL ES 3.0 Chromium)')
    if not marker:
        observed.pop('webglIdentitySchema')
    probe=kernels._probe_with_browser(_FakeBrowser(observed),'153.0.7988.0',_kernel(),device)
    return device,probe


def make_persona(device,probe,kernel=None):
    return persona_from_kernel_probe(kernel or _kernel(),device,probe,persona_id='canonical-capture',name='Canonical capture',
        kernel_id='k-1',os_family='windows',os_version='11',architecture='x86_64',country='US',locale='en-US',timezone_name='America/Chicago')


def test_legacy_webgl_evidence_cannot_mint_a_new_ambiguous_contract():
    with pytest.raises(ContractError,match='recapture'):
        make_persona(*captured(False))


def test_canonical_graphics_values_are_preserved_in_contract_and_evidence():
    persona,evidence=make_persona(*captured())
    assert persona['identity_contract']['expected']['rendering.webgl.renderer']=='ANGLE (NVIDIA GPU)'
    assert persona['identity_contract']['expected']['rendering.webgl.version']=='WebGL 2.0 (OpenGL ES 3.0 Chromium)'
    assert evidence['probe']['observed']['webglIdentitySchema']=='webgl2-preferred-unmasked-v1'


@pytest.mark.parametrize(('field', 'value'), [
    ('schema', 'browser-core.kernel-probe/0'),
    ('kernel_id', 'other-kernel'),
    ('engine', 'firefox'),
    ('device_id', 'other-device'),
    ('device_realization', 'native-host'),
])
def test_passing_probe_must_belong_to_selected_kernel_and_device(field, value):
    device, probe = captured()
    probe[field] = value
    with pytest.raises(ContractError, match='probe provenance'):
        make_persona(device, probe)


def test_passing_probe_cannot_hide_a_failed_realization_check():
    device, probe = captured()
    probe['checks']['viewport'] = False
    assert probe['passed'] is True
    with pytest.raises(ContractError, match='probe checks'):
        make_persona(device, probe)


@pytest.mark.parametrize(('section', 'field', 'delta'), [
    ('viewport', 'width', -100),
    ('viewport', 'height', -100),
    ('screen', 'width', 100),
    ('screen', 'height', 100),
    (None, 'device_scale_factor', 0.5),
])
def test_passing_probe_cannot_mint_against_changed_device_geometry(section, field, delta):
    device, probe = captured()
    target = device[section] if section else device
    target[field] += delta
    assert probe['passed'] is True
    with pytest.raises(ContractError, match='probe observation does not match selected device'):
        make_persona(device, probe)


@pytest.mark.parametrize('missing', [
    'owned_fixture', 'secure_context', 'viewport', 'screen',
    'scale', 'touch', 'locale', 'timezone',
    'user_agent', 'user_agent_matches_client_hints', 'client_hints_mobile',
])
def test_passing_probe_cannot_omit_a_required_realization_check(missing):
    device, probe = captured()
    del probe['checks'][missing]
    assert probe['passed'] is True
    with pytest.raises(ContractError, match='probe checks'):
        make_persona(device, probe)


def test_passing_mobile_probe_cannot_omit_multi_touch_check():
    device=kernels.device_from_playwright('Pixel 7',locale='en-US',timezone='America/Chicago')
    observed=_observation(device,kernels.align_user_agent_version(device['user_agent'],'153.0.7988.0'))
    probe=kernels._probe_with_browser(_FakeBrowser(observed),'153.0.7988.0',_kernel(),device)
    assert probe['passed'] is True
    del probe['checks']['multi_touch']
    with pytest.raises(ContractError, match='probe checks'):
        persona_from_kernel_probe(
            _kernel(),device,probe,persona_id='missing-multi-touch',name='Missing multi touch',
            kernel_id='k-1',os_family='android',os_version='14',architecture='arm64',
            country='US',locale='en-US',timezone_name='America/Chicago',
        )


@pytest.mark.parametrize('value', [None, '', 1, False])
def test_missing_or_invalid_intl_locale_cannot_be_inferred_from_language(value):
    device,probe=captured()
    probe['observed']['intlLocale']=value
    with pytest.raises(ContractError,match='measured Intl locale'):
        make_persona(device,probe)


def test_actual_formatting_locale_does_not_silently_become_language_preference():
    device,probe=captured()
    probe['observed']['intlLocale']='de-DE'
    with pytest.raises(ContractError,match='contradict'):
        make_persona(device,probe)


def test_native_desktop_capture_does_not_substitute_a_preset_user_agent():
    device,probe=captured()
    kernel=_kernel()
    kernel.update(product='browser-core',source={'kind':'attested-browser-core'})
    browser=_FakeBrowser(probe['observed'])
    native_probe=kernels._probe_with_browser(browser,'153.0.7988.0',kernel,device)
    assert 'user_agent' not in browser.options
    assert 'user_agent' not in native_probe['checks']
    persona,_=make_persona(device,native_probe,kernel)
    assert persona['kernel']['product']=='browser-core'


def test_single_native_probe_uses_the_named_executable(monkeypatch):
    selected=[]
    class Browser:
        version='153.0.7988.0'
        def close(self):pass
    def launch(**kwargs):
        selected.append(kwargs)
        return Browser()
    kernel={'engine':'chromium','source':{'kind':'attested-browser-core'},'executable':'owned/native/chrome.exe'}
    monkeypatch.setattr(kernels,'_check_probe_preconditions',lambda k,d:(k,d))
    monkeypatch.setattr(kernels,'_verify_probe_executable',lambda k,b:None)
    monkeypatch.setattr(kernels,'_playwright',lambda:(lambda:nullcontext(SimpleNamespace(chromium=SimpleNamespace(launch=launch))),'test'))
    monkeypatch.setattr(kernels,'_probe_with_browser',lambda *args:{'passed':True})
    assert kernels.probe_playwright_kernel(kernel,{})['passed']
    assert selected[0]['executable_path']=='owned/native/chrome.exe'
    assert '--browser-core-evaluation' in selected[0]['args']
