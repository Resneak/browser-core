import pytest
import browser_core.browser_facts as facts
from browser_core.contracts import ContractError


def observation(width):
    return {'window':{'inner_width':800,'inner_height':600,'outer_width':width,'outer_height':680}}


def controlled_clock(monkeypatch):
    clock=[0.0]
    monkeypatch.setattr(facts.time,'monotonic',lambda:clock[0])
    monkeypatch.setattr(facts.time,'sleep',lambda delay:clock.__setitem__(0,clock[0]+delay))
    return clock


def test_startup_zero_waits_for_real_geometry_and_recaptures(monkeypatch):
    clock=controlled_clock(monkeypatch)
    observations=iter([observation(0),observation(816)])
    probes=iter([False,False,True])
    result=facts._collect_ready_browser_facts(lambda:next(observations),lambda:next(probes),1)
    assert result['window']['outer_width']==816
    assert clock[0]==pytest.approx(.15)
    with pytest.raises(StopIteration):next(observations)


def test_permanent_zero_expires_without_fabricating_facts(monkeypatch):
    clock=controlled_clock(monkeypatch)
    with pytest.raises(ContractError,match='timed out'):
        facts._collect_ready_browser_facts(lambda:observation(0),lambda:False,.13)
    assert clock[0]==pytest.approx(.13)


@pytest.mark.parametrize('width',[-1,False,'0',816])
def test_invalid_or_ready_geometry_is_left_for_existing_validation(width):
    original=observation(width)
    def no_probe():raise AssertionError('not the startup race')
    assert facts._collect_ready_browser_facts(lambda:original,no_probe,0) is original


def test_invalid_readiness_is_not_truthiness_coerced(monkeypatch):
    controlled_clock(monkeypatch)
    with pytest.raises(ContractError,match='non-boolean'):
        facts._collect_ready_browser_facts(lambda:observation(0),lambda:{'ready':True},1)
