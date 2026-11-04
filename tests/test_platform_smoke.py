from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import browser_core.platform_smoke as smoke_module
from browser_core.contracts import ContractError
from browser_core.platform_smoke import (
    CONTROL_PLANE_PREFLIGHT_URL,
    ControlPlaneSmoke,
    _complete_leased_job,
    _preflight_control_plane_smoke,
    run_control_plane_smoke,
    validate_control_plane_smoke_config,
)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda config, root: (object(), root),
        lambda config, root: (replace(config, workspace="workspace"), root),
        lambda config, _root: (config, "repository"),
        lambda config, root: (replace(config, network_route_id=True), root),
        lambda config, root: (replace(config, network_route_id="../route"), root),
        lambda config, root: (replace(config, network_route_id="\ud800"), root),
    ],
)
def test_control_plane_smoke_config_rejects_malformed_intent_purely(
    tmp_path: Path,
    mutation,
) -> None:
    config = ControlPlaneSmoke(tmp_path / "workspace", "route-one")
    mutated_config, repository_root = mutation(config, tmp_path)

    with pytest.raises(ContractError):
        validate_control_plane_smoke_config(mutated_config, repository_root)

    assert list(tmp_path.iterdir()) == []


def test_control_plane_smoke_preflights_route_before_durable_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = ControlPlaneSmoke(tmp_path / "workspace", "route-one")
    store_contact: list[bool] = []
    monkeypatch.setattr(
        smoke_module,
        "load_network_route",
        lambda *_args, **_kwargs: {
            "id": "route-one",
            "preflight_url": "https://example.invalid/probe",
        },
    )
    monkeypatch.setattr(
        smoke_module,
        "ControlStore",
        lambda *_args, **_kwargs: store_contact.append(True),
    )

    with pytest.raises(ContractError, match="preflight URL"):
        run_control_plane_smoke(config, tmp_path)

    assert store_contact == []
    assert not (tmp_path / "workspace" / "acceptance").exists()


def test_control_plane_smoke_preflight_returns_bound_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = ControlPlaneSmoke(tmp_path / "workspace", "route-one")
    route = {
        "id": "route-one",
        "preflight_url": CONTROL_PLANE_PREFLIGHT_URL,
    }
    calls: list[tuple[Path, str]] = []

    def load(workspace: Path, route_id: str) -> dict:
        calls.append((workspace, route_id))
        return route

    monkeypatch.setattr(smoke_module, "load_network_route", load)

    assert _preflight_control_plane_smoke(config, tmp_path) is route
    assert calls == [(config.workspace, "route-one")]


def test_control_plane_smoke_normalizes_store_initialization_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = ControlPlaneSmoke(tmp_path / "workspace", "route-one")
    monkeypatch.setattr(
        smoke_module,
        "load_network_route",
        lambda *_args, **_kwargs: {
            "id": "route-one",
            "preflight_url": CONTROL_PLANE_PREFLIGHT_URL,
        },
    )
    monkeypatch.setattr(
        smoke_module,
        "ControlStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("private database path")
        ),
    )

    with pytest.raises(
        ContractError,
        match=r"store could not initialize \(OSError\)",
    ) as raised:
        run_control_plane_smoke(config, tmp_path)

    assert "private database path" not in str(raised.value)


@pytest.mark.parametrize(
    "leased",
    [
        [],
        {"id": "job-one", "lease_token": None},
        {"id": "job-one", "lease_token": "bad token"},
        {"id": "job-one", "lease_token": "\ud800"},
    ],
)
def test_complete_leased_job_rejects_bad_lease_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    leased,
) -> None:
    executed: list[bool] = []
    monkeypatch.setattr(
        smoke_module,
        "execute_typed_job",
        lambda *_args, **_kwargs: executed.append(True),
    )

    with pytest.raises(ContractError):
        _complete_leased_job(
            object(),  # type: ignore[arg-type]
            leased,
            repository_root=tmp_path,
            workspace=tmp_path,
            network_route={},
        )

    assert executed == []


@pytest.mark.parametrize(
    "completion",
    [
        None,
        [],
        {"id": "job-two", "state": "succeeded"},
        {"id": "job-one", "state": "running"},
    ],
)
def test_complete_leased_job_requires_matching_terminal_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    completion,
) -> None:
    monkeypatch.setattr(
        smoke_module,
        "execute_typed_job",
        lambda *_args, **_kwargs: {"passed": True},
    )
    monkeypatch.setattr(
        smoke_module,
        "validate_network_preflight_receipt",
        lambda result, _route: result,
    )

    class Client:
        def worker_complete(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
            return completion

    with pytest.raises(ContractError, match="typed job did not succeed"):
        _complete_leased_job(
            Client(),  # type: ignore[arg-type]
            {"id": "job-one", "lease_token": "lease-token"},
            repository_root=tmp_path,
            workspace=tmp_path,
            network_route={},
        )


def test_complete_leased_job_returns_matching_terminal_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        smoke_module,
        "execute_typed_job",
        lambda *_args, **_kwargs: {"passed": True},
    )
    monkeypatch.setattr(
        smoke_module,
        "validate_network_preflight_receipt",
        lambda result, _route: result,
    )
    receipt = {"id": "job-one", "state": "succeeded"}

    class Client:
        def worker_complete(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
            return receipt

    assert (
        _complete_leased_job(
            Client(),  # type: ignore[arg-type]
            {"id": "job-one", "lease_token": "lease-token"},
            repository_root=tmp_path,
            workspace=tmp_path,
            network_route={},
        )
        is receipt
    )


def test_complete_leased_job_rejects_invalid_result_before_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        smoke_module,
        "execute_typed_job",
        lambda *_args, **_kwargs: {"passed": False},
    )
    monkeypatch.setattr(
        smoke_module,
        "validate_network_preflight_receipt",
        lambda *_args: (_ for _ in ()).throw(ContractError("invalid preflight")),
    )

    class Client:
        def worker_complete(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
            pytest.fail("invalid result must not reach completion")

    with pytest.raises(ContractError, match="invalid preflight"):
        _complete_leased_job(
            Client(),  # type: ignore[arg-type]
            {"id": "job-one", "lease_token": "lease-token"},
            repository_root=tmp_path,
            workspace=tmp_path,
            network_route={},
        )
