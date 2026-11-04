from __future__ import annotations

import base64
import hashlib
import io
import os
import socket
import subprocess
import threading
import urllib.error
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.network as network_module
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from browser_core.network import (
    _connect_http_proxy,
    _connect_socks5_proxy,
    _recv_exact,
    _recv_headers,
    add_network_route,
    add_network_route_with_receipt,
    build_network_route,
    list_network_routes,
    load_network_route,
    normalize_geo_observation,
    observe_geo_alignment,
    preflight_network_route,
    resolve_network_route,
    rollback_network_route_publication,
    route_digest,
    validate_network_route,
    validate_geo_alignment,
)


def test_route_inventory_stops_scanning_after_entry_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(network_module, "MAX_NETWORK_ROUTE_DIRECTORY_ENTRIES", 2)

    class Entries:
        requests = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            self.requests += 1
            if self.requests > 3:
                pytest.fail("route inventory scanned beyond its limit")
            return SimpleNamespace(name=f"{self.requests}.json")

    entries = Entries()
    monkeypatch.setattr(network_module.os, "scandir", lambda _: entries)
    with pytest.raises(ContractError, match="too many entries"):
        network_module._network_route_inventory(tmp_path)
    assert entries.requests == 3


def test_route_inventory_rejects_casefold_duplicate_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "Alpha.json"
    second = tmp_path / "alpha-other.json"
    first.write_bytes(b"{}")
    second.write_bytes(b"{}")
    entries = (
        SimpleNamespace(name="Alpha.json", path=str(first), is_symlink=lambda: False),
        SimpleNamespace(name="alpha.json", path=str(second), is_symlink=lambda: False),
    )

    class SyntheticScan:
        def __enter__(self):
            return iter(entries)

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(network_module.os, "scandir", lambda _path: SyntheticScan())
    with pytest.raises(ContractError, match="duplicate IDs"):
        network_module._network_route_inventory(tmp_path)


def geography() -> dict:
    return {
        "country": "US",
        "locale": "en-US",
        "timezone": "America/Chicago",
        "coordinates": {"latitude": 41.8781, "longitude": -87.6298, "radius_km": 100},
    }


def proxy_route(protocol: str = "http", port: int = 3128) -> dict:
    return build_network_route(
        route_id=f"lab-{protocol}",
        name=f"Lab {protocol}",
        mode="proxy",
        endpoint={"protocol": protocol, "host": "127.0.0.1", "port": port},
        auth={"username_env": "LAB_PROXY_USER", "password_env": "LAB_PROXY_PASSWORD"},
        geography=geography(),
    )


@pytest.mark.parametrize("host", ["[owned.example]", "[127.0.0.1]"])
def test_proxy_target_rejects_brackets_for_non_ipv6(host: str) -> None:
    with pytest.raises(ContractError, match="target host is invalid"):
        network_module._target_host_forms(host)


def test_proxy_target_keeps_bracketed_ipv6_authority() -> None:
    assert network_module._target_host_forms("[2001:db8::1]") == (
        "2001:db8::1",
        "[2001:db8::1]",
    )


@pytest.mark.parametrize("protocol", ["http", "https"])
def test_http_proxy_rejects_colon_in_username(protocol: str) -> None:
    with pytest.raises(ContractError, match="credentials are invalid"):
        resolve_network_route(
            proxy_route(protocol),
            {"LAB_PROXY_USER": "alice:other", "LAB_PROXY_PASSWORD": "password"},
        )


def test_socks5_credentials_keep_colon_in_username() -> None:
    resolved = resolve_network_route(
        proxy_route("socks5"),
        {"LAB_PROXY_USER": "alice:other", "LAB_PROXY_PASSWORD": "password"},
    )
    assert resolved.username == "alice:other"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
@pytest.mark.parametrize("operation", ["load", "list", "add"])
def test_network_routes_reject_network_parent_junction(
    tmp_path: Path, operation: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    external = tmp_path / "external"
    routes = external / "routes"
    routes.mkdir(parents=True)
    existing = proxy_route()
    (routes / f"{existing['id']}.json").write_bytes(canonical_json_bytes(existing))
    junction = workspace / "network"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
        capture_output=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        with pytest.raises(ContractError, match="network route directory"):
            if operation == "load":
                load_network_route(workspace, existing["id"])
            elif operation == "list":
                list_network_routes(workspace)
            else:
                add_network_route(workspace, proxy_route("socks5"))
        assert sorted(path.name for path in routes.iterdir()) == [f"{existing['id']}.json"]
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
@pytest.mark.parametrize("operation", ["load", "list", "add"])
def test_network_routes_reject_workspace_junction(tmp_path: Path, operation: str) -> None:
    external = tmp_path / "external"
    routes = external / "network" / "routes"
    routes.mkdir(parents=True)
    existing = proxy_route()
    (routes / f"{existing['id']}.json").write_bytes(canonical_json_bytes(existing))
    junction = tmp_path / "workspace"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
        capture_output=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        with pytest.raises(ContractError, match="network route directory"):
            if operation == "load":
                load_network_route(junction, existing["id"])
            elif operation == "list":
                list_network_routes(junction)
            else:
                add_network_route(junction, proxy_route("socks5"))
        assert sorted(path.name for path in routes.iterdir()) == [f"{existing['id']}.json"]
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_route_load_rechecks_workspace_after_path_admission(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hidden = tmp_path / "original-workspace"
    external = tmp_path / "external"
    routes = external / "network" / "routes"
    routes.mkdir(parents=True)
    route = proxy_route()
    (routes / f"{route['id']}.json").write_bytes(canonical_json_bytes(route))
    original_identity = network_module.directory_identity
    swapped = False

    def switch_after_workspace_check(path, *, label):
        nonlocal swapped
        identity = original_identity(path, label=label)
        if path == workspace and not swapped:
            workspace.rename(hidden)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(workspace), str(external)],
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                hidden.rename(workspace)
                pytest.skip("directory junction creation is unavailable")
            swapped = True
        return identity

    monkeypatch.setattr(network_module, "directory_identity", switch_after_workspace_check)
    try:
        with pytest.raises(ContractError, match="network route directory"):
            load_network_route(workspace, route["id"])
        assert swapped
    finally:
        if swapped:
            workspace.rmdir()
            hidden.rename(workspace)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_empty_route_list_rechecks_workspace_after_path_admission(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hidden = tmp_path / "original-workspace"
    external = tmp_path / "external"
    (external / "network" / "routes").mkdir(parents=True)
    original_identity = network_module.directory_identity
    swapped = False

    def switch_after_workspace_check(path, *, label):
        nonlocal swapped
        identity = original_identity(path, label=label)
        if path == workspace and not swapped:
            workspace.rename(hidden)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(workspace), str(external)],
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                hidden.rename(workspace)
                pytest.skip("directory junction creation is unavailable")
            swapped = True
        return identity

    monkeypatch.setattr(network_module, "directory_identity", switch_after_workspace_check)
    try:
        with pytest.raises(ContractError, match="network route directory"):
            list_network_routes(workspace)
        assert swapped
    finally:
        if swapped:
            workspace.rmdir()
            hidden.rename(workspace)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_route_publish_rechecks_workspace_after_missing_route_read(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hidden = tmp_path / "original-workspace"
    external = tmp_path / "external"
    external.mkdir()
    original_load = network_module._load_network_route_snapshot
    swapped = False

    def switch_after_missing_read(*args, **kwargs):
        nonlocal swapped
        result = original_load(*args, **kwargs)
        if not swapped:
            workspace.rename(hidden)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(workspace), str(external)],
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                hidden.rename(workspace)
                pytest.skip("directory junction creation is unavailable")
            swapped = True
        return result

    monkeypatch.setattr(network_module, "_load_network_route_snapshot", switch_after_missing_read)
    try:
        with pytest.raises(ContractError, match="network route directory"):
            add_network_route(workspace, proxy_route())
        assert swapped
        assert list(external.iterdir()) == []
    finally:
        if swapped:
            workspace.rmdir()
            hidden.rename(workspace)


def test_route_builder_rejects_explicit_empty_policies() -> None:
    with pytest.raises(ContractError, match="policies are required"):
        build_network_route(
            route_id="lab-direct",
            name="Lab direct",
            geography=geography(),
            policies={},
        )


@pytest.mark.parametrize("route_id", ["NUL", "con.log", "LPT9.backup"])
def test_route_builder_rejects_windows_device_basename(route_id: str) -> None:
    with pytest.raises(ContractError, match="network route ID"):
        build_network_route(route_id=route_id, name="Fixture", geography=geography())


def test_route_store_rejects_device_basename_before_creating_directory(
    tmp_path: Path,
) -> None:
    route = build_network_route(route_id="safe-route", name="Fixture", geography=geography())
    route["id"] = "NUL"
    route["integrity_sha256"] = route_digest(route)
    with pytest.raises(ContractError, match="network route ID"):
        add_network_route(tmp_path, route)
    assert not (tmp_path / "network").exists()


def test_route_builder_detaches_caller_owned_nested_documents() -> None:
    location = geography()
    endpoint = {"protocol": "http", "host": "proxy.example", "port": 3128}
    auth = {"username_env": "PROXY_USER", "password_env": "PROXY_PASS"}
    policies = {"dns": "route", "webrtc": "route-only", "require_alignment": True}
    route = build_network_route(
        route_id="owned-inputs",
        name="Owned inputs",
        geography=location,
        mode="proxy",
        endpoint=endpoint,
        auth=auth,
        policies=policies,
    )
    saved = canonical_json_bytes(route)

    location["country"] = "CA"
    location["coordinates"]["latitude"] = 49.0
    endpoint["host"] = "replacement.example"
    auth["username_env"] = "OTHER_USER"
    policies["dns"] = "system"

    assert canonical_json_bytes(route) == saved
    assert validate_network_route(route) == route


def test_route_rejects_nonstring_created_at_without_coercion() -> None:
    route = build_network_route(
        route_id="lab-direct",
        name="Lab direct",
        geography=geography(),
    )

    class UnexpectedStringConversion:
        def __str__(self) -> str:
            pytest.fail("invalid created_at was converted before type validation")

    route["created_at"] = UnexpectedStringConversion()
    with pytest.raises(ContractError, match="created_at is invalid"):
        validate_network_route(route)


def preflight_receipt(route: dict) -> dict:
    endpoint = route["endpoint"]
    endpoint_label = (
        "direct"
        if endpoint is None
        else f"{endpoint['protocol']}://{endpoint['host']}:{endpoint['port']}"
    )
    return {
        "schema": "browser-core.network-preflight/1",
        "route_id": route["id"],
        "route_sha256_16": route["integrity_sha256"][:16],
        "endpoint_sha256_16": hashlib.sha256(
            endpoint_label.encode("utf-8")
        ).hexdigest()[:16],
        "protocol": "direct" if endpoint is None else endpoint["protocol"],
        "credential_refs_resolved": route["auth"] is not None,
        "target_host": "tls.peet.ws",
        "target_port": 443,
        "latency_ms": 1,
        "passed": True,
    }


@contextmanager
def one_connection_server(handler):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    thread_error = []

    def run() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                handler(connection)
        except Exception as exc:  # pragma: no cover - surfaced below
            thread_error.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=run)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        thread.join(timeout=5)
        assert not thread.is_alive()
        if thread_error:
            raise thread_error[0]


def test_routes_store_references_but_never_credentials(tmp_path: Path) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    assert list_network_routes(tmp_path) == [route]
    serialized = next((tmp_path / "network" / "routes").glob("*.json")).read_text(
        encoding="utf-8"
    )
    assert "real-user" not in serialized and "real-password" not in serialized
    resolved = resolve_network_route(
        route, {"LAB_PROXY_USER": "real-user", "LAB_PROXY_PASSWORD": "real-password"}
    )
    assert "real-user" not in repr(resolved) and "real-password" not in repr(resolved)
    with pytest.raises(ContractError, match="unresolved"):
        resolve_network_route(route, {})


def test_resolve_network_route_reads_mutable_credentials_once() -> None:
    class ChangingEnv(dict[str, str]):
        def get(self, key: str, default: object = None) -> object:
            value = super().get(key, default)
            self.pop(key, None)
            return value

    env = ChangingEnv(
        LAB_PROXY_USER="alice",
        LAB_PROXY_PASSWORD="secret",
    )
    resolved = resolve_network_route(proxy_route(), env)
    assert resolved.username == "alice"
    assert resolved.password == "secret"


def test_resolve_network_route_rejects_nonmapping_credentials() -> None:
    with pytest.raises(ContractError, match="credential environment is invalid"):
        resolve_network_route(proxy_route(), [])  # type: ignore[arg-type]


def test_resolve_network_route_maps_failed_credential_lookup() -> None:
    class BrokenEnv(dict[str, str]):
        def __getitem__(self, key: str) -> str:
            raise RuntimeError("credential-secret-must-not-escape")

    with pytest.raises(
        ContractError, match="credential environment is invalid"
    ) as captured:
        resolve_network_route(proxy_route(), BrokenEnv())
    assert "credential-secret-must-not-escape" not in str(captured.value)


def test_resolved_route_retains_one_validated_route_population() -> None:
    route = proxy_route()
    resolved = resolve_network_route(
        route,
        {"LAB_PROXY_USER": "real-user", "LAB_PROXY_PASSWORD": "real-password"},
    )
    route["endpoint"]["port"] = 9
    route["name"] = "mutated"
    assert resolved.route["endpoint"]["port"] == 3128
    assert resolved.route["name"] == "Lab http"


def test_ipv6_proxy_route_formats_browser_server_as_url() -> None:
    route = build_network_route(
        route_id="ipv6-proxy",
        name="IPv6 proxy",
        mode="proxy",
        endpoint={"protocol": "http", "host": "::1", "port": 3128},
        geography=geography(),
    )
    resolved = resolve_network_route(route)
    assert resolved.browser_server() == "http://[::1]:3128"
    assert resolved.browser_server(("::1", 4444)) == "http://[::1]:4444"


@pytest.mark.parametrize(
    "gateway",
    [
        ("user:pass@other.example", 4444),
        ("127.0.0.1", True),
        ("127.0.0.1", 0),
        ("127.0.0.1", 65536),
        ("127.0.0.1", "4444"),
        ("127.0.0.1",),
    ],
)
def test_browser_server_rejects_malformed_local_gateway(gateway: object) -> None:
    route = build_network_route(
        route_id="formatted-proxy",
        name="Formatted proxy",
        mode="proxy",
        endpoint={"protocol": "http", "host": "127.0.0.1", "port": 3128},
        geography=geography(),
    )
    resolved = resolve_network_route(route)
    with pytest.raises(ContractError, match="local gateway"):
        resolved.browser_server(gateway)  # type: ignore[arg-type]


@pytest.mark.parametrize("gateway", [None, ("127.0.0.1", 4444)])
def test_browser_server_rejects_mutated_resolved_route(gateway) -> None:
    route = build_network_route(
        route_id="stable-proxy",
        name="Stable proxy",
        mode="proxy",
        endpoint={"protocol": "http", "host": "127.0.0.1", "port": 3128},
        geography=geography(),
    )
    resolved = resolve_network_route(route)
    resolved.route["endpoint"]["host"] = "changed.example"
    with pytest.raises(ContractError, match="integrity digest"):
        resolved.browser_server(gateway)


def test_resolved_route_protocol_rejects_mutated_route() -> None:
    resolved = resolve_network_route(
        build_network_route(
            route_id="protocol-proxy",
            name="Protocol proxy",
            mode="proxy",
            endpoint={"protocol": "http", "host": "127.0.0.1", "port": 3128},
            geography=geography(),
        )
    )
    resolved.route["endpoint"]["protocol"] = "socks5"
    with pytest.raises(ContractError, match="integrity digest"):
        _ = resolved.protocol


def test_browser_server_rechecks_route_copied_after_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="copy-race-proxy",
        name="Copy race proxy",
        mode="proxy",
        endpoint={"protocol": "http", "host": "127.0.0.1", "port": 3128},
        geography=geography(),
    )
    resolved = resolve_network_route(route)
    original_validate = network_module.validate_network_route

    def mutate_after_validation(document):
        validated = original_validate(document)
        if document is resolved.route:
            document["endpoint"]["host"] = "changed.example"
        return validated

    monkeypatch.setattr(network_module, "validate_network_route", mutate_after_validation)
    with pytest.raises(ContractError, match="integrity digest"):
        resolved.browser_server()


@pytest.mark.parametrize(
    "host",
    [
        "-bad.example",
        "bad-.example",
        "good.-bad.example",
        "2130706433",
        "127.1",
        "0x7f000001",
        "example.42",
        "fe80::1%eth0",
    ],
)
def test_network_route_rejects_invalid_dns_labels(host: str) -> None:
    with pytest.raises(ContractError, match="host"):
        build_network_route(
            route_id="bad-host",
            name="Bad host",
            mode="proxy",
            endpoint={"protocol": "http", "host": host, "port": 3128},
            geography=geography(),
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://owned.example:0/",
        "https://bad-.example/",
        "https://good.-bad.example/",
        "https://éxample.test/",
        "https://[broken",
        "https://@tls.peet.ws/",
        "https://tls.peet.ws/?",
        "https://tls.peet.ws/#",
        "https://2130706433/",
        "https://127.1/",
        "https://0x7f000001/",
        "https://example.42/",
        "https://[fe80::1%25eth0]/",
    ],
)
def test_network_route_rejects_invalid_preflight_authority(url: str) -> None:
    with pytest.raises(ContractError, match="preflight URL"):
        build_network_route(
            route_id="bad-preflight",
            name="Bad preflight",
            geography=geography(),
            preflight_url=url,
        )


@pytest.mark.parametrize('url', [
    'https://[broken', 'https://@tls.peet.ws/',
    'https://tls.peet.ws/?', 'https://tls.peet.ws/#',
    'https://2130706433/', 'https://127.1/',
])
def test_preflight_rejects_malformed_url_before_network_contact(monkeypatch, url):
    route = build_network_route(
        route_id='local-direct', name='Local direct', geography=geography(),
    )
    resolved = resolve_network_route(route)
    monkeypatch.setattr(
        network_module.socket, 'create_connection',
        lambda *_args, **_kwargs: pytest.fail('malformed URL reached network'),
    )
    with pytest.raises(ContractError, match='preflight URL'):
        preflight_network_route(resolved, url)


@pytest.mark.parametrize("value", [float("nan"), "\ud800"])
def test_network_route_digest_rejects_nonportable_json(value: object) -> None:
    with pytest.raises(ContractError, match="strict JSON") as failure:
        route_digest({"coordinate": value})
    assert "coordinate" not in str(failure.value)


def test_network_route_digest_rejects_extreme_nesting() -> None:
    deeply_nested: object = 0
    for _ in range(2_000):
        deeply_nested = [deeply_nested]

    with pytest.raises(ContractError, match="strict JSON"):
        route_digest({"coordinate": deeply_nested})


@pytest.mark.parametrize(
    "mutate",
    [
        lambda route: route.__setitem__("password", "private-route-password"),
        lambda route: route["endpoint"].__setitem__("private_detail", "tenant-a"),
        lambda route: route["geography"].__setitem__("private_detail", "tenant-a"),
        lambda route: route["policies"].__setitem__("private_detail", "tenant-a"),
    ],
)
def test_network_route_integrity_cannot_cover_uninterpreted_fields(mutate) -> None:
    route = proxy_route()
    mutate(route)
    route["integrity_sha256"] = route_digest(route)

    with pytest.raises(ContractError, match="fields are invalid|required"):
        validate_network_route(route)


@pytest.mark.parametrize(
    ("field_path", "value", "message"),
    [
        (("mode",), [], "mode"),
        (("endpoint", "protocol"), {}, "protocol"),
        (("policies", "dns"), [], "DNS policy"),
        (("policies", "webrtc"), {}, "WebRTC policy"),
    ],
)
def test_network_route_rejects_unhashable_json_enums(
    tmp_path: Path, field_path: tuple[str, ...], value: object, message: str
) -> None:
    route = proxy_route()
    field = route
    for key in field_path[:-1]:
        field = field[key]
    field[field_path[-1]] = value
    route["integrity_sha256"] = route_digest(route)

    with pytest.raises(ContractError, match=message):
        validate_network_route(route)

    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(canonical_json_bytes(route))
    with pytest.raises(ContractError, match="invalid managed document"):
        load_network_route(tmp_path, route["id"])


def test_network_route_load_is_bounded_before_json_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    monkeypatch.setattr(
        network_module, "MAX_NETWORK_ROUTE_BYTES", len(path.read_bytes()) - 1
    )

    with pytest.raises(ContractError, match="exceeds"):
        load_network_route(tmp_path, route["id"])


@pytest.mark.parametrize("mutation", ["duplicate", "nonfinite"])
def test_network_route_load_requires_canonical_strict_json(
    mutation: str,
    tmp_path: Path,
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    body = path.read_bytes()
    if mutation == "duplicate":
        body = body.replace(
            b'"id":"lab-http"',
            b'"id":"lab-http","id":"lab-http"',
            1,
        )
    else:
        body = body.replace(b'"latitude":41.8781', b'"latitude":NaN', 1)
    path.write_bytes(body)
    with pytest.raises(ContractError, match="invalid managed document"):
        load_network_route(tmp_path, route["id"])


def test_network_route_load_binds_file_name_to_document_id(tmp_path: Path) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    source = tmp_path / "network" / "routes" / f"{route['id']}.json"
    (source.parent / "other-route.json").write_bytes(source.read_bytes())
    with pytest.raises(ContractError, match="invalid managed document"):
        load_network_route(tmp_path, "other-route")


def test_network_route_load_rejects_hard_linked_document(tmp_path: Path) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    os.link(path, tmp_path / "owned-hard-link")
    with pytest.raises(ContractError, match="hard links"):
        load_network_route(tmp_path, route["id"])


@pytest.mark.parametrize("mutation", ["contents", "same-bytes-replacement"])
def test_network_route_load_rechecks_saved_file_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    competitor = build_network_route(
        route_id=route["id"], name="Changed route", geography=geography()
    )
    competitor_bytes = canonical_json_bytes(competitor)
    original_bytes = path.read_bytes()
    original_inode = path.stat().st_ino
    original_validate = network_module.validate_network_route
    changed = False

    def replace_after_validation(document: object):
        nonlocal changed
        validated = original_validate(document)
        if not changed:
            if mutation == "contents":
                path.write_bytes(competitor_bytes)
            else:
                replacement = path.with_name("replacement.tmp")
                replacement.write_bytes(original_bytes)
                os.replace(replacement, path)
                assert path.stat().st_ino != original_inode
            changed = True
        return validated

    monkeypatch.setattr(network_module, "validate_network_route", replace_after_validation)
    with pytest.raises(ContractError, match="changed during read"):
        load_network_route(tmp_path, route["id"])
    assert changed
    assert path.read_bytes() == (
        competitor_bytes if mutation == "contents" else original_bytes
    )


@pytest.mark.parametrize("reader", ["load", "list"])
def test_network_route_reads_reject_relocated_workspace_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    selected = tmp_path / "selected"
    workspace = selected / "workspace"
    workspace.mkdir(parents=True)
    route = proxy_route()
    add_network_route(workspace, route)
    path = workspace / "network" / "routes" / f"{route['id']}.json"
    original_bytes = path.read_bytes()
    retained = tmp_path / "retained-selected"
    moved = False

    def relocate() -> None:
        nonlocal moved
        selected.rename(retained)
        selected.mkdir()
        (retained / "workspace").rename(workspace)
        moved = True

    if reader == "load":
        original = network_module.read_bounded_control_snapshot_result

        def relocate_after_read(target: Path, **kwargs):
            result = original(target, **kwargs)
            if target == path and not moved:
                relocate()
            return result

        monkeypatch.setattr(
            network_module, "read_bounded_control_snapshot_result",
            relocate_after_read,
        )
    else:
        original_inventory = network_module._network_route_inventory

        def relocate_after_inventory(directory: Path):
            result = original_inventory(directory)
            if not moved:
                relocate()
            return result

        monkeypatch.setattr(
            network_module, "_network_route_inventory", relocate_after_inventory
        )
    with pytest.raises(ContractError, match="changed"):
        if reader == "load":
            load_network_route(workspace, route["id"])
        else:
            list_network_routes(workspace)
    assert moved
    assert path.read_bytes() == original_bytes


def test_network_route_list_bounds_route_count_and_aggregate_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = proxy_route()
    second = build_network_route(
        route_id="second-route",
        name="Second",
        geography=geography(),
    )
    add_network_route(tmp_path, first)
    add_network_route(tmp_path, second)
    monkeypatch.setattr(network_module, "MAX_NETWORK_ROUTES", 1)
    with pytest.raises(ContractError, match="route limit"):
        list_network_routes(tmp_path)
    monkeypatch.setattr(network_module, "MAX_NETWORK_ROUTES", 4096)
    directory = tmp_path / "network" / "routes"
    total = sum(path.stat().st_size for path in directory.glob("*.json"))
    monkeypatch.setattr(network_module, "MAX_NETWORK_ROUTE_TOTAL_BYTES", total - 1)
    with pytest.raises(ContractError, match="aggregate"):
        list_network_routes(tmp_path)


def test_network_route_list_rejects_population_appearance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    original = network_module._network_route_inventory
    calls = 0

    def appearing_inventory(directory: Path):
        nonlocal calls
        calls += 1
        result = original(directory)
        if calls == 1:
            (directory / "appeared.json").write_text("{}\n", encoding="utf-8")
        return result

    monkeypatch.setattr(network_module, "_network_route_inventory", appearing_inventory)
    with pytest.raises(ContractError, match="population changed"):
        list_network_routes(tmp_path)


def test_network_route_list_rejects_noncanonical_json_extension(
    tmp_path: Path,
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    directory = tmp_path / "network" / "routes"
    saved = directory / f"{route['id']}.json"
    temporary = directory / "renaming.tmp"
    saved.rename(temporary)
    uppercase = directory / f"{route['id']}.JSON"
    temporary.rename(uppercase)
    if os.name == "nt":
        assert load_network_route(tmp_path, route["id"]) == route
    with pytest.raises(ContractError, match="candidate name is invalid"):
        list_network_routes(tmp_path)
    assert uppercase.is_file()


def test_network_route_list_rejects_appearance_during_final_byte_rebind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    second = build_network_route(
        route_id="second-route",
        name="Second",
        geography=geography(),
    )
    first_path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    second_path = first_path.parent / "second-route.json"
    original = network_module.read_bounded_control_snapshot_result
    reads = 0

    def add_after_final_read(target: Path, **kwargs):
        nonlocal reads
        result = original(target, **kwargs)
        if target == first_path:
            reads += 1
            if reads == 3:
                second_path.write_bytes(canonical_json_bytes(second))
        return result

    monkeypatch.setattr(
        network_module, "read_bounded_control_snapshot_result", add_after_final_read
    )
    with pytest.raises(ContractError, match="population changed during load"):
        list_network_routes(tmp_path)
    assert second_path.read_bytes() == canonical_json_bytes(second)


@pytest.mark.skipif(os.name != "nt", reason="Windows restored-mtime file identity")
def test_network_route_list_rechecks_bytes_after_stable_metadata_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    competitor = {**route, "name": "New http"}
    competitor["integrity_sha256"] = route_digest(competitor)
    competitor_bytes = canonical_json_bytes(competitor)
    assert len(competitor_bytes) == len(path.read_bytes())
    original_load = network_module._load_network_route_snapshot
    changed = False

    def change_after_load(*args: object, **kwargs: object):
        nonlocal changed
        result = original_load(*args, **kwargs)  # type: ignore[arg-type]
        if not changed:
            before = os.lstat(path)
            path.write_bytes(competitor_bytes)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            assert network_module._route_file_identity(os.lstat(path)) == (
                network_module._route_file_identity(before)
            )
            changed = True
        return result

    monkeypatch.setattr(network_module, "_load_network_route_snapshot", change_after_load)
    with pytest.raises(ContractError, match="population changed during load"):
        list_network_routes(tmp_path)
    assert changed
    assert path.read_bytes() == competitor_bytes


@pytest.mark.skipif(os.name != "nt", reason="Windows restored-mtime file identity")
def test_network_route_list_rechecks_bytes_after_final_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    competitor = {**route, "name": "New http"}
    competitor["integrity_sha256"] = route_digest(competitor)
    competitor_bytes = canonical_json_bytes(competitor)
    assert len(competitor_bytes) == len(path.read_bytes())
    original_inventory = network_module._network_route_inventory
    calls = 0

    def change_after_final_inventory(directory: Path):
        nonlocal calls
        calls += 1
        result = original_inventory(directory)
        if calls == 3:
            before = os.lstat(path)
            path.write_bytes(competitor_bytes)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            assert network_module._route_file_identity(os.lstat(path)) == (
                network_module._route_file_identity(before)
            )
        return result

    monkeypatch.setattr(
        network_module, "_network_route_inventory", change_after_final_inventory
    )
    with pytest.raises(ContractError, match="population changed during load"):
        list_network_routes(tmp_path)
    assert calls == 3
    assert path.read_bytes() == competitor_bytes


def test_network_route_writer_preserves_a_concurrent_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = proxy_route()
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    real_publish = network_module.publish_json_exclusive_result

    def _race(target: Path, document: dict, **kwargs) -> bytes:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"foreign route")
        return real_publish(target, document, **kwargs)

    monkeypatch.setattr(network_module, "publish_json_exclusive_result", _race)

    with pytest.raises(ContractError, match="cannot read network route"):
        add_network_route(tmp_path, route)

    assert path.read_bytes() == b"foreign route"
    assert not list(path.parent.glob(f".{path.name}.tmp-*"))


def test_network_route_writer_creates_a_new_owned_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "new-workspace"
    route = proxy_route()
    publication = add_network_route_with_receipt(workspace, route)
    assert publication.created is True
    assert load_network_route(workspace, route["id"]) == route


def test_network_route_writer_validates_detached_input_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = proxy_route()
    original_validate = network_module.validate_network_route

    def mutate_after_validation(document):
        validated = original_validate(document)
        if document is route:
            document["endpoint"]["host"] = "changed.example"
        return validated

    monkeypatch.setattr(network_module, "validate_network_route", mutate_after_validation)
    with pytest.raises(ContractError):
        add_network_route_with_receipt(tmp_path, route)
    assert not (tmp_path / "network").exists()


@pytest.mark.parametrize("failed_parent", ["network", "routes"])
def test_network_route_writer_maps_directory_creation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_parent: str
) -> None:
    route = proxy_route()
    network = tmp_path / "network"
    if failed_parent == "routes":
        network.mkdir()
    rejected = network if failed_parent == "network" else network / "routes"
    original_mkdir = Path.mkdir

    def fail_selected_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        if path == rejected:
            raise PermissionError("private host path")
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_selected_mkdir)
    with pytest.raises(ContractError, match="network route directory could not be created"):
        add_network_route_with_receipt(tmp_path, route)
    assert not (network / "routes" / f"{route['id']}.json").exists()


def test_network_route_writer_fails_cleanly_if_workspace_appears_during_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "new-workspace"
    route = proxy_route()
    path = workspace / "network" / "routes" / f"{route['id']}.json"
    original_load = network_module._load_network_route_snapshot

    def create_before_load(*args: object, **kwargs: object):
        path.parent.mkdir(parents=True)
        path.write_bytes(canonical_json_bytes(route))
        monkeypatch.setattr(network_module, "_load_network_route_snapshot", original_load)
        return original_load(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(network_module, "_load_network_route_snapshot", create_before_load)
    with pytest.raises(ContractError, match="changed before receipt"):
        add_network_route_with_receipt(workspace, route)
    assert path.read_bytes() == canonical_json_bytes(route)


@pytest.mark.parametrize("mutation", ["contents", "same-bytes-replacement"])
def test_network_route_publication_rechecks_final_saved_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    route = proxy_route()
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    competitor = {**route, "name": "Replacement route"}
    competitor["integrity_sha256"] = route_digest(competitor)
    real_publish = network_module.publish_json_exclusive_result
    replacement_body: bytes | None = None

    def replace_after_publication(target: Path, document: dict, **kwargs):
        nonlocal replacement_body
        result = real_publish(target, document, **kwargs)
        replacement_body = (
            canonical_json_bytes(competitor)
            if mutation == "contents"
            else result.body
        )
        if mutation == "contents":
            target.write_bytes(replacement_body)
        else:
            replacement = tmp_path / "same-body-replacement"
            replacement.write_bytes(replacement_body)
            os.replace(replacement, target)
        return result

    monkeypatch.setattr(
        network_module, "publish_json_exclusive_result", replace_after_publication
    )
    with pytest.raises(ContractError, match="changed after publication"):
        add_network_route_with_receipt(tmp_path, route)
    assert replacement_body is not None
    assert path.read_bytes() == replacement_body


@pytest.mark.parametrize("mutation", ["contents", "same-bytes-replacement"])
def test_existing_network_route_receipt_rechecks_saved_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    route = proxy_route()
    add_network_route(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    competitor = {**route, "name": "Replacement route"}
    competitor["integrity_sha256"] = route_digest(competitor)
    replacement_body = (
        canonical_json_bytes(competitor)
        if mutation == "contents"
        else path.read_bytes()
    )
    original_load = network_module._load_network_route_snapshot
    loads = 0

    def change_after_existing_load(*args: object, **kwargs: object):
        nonlocal loads
        result = original_load(*args, **kwargs)  # type: ignore[arg-type]
        loads += 1
        if loads == 1:
            if mutation == "contents":
                path.write_bytes(replacement_body)
            else:
                replacement = tmp_path / "same-body-replacement"
                replacement.write_bytes(replacement_body)
                os.replace(replacement, path)
        return result

    monkeypatch.setattr(
        network_module, "_load_network_route_snapshot", change_after_existing_load
    )
    with pytest.raises(ContractError, match="changed before receipt"):
        add_network_route_with_receipt(tmp_path, route)
    assert path.read_bytes() == replacement_body


def test_a_new_route_publication_can_be_rolled_back_by_exact_receipt(
    tmp_path: Path,
) -> None:
    route = proxy_route()
    publication = add_network_route_with_receipt(tmp_path, route)
    assert publication.created is True

    rollback_network_route_publication(tmp_path, publication)

    assert not (tmp_path / "network" / "routes" / f"{route['id']}.json").exists()


def test_route_rollback_rejects_replaced_workspace_with_same_route(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    route = proxy_route()
    publication = add_network_route_with_receipt(workspace, route)
    detached = tmp_path / "detached-workspace"
    workspace.rename(detached)
    workspace.mkdir()
    (detached / "network").rename(workspace / "network")
    path = workspace / "network" / "routes" / f"{route['id']}.json"
    original = path.read_bytes()

    with pytest.raises(ContractError, match="workspace changed before rollback"):
        rollback_network_route_publication(workspace, publication)

    assert path.read_bytes() == original


def test_route_rollback_rejects_replaced_routes_directory_with_same_route(
    tmp_path: Path,
) -> None:
    route = proxy_route()
    publication = add_network_route_with_receipt(tmp_path, route)
    routes = tmp_path / "network" / "routes"
    detached = tmp_path / "detached-routes"
    routes.rename(detached)
    routes.mkdir()
    (detached / f"{route['id']}.json").rename(routes / f"{route['id']}.json")
    path = routes / f"{route['id']}.json"
    original = path.read_bytes()

    with pytest.raises(ContractError, match="directory changed before rollback"):
        rollback_network_route_publication(tmp_path, publication)

    assert path.read_bytes() == original


def test_route_conflict_diagnostic_does_not_echo_route_id(tmp_path: Path) -> None:
    private_id = "private-route-location-marker"
    first = build_network_route(route_id=private_id, name="First", geography=geography())
    second = build_network_route(route_id=private_id, name="Second", geography=geography())
    add_network_route(tmp_path, first)
    with pytest.raises(ContractError) as failure:
        add_network_route(tmp_path, second)
    assert private_id not in str(failure.value)


def test_route_rollback_preserves_a_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = proxy_route()
    publication = add_network_route_with_receipt(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    replacement = b"replacement route"
    real_remove = network_module.remove_control_conditionally

    def _race(target: Path, **kwargs) -> None:
        target.unlink()
        target.write_bytes(replacement)
        real_remove(target, **kwargs)

    monkeypatch.setattr(network_module, "remove_control_conditionally", _race)
    with pytest.raises(ContractError, match="changed before removal"):
        rollback_network_route_publication(tmp_path, publication)

    assert path.read_bytes() == replacement


def test_route_rollback_rechecks_path_after_successful_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = proxy_route()
    publication = add_network_route_with_receipt(tmp_path, route)
    path = tmp_path / "network" / "routes" / f"{route['id']}.json"
    real_remove = network_module.remove_control_conditionally

    def remove_then_reappear(target: Path, **kwargs) -> None:
        real_remove(target, **kwargs)
        target.write_bytes(publication.body)

    monkeypatch.setattr(
        network_module, "remove_control_conditionally", remove_then_reappear
    )
    with pytest.raises(ContractError, match="reappeared during rollback"):
        rollback_network_route_publication(tmp_path, publication)

    assert path.read_bytes() == publication.body


def test_http_proxy_preflight_proves_auth_without_leaking_secret() -> None:
    expected = "Basic " + base64.b64encode(b"alice:wonderland").decode("ascii")

    def handler(connection: socket.socket) -> None:
        request = connection.recv(65536).decode("ascii")
        assert "CONNECT owned.example:443" in request
        assert f"Proxy-Authorization: {expected}" in request
        connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    with one_connection_server(handler) as port:
        resolved = resolve_network_route(
            proxy_route(port=port),
            {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"},
        )
        result = preflight_network_route(resolved, "https://owned.example/health")
    assert result["passed"] is True and result["credential_refs_resolved"] is True
    assert "alice" not in str(result) and "wonderland" not in str(result)


def test_http_proxy_preflight_fails_closed_on_auth_rejection() -> None:
    def handler(connection: socket.socket) -> None:
        connection.recv(65536)
        connection.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")

    with one_connection_server(handler) as port:
        resolved = resolve_network_route(
            proxy_route(port=port),
            {"LAB_PROXY_USER": "bad", "LAB_PROXY_PASSWORD": "bad"},
        )
        with pytest.raises(ContractError, match="407"):
            preflight_network_route(resolved, "https://owned.example/health")


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/2 200 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\n",
    ],
)
def test_http_proxy_preflight_rejects_ambiguous_response_framing(
    response: bytes,
) -> None:
    def handler(connection: socket.socket) -> None:
        connection.recv(65536)
        connection.sendall(response)

    with one_connection_server(handler) as port:
        resolved = resolve_network_route(
            proxy_route(port=port),
            {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"},
        )
        with pytest.raises(ContractError, match="response|header|framing|status"):
            preflight_network_route(resolved, "https://owned.example/health")


def test_http_proxy_target_injection_fails_before_socket_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = resolve_network_route(
        proxy_route(),
        {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"},
    )
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("invalid target reached socket contact"),
    )
    with pytest.raises(ContractError, match="target host"):
        _connect_http_proxy(resolved, "owned.example\r\nInjected: yes", 443, 1)


def test_http_proxy_formats_ipv6_authority_with_brackets() -> None:
    def handler(connection: socket.socket) -> None:
        request = connection.recv(65536)
        assert request.startswith(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n")
        assert b"\r\nHost: [2001:db8::1]:443\r\n" in request
        connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    with one_connection_server(handler) as port:
        result = preflight_network_route(
            resolve_network_route(
                proxy_route(port=port),
                {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"},
            ),
            "https://[2001:db8::1]/health",
        )
    assert result["target_host"] == "2001:db8::1"


def test_header_reader_enforces_the_shared_handshake_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Connection:
        def settimeout(self, timeout: float) -> None:
            pytest.fail("expired deadline must not configure or read the socket")

        def recv(self, count: int) -> bytes:
            pytest.fail("expired deadline reached socket read")

    monkeypatch.setattr(network_module.time, "monotonic", lambda: 2.0)
    with pytest.raises(ContractError, match="timed out"):
        _recv_headers(Connection(), deadline=1.0)  # type: ignore[arg-type]


@pytest.mark.parametrize("reader", ["headers", "exact"])
def test_proxy_reader_rejects_bytes_received_after_handshake_deadline(
    monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    now = [0.0]
    monkeypatch.setattr(network_module.time, "monotonic", lambda: now[0])

    class Connection:
        def settimeout(self, _timeout: float) -> None:
            return None

        def recv(self, _maximum: int) -> bytes:
            now[0] = 2.0
            return b"HTTP/1.1 200 OK\r\n\r\n" if reader == "headers" else b"\x05\x00"

    with pytest.raises(ContractError, match="timed out"):
        if reader == "headers":
            _recv_headers(Connection(), deadline=1.0)  # type: ignore[arg-type]
        else:
            _recv_exact(Connection(), 2, 1.0)  # type: ignore[arg-type]


def test_http_proxy_does_not_send_credentials_after_header_preparation_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    sent: list[bytes] = []
    monkeypatch.setattr(network_module.time, "monotonic", lambda: clock[0])
    original_encode = base64.b64encode

    def late_encode(value: bytes) -> bytes:
        clock[0] = 2.0
        return original_encode(value)

    monkeypatch.setattr(network_module.base64, "b64encode", late_encode)

    class Connection:
        closed = False

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, body: bytes) -> None:
            sent.append(body)

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )
    resolved = resolve_network_route(
        proxy_route(),
        {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "secret"},
    )
    with pytest.raises(ContractError, match="timed out"):
        _connect_http_proxy(resolved, "owned.example", 443, 1.0)
    assert sent == []
    assert connection.closed is True


def test_socks_proxy_does_not_send_auth_after_handshake_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    sent: list[bytes] = []
    monkeypatch.setattr(network_module.time, "monotonic", lambda: clock[0])

    class Connection:
        closed = False

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, body: bytes) -> None:
            sent.append(body)

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )

    def late_method_reply(*_args, **_kwargs) -> bytes:
        clock[0] = 2.0
        return b"\x05\x02"

    monkeypatch.setattr(network_module, "_recv_exact", late_method_reply)
    resolved = resolve_network_route(
        proxy_route("socks5"),
        {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "secret"},
    )
    with pytest.raises(ContractError, match="timed out"):
        _connect_socks5_proxy(resolved, "owned.example", 443, 1.0)
    assert sent == [b"\x05\x01\x02"]
    assert connection.closed is True


@pytest.mark.parametrize("protocol", ["http", "socks5"])
def test_proxy_handshake_cannot_return_after_final_processing_deadline(
    monkeypatch: pytest.MonkeyPatch,
    protocol: str,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(network_module.time, "monotonic", lambda: clock[0])

    class Connection:
        closed = False

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _body: bytes) -> None:
            return None

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )
    resolved = resolve_network_route(
        proxy_route(protocol),
        {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "secret"},
    )
    if protocol == "http":
        monkeypatch.setattr(
            network_module,
            "_recv_headers",
            lambda *_args, **_kwargs: b"HTTP/1.1 200 OK\r\n\r\n",
        )

        def late_parse(_response: bytes) -> int:
            clock[0] = 2.0
            return 200

        monkeypatch.setattr(network_module, "_parse_http_connect_response", late_parse)
        operation = _connect_http_proxy
    else:
        replies = iter([b"\x05\x02", b"\x01\x00", b"\x05\x00\x00\x01", b"\x00" * 6])

        def late_final_reply(*_args, **_kwargs) -> bytes:
            reply = next(replies)
            if len(reply) == 6:
                clock[0] = 2.0
            return reply

        monkeypatch.setattr(network_module, "_recv_exact", late_final_reply)
        operation = _connect_socks5_proxy

    with pytest.raises(ContractError, match="timed out"):
        operation(resolved, "owned.example", 443, 1.0)
    assert connection.closed is True


def test_direct_preflight_rejects_connection_after_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(network_module.time, "monotonic", lambda: clock[0])

    class Connection:
        closed = False

        def close(self) -> None:
            self.closed = True

    connection = Connection()

    def late_connection(*_args, **_kwargs):
        clock[0] = 2.0
        return connection

    monkeypatch.setattr(network_module.socket, "create_connection", late_connection)
    route = build_network_route(
        route_id="direct-lab",
        name="Direct lab",
        geography=geography(),
    )
    with pytest.raises(ContractError, match="preflight timed out"):
        preflight_network_route(
            resolve_network_route(route),
            "https://owned.example/health",
            timeout_seconds=1.0,
        )
    assert connection.closed is True


def test_direct_preflight_rejects_cleanup_after_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(network_module.time, "monotonic", lambda: clock[0])

    class Connection:
        closed = False

        def close(self) -> None:
            clock[0] = 2.0
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )
    route = build_network_route(
        route_id="direct-cleanup-timeout",
        name="Direct cleanup timeout",
        geography=geography(),
    )
    with pytest.raises(ContractError, match="preflight timed out"):
        preflight_network_route(
            resolve_network_route(route),
            "https://owned.example/health",
            timeout_seconds=1.0,
        )
    assert connection.closed is True


@pytest.mark.parametrize("chunk", [bytearray(b"private"), "private"])
@pytest.mark.parametrize("reader", ["headers", "exact"])
def test_proxy_readers_require_exact_byte_chunks(chunk, reader) -> None:
    class Connection:
        def settimeout(self, _timeout):
            return None

        def recv(self, _size):
            return chunk

    with pytest.raises(
        ContractError, match="transport returned invalid bytes"
    ) as failure:
        if reader == "headers":
            _recv_headers(Connection())  # type: ignore[arg-type]
        else:
            _recv_exact(Connection(), 2, float("inf"))  # type: ignore[arg-type]
    assert "private" not in str(failure.value)


@pytest.mark.parametrize("reader", ["headers", "exact"])
def test_proxy_readers_reject_adapter_over_return(reader) -> None:
    class Connection:
        def settimeout(self, _timeout):
            return None

        def recv(self, size):
            return b"x" * (size + 1)

    with pytest.raises(ContractError, match="transport returned invalid bytes"):
        if reader == "headers":
            _recv_headers(Connection())  # type: ignore[arg-type]
        else:
            _recv_exact(Connection(), 2, float("inf"))  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [True, "1", float("nan"), float("inf"), 0, 301])
def test_network_preflight_rejects_invalid_timeout_before_connect(timeout) -> None:
    route = build_network_route(
        route_id="direct-timeout",
        name="Direct timeout",
        geography=geography(),
    )
    with pytest.raises(ContractError, match="timeout must be finite"):
        preflight_network_route(
            resolve_network_route(route),
            route["preflight_url"],
            timeout_seconds=timeout,
        )


def test_network_preflight_normalizes_invalid_url_port() -> None:
    route = build_network_route(
        route_id="direct-port",
        name="Direct port",
        geography=geography(),
    )
    with pytest.raises(ContractError, match="port is invalid"):
        preflight_network_route(
            resolve_network_route(route), "https://owned.example:99999/"
        )


def test_network_preflight_rejects_explicit_zero_port_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-zero-port",
        name="Direct zero port",
        geography=geography(),
    )
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("zero port reached socket contact"),
    )
    with pytest.raises(ContractError, match="target port"):
        preflight_network_route(
            resolve_network_route(route), "https://owned.example:0/"
        )


def test_network_preflight_close_failure_blocks_a_passing_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-close-failure",
        name="Direct close failure",
        geography=geography(),
    )

    class Connection:
        def close(self) -> None:
            raise OSError("private direct close diagnostic")

    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: Connection(),
    )
    with pytest.raises(ContractError) as raised:
        preflight_network_route(
            resolve_network_route(route),
            route["preflight_url"],
        )
    assert str(raised.value) == "network preflight cleanup failed (connection-close)"
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


def test_http_proxy_handshake_cleanup_failure_retains_safe_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = resolve_network_route(
        proxy_route(),
        {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"},
    )

    class Connection:
        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _body: bytes) -> None:
            return None

        def recv(self, _maximum: int) -> bytes:
            return b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"

        def close(self) -> None:
            raise RuntimeError("private proxy close diagnostic")

    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: Connection(),
    )
    with pytest.raises(ContractError) as raised:
        _connect_http_proxy(resolved, "owned.example", 443, 1)
    assert str(raised.value) == (
        "network HTTP proxy handshake cleanup failed (connection-close)"
    )
    assert isinstance(raised.value.__cause__, ContractError)
    assert "407" in str(raised.value.__cause__)
    assert "private" not in str(raised.value)


def test_socks5_handshake_cleanup_failure_retains_safe_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = resolve_network_route(
        proxy_route("socks5"),
        {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"},
    )

    class Connection:
        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _body: bytes) -> None:
            return None

        def recv(self, _maximum: int) -> bytes:
            return b"\x05\xff"

        def close(self) -> None:
            raise ValueError("private SOCKS close diagnostic")

    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: Connection(),
    )
    with pytest.raises(ContractError) as raised:
        _connect_socks5_proxy(resolved, "owned.example", 443, 1)
    assert str(raised.value) == (
        "network SOCKS5 proxy handshake cleanup failed (connection-close)"
    )
    assert isinstance(raised.value.__cause__, ContractError)
    assert "authentication method" in str(raised.value.__cause__)
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("protocol", ["http", "socks5"])
def test_proxy_handshakes_require_complete_sendall_semantics(
    monkeypatch: pytest.MonkeyPatch, protocol: str
) -> None:
    resolved = resolve_network_route(
        proxy_route(protocol),
        {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"},
    )

    class Connection:
        def __init__(self) -> None:
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _body: bytes) -> int:
            return 1

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )
    operation = _connect_http_proxy if protocol == "http" else _connect_socks5_proxy
    with pytest.raises(ContractError, match="transport write is invalid"):
        operation(resolved, "owned.example", 443, 1)
    assert connection.closed is True


def test_socks5_preflight_authenticates_and_connects() -> None:
    def handler(connection: socket.socket) -> None:
        assert connection.recv(3) == b"\x05\x01\x02"
        connection.sendall(b"\x05\x02")
        auth = connection.recv(1024)
        assert auth == b"\x01\x05alice\x0awonderland"
        connection.sendall(b"\x01\x00")
        request = connection.recv(1024)
        assert request.startswith(b"\x05\x01\x00\x03") and b"owned.example" in request
        connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")

    with one_connection_server(handler) as port:
        route = proxy_route("socks5", port)
        result = preflight_network_route(
            resolve_network_route(
                route, {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"}
            ),
            "https://owned.example/health",
        )
    assert result["protocol"] == "socks5" and result["passed"] is True


def test_socks5_oversized_credentials_fail_before_socket_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = proxy_route("socks5")
    resolved = resolve_network_route(
        route,
        {"LAB_PROXY_USER": "u" * 256, "LAB_PROXY_PASSWORD": "password"},
    )
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail(
            "invalid SOCKS credentials reached socket contact"
        ),
    )
    with pytest.raises(ContractError, match="protocol limits"):
        _connect_socks5_proxy(resolved, "owned.example", 443, 1)


def test_socks5_exact_reader_accepts_fragmented_responses() -> None:
    def handler(connection: socket.socket) -> None:
        assert connection.recv(3) == b"\x05\x01\x02"
        connection.sendall(b"\x05")
        connection.sendall(b"\x02")
        assert connection.recv(1024) == b"\x01\x05alice\x0awonderland"
        connection.sendall(b"\x01")
        connection.sendall(b"\x00")
        request = connection.recv(1024)
        assert request.startswith(b"\x05\x01\x00\x03")
        for byte in b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb":
            connection.sendall(bytes([byte]))

    with one_connection_server(handler) as port:
        result = preflight_network_route(
            resolve_network_route(
                proxy_route("socks5", port),
                {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "wonderland"},
            ),
            "https://owned.example/health",
        )
    assert result["passed"] is True


def test_socks5_rejects_empty_reply_domain_before_tunnel_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Connection:
        def __init__(self) -> None:
            self.replies = iter(
                [b"\x05\x02", b"\x01\x00", b"\x05\x00\x00\x03", b"\x00", b"\x01\xbb"]
            )
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _request: bytes) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            return next(self.replies)

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        network_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )
    resolved = resolve_network_route(
        proxy_route("socks5"),
        {"LAB_PROXY_USER": "alice", "LAB_PROXY_PASSWORD": "password"},
    )
    with pytest.raises(ContractError, match="reply domain is invalid"):
        _connect_socks5_proxy(resolved, "owned.example", 443, 1.0)
    assert connection.closed is True


def test_geo_alignment_is_redacted_and_strict() -> None:
    route = build_network_route(
        route_id="direct-us", name="Direct US", geography=geography()
    )
    observation = {
        "ip": "203.0.113.9",
        "country": "US",
        "timezone": "America/Chicago",
        "locale": "en-US",
        "latitude": 41.9,
        "longitude": -87.6,
    }
    result = validate_geo_alignment(route, observation)
    assert result["passed"] is True and result["checks"] == {
        "country": True,
        "timezone": True,
        "locale": True,
        "coordinates": True,
    }
    assert "203.0.113.9" not in str(result)
    mismatch = {**observation, "country": "CA"}
    assert validate_geo_alignment(route, mismatch)["passed"] is False


def test_geo_alignment_retains_validated_route_during_observation_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-geo-snapshot",
        name="Direct geo snapshot",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    original_normalize = network_module.normalize_geo_observation

    def mutate_during_normalization(observation):
        normalized = original_normalize(observation)
        route["geography"]["country"] = "CA"
        return normalized

    monkeypatch.setattr(
        network_module, "normalize_geo_observation", mutate_during_normalization
    )
    result = validate_geo_alignment(
        route,
        {
            "ip": "203.0.113.9",
            "country": "CA",
            "locale": "en-US",
            "timezone": "America/Chicago",
        },
    )
    assert result["checks"]["country"] is False
    assert result["passed"] is False


def test_geo_observation_reads_one_detached_field_snapshot() -> None:
    route = build_network_route(
        route_id="direct-observation-fields",
        name="Direct observation fields",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )

    class MutableObservation(dict):
        def get(self, key, default=None):
            if key == "country":
                self["timezone"] = "America/Chicago"
            return super().get(key, default)

    observation = MutableObservation(
        {
            "ip": "203.0.113.9",
            "country": "US",
            "locale": "en-US",
            "timezone": "America/New_York",
        }
    )
    result = validate_geo_alignment(route, observation)
    assert result["checks"]["timezone"] is False
    assert result["passed"] is False


def test_optional_geo_alignment_requires_observed_geography() -> None:
    route = build_network_route(
        route_id="optional-geo",
        name="Optional geography",
        geography=geography(),
        policies={
            "dns": "route",
            "webrtc": "route-only",
            "require_alignment": False,
        },
    )
    unknown = validate_geo_alignment(route, {"ip": "203.0.113.9"})
    assert set(unknown["checks"].values()) == {None}
    assert unknown["passed"] is False

    matched = validate_geo_alignment(
        route, {"ip": "203.0.113.9", "country": "US"}
    )
    assert matched["checks"]["country"] is True
    assert matched["passed"] is True


def test_geo_observation_rejects_invalid_ip() -> None:
    with pytest.raises(ContractError, match="IP"):
        normalize_geo_observation({"ip": "not-an-ip"})


@pytest.mark.parametrize(
    "observation",
    [
        {"ip": "203.0.113.1", "latitude": float("nan"), "longitude": 1.0},
        {"ip": "203.0.113.1", "latitude": 91.0, "longitude": 1.0},
        {"ip": "203.0.113.1", "latitude": 1.0},
        {"ip": "203.0.113.1", "country": "us"},
        {"ip": "203.0.113.1", "timezone": "bad timezone"},
        {"ip": "203.0.113.1", "locale": "bad_locale"},
        {"ip": "203.0.113.1", "private": "marker"},
    ],
)
def test_geo_observation_rejects_nonfinite_incomplete_or_unbounded_fields(
    observation: dict,
) -> None:
    with pytest.raises(ContractError, match="geography observation"):
        normalize_geo_observation(observation)


def test_network_numeric_boundaries_normalize_huge_integers_before_contact() -> None:
    huge = 10**1_000
    route = proxy_route()
    route["geography"]["coordinates"]["latitude"] = huge

    with pytest.raises(ContractError, match="coordinates"):
        validate_network_route(route)
    with pytest.raises(ContractError, match="geography observation"):
        normalize_geo_observation(
            {"ip": "203.0.113.1", "latitude": huge, "longitude": 1.0}
        )
    with pytest.raises(ContractError, match="proxy timeout"):
        network_module._validated_proxy_timeout(huge)

    class Opener:
        def open(self, *_args, **_kwargs):
            pytest.fail("huge timeout reached geography transport")

    with pytest.raises(ContractError, match="timeout"):
        network_module._read_geography_observer_response(
            Opener(),
            network_module.urllib.request.Request("https://ipwho.is/"),
            timeout_seconds=huge,
        )


def test_geo_observation_normalizes_ip_before_redacted_digest() -> None:
    expanded = normalize_geo_observation({"ip": "2001:0db8:0:0:0:0:0:1"})
    compressed = normalize_geo_observation({"ip": "2001:db8::1"})
    assert expanded["ip_sha256_16"] == compressed["ip_sha256_16"]


@pytest.mark.parametrize("ip_value", ["2001:db8::1%private-zone", "1" * 129])
def test_geo_observation_rejects_scoped_or_overlong_ip_forms(ip_value: str) -> None:
    with pytest.raises(ContractError, match="geography observation IP is invalid"):
        normalize_geo_observation({"ip": ip_value})


def test_route_rejects_web_rtc_policy_that_cannot_be_realized() -> None:
    with pytest.raises(ContractError, match="WebRTC"):
        build_network_route(
            route_id="invalid-webrtc",
            name="Invalid WebRTC",
            geography=geography(),
            policies={"dns": "route", "webrtc": "disabled", "require_alignment": True},
        )


def test_live_observer_redacts_provider_ip(monkeypatch) -> None:
    route = build_network_route(
        route_id="direct-us",
        name="Direct US",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    monkeypatch.setattr(
        "browser_core.network.preflight_network_route",
        lambda resolved, url, timeout_seconds: preflight_receipt(route),
    )

    class Response:
        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def close(self):
            self.closed = True

        def getcode(self):
            return 200

        def read(self, maximum):
            return (
                b'{"success":true,"ip":"203.0.113.10","country_code":"US",'
                b'"latitude":41.88,"longitude":-87.63,"timezone":{"id":"America/Chicago"}}'
            )

    class Opener:
        def open(self, request, timeout):
            return Response()

    monkeypatch.setattr(
        "browser_core.network.urllib.request.build_opener", lambda *_handlers: Opener()
    )
    result = observe_geo_alignment(
        route, browser_locale="en-US", browser_timezone="America/Chicago"
    )
    assert result["passed"] is True and result["checks"]["egress_timezone"] is True
    assert "203.0.113.10" not in str(result)


def test_live_observer_keeps_preflight_and_result_bound_to_one_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-observer-snapshot",
        name="Direct observer snapshot",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    preflight = preflight_receipt(route)

    def mutate_during_observation(*_args: object, **_kwargs: object) -> tuple[int, bytes]:
        route["geography"]["country"] = "CA"
        route["integrity_sha256"] = route_digest(route)
        return (
            200,
            b'{"success":true,"ip":"203.0.113.10","country_code":"CA",'
            b'"latitude":43.0,"longitude":-79.0,'
            b'"timezone":{"id":"America/Chicago"}}',
        )

    monkeypatch.setattr(
        network_module.urllib.request, "build_opener", lambda *_args: object()
    )
    monkeypatch.setattr(
        network_module,
        "_read_geography_observer_response",
        mutate_during_observation,
    )
    result = observe_geo_alignment(
        route,
        browser_locale="en-US",
        browser_timezone="America/Chicago",
        preflight=preflight,
    )
    assert route["integrity_sha256"][:16] != preflight["route_sha256_16"]
    assert result["route_sha256_16"] == preflight["route_sha256_16"]
    assert result["passed"] is False


def test_live_observer_rechecks_route_copied_after_validation_before_contact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-observer-copy-race",
        name="Direct observer copy race",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    receipt = preflight_receipt(route)
    original_validate = network_module.validate_network_route

    def mutate_after_validation(document):
        validated = original_validate(document)
        if document is route:
            document["geography"]["country"] = "CA"
        return validated

    monkeypatch.setattr(network_module, "validate_network_route", mutate_after_validation)
    monkeypatch.setattr(
        network_module.urllib.request,
        "build_opener",
        lambda *_args: pytest.fail("changed route reached observer contact"),
    )
    with pytest.raises(ContractError, match="integrity digest"):
        observe_geo_alignment(
            route,
            browser_locale="en-US",
            browser_timezone="America/Chicago",
            preflight=receipt,
        )


def test_public_preflight_receipt_rechecks_route_after_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-preflight-copy-race",
        name="Direct preflight copy race",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    receipt = preflight_receipt(route)
    original_validate = network_module.validate_network_route

    def mutate_after_validation(document):
        validated = original_validate(document)
        if document is route:
            document["geography"]["country"] = "CA"
        return validated

    monkeypatch.setattr(network_module, "validate_network_route", mutate_after_validation)
    with pytest.raises(ContractError, match="integrity digest"):
        network_module.validate_network_preflight_receipt(receipt, route)


def test_public_preflight_receipt_detaches_fields_during_validation() -> None:
    route = build_network_route(
        route_id="direct-preflight-fields",
        name="Direct preflight fields",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    receipt = preflight_receipt(route)
    expected_hash = receipt["endpoint_sha256_16"]

    class MutableReceipt(dict):
        def get(self, key, default=None):
            if key == "passed":
                self["endpoint_sha256_16"] = "0" * 16
            return super().get(key, default)

    result = network_module.validate_network_preflight_receipt(
        MutableReceipt(receipt), route
    )
    assert result["passed"] is True
    assert result["endpoint_sha256_16"] == expected_hash


def test_geography_observer_does_not_follow_redirected_provider_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/target")
                self.end_headers()
            else:
                target_requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

        def log_message(self, *_args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    route = build_network_route(
        route_id="direct-redirect",
        name="Direct redirect",
        geography=geography(),
    )
    original_reader = network_module._read_geography_observer_response

    def read_loopback(opener, _request, *, timeout_seconds):
        request = network_module.urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/start"
        )
        return original_reader(opener, request, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(
        network_module, "_read_geography_observer_response", read_loopback
    )
    thread.start()
    try:
        with pytest.raises(ContractError):
            observe_geo_alignment(
                route,
                browser_locale="en-US",
                browser_timezone="America/Chicago",
                preflight=preflight_receipt(route),
            )
        assert target_requests == []
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"extra": "private-marker"}, "preflight"),
        ({"target_host": "other.example"}, "preflight"),
        ({"latency_ms": True}, "preflight"),
        ({"passed": 1}, "preflight"),
    ],
)
def test_live_observer_rejects_ambiguous_preflight_before_provider_contact(
    changes: dict,
    match: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-preflight",
        name="Direct preflight",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    receipt = preflight_receipt(route)
    receipt.update(changes)
    monkeypatch.setattr(
        network_module.urllib.request,
        "build_opener",
        lambda *_args: pytest.fail("invalid preflight reached provider contact"),
    )
    with pytest.raises(ContractError, match=match):
        observe_geo_alignment(
            route,
            browser_locale="en-US",
            browser_timezone="America/Chicago",
            preflight=receipt,
        )


@pytest.mark.parametrize(
    ("locale", "timezone", "timeout"),
    [
        ("bad_locale", "America/Chicago", 1),
        ("en-US", "bad timezone", 1),
        ("en-US", "America/Chicago", True),
        ("en-US", "America/Chicago", float("nan")),
        ("en-US", "America/Chicago", 301),
    ],
)
def test_live_observer_rejects_invalid_controls_before_preflight(
    locale: str,
    timezone: str,
    timeout: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-controls",
        name="Direct controls",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    monkeypatch.setattr(
        network_module,
        "preflight_network_route",
        lambda *_args, **_kwargs: pytest.fail("invalid controls reached preflight"),
    )
    with pytest.raises(ContractError, match="observer"):
        observe_geo_alignment(
            route,
            browser_locale=locale,
            browser_timezone=timezone,
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize('gateway', ['http://[broken', 'http://@127.0.0.1:8123/'])
def test_live_observer_rejects_malformed_gateway_before_network_contact(monkeypatch, gateway):
    route = proxy_route()
    monkeypatch.setattr(
        network_module, 'preflight_network_route',
        lambda *_args, **_kwargs: pytest.fail('malformed gateway reached preflight'),
    )
    monkeypatch.setattr(
        network_module.urllib.request, 'build_opener',
        lambda *_args, **_kwargs: pytest.fail('malformed gateway reached observer'),
    )
    with pytest.raises(ContractError, match='gateway'):
        observe_geo_alignment(
            route,
            browser_locale='en-US',
            browser_timezone='America/Chicago',
            gateway_endpoint=gateway,
            preflight=preflight_receipt(route),
        )


@pytest.mark.parametrize(
    ("body", "status"),
    [
        (
            b'{"success":true,"success":true,"ip":"203.0.113.1",'
            b'"country_code":"US","latitude":1,"longitude":1,'
            b'"timezone":{"id":"America/Chicago"}}',
            200,
        ),
        (
            b'{"success":true,"ip":"203.0.113.1","country_code":"US",'
            b'"latitude":NaN,"longitude":1,"timezone":{"id":"America/Chicago"}}',
            200,
        ),
        (
            b'{"success":true,"ip":"203.0.113.1","country_code":"US",'
            b'"latitude":1e400,"longitude":1,"timezone":{"id":"America/Chicago"}}',
            200,
        ),
        (
            b'{"success":true,"ip":"203.0.113.1","country_code":"us",'
            b'"latitude":1,"longitude":1,"timezone":{"id":"America/Chicago"}}',
            200,
        ),
        (
            b'{"success":true,"ip":"203.0.113.1","country_code":"US",'
            b'"latitude":1,"longitude":1,"timezone":{"id":"bad timezone"}}',
            200,
        ),
        (
            b'{"success":true,"ip":"203.0.113.1","country_code":"US",'
            b'"latitude":1,"longitude":1,"timezone":{"id":"America/Chicago"}}',
            503,
        ),
        (
            b'{"success":true,"ip":"203.0.113.1","country_code":"US",'
            b'"latitude":1,"longitude":1,"timezone":{"id":"America/Chicago"}}',
            type("StatusSubclass", (int,), {})(200),
        ),
    ],
)
def test_live_observer_rejects_ambiguous_provider_evidence(
    body: bytes,
    status: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-provider",
        name="Direct provider",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )

    class Response:
        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def close(self):
            self.closed = True

        def getcode(self):
            return status

        def read(self, maximum):
            return body

    class Opener:
        def open(self, request, timeout):
            return Response()

    monkeypatch.setattr(
        network_module.urllib.request,
        "build_opener",
        lambda *_handlers: Opener(),
    )
    with pytest.raises(ContractError):
        observe_geo_alignment(
            route,
            browser_locale="en-US",
            browser_timezone="America/Chicago",
            preflight=preflight_receipt(route),
        )


def test_live_observer_retains_validated_preflight_population(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-retained",
        name="Direct retained",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )
    receipt = preflight_receipt(route)

    class Response:
        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def close(self):
            self.closed = True

        def getcode(self):
            return 200

        def read(self, maximum):
            return (
                b'{"success":true,"ip":"203.0.113.10","country_code":"US",'
                b'"latitude":41.88,"longitude":-87.63,'
                b'"timezone":{"id":"America/Chicago"}}'
            )

    class Opener:
        def open(self, request, timeout):
            receipt["latency_ms"] = 999
            return Response()

    monkeypatch.setattr(
        network_module.urllib.request,
        "build_opener",
        lambda *_handlers: Opener(),
    )
    result = observe_geo_alignment(
        route,
        browser_locale="en-US",
        browser_timezone="America/Chicago",
        preflight=receipt,
    )
    assert result["preflight"]["latency_ms"] == 1


def test_live_observer_owns_response_without_entering_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-owned-response",
        name="Direct owned response",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )

    class Response:
        def __init__(self):
            self.closed = False

        def __enter__(self):
            raise AssertionError("implicit response context must not be entered")

        def getcode(self):
            return 200

        def read(self, _maximum):
            return (
                b'{"success":true,"ip":"203.0.113.10","country_code":"US",'
                b'"latitude":41.88,"longitude":-87.63,'
                b'"timezone":{"id":"America/Chicago"}}'
            )

        def close(self):
            self.closed = True

    response = Response()

    class Opener:
        def open(self, _request, _timeout=None, **_kwargs):
            return response

    monkeypatch.setattr(
        network_module.urllib.request,
        "build_opener",
        lambda *_args: Opener(),
    )
    result = observe_geo_alignment(
        route,
        browser_locale="en-US",
        browser_timezone="America/Chicago",
        preflight=preflight_receipt(route),
    )
    assert result["passed"] is True
    assert response.closed is True


def test_live_observer_close_failure_blocks_valid_geography(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-close-failure",
        name="Direct close failure",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )

    class Response:
        def getcode(self):
            return 200

        def read(self, _maximum):
            return (
                b'{"success":true,"ip":"203.0.113.10","country_code":"US",'
                b'"latitude":41.88,"longitude":-87.63,'
                b'"timezone":{"id":"America/Chicago"}}'
            )

        def close(self):
            raise OSError("private geography close diagnostic")

    class Opener:
        def open(self, _request, _timeout=None, **_kwargs):
            return Response()

    monkeypatch.setattr(
        network_module.urllib.request,
        "build_opener",
        lambda *_args: Opener(),
    )
    with pytest.raises(ContractError) as raised:
        observe_geo_alignment(
            route,
            browser_locale="en-US",
            browser_timezone="America/Chicago",
            preflight=preflight_receipt(route),
        )
    assert str(raised.value) == ("geography observer cleanup failed (response-close)")
    assert raised.value.__cause__ is None
    assert "private" not in str(raised.value)


def test_live_observer_cleanup_failure_retains_only_safe_read_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = build_network_route(
        route_id="direct-read-close-failure",
        name="Direct read close failure",
        geography={"country": "US", "locale": "en-US", "timezone": "America/Chicago"},
    )

    class Response:
        def getcode(self):
            return 200

        def read(self, _maximum):
            raise RuntimeError("private geography read diagnostic")

        def close(self):
            raise ValueError("private geography close diagnostic")

    class Opener:
        def open(self, _request, _timeout=None, **_kwargs):
            return Response()

    monkeypatch.setattr(
        network_module.urllib.request,
        "build_opener",
        lambda *_args: Opener(),
    )
    with pytest.raises(ContractError) as raised:
        observe_geo_alignment(
            route,
            browser_locale="en-US",
            browser_timezone="America/Chicago",
            preflight=preflight_receipt(route),
        )
    assert str(raised.value) == ("geography observer cleanup failed (response-close)")
    assert isinstance(raised.value.__cause__, ContractError)
    assert str(raised.value.__cause__) == (
        "geography observer response failed (RuntimeError)"
    )
    assert "private" not in str(raised.value)


def test_live_observer_passes_primary_failure_into_gateway_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = proxy_route()
    monkeypatch.setenv("LAB_PROXY_USER", "owned-user")
    monkeypatch.setenv("LAB_PROXY_PASSWORD", "owned-password")
    exit_error = None

    class GatewayContext:
        def __enter__(self):
            return "127.0.0.1", 3128

        def __exit__(self, _error_type, error, _traceback):
            nonlocal exit_error
            exit_error = error
            cleanup = ContractError("owned gateway cleanup failed")
            if error is not None:
                raise cleanup from error
            raise cleanup from None

    monkeypatch.setattr(
        "browser_core.gateway.serve_gateway",
        lambda _resolved: GatewayContext(),
    )

    class Response:
        def __init__(self):
            self.read_called = False

        def getcode(self):
            return 503

        def read(self, _maximum):
            self.read_called = True
            return b"{}"

        def close(self):
            return None

    response = Response()

    class Opener:
        def open(self, _request, **_kwargs):
            return response

    monkeypatch.setattr(
        network_module.urllib.request,
        "build_opener",
        lambda *_args: Opener(),
    )

    with pytest.raises(ContractError) as raised:
        observe_geo_alignment(
            route,
            browser_locale="en-US",
            browser_timezone="America/Chicago",
            preflight=preflight_receipt(route),
        )
    assert str(raised.value) == "owned gateway cleanup failed"
    assert isinstance(exit_error, ContractError)
    assert str(exit_error) == "geography observer returned an unexpected status"
    assert raised.value.__cause__ is exit_error
    assert response.read_called is False


@pytest.mark.parametrize("timeout", [True, 0, float("nan"), 301])
def test_geography_observer_reader_rejects_timeout_before_contact(
    timeout,
) -> None:
    class Opener:
        def open(self, *_args, **_kwargs):
            pytest.fail("invalid timeout reached transport")

    with pytest.raises(ContractError, match="timeout"):
        network_module._read_geography_observer_response(
            Opener(),
            network_module.urllib.request.Request("https://ipwho.is/"),
            timeout_seconds=timeout,
        )


def test_geography_observer_reader_closes_http_error_body() -> None:
    body = io.BytesIO(b"private geography error body")
    error = urllib.error.HTTPError("https://ipwho.is/", 503, "private", {}, body)

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> None:
            raise error

    with pytest.raises(ContractError, match=r"geography observer response failed \(HTTPError\)"):
        network_module._read_geography_observer_response(
            Opener(),
            network_module.urllib.request.Request("https://ipwho.is/"),
            timeout_seconds=1,
        )
    assert body.closed


def test_geography_observer_reader_stops_fragmented_body_at_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(network_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    class Response:
        closed = False

        def getcode(self) -> int:
            return 200

        def read(self, _size: int) -> bytes:
            pytest.fail("aggregate geography read can outlive the deadline")

        def read1(self, _size: int) -> bytes:
            clock[0] += 0.06
            return b"x"

        def close(self) -> None:
            self.closed = True

    response = Response()

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> Response:
            return response

    with pytest.raises(ContractError, match="deadline"):
        network_module._read_geography_observer_response(
            Opener(),
            network_module.urllib.request.Request("https://ipwho.is/"),
            timeout_seconds=0.1,
        )
    assert response.closed


def test_geography_observer_rejects_complete_json_in_short_declared_body() -> None:
    class Response:
        def __init__(self) -> None:
            self.length = 4
            self.sent = False
            self.closed = False

        def getcode(self) -> int:
            return 200

        def read1(self, _maximum: int) -> bytes:
            if self.sent:
                return b""
            self.sent = True
            self.length -= 2
            return b"{}"

        def close(self) -> None:
            self.closed = True

    response = Response()

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> Response:
            return response

    with pytest.raises(ContractError, match="declared length"):
        network_module._read_geography_observer_response(
            Opener(),
            network_module.urllib.request.Request("https://ipwho.is/"),
            timeout_seconds=1,
        )
    assert response.closed


def test_geography_observer_reader_rejects_cleanup_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(
        network_module, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )

    class Response:
        closed = False

        def getcode(self) -> int:
            return 200

        def read(self, _size: int) -> bytes:
            return b"{}"

        def close(self) -> None:
            clock[0] = 2.0
            self.closed = True

    response = Response()

    class Opener:
        def open(self, *_args: object, **_kwargs: object) -> Response:
            return response

    with pytest.raises(ContractError, match="response deadline exceeded"):
        network_module._read_geography_observer_response(
            Opener(),
            network_module.urllib.request.Request("https://ipwho.is/"),
            timeout_seconds=1.0,
        )
    assert response.closed


@pytest.mark.parametrize("endpoint", [
    "http://example.com:3128",
    "http://127.0.0.1:3128?",
    "http://127.0.0.1:3128#",
])
def test_live_observer_rejects_non_loopback_gateway(monkeypatch, endpoint) -> None:
    route = proxy_route()
    monkeypatch.setenv("LAB_PROXY_USER", "owned-user")
    monkeypatch.setenv("LAB_PROXY_PASSWORD", "owned-password")
    monkeypatch.setattr(
        network_module, "_read_geography_observer_response",
        lambda *_args, **_kwargs: pytest.fail("invalid gateway reached transport"),
    )
    preflight = {
        "schema": "browser-core.network-preflight/1",
        "route_id": route["id"],
        "route_sha256_16": route["integrity_sha256"][:16],
        "passed": True,
    }
    with pytest.raises(ContractError, match="loopback"):
        observe_geo_alignment(
            route,
            browser_locale="en-US",
            browser_timezone="America/Chicago",
            gateway_endpoint=endpoint,
            preflight=preflight,
        )
