from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import time
import urllib.error
import urllib.request
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .contracts import ContractError
from .control_files import (
    BoundedControlSnapshot,
    decode_strict_json_bytes,
    load_canonical_json_document,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
    remove_control_conditionally,
)
from .http_deadline import (
    clamp_urllib_response_read_timeout,
    urllib_response_has_unread_declared_bytes,
)
from .profiles import PROFILE_ID_RE, has_windows_device_basename
from .numeric import is_finite_number
from .owned_paths import DirectoryIdentity, directory_identity


ROUTE_SCHEMA = "browser-core.network-route/1"
MAX_NETWORK_ROUTE_BYTES = 64 * 1024
MAX_NETWORK_ROUTES = 4096
MAX_NETWORK_ROUTE_DIRECTORY_ENTRIES = 8192
MAX_NETWORK_ROUTE_TOTAL_BYTES = 256 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
LOCALE_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")
TIMEZONE_RE = re.compile(r"^[A-Za-z_+-]+(?:/[A-Za-z0-9_+.-]+)+$")
DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MAX_NETWORK_CREDENTIAL_BYTES = 4096
MAX_PROXY_RESPONSE_HEADER_BYTES = 64 * 1024
MAX_PROXY_RESPONSE_HEADER_FIELDS = 128
MAX_GEOGRAPHY_OBSERVER_RESPONSE_BYTES = 1024 * 1024
MAX_GEOGRAPHY_OBSERVER_READ_CALLS = 65_536
_HTTP_HEADER_NAME_RE = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise ContractError("network route is not strict JSON") from None


def _route_payload(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "integrity_sha256"}


def route_digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(_route_payload(document))).hexdigest()


def _ambiguous_numeric_host_label(label: str) -> bool:
    # URL parsers and socket resolvers can treat a numeric final DNS label as
    # an abbreviated or encoded IPv4 address instead of the written hostname.
    return label.isdecimal() or re.fullmatch(r"0[xX][0-9A-Fa-f]+", label) is not None


def _validate_host(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ContractError("network route host is invalid")
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
            raise ContractError("network route host is invalid")
        return value
    except ValueError:
        labels = value[:-1].split(".") if value.endswith(".") else value.split(".")
        if (
            not HOST_RE.fullmatch(value)
            or not labels
            or any(DNS_LABEL_RE.fullmatch(label) is None for label in labels)
            or _ambiguous_numeric_host_label(labels[-1])
        ):
            raise ContractError("network route host is invalid") from None
    return value


def validate_network_route(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != ROUTE_SCHEMA:
        raise ContractError("unsupported network route")
    if set(document) != {
        "schema",
        "id",
        "name",
        "created_at",
        "mode",
        "endpoint",
        "auth",
        "geography",
        "policies",
        "preflight_url",
        "integrity_sha256",
    }:
        raise ContractError("network route fields are invalid")
    route_id = document.get("id")
    if (not isinstance(route_id, str) or not PROFILE_ID_RE.fullmatch(route_id)
            or has_windows_device_basename(route_id)):
        raise ContractError("network route ID is invalid")
    name = document.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise ContractError("network route name is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise ContractError("network route name is invalid")
    created_at = document.get("created_at")
    if not isinstance(created_at, str) or len(created_at) > 64:
        raise ContractError("network route created_at is invalid")
    try:
        created_at_value = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("network route created_at is invalid") from None
    if created_at_value.utcoffset() is None:
        raise ContractError("network route created_at is invalid")
    mode = document.get("mode")
    if mode not in ("direct", "proxy"):
        raise ContractError("network route mode must be direct or proxy")
    endpoint = document.get("endpoint")
    auth = document.get("auth")
    if mode == "direct":
        if endpoint is not None or auth is not None:
            raise ContractError(
                "direct network routes cannot contain an endpoint or auth"
            )
    else:
        if not isinstance(endpoint, dict) or endpoint.get("protocol") not in (
            "http",
            "https",
            "socks5",
        ):
            raise ContractError("proxy route protocol is unsupported")
        if set(endpoint) != {"protocol", "host", "port"}:
            raise ContractError("proxy route endpoint fields are invalid")
        _validate_host(endpoint.get("host"))
        port = endpoint.get("port")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ContractError("proxy route port is invalid")
        if auth is not None:
            if not isinstance(auth, dict) or set(auth) != {
                "username_env",
                "password_env",
            }:
                raise ContractError(
                    "proxy auth must contain only username/password environment references"
                )
            if any(
                not isinstance(value, str) or not ENV_RE.fullmatch(value)
                for value in auth.values()
            ):
                raise ContractError("proxy auth environment reference is invalid")
            if auth["username_env"] == auth["password_env"]:
                raise ContractError(
                    "proxy username and password references must differ"
                )

    geography = document.get("geography")
    if not isinstance(geography, dict) or set(geography) not in (
        {"country", "locale", "timezone"},
        {"country", "locale", "timezone", "coordinates"},
    ):
        raise ContractError("network route geography is required")
    country = geography.get("country")
    if not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country):
        raise ContractError("network route country must be ISO alpha-2 uppercase")
    locale = geography.get("locale")
    if not isinstance(locale, str) or not LOCALE_RE.fullmatch(locale):
        raise ContractError("network route locale is invalid")
    timezone_name = geography.get("timezone")
    if not isinstance(timezone_name, str) or not TIMEZONE_RE.fullmatch(timezone_name):
        raise ContractError("network route time zone is invalid")
    coordinates = geography.get("coordinates")
    if coordinates is not None:
        if not isinstance(coordinates, dict) or set(coordinates) != {
            "latitude",
            "longitude",
            "radius_km",
        }:
            raise ContractError("network route coordinates are invalid")
        latitude = coordinates.get("latitude")
        longitude = coordinates.get("longitude")
        radius = coordinates.get("radius_km")
        if any(
            not is_finite_number(item)
            for item in (latitude, longitude, radius)
        ):
            raise ContractError("network route coordinates must be numeric")
        if (
            not -90 <= latitude <= 90
            or not -180 <= longitude <= 180
            or not 0 < radius <= 20000
        ):
            raise ContractError("network route coordinates are out of range")
    policies = document.get("policies")
    if not isinstance(policies, dict) or set(policies) != {
        "dns",
        "webrtc",
        "require_alignment",
    }:
        raise ContractError("network route policies are required")
    if policies.get("dns") not in ("route", "system"):
        raise ContractError("network route DNS policy is invalid")
    if policies.get("webrtc") not in ("route-only", "default"):
        raise ContractError("network route WebRTC policy is invalid")
    if not isinstance(policies.get("require_alignment"), bool):
        raise ContractError("network route alignment policy must be boolean")
    preflight_url = document.get("preflight_url")
    if (
        not isinstance(preflight_url, str)
        or len(preflight_url) > 16_384
        or any(
            ord(character) < 32 or ord(character) == 127 for character in preflight_url
        )
    ):
        raise ContractError("network route preflight URL must be credential-free HTTPS")
    try:
        parsed_preflight = urlparse(preflight_url)
        parsed_preflight_host = parsed_preflight.hostname
        parsed_preflight_port = parsed_preflight.port
    except ValueError:
        parsed_preflight = None
        parsed_preflight_host = None
        parsed_preflight_port = None
    if (
        parsed_preflight is None
        or parsed_preflight.scheme != "https"
        or not parsed_preflight_host
        or parsed_preflight.username is not None
        or parsed_preflight.password is not None
        or parsed_preflight.query
        or parsed_preflight.fragment
        or "?" in preflight_url
        or "#" in preflight_url
        or (
            parsed_preflight_port is not None
            and not 1 <= parsed_preflight_port <= 65535
        )
    ):
        raise ContractError("network route preflight URL must be credential-free HTTPS")
    try:
        _target_host_forms(parsed_preflight_host)
    except ContractError:
        raise ContractError(
            "network route preflight URL must be credential-free HTTPS"
        ) from None
    integrity = document.get("integrity_sha256")
    if (
        not isinstance(integrity, str)
        or not SHA256_RE.fullmatch(integrity)
        or integrity != route_digest(document)
    ):
        raise ContractError("network route integrity digest does not match")
    return document


def build_network_route(
    *,
    route_id: str,
    name: str,
    geography: dict[str, Any],
    mode: str = "direct",
    endpoint: dict[str, Any] | None = None,
    auth: dict[str, str] | None = None,
    policies: dict[str, Any] | None = None,
    preflight_url: str = "https://tls.peet.ws/api/all",
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": ROUTE_SCHEMA,
        "id": route_id,
        "name": name,
        "created_at": _utc_now(),
        "mode": mode,
        "endpoint": endpoint,
        "auth": auth,
        "geography": geography,
        "policies": (
            policies
            if policies is not None
            else {"dns": "route", "webrtc": "route-only", "require_alignment": True}
        ),
        "preflight_url": preflight_url,
    }
    # Keep the validated route independent of caller-owned nested inputs.
    document = json.loads(_canonical(document))
    document["integrity_sha256"] = route_digest(document)
    return validate_network_route(document)


def _route_workspace_path(workspace: Path) -> Path:
    if not isinstance(workspace, Path):
        raise ContractError("network route workspace must be a Path")
    path = Path(os.path.abspath(workspace))
    for ancestor in reversed((path, *path.parents)):
        directory_identity(ancestor, label="network route directory")
    return path


def _route_path(workspace: Path, route_id: str) -> Path:
    if (not isinstance(route_id, str) or not PROFILE_ID_RE.fullmatch(route_id)
            or has_windows_device_basename(route_id)):
        raise ContractError("network route ID is invalid")
    return _route_workspace_path(workspace) / "network" / "routes" / f"{route_id}.json"


def _route_parent_identities(
    directory: Path,
) -> tuple[DirectoryIdentity | None, DirectoryIdentity | None]:
    """Reject links at both levels of the managed route directory."""
    return (
        directory_identity(directory.parent, label="network route directory"),
        directory_identity(directory, label="network route directory"),
    )


def _route_workspace_ancestry(
    workspace: Path,
) -> tuple[DirectoryIdentity | None, ...]:
    root = _route_workspace_path(workspace)
    return tuple(
        directory_identity(ancestor, label="network route workspace")
        for ancestor in reversed((root, *root.parents))
    )


def _route_file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _network_route_inventory(
    directory: Path,
) -> tuple[
    str,
    tuple[int, int, int, int, int, int] | None,
    tuple[tuple[str, tuple[int, int, int, int, int, int]], ...],
]:
    try:
        root_before = os.lstat(directory)
    except FileNotFoundError:
        return "missing", None, ()
    except OSError:
        raise ContractError("network route directory inventory failed") from None
    if not stat.S_ISDIR(root_before.st_mode) or bool(
        getattr(root_before, "st_file_attributes", 0) & 0x400
    ):
        raise ContractError("network route directory is not a stable directory")
    try:
        with os.scandir(directory) as iterator:
            entries = sorted(
                islice(iterator, MAX_NETWORK_ROUTE_DIRECTORY_ENTRIES + 1),
                key=lambda entry: entry.name,
            )
    except OSError:
        raise ContractError("network route directory inventory failed") from None
    if len(entries) > MAX_NETWORK_ROUTE_DIRECTORY_ENTRIES:
        raise ContractError("network route directory has too many entries")
    routes: list[tuple[str, tuple[int, int, int, int, int, int]]] = []
    total = 0
    for entry in entries:
        try:
            metadata = os.lstat(entry.path)
        except OSError:
            raise ContractError(
                "network route directory changed during inventory"
            ) from None
        if entry.is_symlink() or bool(
            getattr(metadata, "st_file_attributes", 0) & 0x400
        ):
            raise ContractError("network route directory contains a link")
        if entry.name.casefold().endswith(".json") and not entry.name.endswith(".json"):
            raise ContractError("network route candidate name is invalid")
        if not entry.name.endswith(".json"):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError("network route candidate is not a regular file")
        stem = entry.name[:-5]
        if PROFILE_ID_RE.fullmatch(stem) is None or has_windows_device_basename(stem):
            raise ContractError("network route candidate name is invalid")
        if metadata.st_nlink != 1:
            raise ContractError(
                "network route candidate must not have additional hard links"
            )
        if metadata.st_size > MAX_NETWORK_ROUTE_BYTES:
            raise ContractError("network route candidate exceeds the byte limit")
        total += metadata.st_size
        if total > MAX_NETWORK_ROUTE_TOTAL_BYTES:
            raise ContractError(
                "network route population exceeds the aggregate byte limit"
            )
        routes.append((entry.name, _route_file_identity(metadata)))
    if len(routes) > MAX_NETWORK_ROUTES:
        raise ContractError("network route population exceeds the route limit")
    if len({name[:-5].casefold() for name, _identity in routes}) != len(routes):
        raise ContractError("network route population contains duplicate IDs")
    try:
        root_after = os.lstat(directory)
    except OSError:
        raise ContractError(
            "network route directory changed during inventory"
        ) from None
    if _route_file_identity(root_before) != _route_file_identity(root_after):
        raise ContractError("network route directory changed during inventory")
    return "complete", _route_file_identity(root_after), tuple(routes)


@dataclass(frozen=True)
class NetworkRoutePublication:
    route: dict[str, Any]
    route_id: str
    created: bool
    body: bytes
    identity: tuple[int, int, int, int, int, int]
    workspace_ancestry: tuple[DirectoryIdentity | None, ...]
    route_parents: tuple[DirectoryIdentity | None, DirectoryIdentity | None]


def _load_network_route_snapshot(
    workspace: Path,
    route_id: str,
    *,
    missing_ok: bool = False,
) -> tuple[dict[str, Any] | None, BoundedControlSnapshot]:
    path = _route_path(workspace, route_id)
    workspace_before = _route_workspace_ancestry(workspace)
    root = path.parent.parent.parent
    root_before = directory_identity(root, label="network route directory")
    parents = _route_parent_identities(path.parent)
    if None in parents:
        snapshot = BoundedControlSnapshot("missing")
    else:
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_NETWORK_ROUTE_BYTES,
            label="network route",
            require_single_link=True,
        )
        if _route_parent_identities(path.parent) != parents:
            raise ContractError("network route directory changed during read")
    if _route_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("network route workspace changed during read")
    if directory_identity(root, label="network route directory") != root_before:
        raise ContractError("network route workspace changed during read")
    if snapshot.state == "missing" and missing_ok:
        return None, snapshot
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"network route is {snapshot.state}")
    try:
        document = load_canonical_json_document(snapshot.body, label="network route")
        validated = copy.deepcopy(validate_network_route(document))
        if validated["id"] != route_id:
            raise ContractError("network route file name does not match its ID")
    except ContractError:
        raise ContractError(
            "cannot read network route: invalid managed document"
        ) from None
    # Validation can outlast the first saved-file read. Rebind both its bytes
    # and pathname authority before returning a route from this public loader.
    final = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_NETWORK_ROUTE_BYTES,
        label="network route",
        require_single_link=True,
    )
    if (
        final.state != "complete"
        or final.body != snapshot.body
        or final.identity != snapshot.identity
        or _route_parent_identities(path.parent) != parents
    ):
        raise ContractError("network route changed during read")
    if _route_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("network route workspace changed during read")
    if directory_identity(root, label="network route directory") != root_before:
        raise ContractError("network route workspace changed during read")
    return validated, snapshot


def add_network_route_with_receipt(
    workspace: Path,
    document: dict[str, Any],
) -> NetworkRoutePublication:
    route = copy.deepcopy(validate_network_route(document))
    # Caller mutation after the first validation must not publish an unchecked
    # detached route before the saved-document readback can reject it.
    validate_network_route(route)
    path = _route_path(workspace, route["id"])
    root = path.parent.parent.parent
    root_before = directory_identity(root, label="network route directory")
    parents_before = _route_parent_identities(path.parent)
    workspace_before = _route_workspace_ancestry(workspace)

    def require_current_receipt(
        expected_route: dict[str, Any],
        expected_body: bytes,
        expected_identity: tuple[int, int, int, int, int, int],
        expected_root: DirectoryIdentity,
        expected_parents: tuple[DirectoryIdentity, DirectoryIdentity],
        expected_workspace: tuple[DirectoryIdentity | None, ...],
        *,
        error: str,
    ) -> None:
        try:
            saved, final = _load_network_route_snapshot(workspace, route["id"])
            _route_workspace_path(workspace)
            current_root = directory_identity(root, label="network route directory")
            current_parents = _route_parent_identities(path.parent)
            current_workspace = _route_workspace_ancestry(workspace)
        except ContractError:
            raise ContractError(error) from None
        if (
            saved != expected_route
            or final.body != expected_body
            or final.identity != expected_identity
            or current_root != expected_root
            or current_parents != expected_parents
            or current_workspace != expected_workspace
        ):
            raise ContractError(error)

    existing, snapshot = _load_network_route_snapshot(
        workspace,
        route["id"],
        missing_ok=True,
    )
    if existing is not None:
        if existing["integrity_sha256"] == route["integrity_sha256"]:
            assert snapshot.body is not None and snapshot.identity is not None
            if root_before is None or None in parents_before:
                raise ContractError("network route changed before receipt")
            require_current_receipt(
                existing,
                snapshot.body,
                snapshot.identity,
                root_before,
                parents_before,
                workspace_before,
                error="network route changed before receipt",
            )
            return NetworkRoutePublication(
                route=existing,
                route_id=route["id"],
                created=False,
                body=snapshot.body,
                identity=snapshot.identity,
                workspace_ancestry=workspace_before,
                route_parents=parents_before,
            )
        raise ContractError("network route ID conflict")
    _route_workspace_path(workspace)
    if directory_identity(root, label="network route directory") != root_before:
        raise ContractError("network route workspace changed before publication")
    network_directory = path.parent.parent
    network_before = directory_identity(network_directory, label="network route directory")
    routes_before = directory_identity(path.parent, label="network route directory")
    try:
        network_directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise ContractError("network route directory could not be created") from None
    network_after = directory_identity(network_directory, label="network route directory")
    if network_after is None or (network_before is not None and network_after != network_before):
        raise ContractError("network route directory changed before publication")
    try:
        path.parent.mkdir(exist_ok=True)
    except OSError:
        raise ContractError("network route directory could not be created") from None
    routes_after = directory_identity(path.parent, label="network route directory")
    if (
        routes_after is None
        or (routes_before is not None and routes_after != routes_before)
        or directory_identity(network_directory, label="network route directory") != network_after
    ):
        raise ContractError("network route directory changed before publication")
    root_after = directory_identity(root, label="network route directory")
    if root_after is None or (root_before is not None and root_after != root_before):
        raise ContractError("network route workspace changed before publication")
    workspace_after = _route_workspace_ancestry(workspace)
    if workspace_after[-1] != root_after:
        raise ContractError("network route workspace changed before publication")
    parents_after = (network_after, routes_after)
    try:
        publication = publish_json_exclusive_result(
            path,
            route,
            maximum=MAX_NETWORK_ROUTE_BYTES,
            label="network route",
        )
    except ContractError as exc:
        if "cleanup incomplete" in str(exc):
            raise
        raced, raced_snapshot = _load_network_route_snapshot(
            workspace,
            route["id"],
            missing_ok=True,
        )
        if raced is None:
            raise
        if raced["integrity_sha256"] != route["integrity_sha256"]:
            raise ContractError("network route ID conflict") from None
        assert raced_snapshot.body is not None and raced_snapshot.identity is not None
        require_current_receipt(
            raced,
            raced_snapshot.body,
            raced_snapshot.identity,
            root_after,
            parents_after,
            workspace_after,
            error="network route changed before receipt",
        )
        return NetworkRoutePublication(
            route=raced,
            route_id=route["id"],
            created=False,
            body=raced_snapshot.body,
            identity=raced_snapshot.identity,
            workspace_ancestry=workspace_after,
            route_parents=parents_after,
        )
    require_current_receipt(
        route,
        publication.body,
        publication.identity,
        root_after,
        parents_after,
        workspace_after,
        error="network route changed after publication",
    )
    return NetworkRoutePublication(
        route=route,
        route_id=route["id"],
        created=True,
        body=publication.body,
        identity=publication.identity,
        workspace_ancestry=workspace_after,
        route_parents=parents_after,
    )


def rollback_network_route_publication(
    workspace: Path,
    publication: NetworkRoutePublication,
) -> None:
    if not isinstance(publication, NetworkRoutePublication) or not publication.created:
        raise ContractError("network route rollback receipt is invalid")
    path = _route_path(workspace, publication.route_id)
    if _route_workspace_ancestry(workspace) != publication.workspace_ancestry:
        raise ContractError("network route workspace changed before rollback")
    parents = _route_parent_identities(path.parent)
    if None in parents:
        raise ContractError("network route directory is unavailable for rollback")
    if parents != publication.route_parents:
        raise ContractError("network route directory changed before rollback")
    remove_control_conditionally(
        path,
        expected_body=publication.body,
        expected_identity=publication.identity,
        maximum=MAX_NETWORK_ROUTE_BYTES,
        label="network route",
    )
    if _route_parent_identities(path.parent) != publication.route_parents:
        raise ContractError("network route directory changed during rollback")
    if _route_workspace_ancestry(workspace) != publication.workspace_ancestry:
        raise ContractError("network route workspace changed during rollback")
    remaining, _ = _load_network_route_snapshot(
        workspace, publication.route_id, missing_ok=True
    )
    if remaining is not None:
        raise ContractError("network route reappeared during rollback")
    if _route_workspace_ancestry(workspace) != publication.workspace_ancestry:
        raise ContractError("network route workspace changed during rollback")
    if _route_parent_identities(path.parent) != publication.route_parents:
        raise ContractError("network route directory changed during rollback")


def add_network_route(workspace: Path, document: dict[str, Any]) -> dict[str, Any]:
    return add_network_route_with_receipt(workspace, document).route


def load_network_route(workspace: Path, route_id: str) -> dict[str, Any]:
    document, _snapshot = _load_network_route_snapshot(workspace, route_id)
    assert document is not None
    return document


def list_network_routes(workspace: Path) -> list[dict[str, Any]]:
    if not isinstance(workspace, Path):
        raise ContractError("network route workspace must be a Path")
    directory = _route_workspace_path(workspace) / "network" / "routes"
    workspace_before = _route_workspace_ancestry(workspace)
    root = directory.parent.parent
    root_before = directory_identity(root, label="network route directory")
    parents = _route_parent_identities(directory)
    before = _network_route_inventory(directory)
    routes: list[dict[str, Any]] = []
    loaded_digests: list[bytes] = []
    for name, expected_identity in before[2]:
        document, snapshot = _load_network_route_snapshot(workspace, name[:-5])
        if snapshot.identity != expected_identity:
            raise ContractError("network route changed during population load")
        assert document is not None
        assert snapshot.body is not None
        routes.append(document)
        loaded_digests.append(hashlib.sha256(snapshot.body).digest())
    after = _network_route_inventory(directory)
    if _route_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("network route workspace changed during load")
    if directory_identity(root, label="network route directory") != root_before:
        raise ContractError("network route workspace changed during load")
    if after != before or _route_parent_identities(directory) != parents:
        raise ContractError("network route population changed during load")
    if _network_route_inventory(directory) != before:
        raise ContractError("network route population changed during load")
    # Windows metadata can remain identical after an in-place same-size edit
    # with restored mtime, including during the last inventory. Rebind
    # returned routes to bounded bytes after that inventory.
    for (name, expected_identity), expected_digest in zip(before[2], loaded_digests):
        final = read_bounded_control_snapshot_result(
            directory / name,
            maximum=MAX_NETWORK_ROUTE_BYTES,
            label="network route",
            require_single_link=True,
        )
        if (
            final.state != "complete"
            or final.body is None
            or final.identity != expected_identity
            or hashlib.sha256(final.body).digest() != expected_digest
        ):
            raise ContractError("network route population changed during load")
    if _network_route_inventory(directory) != before:
        raise ContractError("network route population changed during load")
    if _route_workspace_ancestry(workspace) != workspace_before:
        raise ContractError("network route workspace changed during load")
    if (directory_identity(root, label="network route directory") != root_before
            or _route_parent_identities(directory) != parents):
        raise ContractError("network route population changed during load")
    return routes


@dataclass(frozen=True)
class ResolvedNetworkRoute:
    route: dict[str, Any]
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)

    @property
    def protocol(self) -> str:
        retained = _validated_resolved_network_route(self)
        return (
            "direct"
            if retained.route["mode"] == "direct"
            else retained.route["endpoint"]["protocol"]
        )

    def browser_server(
        self, local_gateway: tuple[str, int] | None = None
    ) -> str | None:
        retained = _validated_resolved_network_route(self)
        if retained.route["mode"] == "direct":
            return None
        if local_gateway is not None:
            if not isinstance(local_gateway, tuple) or len(local_gateway) != 2:
                raise ContractError("network local gateway is invalid")
            host, port = local_gateway
            try:
                _socket_host, authority_host, port = _validated_target(host, port)
            except ContractError:
                raise ContractError("network local gateway is invalid") from None
            return f"http://{authority_host}:{port}"
        endpoint = retained.route["endpoint"]
        host = endpoint["host"]
        authority_host = f"[{host}]" if ":" in host else host
        return f"{endpoint['protocol']}://{authority_host}:{endpoint['port']}"


def _validated_credentials(
    route: dict[str, Any],
    username: object,
    password: object,
) -> tuple[str | None, str | None]:
    if route["auth"] is None:
        if username is not None or password is not None:
            raise ContractError("network route credentials are invalid")
        return None, None
    encoded: list[str] = []
    for value in (username, password):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ContractError("network route credentials are invalid")
        try:
            raw = value.encode("utf-8")
        except UnicodeError:
            raise ContractError("network route credentials are invalid") from None
        if len(raw) > MAX_NETWORK_CREDENTIAL_BYTES:
            raise ContractError("network route credentials are invalid")
        encoded.append(value)
    if route["endpoint"]["protocol"] in {"http", "https"} and ":" in encoded[0]:
        raise ContractError("network route credentials are invalid")
    return encoded[0], encoded[1]


def _validated_resolved_network_route(resolved: object) -> ResolvedNetworkRoute:
    if not isinstance(resolved, ResolvedNetworkRoute):
        raise ContractError("resolved network route is invalid")
    route = copy.deepcopy(validate_network_route(resolved.route))
    # The caller still owns `resolved.route` during its first validation. A
    # change before the copy must not turn the retained route into an unchecked
    # browser server or proxy target.
    validate_network_route(route)
    username, password = _validated_credentials(
        route, resolved.username, resolved.password
    )
    return ResolvedNetworkRoute(route, username=username, password=password)


def resolve_network_route(
    document: dict[str, Any], env: Mapping[str, str] | None = None
) -> ResolvedNetworkRoute:
    route = copy.deepcopy(validate_network_route(document))
    auth = route.get("auth")
    if auth is None:
        return _validated_resolved_network_route(ResolvedNetworkRoute(route))
    values = os.environ if env is None else env
    if not isinstance(values, Mapping):
        raise ContractError("network route credential environment is invalid")
    try:
        username = values[auth["username_env"]]
        password = values[auth["password_env"]]
    except KeyError:
        raise ContractError("network route credential references are unresolved") from None
    except Exception:
        raise ContractError("network route credential environment is invalid") from None
    if not username or not password:
        raise ContractError("network route credential references are unresolved")
    return _validated_resolved_network_route(
        ResolvedNetworkRoute(
            route,
            username=username,
            password=password,
        )
    )


def _recv_headers(
    connection: socket.socket,
    maximum: int = MAX_PROXY_RESPONSE_HEADER_BYTES,
    *,
    deadline: float | None = None,
) -> bytes:
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= 1024 * 1024
    ):
        raise ContractError("network response header limit is invalid")
    data = bytearray()
    while True:
        end = data.find(b"\r\n\r\n")
        if end >= 0:
            header_end = end + 4
            if header_end > maximum:
                raise ContractError("network preflight response headers are too large")
            if header_end != len(data):
                raise ContractError(
                    "network preflight response has unexpected bytes after headers"
                )
            return bytes(data)
        if len(data) >= maximum:
            raise ContractError("network preflight response headers are too large")
        if deadline is not None:
            connection.settimeout(_remaining(deadline))
        requested = min(4096, maximum + 4096 - len(data))
        chunk = connection.recv(requested)
        if type(chunk) is not bytes or len(chunk) > requested:
            raise ContractError("network proxy transport returned invalid bytes")
        if deadline is not None:
            _remaining(deadline)
        if not chunk:
            raise ContractError("network preflight response headers ended early")
        data.extend(chunk)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractError("network proxy handshake timed out")
    return remaining


def _target_host_forms(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ContractError("network preflight target host is invalid")
    host = value
    bracketed = value.startswith("[") or value.endswith("]")
    if bracketed:
        if not (value.startswith("[") and value.endswith("]")):
            raise ContractError("network preflight target host is invalid")
        host = value[1:-1]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if bracketed:
            raise ContractError("network preflight target host is invalid") from None
        try:
            wire = host.encode("ascii")
        except UnicodeError:
            raise ContractError("network preflight target host is invalid") from None
        labels = host[:-1].split(".") if host.endswith(".") else host.split(".")
        if (
            not wire
            or not labels
            or any(DNS_LABEL_RE.fullmatch(label) is None for label in labels)
        ):
            raise ContractError("network preflight target host is invalid")
        if _ambiguous_numeric_host_label(labels[-1]):
            raise ContractError("network preflight URL host is ambiguous")
        return host, host
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ContractError("network preflight target host is invalid")
    if bracketed and not isinstance(address, ipaddress.IPv6Address):
        raise ContractError("network preflight target host is invalid")
    normalized = str(address)
    return normalized, f"[{normalized}]" if address.version == 6 else normalized


def _validated_target(target_host: object, target_port: object) -> tuple[str, str, int]:
    if (
        isinstance(target_port, bool)
        or not isinstance(target_port, int)
        or not 1 <= target_port <= 65535
    ):
        raise ContractError("network preflight target port is invalid")
    socket_host, authority_host = _target_host_forms(target_host)
    return socket_host, authority_host, target_port


def _validated_proxy_timeout(timeout: object) -> float:
    if (
        not is_finite_number(timeout)
        or not 0 < timeout <= 300
    ):
        raise ContractError("network proxy timeout must be finite and in (0, 300]")
    return float(timeout)


def _parse_http_connect_response(response: bytes) -> int:
    if not response.endswith(b"\r\n\r\n"):
        raise ContractError("network proxy CONNECT response is incomplete")
    rows = response[:-4].split(b"\r\n")
    if not rows or len(rows) > MAX_PROXY_RESPONSE_HEADER_FIELDS + 1:
        raise ContractError("network proxy CONNECT response header count is invalid")
    match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?", rows[0])
    if match is None:
        raise ContractError("network proxy CONNECT response status is invalid")
    headers: dict[bytes, bytes] = {}
    for row in rows[1:]:
        if not row or row[:1] in {b" ", b"\t"}:
            raise ContractError("network proxy CONNECT response header is invalid")
        name, separator, value = row.partition(b":")
        normalized_name = name.lower()
        normalized_value = value.strip(b" \t")
        if (
            not separator
            or _HTTP_HEADER_NAME_RE.fullmatch(name) is None
            or normalized_name in headers
            or any(byte < 0x20 or byte == 0x7F for byte in normalized_value)
        ):
            raise ContractError("network proxy CONNECT response header is invalid")
        headers[normalized_name] = normalized_value
    if b"transfer-encoding" in headers or headers.get(b"content-length", b"0") != b"0":
        raise ContractError("network proxy CONNECT response body framing is invalid")
    return int(match.group(1))


def _recv_exact(connection: socket.socket, count: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < count:
        connection.settimeout(_remaining(deadline))
        requested = count - len(data)
        chunk = connection.recv(requested)
        if type(chunk) is not bytes or len(chunk) > requested:
            raise ContractError("network proxy transport returned invalid bytes")
        _remaining(deadline)
        if not chunk:
            raise ContractError("network SOCKS5 proxy response ended early")
        data.extend(chunk)
    return bytes(data)


def _send_proxy_bytes(connection: Any, body: bytes) -> None:
    if type(body) is not bytes or not body:
        raise ContractError("network proxy request bytes are invalid")
    if connection.sendall(body) is not None:
        raise ContractError("network proxy transport write is invalid")


def _close_network_connection(
    connection: Any,
    *,
    label: str,
    primary_error: BaseException | None = None,
) -> None:
    cleanup_error: ContractError | None = None
    try:
        connection.close()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        cleanup_error = ContractError(f"{label} cleanup failed (connection-close)")
    if cleanup_error is not None:
        if primary_error is None:
            raise cleanup_error from None
        if isinstance(primary_error, ContractError):
            raise cleanup_error from primary_error
        if isinstance(
            primary_error,
            (AttributeError, OSError, RuntimeError, TypeError, ValueError),
        ):
            raise cleanup_error from ContractError(
                f"{label} failed ({type(primary_error).__name__})"
            )
        raise cleanup_error from primary_error
    if primary_error is not None:
        raise primary_error


def _connect_http_proxy(
    resolved: ResolvedNetworkRoute, target_host: str, target_port: int, timeout: float
) -> socket.socket:
    retained = _validated_resolved_network_route(resolved)
    socket_host, authority_host, port = _validated_target(target_host, target_port)
    del socket_host
    timeout_value = _validated_proxy_timeout(timeout)
    if retained.protocol not in {"http", "https"}:
        raise ContractError("network HTTP proxy route is invalid")
    endpoint = retained.route["endpoint"]
    deadline = time.monotonic() + timeout_value
    connection: socket.socket | None = None
    try:
        connection = socket.create_connection(
            (endpoint["host"], endpoint["port"]), timeout=_remaining(deadline)
        )
        connection.settimeout(_remaining(deadline))
        if endpoint["protocol"] == "https":
            context = ssl.create_default_context()
            connection = context.wrap_socket(
                connection,
                server_hostname=endpoint["host"],
            )
            connection.settimeout(_remaining(deadline))
        headers = [
            f"CONNECT {authority_host}:{port} HTTP/1.1",
            f"Host: {authority_host}:{port}",
            "Proxy-Connection: keep-alive",
        ]
        if retained.username is not None and retained.password is not None:
            token = base64.b64encode(
                f"{retained.username}:{retained.password}".encode("utf-8")
            ).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {token}")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
        connection.settimeout(_remaining(deadline))
        _send_proxy_bytes(connection, request)
        connection.settimeout(_remaining(deadline))
        response = _recv_headers(connection, deadline=deadline)
        status = _parse_http_connect_response(response)
        if status != 200:
            raise ContractError(
                f"network proxy CONNECT preflight failed with status {status}"
            )
        connection.settimeout(timeout_value)
        _remaining(deadline)
        return connection
    except BaseException as exc:
        if connection is not None:
            _close_network_connection(
                connection,
                label="network HTTP proxy handshake",
                primary_error=exc,
            )
        raise


def _connect_socks5_proxy(
    resolved: ResolvedNetworkRoute, target_host: str, target_port: int, timeout: float
) -> socket.socket:
    retained = _validated_resolved_network_route(resolved)
    socket_host, _authority_host, port = _validated_target(target_host, target_port)
    timeout_value = _validated_proxy_timeout(timeout)
    if retained.protocol != "socks5":
        raise ContractError("network SOCKS5 proxy route is invalid")
    has_auth = retained.username is not None and retained.password is not None
    username = retained.username.encode("utf-8") if has_auth else b""
    password = retained.password.encode("utf-8") if has_auth else b""
    if has_auth and (not 1 <= len(username) <= 255 or not 1 <= len(password) <= 255):
        raise ContractError("network SOCKS5 credentials exceed protocol limits")
    try:
        address = ipaddress.ip_address(socket_host)
    except ValueError:
        encoded_host = socket_host.encode("ascii")
        if not 1 <= len(encoded_host) <= 255:
            raise ContractError("network preflight target host is too long")
        address_field = b"\x03" + bytes([len(encoded_host)]) + encoded_host
    else:
        address_field = (b"\x01" if address.version == 4 else b"\x04") + address.packed
    endpoint = retained.route["endpoint"]
    deadline = time.monotonic() + timeout_value
    connection: socket.socket | None = None
    try:
        connection = socket.create_connection(
            (endpoint["host"], endpoint["port"]), timeout=_remaining(deadline)
        )
        method = 2 if has_auth else 0
        method_request = b"\x05\x01" + bytes([method])
        connection.settimeout(_remaining(deadline))
        _send_proxy_bytes(connection, method_request)
        if _recv_exact(connection, 2, deadline) != bytes([5, method]):
            raise ContractError(
                "network SOCKS5 proxy rejected the authentication method"
            )
        if has_auth:
            auth_request = (
                b"\x01"
                + bytes([len(username)])
                + username
                + bytes([len(password)])
                + password
            )
            connection.settimeout(_remaining(deadline))
            _send_proxy_bytes(connection, auth_request)
            if _recv_exact(connection, 2, deadline) != b"\x01\x00":
                raise ContractError("network SOCKS5 proxy authentication failed")
        connect_request = b"\x05\x01\x00" + address_field + port.to_bytes(2, "big")
        connection.settimeout(_remaining(deadline))
        _send_proxy_bytes(connection, connect_request)
        head = _recv_exact(connection, 4, deadline)
        if head[:3] != b"\x05\x00\x00":
            raise ContractError("network SOCKS5 proxy connect failed")
        address_type = head[3]
        if address_type == 1:
            remaining = 4 + 2
        elif address_type == 4:
            remaining = 16 + 2
        elif address_type == 3:
            domain_length = _recv_exact(connection, 1, deadline)[0]
            if domain_length == 0:
                raise ContractError("network SOCKS5 proxy reply domain is invalid")
            remaining = domain_length + 2
        else:
            raise ContractError("network SOCKS5 proxy returned an invalid address type")
        _recv_exact(connection, remaining, deadline)
        connection.settimeout(timeout_value)
        _remaining(deadline)
        return connection
    except BaseException as exc:
        if connection is not None:
            _close_network_connection(
                connection,
                label="network SOCKS5 proxy handshake",
                primary_error=exc,
            )
        raise


def preflight_network_route(
    resolved: ResolvedNetworkRoute,
    probe_url: str,
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    if (
        not is_finite_number(timeout_seconds)
        or not 0 < timeout_seconds <= 300
    ):
        raise ContractError("network preflight timeout must be finite and in (0, 300]")
    if (
        not isinstance(probe_url, str)
        or not 1 <= len(probe_url) <= 16_384
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in probe_url
        )
    ):
        raise ContractError("network preflight URL must be credential-free HTTPS")
    retained = _validated_resolved_network_route(resolved)
    try:
        parsed = urlparse(probe_url)
        target_host = parsed.hostname
        parsed_port = parsed.port
    except ValueError:
        raise ContractError("network preflight URL port is invalid") from None
    if (
        parsed.scheme != "https"
        or not target_host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ContractError("network preflight URL must be credential-free HTTPS")
    if parsed.query or parsed.fragment or "?" in probe_url or "#" in probe_url:
        raise ContractError("network preflight URL cannot contain query or fragment")
    target_port = 443 if parsed_port is None else parsed_port
    target_host, _authority_host, target_port = _validated_target(
        target_host, target_port
    )
    started = time.monotonic()
    if retained.route["mode"] == "direct":
        connection = socket.create_connection(
            (target_host, target_port), timeout=timeout_seconds
        )
    elif retained.protocol in {"http", "https"}:
        connection = _connect_http_proxy(
            retained, target_host, target_port, timeout_seconds
        )
    else:
        connection = _connect_socks5_proxy(
            retained, target_host, target_port, timeout_seconds
        )
    connected_at = time.monotonic()
    _close_network_connection(connection, label="network preflight")
    if time.monotonic() - started >= timeout_seconds:
        raise ContractError("network preflight timed out")
    endpoint = retained.route.get("endpoint")
    endpoint_label = (
        "direct"
        if endpoint is None
        else f"{endpoint['protocol']}://{endpoint['host']}:{endpoint['port']}"
    )
    return {
        "schema": "browser-core.network-preflight/1",
        "route_id": retained.route["id"],
        "route_sha256_16": retained.route["integrity_sha256"][:16],
        "endpoint_sha256_16": hashlib.sha256(
            endpoint_label.encode("utf-8")
        ).hexdigest()[:16],
        "protocol": retained.protocol,
        "credential_refs_resolved": retained.route.get("auth") is not None,
        "target_host": target_host,
        "target_port": target_port,
        "latency_ms": round((connected_at - started) * 1000),
        "passed": True,
    }


def normalize_geo_observation(observation: Any) -> dict[str, Any]:
    allowed = {"ip", "country", "timezone", "locale", "latitude", "longitude"}
    if not isinstance(observation, dict):
        raise ContractError("geography observation must be an object")
    observation = dict.copy(observation)
    if not set(observation).issubset(allowed):
        raise ContractError("geography observation must be an object")
    ip_value = observation.get("ip")
    if not isinstance(ip_value, str):
        raise ContractError("geography observation IP is required")
    if not ip_value or len(ip_value) > 128:
        raise ContractError("geography observation IP is invalid")
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        raise ContractError("geography observation IP is invalid") from None
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ContractError("geography observation IP is invalid")
    normalized_ip = str(address)
    normalized: dict[str, Any] = {
        "ip_sha256_16": hashlib.sha256(normalized_ip.encode("ascii")).hexdigest()[:16],
    }
    country = observation.get("country")
    if country is not None:
        if not isinstance(country, str) or re.fullmatch(r"[A-Z]{2}", country) is None:
            raise ContractError("geography observation country is invalid")
        normalized["country"] = country
    timezone_name = observation.get("timezone")
    if timezone_name is not None:
        if (
            not isinstance(timezone_name, str)
            or TIMEZONE_RE.fullmatch(timezone_name) is None
        ):
            raise ContractError("geography observation timezone is invalid")
        normalized["timezone"] = timezone_name
    locale = observation.get("locale")
    if locale is not None:
        if not isinstance(locale, str) or LOCALE_RE.fullmatch(locale) is None:
            raise ContractError("geography observation locale is invalid")
        normalized["locale"] = locale
    for coordinate_name in ("latitude", "longitude"):
        value = observation.get(coordinate_name)
        if value is not None:
            if (
                not is_finite_number(value)
                or (coordinate_name == "latitude" and not -90 <= value <= 90)
                or (coordinate_name == "longitude" and not -180 <= value <= 180)
            ):
                raise ContractError(
                    f"geography observation {coordinate_name} is invalid"
                )
            normalized[coordinate_name] = float(value)
    if ("latitude" in normalized) != ("longitude" in normalized):
        raise ContractError("geography observation coordinates are incomplete")
    return normalized


def _strict_json_object(body: bytes, *, label: str) -> dict[str, Any]:
    try:
        document = decode_strict_json_bytes(body, label=label)
    except ContractError:
        raise ContractError(f"{label} returned invalid JSON") from None
    if not isinstance(document, dict):
        raise ContractError(f"{label} returned a non-object")
    return document


def _validated_preflight_receipt(
    document: object,
    route: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ContractError("geography observation route preflight is invalid")
    # Read every field from one plain dictionary so caller-owned subclasses or
    # concurrent updates cannot change a field after its comparison.
    document = dict.copy(document)
    fields = {
        "schema",
        "route_id",
        "route_sha256_16",
        "endpoint_sha256_16",
        "protocol",
        "credential_refs_resolved",
        "target_host",
        "target_port",
        "latency_ms",
        "passed",
    }
    if set(document) != fields:
        raise ContractError("geography observation route preflight is invalid")
    endpoint = route.get("endpoint")
    endpoint_label = (
        "direct"
        if endpoint is None
        else f"{endpoint['protocol']}://{endpoint['host']}:{endpoint['port']}"
    )
    expected_protocol = "direct" if endpoint is None else endpoint["protocol"]
    parsed = urlparse(route["preflight_url"])
    try:
        expected_host = parsed.hostname
        expected_port = 443 if parsed.port is None else parsed.port
    except ValueError:
        raise ContractError(
            "geography observation route preflight is invalid"
        ) from None
    expected_host, _authority, expected_port = _validated_target(
        expected_host, expected_port
    )
    target_host = document.get("target_host")
    target_port = document.get("target_port")
    try:
        target_host, _authority, target_port = _validated_target(
            target_host, target_port
        )
    except ContractError:
        raise ContractError(
            "geography observation route preflight is invalid"
        ) from None
    latency = document.get("latency_ms")
    if (
        document.get("schema") != "browser-core.network-preflight/1"
        or document.get("route_id") != route["id"]
        or document.get("route_sha256_16") != route["integrity_sha256"][:16]
        or document.get("endpoint_sha256_16")
        != hashlib.sha256(endpoint_label.encode("utf-8")).hexdigest()[:16]
        or document.get("protocol") != expected_protocol
        or document.get("credential_refs_resolved") is not (route["auth"] is not None)
        or target_host != expected_host
        or target_port != expected_port
        or isinstance(latency, bool)
        or not isinstance(latency, int)
        or not 0 <= latency <= 300_000
        or document.get("passed") is not True
    ):
        raise ContractError("geography observation route preflight is invalid")
    return {
        "schema": "browser-core.network-preflight/1",
        "route_id": route["id"],
        "route_sha256_16": route["integrity_sha256"][:16],
        "endpoint_sha256_16": document["endpoint_sha256_16"],
        "protocol": expected_protocol,
        "credential_refs_resolved": route["auth"] is not None,
        "target_host": target_host,
        "target_port": target_port,
        "latency_ms": latency,
        "passed": True,
    }


def validate_network_preflight_receipt(
    document: object,
    route: dict[str, Any],
) -> dict[str, Any]:
    """Return an exact, route-bound public network-preflight receipt."""

    retained_route = copy.deepcopy(validate_network_route(route))
    validate_network_route(retained_route)
    return _validated_preflight_receipt(document, retained_route)


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math

    radius = 6371.0088
    first = math.radians(lat1)
    second = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    value = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(first) * math.cos(second) * math.sin(delta_lon / 2) ** 2
    )
    return 2 * radius * math.asin(min(1.0, math.sqrt(value)))


def validate_geo_alignment(
    route: dict[str, Any], observation: dict[str, Any]
) -> dict[str, Any]:
    validated_route = copy.deepcopy(validate_network_route(route))
    validate_network_route(validated_route)
    observed = normalize_geo_observation(observation)
    expected = validated_route["geography"]
    checks: dict[str, bool | None] = {
        "country": observed.get("country") == expected["country"]
        if "country" in observed
        else None,
        "timezone": observed.get("timezone") == expected["timezone"]
        if "timezone" in observed
        else None,
        "locale": observed.get("locale", "").casefold() == expected["locale"].casefold()
        if "locale" in observed
        else None,
    }
    coordinates = expected.get("coordinates")
    distance_km: float | None = None
    if coordinates is not None and "latitude" in observed and "longitude" in observed:
        distance_km = _haversine_km(
            coordinates["latitude"],
            coordinates["longitude"],
            observed["latitude"],
            observed["longitude"],
        )
        checks["coordinates"] = distance_km <= coordinates["radius_km"]
    elif coordinates is not None:
        checks["coordinates"] = None
    required = validated_route["policies"]["require_alignment"]
    passed = (
        all(value is True for value in checks.values())
        if required
        else any(value is True for value in checks.values())
        and not any(value is False for value in checks.values())
    )
    return {
        "schema": "browser-core.geo-alignment/1",
        "route_id": validated_route["id"],
        "route_sha256_16": validated_route["integrity_sha256"][:16],
        "required": required,
        "passed": passed,
        "checks": checks,
        "distance_km": round(distance_km, 3) if distance_km is not None else None,
        "observed": observed,
    }


class _NoGeographyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _read_geography_observer_response(
    opener: Any,
    request: urllib.request.Request,
    *,
    timeout_seconds: float,
) -> tuple[Any, Any]:
    if (
        not is_finite_number(timeout_seconds)
        or not 0 < timeout_seconds <= 300
    ):
        raise ContractError("geography observer timeout is invalid")
    timeout_seconds = float(timeout_seconds)
    response: Any | None = None
    status: Any = None
    body: Any = None
    primary_error: BaseException | None = None
    try:
        deadline = time.monotonic() + timeout_seconds
        response = opener.open(request, timeout=timeout_seconds)
        status = response.getcode()
        if type(status) is int and status == 200:
            reader = getattr(response, "read1", None)
            if callable(reader):
                parts = bytearray()
                for _ in range(MAX_GEOGRAPHY_OBSERVER_READ_CALLS):
                    if not clamp_urllib_response_read_timeout(
                        response, deadline - time.monotonic()
                    ):
                        raise ContractError("geography observer response deadline exceeded")
                    remaining = MAX_GEOGRAPHY_OBSERVER_RESPONSE_BYTES + 1 - len(parts)
                    try:
                        chunk = reader(remaining)
                    except TimeoutError:
                        raise ContractError(
                            "geography observer response deadline exceeded"
                        ) from None
                    if time.monotonic() > deadline:
                        raise ContractError("geography observer response deadline exceeded")
                    if type(chunk) is not bytes or len(chunk) > remaining:
                        raise ContractError("geography observer response body is invalid")
                    parts.extend(chunk)
                    if not chunk or len(parts) > MAX_GEOGRAPHY_OBSERVER_RESPONSE_BYTES:
                        break
                else:
                    raise ContractError("geography observer response has too many fragments")
                body = bytes(parts)
            else:
                if not clamp_urllib_response_read_timeout(
                    response, deadline - time.monotonic()
                ):
                    raise ContractError("geography observer response deadline exceeded")
                try:
                    body = response.read(MAX_GEOGRAPHY_OBSERVER_RESPONSE_BYTES + 1)
                except TimeoutError:
                    raise ContractError(
                        "geography observer response deadline exceeded"
                    ) from None
                if time.monotonic() > deadline:
                    raise ContractError("geography observer response deadline exceeded")
            if (
                type(body) is bytes
                and len(body) <= MAX_GEOGRAPHY_OBSERVER_RESPONSE_BYTES
                and urllib_response_has_unread_declared_bytes(response)
            ):
                raise ContractError(
                    "geography observer response ended before declared length"
                )
    except BaseException as exc:
        if isinstance(exc, urllib.error.HTTPError):
            response = exc
        if isinstance(exc, ContractError):
            primary_error = exc
        elif isinstance(
            exc, (AttributeError, OSError, RuntimeError, TypeError, ValueError)
        ):
            primary_error = ContractError(
                f"geography observer response failed ({type(exc).__name__})"
            )
        else:
            primary_error = exc

    cleanup_error: ContractError | None = None
    if response is not None:
        try:
            response.close()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            cleanup_error = ContractError(
                "geography observer cleanup failed (response-close)"
            )
    if cleanup_error is not None:
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error from None
    if primary_error is not None:
        raise primary_error from None
    if time.monotonic() >= deadline:
        raise ContractError("geography observer response deadline exceeded")
    return status, body


def observe_geo_alignment(
    route: dict[str, Any],
    *,
    browser_locale: str,
    browser_timezone: str,
    timeout_seconds: float = 15.0,
    gateway_endpoint: str | None = None,
    preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Observe egress through the realized route and return only redacted data."""

    # A blocking preflight or observer read must not let caller mutation change
    # the route after its preflight receipt has been accepted.
    validated_route = copy.deepcopy(validate_network_route(route))
    validate_network_route(validated_route)
    if (
        not is_finite_number(timeout_seconds)
        or not 0 < timeout_seconds <= 300
    ):
        raise ContractError("geography observer timeout is invalid")
    if (
        not isinstance(browser_locale, str)
        or LOCALE_RE.fullmatch(browser_locale) is None
    ):
        raise ContractError("geography observer browser locale is invalid")
    if (
        not isinstance(browser_timezone, str)
        or TIMEZONE_RE.fullmatch(browser_timezone) is None
    ):
        raise ContractError("geography observer browser timezone is invalid")
    if gateway_endpoint is not None and (
        not isinstance(gateway_endpoint, str)
        or not 1 <= len(gateway_endpoint) <= 128
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in gateway_endpoint
        )
    ):
        raise ContractError(
            "geography observer gateway must be credential-free loopback HTTP"
        )
    if gateway_endpoint is not None:
        try:
            parsed_gateway = urlparse(gateway_endpoint)
            gateway_port = parsed_gateway.port
        except ValueError:
            parsed_gateway = None
            gateway_port = None
        if (
            validated_route["mode"] != "proxy"
            or parsed_gateway is None
            or parsed_gateway.scheme != "http"
            or parsed_gateway.hostname != "127.0.0.1"
            or gateway_port is None
            or parsed_gateway.username is not None
            or parsed_gateway.password is not None
            or parsed_gateway.path not in {"", "/"}
            or parsed_gateway.query
            or parsed_gateway.fragment
            or "?" in gateway_endpoint
            or "#" in gateway_endpoint
        ):
            if validated_route["mode"] == "direct":
                raise ContractError(
                    "direct geography observation cannot use a gateway endpoint"
                )
            raise ContractError(
                "geography observer gateway must be credential-free loopback HTTP"
            )
    preflight_result = preflight
    if preflight_result is None:
        # Resolve credentials only on the path that needs them. A caller that
        # supplies both a preflight and a gateway endpoint has already made the
        # connection, and demanding the environment hold the credential a second
        # time made callers that store credentials elsewhere fail here for no
        # reason -- after the proxy had already answered.
        preflight_result = preflight_network_route(
            resolve_network_route(validated_route),
            validated_route["preflight_url"],
            timeout_seconds=timeout_seconds,
        )
    preflight_result = _validated_preflight_receipt(preflight_result, validated_route)
    proxy_url = None
    gateway_manager: Any = nullcontext(None)
    if validated_route["mode"] == "proxy":
        if gateway_endpoint is not None:
            proxy_url = gateway_endpoint
        else:
            # Imported lazily to keep the route contract independent from its
            # credential-isolating realization sidecar.
            from .gateway import serve_gateway

            gateway_manager = serve_gateway(resolve_network_route(validated_route))
    with gateway_manager as gateway_address:
        if gateway_address is not None:
            host, port = gateway_address
            proxy_url = f"http://{host}:{port}"
        handler = urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url} if proxy_url else {}
        )
        opener = urllib.request.build_opener(handler, _NoGeographyRedirectHandler())
        request = urllib.request.Request(
            "https://ipwho.is/",
            headers={"Accept": "application/json", "User-Agent": "BrowserCoreGeo/1"},
        )
        status, body = _read_geography_observer_response(
            opener,
            request,
            timeout_seconds=timeout_seconds,
        )
        if type(status) is not int or status != 200:
            raise ContractError("geography observer returned an unexpected status")
        if type(body) is not bytes:
            raise ContractError("geography observer response is invalid")
        if len(body) > MAX_GEOGRAPHY_OBSERVER_RESPONSE_BYTES:
            raise ContractError("geography observer response is too large")
        payload = _strict_json_object(body, label="geography observer")
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise ContractError("geography observer reported failure")
    timezone_value = payload.get("timezone")
    provider_timezone = (
        timezone_value.get("id") if isinstance(timezone_value, dict) else None
    )
    if (
        not isinstance(provider_timezone, str)
        or TIMEZONE_RE.fullmatch(provider_timezone) is None
    ):
        raise ContractError("geography observer returned an invalid timezone")
    raw_observation = {
        "ip": payload.get("ip"),
        "country": payload.get("country_code"),
        "timezone": browser_timezone,
        "locale": browser_locale,
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
    }
    alignment = validate_geo_alignment(validated_route, raw_observation)
    alignment["checks"]["egress_timezone"] = (
        provider_timezone == validated_route["geography"]["timezone"]
        if isinstance(provider_timezone, str)
        else None
    )
    # Report the zone the exit actually sits in, not only whether it matched. A
    # rotating residential pool spans every zone in a country, so "false" here is
    # usually not a broken route -- it is the route needing to be told which zone
    # this particular exit landed in, and that is impossible to act on if the
    # observed value is thrown away.
    alignment["egress_timezone"] = (
        provider_timezone if isinstance(provider_timezone, str) else None
    )
    required = validated_route["policies"]["require_alignment"]
    alignment["passed"] = (
        all(value is True for value in alignment["checks"].values())
        if required
        else any(value is True for value in alignment["checks"].values())
        and not any(value is False for value in alignment["checks"].values())
    )
    alignment["schema"] = "browser-core.geo-realization/1"
    alignment["preflight"] = preflight_result
    alignment["observer"] = "ipwho.is"
    return alignment
