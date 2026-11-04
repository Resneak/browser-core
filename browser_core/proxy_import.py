"""Turn a pasted provider proxy string into a verified network route.

Browser Core already had everything needed to *run* a proxy: routes with
geography, a credential-isolating loopback gateway, CONNECT/SOCKS5 preflight,
WebRTC and DNS policy, and a post-launch check that the exit IP's country
actually matches what the identity claims. What it did not have was the thirty
seconds at the start where a person pastes the line their provider gave them.

That gap is the whole reason this module exists. Commercial anti-detect browsers
take ``host:port:user:pass`` in a text box; here you had to hand-author a route
document and export two environment variables first. Everything below is
ergonomics on top of the existing contract -- no new trust, no new network
behaviour, and the route schema is untouched.

Three things are worth knowing about the design:

**Credentials never enter a route.** ``network-route/1`` stores only
``{username_env, password_env}`` -- names of environment variables, not values --
which is what keeps proxy passwords out of every record, bundle, and evidence
pack the tool emits. Rather than weaken that, the pasted secret goes to a
separate per-route file under ``<workspace>/network/secrets/`` and is handed to
``resolve_network_route`` through its existing ``env`` parameter. The process
environment is never mutated, and the secret is never an argument on a command
line where another local process could read it out of the process table.

**Residential usernames are a structured field, not an opaque token.** Providers
encode the exit country and the session pin *inside* the username, e.g.
``customer-USER-cc-us-sessid-a1b2c3d4e5-sesstime-10``. Parsing that grammar is
what lets the importer fill in a route's geography from the proxy itself instead
of asking, and it is what makes the next point possible.

**One route, many sticky exits.** A list of 1,000 pre-minted session strings is
1,000 fixed exit IPs. Reading the grammar instead means one imported route can
mint a *deterministic* session ID per identity: two profiles never share an exit,
and the supply is not capped by how many lines were in the file.
``sticky_session_id`` is a pure function of the key, so the pin survives restarts
with no state to lose.

What the pin does *not* do is hold an IP forever. The vendor honours a session
for the TTL in the username -- ``sesstime-10`` means ten minutes -- and after
that the same pin is issued a fresh address. Measured on this host: two checks
run back to back returned one IP, and the same key checked again a quarter of an
hour later returned another. Sticky means stable within the window, and the
window is the vendor's to set.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import io
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import unquote

from .control_files import (
    BoundedControlSnapshot,
    canonical_json_bytes,
    decode_strict_json_bytes,
    publish_json_exclusive,
    read_bounded_control_snapshot_result,
    require_bounded_control_snapshot_unchanged,
    remove_control_conditionally,
    replace_json_conditionally,
)
from .contracts import ContractError
from .errors import safe_failure_receipt
from .network import (
    MAX_NETWORK_CREDENTIAL_BYTES,
    NetworkRoutePublication,
    ResolvedNetworkRoute,
    _load_network_route_snapshot,
    _route_parent_identities,
    _route_path,
    _route_workspace_ancestry,
    _validate_host,
    add_network_route_with_receipt,
    build_network_route,
    load_network_route,
    resolve_network_route,
    validate_network_route,
)
from .numeric import is_ascii_decimal
from .owned_paths import directory_identity
from .personas import BULK_GEOGRAPHIES
from .profiles import PROFILE_ID_RE, has_windows_device_basename

PROXY_SECRET_SCHEMA = "browser-core.proxy-secret/1"
PROXY_IMPORT_SCHEMA = "browser-core.proxy-import/1"
PROXY_FILE_IMPORT_SCHEMA = "browser-core.proxy-file-import/1"
MAX_PROXY_SECRET_BYTES = 64 * 1024
MAX_PROXY_IMPORT_FILE_BYTES = 16 * 1024 * 1024
MAX_PROXY_IMPORT_LINES = 100_000
MAX_PROXY_IMPORT_PHYSICAL_LINES = 200_000

# Protocols the existing route contract already knows how to preflight and relay.
SUPPORTED_PROTOCOLS = ("http", "https", "socks5")
_PROTOCOL_ALIASES = {
    "socks": "socks5",
    "socks5h": "socks5",
    "http": "http",
    "https": "https",
    "socks5": "socks5",
}

# Dash-token username grammar shared by the major residential vendors. The key
# names differ per vendor but the shape does not: ``label-value`` pairs joined by
# dashes, with the account name in the first pair.
_COUNTRY_KEYS = ("cc", "country", "region")
_SESSION_KEYS = ("sessid", "session", "sessionid", "sess", "sid")
_TTL_KEYS = ("sesstime", "sessionduration", "sessiontime", "lifetime", "ttl")

_SESSION_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
_COUNTRY_TOKEN_RE = re.compile(r"^[A-Za-z]{2}$")
_CANONICAL_ROUTE_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

_PROXY_LINE_FAILURE_REASONS = {
    "proxy line must be a string": "non-text-line",
    "proxy line text is invalid": "invalid-line-text",
    "proxy line is empty or too long": "empty-or-oversize-line",
    "proxy line cannot contain whitespace": "embedded-whitespace",
    "proxy URL has no scheme": "missing-scheme",
    "proxy protocol is unsupported": "unsupported-protocol",
    "proxy URL has no authority": "missing-authority",
    "proxy authority is incomplete": "incomplete-authority",
    "proxy credentials must be username:password": "invalid-credentials",
    "proxy authority must include a port": "missing-port",
    "proxy host or port is invalid": "invalid-host-or-port",
    (
        "proxy line is ambiguous -- both field orders parse; "
        "use scheme://user:pass@host:port instead"
    ): "ambiguous-field-order",
    "proxy line format is not recognized": "unrecognized-format",
}

# Locale/time-zone defaults reuse the persona catalog's own table so an imported
# route and a persona created for the same country cannot disagree by accident --
# ``profile_bindings`` rejects that pairing outright, and a second table here
# would be a slow way to discover it.
_GEO_DEFAULTS: dict[str, dict[str, str]] = {
    entry["country"]: entry for entry in BULK_GEOGRAPHIES
}


def _bounded_utf8_text(value: Any, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} is invalid") from None
    if len(encoded) > maximum or any(
        byte < 0x20 or byte == 0x7F for byte in encoded
    ):
        raise ContractError(f"{label} is invalid")
    return encoded


class ParsedProxy:
    """A parsed provider line. Credentials are held but never rendered."""

    __slots__ = ("protocol", "host", "port", "username", "password")

    def __init__(
        self,
        *,
        protocol: str,
        host: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        self.protocol = protocol
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def __repr__(self) -> str:  # pragma: no cover - defensive, exercised by tests
        marker = "with-credentials" if self.username else "anonymous"
        return f"ParsedProxy({self.protocol}://{self.host}:{self.port} {marker})"

    @property
    def has_credentials(self) -> bool:
        return self.username is not None and self.password is not None

    @property
    def credential_sha256_16(self) -> str | None:
        """Stable short fingerprint so two credentials can be told apart safely."""
        if not self.has_credentials:
            return None
        username = _bounded_utf8_text(
            self.username, label="proxy credentials", maximum=4096
        )
        password = _bounded_utf8_text(
            self.password, label="proxy credentials", maximum=4096
        )
        material = username + b"\0" + password
        return hashlib.sha256(material).hexdigest()[:16]

    def endpoint(self) -> dict[str, Any]:
        return {"protocol": self.protocol, "host": self.host, "port": self.port}

    def redacted(self) -> dict[str, Any]:
        session = parse_session_username(self.username) if self.username else None
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "authenticated": self.has_credentials,
            "credential_sha256_16": self.credential_sha256_16,
            "session_grammar": None if session is None else session["grammar"],
            "country_hint": None if session is None else session["country"],
            "session_minutes": None if session is None else session["session_minutes"],
        }


def _detached_parsed_proxy(parsed: ParsedProxy) -> ParsedProxy:
    return ParsedProxy(
        protocol=parsed.protocol,
        host=parsed.host,
        port=parsed.port,
        username=parsed.username,
        password=parsed.password,
    )


def _validate_relay_credentials(parsed: ParsedProxy) -> None:
    """Reject credentials that the selected proxy handshake cannot transmit."""
    if parsed.protocol not in SUPPORTED_PROTOCOLS:
        raise ContractError("proxy credentials are invalid")
    try:
        username = _bounded_utf8_text(
            parsed.username,
            label="proxy credentials",
            maximum=MAX_NETWORK_CREDENTIAL_BYTES,
        )
        password = _bounded_utf8_text(
            parsed.password,
            label="proxy credentials",
            maximum=MAX_NETWORK_CREDENTIAL_BYTES,
        )
    except ContractError:
        raise ContractError("proxy credentials are invalid") from None
    if parsed.protocol in {"http", "https"} and b":" in username:
        raise ContractError("proxy credentials are invalid")
    if parsed.protocol == "socks5" and (len(username) > 255 or len(password) > 255):
        raise ContractError("proxy credentials are invalid")


def _normalize_protocol(value: str | None, *, default: str = "http") -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ContractError("proxy protocol is unsupported")
    if not value:
        return default
    protocol = _PROTOCOL_ALIASES.get(value.strip(" \t").lower())
    if protocol is None:
        raise ContractError("proxy protocol is unsupported")
    return protocol


def _valid_port(value: str) -> int | None:
    if not is_ascii_decimal(value) or len(value) > 5:
        return None
    port = int(value)
    return port if 1 <= port <= 65535 else None


def _valid_host(value: str) -> bool:
    if not value or len(value) > 253 or _HOST_RE.fullmatch(value) is None:
        return False
    try:
        _validate_host(value)
    except ContractError:
        return False
    return True


def _normalized_host(value: str) -> str | None:
    if value.startswith("["):
        if not value.endswith("]"):
            return None
        try:
            address = ipaddress.IPv6Address(value[1:-1])
        except ValueError:
            return None
        return None if address.scope_id is not None else str(address)
    return value.lower() if _valid_host(value) else None


def parse_proxy_line(line: str, *, default_protocol: str = "http") -> ParsedProxy:
    """Parse the formats providers actually hand out.

    Accepted, in the order they are tried::

        scheme://user:pass@host:port
        scheme://host:port
        user:pass@host:port
        host:port:user:pass
        user:pass:host:port
        host:port

    The two four-field orderings are told apart by which side parses as a port,
    because both are in circulation and guessing wrong silently sends the
    password to a hostname. When neither side resolves cleanly this raises rather
    than picking one.
    """
    if not isinstance(line, str):
        raise ContractError("proxy line must be a string")
    _bounded_utf8_text(line, label="proxy line text", maximum=4096)
    text = line.strip(" \t\r\n")
    if not text or len(text) > 1024:
        raise ContractError("proxy line is empty or too long")
    if any(character.isspace() for character in text):
        raise ContractError("proxy line cannot contain whitespace")

    protocol = _normalize_protocol(default_protocol, default="http")
    if "://" in text:
        scheme, _, remainder = text.partition("://")
        if not scheme:
            raise ContractError("proxy URL has no scheme")
        protocol = _normalize_protocol(scheme)
        text = remainder
        if not text:
            raise ContractError("proxy URL has no authority")
    username: str | None = None
    password: str | None = None

    if "@" in text:
        credentials, _, authority = text.rpartition("@")
        if not credentials or not authority:
            raise ContractError("proxy authority is incomplete")
        username, separator, password = credentials.partition(":")
        if not separator:
            raise ContractError("proxy credentials must be username:password")
        try:
            username = unquote(username, errors="strict")
            password = unquote(password, errors="strict")
        except UnicodeDecodeError:
            raise ContractError("proxy credentials must be username:password") from None
        if not username or not password:
            raise ContractError("proxy credentials must be username:password")
        try:
            _bounded_utf8_text(username, label="proxy credentials", maximum=4096)
            _bounded_utf8_text(password, label="proxy credentials", maximum=4096)
        except ContractError:
            raise ContractError("proxy credentials must be username:password") from None
        host, separator, raw_port = authority.rpartition(":")
        if not separator:
            raise ContractError("proxy authority must include a port")
        port = _valid_port(raw_port)
        host = _normalized_host(host)
        if port is None or host is None:
            raise ContractError("proxy host or port is invalid")
        return ParsedProxy(
            protocol=protocol,
            host=host,
            port=port,
            username=username,
            password=password,
        )

    if text.startswith("["):
        closing = text.find("]")
        if closing < 2 or text[closing + 1:closing + 2] != ":":
            raise ContractError("proxy host or port is invalid")
        host = _normalized_host(text[:closing + 1])
        raw_port, separator, credentials = text[closing + 2:].partition(":")
        port = _valid_port(raw_port)
        if host is None or port is None:
            raise ContractError("proxy host or port is invalid")
        if not separator:
            return ParsedProxy(protocol=protocol, host=host, port=port)
        username, separator, password = credentials.partition(":")
        if not separator or not username or not password:
            raise ContractError("proxy credentials must be username:password")
        return ParsedProxy(
            protocol=protocol, host=host, port=port,
            username=username, password=password,
        )

    bracketed_tail = re.fullmatch(r"([^:]+):([^:]+):(\[[^\[\]]+\]):([0-9]{1,5})", text)
    if bracketed_tail is not None:
        username, password, raw_host, raw_port = bracketed_tail.groups()
        host = _normalized_host(raw_host)
        port = _valid_port(raw_port)
        if host is None or port is None:
            raise ContractError("proxy host or port is invalid")
        return ParsedProxy(
            protocol=protocol, host=host, port=port,
            username=username, password=password,
        )

    fields = text.split(":")
    if len(fields) == 2:
        port = _valid_port(fields[1])
        if port is None or not _valid_host(fields[0]):
            raise ContractError("proxy host or port is invalid")
        return ParsedProxy(protocol=protocol, host=fields[0].lower(), port=port)

    if len(fields) >= 4:
        # host:port:user:pass -- the password keeps any colons it contains.
        host_first = _valid_host(fields[0]) and _valid_port(fields[1]) is not None
        # user:pass:host:port -- the rarer ordering, and only ever four fields,
        # because a password with a colon in it makes this one unparseable.
        host_last = (
            len(fields) == 4
            and _valid_host(fields[2])
            and _valid_port(fields[3]) is not None
        )
        if host_first and host_last:
            raise ContractError(
                "proxy line is ambiguous -- both field orders parse; "
                "use scheme://user:pass@host:port instead"
            )
        if host_first:
            head, raw_port, user, secret = text.split(":", 3)
            if not user or not secret:
                raise ContractError("proxy credentials must be username:password")
            return ParsedProxy(
                protocol=protocol,
                host=head.lower(),
                port=_valid_port(raw_port),
                username=user,
                password=secret,
            )
        if host_last:
            user, secret, host, raw_port = fields
            if not user or not secret:
                raise ContractError("proxy credentials must be username:password")
            return ParsedProxy(
                protocol=protocol,
                host=host.lower(),
                port=_valid_port(raw_port),
                username=user,
                password=secret,
            )
    raise ContractError("proxy line format is not recognized")


def _proxy_line_failure_reason(exc: ContractError) -> str:
    """Classify a malformed line without retaining any of its text."""
    return _PROXY_LINE_FAILURE_REASONS.get(str(exc), "invalid-proxy-line")


def parse_session_username(username: str | None) -> dict[str, Any]:
    """Read the vendor's dash-token grammar out of a residential username.

    Returns a description of the *shape*, never the account name. ``grammar`` is
    ``"dash-token"`` when label/value pairs were found and ``"opaque"`` when the
    username carries no structure -- ISP and datacenter proxies are usually
    opaque, which is fine; it simply means no session can be pinned by rewriting.
    """
    opaque = {
        "grammar": "opaque",
        "country": None,
        "session_id": None,
        "session_minutes": None,
        "session_key": None,
        "country_key": None,
        "ttl_key": None,
    }
    if not isinstance(username, str) or not username:
        return opaque
    tokens = username.split("-")
    if len(tokens) < 4 or len(tokens) % 2 != 0:
        return opaque
    labels = tokens[0::2]
    values = tokens[1::2]
    if len(labels) != len(set(labels)):
        return opaque
    pairs = dict(zip(labels, values))
    if any(
        sum(key in pairs for key in aliases) > 1
        for aliases in (_COUNTRY_KEYS, _SESSION_KEYS, _TTL_KEYS)
    ):
        return opaque

    def _find(candidates: Iterable[str]) -> str | None:
        for candidate in candidates:
            if candidate in pairs:
                return candidate
        return None

    country_key = _find(_COUNTRY_KEYS)
    session_key = _find(_SESSION_KEYS)
    ttl_key = _find(_TTL_KEYS)
    if country_key is None and session_key is None:
        return opaque
    country = pairs.get(country_key) if country_key else None
    if country is not None and not _COUNTRY_TOKEN_RE.fullmatch(country):
        country = None
    minutes: int | None = None
    if (
        ttl_key is not None
        and len(pairs[ttl_key]) <= 18
        and is_ascii_decimal(pairs[ttl_key])
    ):
        minutes = int(pairs[ttl_key])
    return {
        "grammar": "dash-token",
        "country": country.lower() if country else None,
        "session_id": pairs.get(session_key) if session_key else None,
        "session_minutes": minutes,
        "session_key": session_key,
        "country_key": country_key,
        "ttl_key": ttl_key,
    }


def _sticky_session_length(session: Mapping[str, Any]) -> int | None:
    if session.get("grammar") != "dash-token" or type(session.get("session_key")) is not str:
        return None
    length = session.get("session_id_length")
    if length is None:
        session_id = session.get("session_id")
        if type(session_id) is not str:
            return None
        length = len(session_id) or 10
    return length if type(length) is int and 4 <= length <= 64 else None


def sticky_session_id(key: str, *, length: int = 10) -> str:
    """Derive a stable session ID from an arbitrary key.

    Deterministic on purpose: an identity that comes back tomorrow must land on
    the same exit IP without anything having been written down. Lowercase
    alphanumeric because every vendor accepts that; length defaults to 10 to
    match the most common issued width and is normally taken from the template
    the provider already gave us.
    """
    try:
        key_bytes = _bounded_utf8_text(
            key, label="sticky session key", maximum=4096
        )
    except ContractError:
        raise ContractError("sticky session key must be a non-empty string") from None
    if isinstance(length, bool) or not isinstance(length, int) or not 4 <= length <= 64:
        raise ContractError("sticky session length must be between 4 and 64")
    digest = hashlib.sha256(b"browser-core.sticky-session\0" + key_bytes).digest()
    value = int.from_bytes(digest, "big")
    base = len(_SESSION_ALPHABET)
    characters: list[str] = []
    for _ in range(length):
        value, index = divmod(value, base)
        characters.append(_SESSION_ALPHABET[index])
    return "".join(characters)


def with_session(
    username: str,
    *,
    session_id: str | None = None,
    country: str | None = None,
    session_minutes: int | None = None,
) -> str:
    """Rewrite the session/country/TTL tokens of a dash-token username.

    Raises rather than inventing tokens: adding a ``-sessid-`` pair to a username
    whose vendor does not use that key produces authentication failures that look
    like proxy outages, and that is a bad hour to spend.
    """
    parsed = parse_session_username(username)
    if parsed["grammar"] != "dash-token":
        raise ContractError("username has no dash-token session grammar to rewrite")
    tokens = username.split("-")

    def _set(label: str | None, value: str) -> None:
        if label is None:
            raise ContractError("username has no field for requested session value")
        for index in range(0, len(tokens), 2):
            if tokens[index] == label:
                tokens[index + 1] = value
                return
        raise ContractError("username has no field for requested session value")

    if session_id is not None:
        if not isinstance(session_id, str) or not re.fullmatch(
            r"[A-Za-z0-9]{1,64}", session_id
        ):
            raise ContractError("session ID must be 1-64 alphanumeric characters")
        _set(parsed["session_key"], session_id)
    if country is not None:
        if not isinstance(country, str) or not _COUNTRY_TOKEN_RE.fullmatch(country):
            raise ContractError("session country must be a two-letter code")
        _set(parsed["country_key"], country.lower())
    if session_minutes is not None:
        if isinstance(session_minutes, bool) or not isinstance(session_minutes, int):
            raise ContractError("session minutes must be an integer")
        if not 1 <= session_minutes <= 1440:
            raise ContractError("session minutes must be between 1 and 1440")
        _set(parsed["ttl_key"], str(session_minutes))
    return "-".join(tokens)


def _secret_path(workspace: Path, route_id: str) -> Path:
    if not isinstance(workspace, Path):
        raise ContractError("proxy secret workspace must be a Path")
    if (
        not isinstance(route_id, str)
        or not PROFILE_ID_RE.fullmatch(route_id)
        or has_windows_device_basename(route_id)
    ):
        raise ContractError("network route ID is invalid")
    root = Path(os.path.abspath(workspace))
    for ancestor in reversed((root, *root.parents)):
        directory_identity(ancestor, label="proxy secret directory")
    return root / "network" / "secrets" / f"{route_id}.json"


def credential_env_names(route_id: str) -> tuple[str, str]:
    """Distinct environment references for generated routes, keeping old simple IDs."""
    if (
        not isinstance(route_id, str)
        or not PROFILE_ID_RE.fullmatch(route_id)
        or has_windows_device_basename(route_id)
    ):
        raise ContractError("network route ID is invalid")
    if _CANONICAL_ROUTE_ID_RE.fullmatch(route_id):
        slug = route_id.replace("-", "_").upper()
        stem = f"BROWSER_CORE_PROXY_{slug}"
    else:
        # Base32 keeps every permitted route-ID byte, including its case and
        # separator, while fitting the network route's 128-character env limit.
        encoded = base64.b32encode(route_id.encode("ascii")).decode("ascii").rstrip("=")
        stem = f"BC_PROXY_X{encoded}"
    return f"{stem}_USERNAME", f"{stem}_PASSWORD"


def _validate_proxy_secret(document: Any, *, route_id: str) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "route_id",
        "username_template",
        "secret",
        "credential_sha256_16",
        "session",
    }:
        raise ContractError("proxy secret fields are invalid")
    if document.get("schema") != PROXY_SECRET_SCHEMA:
        raise ContractError("unsupported proxy secret document")
    if document.get("route_id") != route_id:
        raise ContractError("proxy secret belongs to a different route")
    for field in ("username_template", "secret"):
        value = document.get(field)
        try:
            _bounded_utf8_text(value, label="proxy secret field", maximum=4096)
        except ContractError:
            raise ContractError("proxy secret document is incomplete")
    username_bytes = _bounded_utf8_text(
        document["username_template"], label="proxy secret field", maximum=4096
    )
    secret_bytes = _bounded_utf8_text(
        document["secret"], label="proxy secret field", maximum=4096
    )
    expected_digest = hashlib.sha256(username_bytes + b"\0" + secret_bytes).hexdigest()[:16]
    if document.get("credential_sha256_16") != expected_digest:
        raise ContractError("proxy secret credential digest does not match")
    session = document.get("session")
    if not isinstance(session, dict) or set(session) != {
        "grammar",
        "session_key",
        "country_key",
        "ttl_key",
        "session_id_length",
        "session_minutes",
    }:
        raise ContractError("proxy secret session fields are invalid")
    parsed = parse_session_username(document["username_template"])
    expected_session = {
        "grammar": parsed["grammar"],
        "session_key": parsed["session_key"],
        "country_key": parsed["country_key"],
        "ttl_key": parsed["ttl_key"],
        "session_id_length": len(parsed["session_id"] or "") or 10,
        "session_minutes": parsed["session_minutes"],
    }
    if any(
        type(session[field]) is not type(expected_session[field])
        or session[field] != expected_session[field]
        for field in expected_session
    ):
        raise ContractError("proxy secret session metadata does not match")
    return document


def _load_proxy_secret_snapshot(
    workspace: Path,
    route_id: str,
    *,
    missing_ok: bool = False,
) -> tuple[dict[str, Any] | None, BoundedControlSnapshot]:
    path = _secret_path(workspace, route_id)
    _secret_path(workspace, route_id)
    root = path.parent.parent.parent
    root_before = directory_identity(root, label="proxy secret directory")
    parents = (path.parent.parent, path.parent)
    identities = tuple(
        directory_identity(parent, label="proxy secret directory")
        for parent in parents
    )
    if None in identities:
        snapshot = BoundedControlSnapshot("missing")
    else:
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_PROXY_SECRET_BYTES,
            label="proxy secret",
            require_private=True,
        )
        if tuple(
            directory_identity(parent, label="proxy secret directory")
            for parent in parents
        ) != identities:
            raise ContractError("proxy secret directory changed during read")
    _secret_path(workspace, route_id)
    if directory_identity(root, label="proxy secret directory") != root_before:
        raise ContractError("proxy secret workspace changed during read")
    if snapshot.state == "missing" and missing_ok:
        try:
            final = read_bounded_control_snapshot_result(
                path,
                maximum=MAX_PROXY_SECRET_BYTES,
                label="proxy secret",
                require_private=True,
            )
            if (
                final.state != "missing"
                or tuple(
                    directory_identity(parent, label="proxy secret directory")
                    for parent in parents
                ) != identities
                or directory_identity(root, label="proxy secret directory") != root_before
            ):
                raise ContractError("proxy secret changed during read")
        except ContractError:
            raise ContractError("proxy secret changed during read") from None
        return None, snapshot
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"proxy secret is {snapshot.state}")
    document = decode_strict_json_bytes(snapshot.body, label="proxy secret")
    validated = _validate_proxy_secret(document, route_id=route_id)
    try:
        _secret_path(workspace, route_id)
        require_bounded_control_snapshot_unchanged(
            path,
            snapshot,
            maximum=MAX_PROXY_SECRET_BYTES,
            label="proxy secret",
            require_private=True,
        )
        if (
            tuple(
                directory_identity(parent, label="proxy secret directory")
                for parent in parents
            ) != identities
            or directory_identity(root, label="proxy secret directory") != root_before
        ):
            raise ContractError("proxy secret changed during validation")
    except ContractError:
        raise ContractError("proxy secret changed during validation") from None
    return validated, snapshot


def store_proxy_secret(
    workspace: Path,
    route_id: str,
    parsed: ParsedProxy,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Write credentials to the per-route secret file.

    The file is created with owner-only permission bits before anything is
    written to it, so there is no moment where a world-readable file holds a
    password. On Windows only the read-only bit of that mode survives; the real
    protection there is that the workspace lives outside the repository and the
    secret is never an argument, a log line, or a field in any emitted document.
    """
    if not isinstance(parsed, ParsedProxy):
        raise ContractError("proxy credentials are invalid")
    parsed = _detached_parsed_proxy(parsed)
    if not parsed.has_credentials:
        raise ContractError("cannot store a secret for an anonymous proxy")
    _validate_relay_credentials(parsed)
    if not isinstance(overwrite, bool):
        raise ContractError("proxy secret overwrite flag must be boolean")
    path = _secret_path(workspace, route_id)
    session = parse_session_username(parsed.username)
    document = {
        "schema": PROXY_SECRET_SCHEMA,
        "route_id": route_id,
        "username_template": parsed.username,
        "secret": parsed.password,
        "credential_sha256_16": parsed.credential_sha256_16,
        "session": {
            "grammar": session["grammar"],
            "session_key": session["session_key"],
            "country_key": session["country_key"],
            "ttl_key": session["ttl_key"],
            "session_id_length": len(session["session_id"] or "") or 10,
            "session_minutes": session["session_minutes"],
        },
    }
    document = _validate_proxy_secret(document, route_id=route_id)

    def require_stored_secret() -> dict[str, Any]:
        current, _ = _load_proxy_secret_snapshot(
            workspace, route_id, missing_ok=True
        )
        if current != document:
            raise ContractError("proxy secret changed before storage completed")
        return _redacted_secret(current)

    _secret_path(workspace, route_id)
    # Create one level at a time. If network was replaced with a junction
    # before mkdir, detect it before creating secrets in the junction target.
    network_directory = path.parent.parent
    network_before = directory_identity(network_directory, label="proxy secret directory")
    network_directory.mkdir(parents=True, exist_ok=True)
    network_after = directory_identity(network_directory, label="proxy secret directory")
    if network_after is None or (
        network_before is not None and network_after != network_before
    ):
        raise ContractError("proxy secret directory changed before publication")
    path.parent.mkdir(exist_ok=True)
    directory_identity(path.parent, label="proxy secret directory")
    if (
        directory_identity(network_directory, label="proxy secret directory")
        != network_after
    ):
        raise ContractError("proxy secret directory changed before publication")
    existing, snapshot = _load_proxy_secret_snapshot(
        workspace,
        route_id,
        missing_ok=True,
    )
    if existing is not None:
        if (
            existing["username_template"] == document["username_template"]
            and existing["secret"] == document["secret"]
        ):
            return require_stored_secret()
        if not overwrite:
            raise ContractError(
                "a different credential is already stored for this route; pass overwrite"
            )
        assert snapshot.body is not None and snapshot.identity is not None
        replace_json_conditionally(
            path,
            document,
            expected_body=snapshot.body,
            expected_identity=snapshot.identity,
            maximum=MAX_PROXY_SECRET_BYTES,
            label="proxy secret",
        )
    else:
        try:
            publish_json_exclusive(
                path,
                document,
                maximum=MAX_PROXY_SECRET_BYTES,
                label="proxy secret",
            )
        except ContractError as exc:
            if "cleanup incomplete" in str(exc):
                raise
            raced, _raced_snapshot = _load_proxy_secret_snapshot(
                workspace,
                route_id,
                missing_ok=True,
            )
            if raced is None:
                raise
            if (
                raced["username_template"] != document["username_template"]
                or raced["secret"] != document["secret"]
            ):
                raise ContractError(
                    "a different credential is already stored for this route"
                ) from None
            return require_stored_secret()
    return require_stored_secret()


def _redacted_secret(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": PROXY_SECRET_SCHEMA,
        "route_id": document["route_id"],
        "credential_sha256_16": document["credential_sha256_16"],
        "session": dict(document["session"]),
        "stored": True,
    }


def load_proxy_secret(workspace: Path, route_id: str) -> dict[str, Any]:
    document, _snapshot = _load_proxy_secret_snapshot(workspace, route_id)
    assert document is not None
    return document


def has_proxy_secret(workspace: Path, route_id: str) -> bool:
    document, _snapshot = _load_proxy_secret_snapshot(
        workspace,
        route_id,
        missing_ok=True,
    )
    return document is not None


def delete_proxy_secret(workspace: Path, route_id: str) -> bool:
    path = _secret_path(workspace, route_id)
    document, snapshot = _load_proxy_secret_snapshot(
        workspace,
        route_id,
        missing_ok=True,
    )
    if document is None:
        return False
    assert snapshot.body is not None and snapshot.identity is not None
    remove_control_conditionally(
        path,
        expected_body=snapshot.body,
        expected_identity=snapshot.identity,
        maximum=MAX_PROXY_SECRET_BYTES,
        label="proxy secret",
    )
    remaining, _ = _load_proxy_secret_snapshot(
        workspace, route_id, missing_ok=True
    )
    if remaining is not None:
        raise ContractError("proxy secret reappeared during removal")
    return True


def resolve_route_credentials(
    workspace: Path,
    route: dict[str, Any],
    *,
    session_key: str | None = None,
    env: Mapping[str, str] | None = None,
) -> ResolvedNetworkRoute:
    """Resolve a route, preferring the stored secret over the environment.

    ``session_key`` pins a sticky exit: pass the profile or persona ID and the
    same identity returns to the same IP for as long as the vendor's TTL allows.
    Routes with no stored secret fall through to the original environment-variable
    path unchanged, so nothing that worked before this module needs to change.
    """
    validated = validate_network_route(route)
    auth = validated.get("auth")
    if auth is None or not has_proxy_secret(workspace, validated["id"]):
        return resolve_network_route(validated, env)
    path = _secret_path(workspace, validated["id"])
    secret, snapshot = _load_proxy_secret_snapshot(workspace, validated["id"])
    assert secret is not None
    username = secret["username_template"]
    if session_key is not None and secret["session"].get("session_key") is not None:
        length = _sticky_session_length(secret["session"])
        if length is None:
            raise ContractError("proxy route session is not sticky-capable")
        username = with_session(
            username, session_id=sticky_session_id(session_key, length=length)
        )
    resolved = resolve_network_route(
        validated,
        {auth["username_env"]: username, auth["password_env"]: secret["secret"]},
    )
    try:
        _secret_path(workspace, validated["id"])
        require_bounded_control_snapshot_unchanged(
            path,
            snapshot,
            maximum=MAX_PROXY_SECRET_BYTES,
            label="proxy secret",
            require_private=True,
        )
    except ContractError:
        raise ContractError("proxy secret changed before credential resolution") from None
    return resolved


def _geography_for(
    country: str,
    *,
    locale: str | None,
    timezone_name: str | None,
) -> dict[str, str]:
    code = country.upper()
    default = _GEO_DEFAULTS.get(code)
    resolved_locale = locale or (default["locale"] if default else None)
    resolved_timezone = timezone_name or (default["timezone"] if default else None)
    if resolved_locale is None or resolved_timezone is None:
        raise ContractError(
            f"no default locale/time zone for country {code}; pass both explicitly"
        )
    return {"country": code, "locale": resolved_locale, "timezone": resolved_timezone}


def _default_route_name(parsed: ParsedProxy, country: str) -> str:
    host = f"[{parsed.host}]" if ":" in parsed.host else parsed.host
    prefix = f"{parsed.protocol}://"
    full = f"{prefix}{host}:{parsed.port} {country}"
    if len(full) <= 128:
        return full
    digest = hashlib.sha256(full.encode("utf-8")).hexdigest()[:12]
    suffix = f"...:{parsed.port} {country} #{digest}"
    return f"{prefix}{host[:128 - len(prefix) - len(suffix)]}{suffix}"


def _publish_matching_route(
    workspace: Path, route: dict[str, Any]
) -> NetworkRoutePublication:
    """Reuse an immutable route when only a fresh creation timestamp differs."""
    try:
        return add_network_route_with_receipt(workspace, route)
    except ContractError as exc:
        if str(exc) != "network route ID conflict":
            raise
        existing = load_network_route(workspace, route["id"])

        def stable_fields(document: dict[str, Any]) -> dict[str, Any]:
            return {
                key: value
                for key, value in document.items()
                if key not in {"created_at", "integrity_sha256"}
            }

        if canonical_json_bytes(stable_fields(existing)) != canonical_json_bytes(
            stable_fields(route)
        ):
            raise
        return add_network_route_with_receipt(workspace, existing)


def _rebind_route_publication(
    workspace: Path, publication: NetworkRoutePublication
) -> None:
    """Require the published route receipt to remain current after secret work."""
    error = "network route changed before proxy receipt"
    try:
        current, snapshot = _load_network_route_snapshot(workspace, publication.route_id)
        route_path = _route_path(workspace, publication.route_id)
        parents = _route_parent_identities(route_path.parent)
        workspace_ancestry = _route_workspace_ancestry(workspace)
    except ContractError:
        raise ContractError(error) from None
    if (
        current != publication.route
        or snapshot.body != publication.body
        or snapshot.identity != publication.identity
        or parents != publication.route_parents
        or workspace_ancestry != publication.workspace_ancestry
    ):
        raise ContractError(error)


def import_proxy_route(
    workspace: Path,
    line: str | None = None,
    *,
    route_id: str,
    parsed: ParsedProxy | None = None,
    name: str | None = None,
    country: str | None = None,
    locale: str | None = None,
    timezone_name: str | None = None,
    default_protocol: str = "http",
    store_credentials: bool = True,
    overwrite_secret: bool = False,
    require_alignment: bool = True,
    webrtc: str = "route-only",
    dns: str = "route",
) -> dict[str, Any]:
    """Import one pasted proxy line as a stored, verifiable network route.

    Callers that already hold a ``ParsedProxy`` pass it as ``parsed`` rather than
    re-serializing it into a line: a round trip through text is one more place a
    password with an awkward character in it can be mangled.
    """
    from .network import rollback_network_route_publication

    if (line is None) == (parsed is None):
        raise ContractError("import_proxy_route needs exactly one of line or parsed")
    if parsed is not None and not isinstance(parsed, ParsedProxy):
        raise ContractError("parsed proxy must be a ParsedProxy")
    for value, label in (
        (store_credentials, "store_credentials"),
        (overwrite_secret, "overwrite_secret"),
        (require_alignment, "require_alignment"),
    ):
        if not isinstance(value, bool):
            raise ContractError(f"{label} must be boolean")
    if any(
        value is not None and not isinstance(value, str)
        for value in (country, locale, timezone_name)
    ):
        raise ContractError("proxy import geography is invalid")
    if name is not None and not isinstance(name, str):
        raise ContractError("proxy import name is invalid")
    if parsed is None:
        parsed = parse_proxy_line(line or "", default_protocol=default_protocol)
    else:
        # Retain one local proxy throughout route publication, optional secret
        # storage, and the returned receipt. The caller still owns `parsed`.
        parsed = _detached_parsed_proxy(parsed)
    if (
        type(parsed.protocol) is not str
        or parsed.protocol not in SUPPORTED_PROTOCOLS
        or type(parsed.host) is not str
        or not 1 <= len(parsed.host) <= 253
        or type(parsed.port) is not int
        or not 1 <= parsed.port <= 65535
    ):
        raise ContractError("parsed proxy endpoint is invalid")
    if (parsed.username is None) != (parsed.password is None):
        raise ContractError("proxy credentials are incomplete")
    if parsed.has_credentials:
        try:
            parsed.credential_sha256_16
            _validate_relay_credentials(parsed)
        except ContractError:
            raise ContractError("proxy credentials are invalid") from None
    session = parse_session_username(parsed.username)
    resolved_country = country or session["country"]
    if not resolved_country:
        raise ContractError(
            "proxy line does not declare a country; pass one so geography can be checked"
        )
    geography = _geography_for(
        resolved_country, locale=locale, timezone_name=timezone_name
    )
    auth = None
    if parsed.has_credentials:
        username_env, password_env = credential_env_names(route_id)
        auth = {"username_env": username_env, "password_env": password_env}
    route = build_network_route(
        route_id=route_id,
        name=name or _default_route_name(parsed, geography["country"]),
        geography=geography,
        mode="proxy",
        endpoint=parsed.endpoint(),
        auth=auth,
        policies={"dns": dns, "webrtc": webrtc, "require_alignment": require_alignment},
    )
    route_publication = _publish_matching_route(workspace, route)
    stored = route_publication.route
    secret_summary: dict[str, Any] | None = None
    if parsed.has_credentials and store_credentials:
        try:
            secret_summary = store_proxy_secret(
                workspace, stored["id"], parsed, overwrite=overwrite_secret
            )
        except ContractError as primary:
            if route_publication.created:
                try:
                    rollback_network_route_publication(workspace, route_publication)
                except ContractError:
                    raise ContractError(
                        "proxy import failed; network route rollback incomplete"
                    ) from primary
            raise
    if secret_summary is None and parsed.has_credentials:
        # Skipping storage does not imply the route has no saved credential:
        # the immutable route may already have one from an earlier import.
        existing_secret, _ = _load_proxy_secret_snapshot(
            workspace, stored["id"], missing_ok=True
        )
        if existing_secret is not None:
            secret_summary = _redacted_secret(existing_secret)
    _rebind_route_publication(workspace, route_publication)
    return {
        "schema": PROXY_IMPORT_SCHEMA,
        "route_id": stored["id"],
        "route_sha256_16": stored["integrity_sha256"][:16],
        "endpoint": parsed.redacted(),
        "geography": geography,
        "credentials_stored": secret_summary is not None,
        "credential_sha256_16": (
            secret_summary["credential_sha256_16"]
            if secret_summary
            else parsed.credential_sha256_16
        ),
        "session": dict(secret_summary["session"]) if secret_summary else None,
        "sticky_capable": secret_summary is not None
        and _sticky_session_length(secret_summary["session"]) is not None,
        "env_fallback": auth,
    }


def import_proxy_file(
    workspace: Path,
    path: Path,
    *,
    prefix: str = "res",
    limit: int | None = None,
    default_protocol: str = "http",
    locale: str | None = None,
    timezone_name: str | None = None,
    store_credentials: bool = True,
) -> dict[str, Any]:
    """Import a provider list, collapsing lines that differ only by session.

    A thousand pre-minted session strings pointed at one gateway are one route,
    not a thousand: they share an endpoint, an account, and a country, and the
    only thing that varies is the pin that ``sticky_session_id`` can now generate
    on demand. Collapsing them is what turns a fixed list of 1,000 exits into an
    unbounded supply, and it keeps the route catalog readable.
    """
    if not isinstance(workspace, Path):
        raise ContractError("proxy import workspace must be a Path")
    if not isinstance(path, Path):
        raise ContractError("proxy import source must be a Path")
    if isinstance(limit, bool) or (
        limit is not None
        and (not isinstance(limit, int) or not 1 <= limit <= MAX_PROXY_IMPORT_LINES)
    ):
        raise ContractError("limit must be a positive integer")
    if not isinstance(prefix, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", prefix
    ):
        raise ContractError("proxy import prefix is invalid")
    if not isinstance(store_credentials, bool):
        raise ContractError("store_credentials must be boolean")
    normalized_protocol = _normalize_protocol(default_protocol)
    source_label = path.name
    try:
        _bounded_utf8_text(source_label, label="proxy import source name", maximum=255)
    except ContractError:
        raise ContractError("proxy import source name is invalid")
    source = path.absolute()
    snapshot = read_bounded_control_snapshot_result(
        source,
        maximum=MAX_PROXY_IMPORT_FILE_BYTES,
        label="proxy import file",
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"proxy import file is {snapshot.state}")
    try:
        raw = snapshot.body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ContractError("proxy import file encoding is invalid") from None

    groups: dict[tuple[str, str, int, str, bytes], dict[str, Any]] = {}
    malformed: list[dict[str, Any]] = []
    considered = 0
    # Iterate physical CR/LF lines without materializing a list of up to
    # millions of empty strings from one otherwise byte-bounded source.
    for number, text in enumerate(io.StringIO(raw, newline=None), start=1):
        if limit is not None and considered >= limit:
            break
        if number > MAX_PROXY_IMPORT_PHYSICAL_LINES:
            raise ContractError("proxy import file contains too many physical lines")
        stripped = text.strip(" \t\r\n")
        if not stripped or stripped.startswith("#"):
            continue
        considered += 1
        if considered > MAX_PROXY_IMPORT_LINES:
            raise ContractError("proxy import file contains too many candidate lines")
        try:
            parsed = parse_proxy_line(stripped, default_protocol=normalized_protocol)
        except ContractError as exc:
            malformed.append({"line": number, "reason": _proxy_line_failure_reason(exc)})
            continue
        session = parse_session_username(parsed.username)
        username_for_group = parsed.username or ""
        if _sticky_session_length(session) is not None:
            username_for_group = with_session(username_for_group, session_id="0")
        credential_identity = hashlib.sha256(
            username_for_group.encode("utf-8")
            + b"\0"
            + (parsed.password or "").encode("utf-8")
        ).digest()
        country = (session["country"] or "").lower()
        key = (parsed.protocol, parsed.host, parsed.port, country, credential_identity)
        group = groups.get(key)
        if group is None:
            groups[key] = {"parsed": parsed, "lines": 1, "country": country}
        else:
            group["lines"] += 1

    imported: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for index, ((protocol, host, _port, country, _credential), group) in enumerate(
        sorted(groups.items()), start=1
    ):
        suffix = country or "xx"
        stem = re.sub(
            r"[^A-Za-z0-9._-]+", "-", f"{prefix}-{suffix}-{host.split('.')[0]}"
        )
        index_suffix = f"-{index}"
        route_id = f"{stem[: 64 - len(index_suffix)].rstrip('-.')}{index_suffix}"
        try:
            imported.append(
                import_proxy_route(
                    workspace,
                    parsed=group["parsed"],
                    route_id=route_id,
                    country=country or None,
                    locale=locale,
                    timezone_name=timezone_name,
                    default_protocol=protocol,
                    store_credentials=store_credentials,
                )
                | {"collapsed_lines": group["lines"]}
            )
        except ContractError as exc:
            failed.append(
                {"route_id": route_id, "failure": safe_failure_receipt(exc)}
            )
    return {
        "schema": PROXY_FILE_IMPORT_SCHEMA,
        "source": source_label,
        "lines_considered": considered,
        "malformed": malformed,
        "malformed_count": len(malformed),
        "distinct_endpoints": len({key[:4] for key in groups}),
        "imported": imported,
        "imported_count": len(imported),
        "failed": failed,
        "failed_count": len(failed),
        "note": (
            "Lines with the same endpoint, country, and credentials apart from a "
            "mintable recognized session ID collapse into one route; per-identity exits "
            "come from sticky_session_id, not the number of lines in the file."
        ),
    }


def describe_route(workspace: Path, route_id: str) -> dict[str, Any]:
    """Everything about a route that is safe to print."""
    route_path = _route_path(workspace, route_id)
    workspace_before = _route_workspace_ancestry(workspace)
    parents_before = _route_parent_identities(route_path.parent)
    route, route_snapshot = _load_network_route_snapshot(workspace, route_id)
    assert route is not None
    secret, secret_snapshot = _load_proxy_secret_snapshot(
        workspace, route_id, missing_ok=True,
    )
    summary: dict[str, Any] = {
        "schema": "browser-core.network-route-summary/1",
        "id": route["id"],
        "name": route["name"],
        "mode": route["mode"],
        "geography": route["geography"],
        "policies": route["policies"],
        "route_sha256_16": route["integrity_sha256"][:16],
        "credentials_stored": secret is not None,
        "sticky_capable": False,
        "session": None,
        "credential_sha256_16": None,
    }
    if route["mode"] == "proxy":
        endpoint = route["endpoint"]
        summary["endpoint"] = {
            "protocol": endpoint["protocol"],
            "host": endpoint["host"],
            "port": endpoint["port"],
        }
    if secret is not None:
        summary["session"] = dict(secret["session"])
        summary["credential_sha256_16"] = secret["credential_sha256_16"]
        summary["sticky_capable"] = _sticky_session_length(secret["session"]) is not None
    try:
        current, final_snapshot = _load_network_route_snapshot(workspace, route_id)
        parents_after = _route_parent_identities(route_path.parent)
        workspace_after = _route_workspace_ancestry(workspace)
    except ContractError:
        raise ContractError("network route changed before summary") from None
    if (
        current != route
        or final_snapshot.body != route_snapshot.body
        or final_snapshot.identity != route_snapshot.identity
        or parents_after != parents_before
        or workspace_after != workspace_before
    ):
        raise ContractError("network route changed before summary")
    try:
        current_secret, final_secret_snapshot = _load_proxy_secret_snapshot(
            workspace, route_id, missing_ok=True,
        )
    except ContractError:
        raise ContractError("proxy secret changed before summary") from None
    if (
        current_secret != secret
        or final_secret_snapshot.body != secret_snapshot.body
        or final_secret_snapshot.identity != secret_snapshot.identity
        or final_secret_snapshot.state != secret_snapshot.state
    ):
        raise ContractError("proxy secret changed before summary")
    return summary


def check_route(
    workspace: Path,
    route_id: str,
    *,
    session_key: str | None = None,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    """Preflight the route and report where it actually exits.

    This is the ``check proxy`` button: it answers "does this credential work,
    and is the exit really in the country the identity claims" in one call. The
    exit IP is hashed, never printed -- the country and the alignment verdict are
    what a decision gets made on.
    """
    from .network import observe_geo_alignment, preflight_network_route

    if session_key is not None:
        # Validate before any network contact. The derived value is deliberately
        # discarded: reports retain only whether a key was supplied.
        sticky_session_id(session_key)
    route_path = _route_path(workspace, route_id)
    workspace_before = _route_workspace_ancestry(workspace)
    parents_before = _route_parent_identities(route_path.parent)
    route, route_snapshot = _load_network_route_snapshot(workspace, route_id)
    assert route is not None
    geography = route["geography"]
    preflight: dict[str, Any] | None = None
    realization: dict[str, Any] | None = None
    error: str | None = None
    secret_before: dict[str, Any] | None = None
    secret_snapshot = BoundedControlSnapshot("missing")
    # A dead proxy is an answer, not a crash. Every failure mode below -- bad
    # credential, refused CONNECT, unreachable host, wrong exit country -- comes
    # back as a report, because this call is how an operator finds out which of
    # a hundred routes are still alive.
    try:
        if route["auth"] is not None:
            secret_before, secret_snapshot = _load_proxy_secret_snapshot(
                workspace, route_id, missing_ok=True
            )
        resolved = resolve_route_credentials(workspace, route, session_key=session_key)
        used_session = parse_session_username(resolved.username)
        session_length = _sticky_session_length(used_session)
        session_pinned = (
            session_key is not None
            and session_length is not None
            and used_session["session_id"]
            == sticky_session_id(session_key, length=session_length)
        )
        preflight = preflight_network_route(
            resolved, route["preflight_url"], timeout_seconds=timeout_seconds
        )
    except (ContractError, OSError) as exc:
        return {
            "schema": "browser-core.proxy-check/1",
            "route_id": route_id,
            "session_key_supplied": session_key is not None,
            "session_pinned": False,
            "preflight": None,
            "realization": None,
            "error": safe_failure_receipt(exc),
            "passed": False,
        }
    if route["mode"] == "proxy":
        from .gateway import serve_gateway

        try:
            with serve_gateway(resolved) as (host, port):
                realization = observe_geo_alignment(
                    route,
                    browser_locale=geography["locale"],
                    browser_timezone=geography["timezone"],
                    timeout_seconds=timeout_seconds,
                    gateway_endpoint=f"http://{host}:{port}",
                    preflight=preflight,
                )
        except (ContractError, OSError) as exc:
            error = safe_failure_receipt(exc)
    try:
        current, final_snapshot = _load_network_route_snapshot(workspace, route_id)
        parents_after = _route_parent_identities(route_path.parent)
        workspace_after = _route_workspace_ancestry(workspace)
    except ContractError:
        raise ContractError("network route changed before proxy check") from None
    if (
        current != route
        or final_snapshot.body != route_snapshot.body
        or final_snapshot.identity != route_snapshot.identity
        or parents_after != parents_before
        or workspace_after != workspace_before
    ):
        raise ContractError("network route changed before proxy check")
    if route["auth"] is not None:
        try:
            secret_after, secret_final_snapshot = _load_proxy_secret_snapshot(
                workspace, route_id, missing_ok=True
            )
        except ContractError:
            raise ContractError("proxy secret changed before proxy check") from None
        if (
            secret_after != secret_before
            or secret_final_snapshot.state != secret_snapshot.state
            or secret_final_snapshot.body != secret_snapshot.body
            or secret_final_snapshot.identity != secret_snapshot.identity
        ):
            raise ContractError("proxy secret changed before proxy check")
    return {
        "schema": "browser-core.proxy-check/1",
        "route_id": route_id,
        "session_key_supplied": session_key is not None,
        "session_pinned": session_pinned,
        "preflight": preflight,
        "realization": realization,
        "egress_timezone": (realization or {}).get("egress_timezone"),
        "egress_country": ((realization or {}).get("observed") or {}).get("country"),
        "exit_ip_sha256_16": ((realization or {}).get("observed") or {}).get("ip_sha256_16"),
        "error": error,
        # A direct route has no exit to geolocate, so a clean preflight is the
        # whole verdict there; a proxy route must also land in the right country.
        "passed": bool(preflight.get("passed"))
        and (route["mode"] == "direct" or bool((realization or {}).get("passed"))),
    }


def realign_route(
    workspace: Path,
    route_id: str,
    *,
    session_key: str | None = None,
    new_route_id: str | None = None,
    locale: str | None = None,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    """Write a corrected copy of a route whose declared zone missed its exit.

    A rotating residential pool has exits in every time zone of the country it
    sells, so a route that declares one zone will disagree with most of them.
    That disagreement is worth surfacing -- a browser claiming Chicago from a
    Los Angeles IP is exactly the incoherence this tool exists to catch -- but
    it also has an obvious fix, which is to believe the measurement.

    Routes are immutable by ID, so this writes a *new* route rather than editing
    one. Nothing that already referenced the original changes underneath it, and
    the two can be compared.
    """
    from .network import rollback_network_route_publication

    if locale is not None and not isinstance(locale, str):
        raise ContractError("realigned route locale is invalid")
    if new_route_id is not None and (
        not isinstance(new_route_id, str)
        or not PROFILE_ID_RE.fullmatch(new_route_id)
        or has_windows_device_basename(new_route_id)
    ):
        raise ContractError("realigned route ID is invalid")
    observation = check_route(
        workspace, route_id, session_key=session_key, timeout_seconds=timeout_seconds
    )
    egress_timezone = observation.get("egress_timezone")
    egress_country = observation.get("egress_country")
    if not egress_timezone or not egress_country:
        raise ContractError("cannot realign a route whose exit could not be observed")
    original = load_network_route(workspace, route_id)
    realization = observation.get("realization")
    observed_route_digest = (
        realization.get("route_sha256_16")
        if isinstance(realization, dict)
        else None
    )
    if observed_route_digest != original["integrity_sha256"][:16]:
        raise ContractError("source route changed during observation")
    if new_route_id is None:
        target_id = f"{route_id}-aligned"
        if len(target_id) > 64:
            suffix = f"-aligned-{hashlib.sha256(route_id.encode('ascii')).hexdigest()[:16]}"
            target_id = f"{route_id[:64 - len(suffix)].rstrip('._-')}{suffix}"
    else:
        target_id = new_route_id
    if (
        not isinstance(target_id, str)
        or not PROFILE_ID_RE.fullmatch(target_id)
        or has_windows_device_basename(target_id)
    ):
        raise ContractError("realigned route ID is invalid")
    observed_country = egress_country.upper()
    inherited_locale = (
        original["geography"]["locale"]
        if observed_country == original["geography"]["country"]
        else None
    )
    geography = _geography_for(
        observed_country,
        locale=locale or inherited_locale,
        timezone_name=egress_timezone,
    )
    auth = None
    if original.get("auth") is not None:
        username_env, password_env = credential_env_names(target_id)
        auth = {"username_env": username_env, "password_env": password_env}
    zone_suffix = f" @ {egress_timezone}"
    aligned_name = f"{original['name'][:128 - len(zone_suffix)]}{zone_suffix}"
    aligned = build_network_route(
        route_id=target_id,
        name=aligned_name,
        geography=geography,
        mode=original["mode"],
        endpoint=original.get("endpoint"),
        auth=auth,
        policies=dict(original["policies"]),
        preflight_url=original["preflight_url"],
    )
    source_secret = (
        load_proxy_secret(workspace, route_id)
        if auth is not None and has_proxy_secret(workspace, route_id)
        else None
    )
    publication = _publish_matching_route(workspace, aligned)
    stored = publication.route
    copied = False
    if source_secret is not None:
        try:
            copied = (
                store_proxy_secret(
                    workspace,
                    target_id,
                    ParsedProxy(
                        protocol=original["endpoint"]["protocol"],
                        host=original["endpoint"]["host"],
                        port=original["endpoint"]["port"],
                        username=source_secret["username_template"],
                        password=source_secret["secret"],
                    ),
                    overwrite=True,
                )["stored"]
                is True
            )
        except ContractError as primary:
            if publication.created:
                try:
                    rollback_network_route_publication(workspace, publication)
                except ContractError:
                    raise ContractError(
                        "proxy realignment failed; network route rollback incomplete"
                    ) from primary
            raise
    _rebind_route_publication(workspace, publication)
    return {
        "schema": "browser-core.proxy-realign/1",
        "source_route_id": route_id,
        "route_id": stored["id"],
        "route_sha256_16": stored["integrity_sha256"][:16],
        "was": original["geography"],
        "now": geography,
        "session_key_supplied": session_key is not None,
        "credentials_copied": copied,
        "note": (
            "The new route believes the measurement. Exits from a rotating pool "
            "land in other zones; pin a session key to keep one identity on one exit."
        ),
    }
