"""What a pasted proxy line is allowed to become, and where its password may go.

The single property this file exists to defend: a credential enters through
``parse_proxy_line`` and may reach exactly two places -- the per-route secret
file, and the socket. It may not reach a route document, a summary, an import
result, a ``repr``, or an exception message. Most of the tests below are that
one claim asked from a different angle, because the ways a secret leaks are
mostly the ways nobody thought to look.

The sample credentials here are fictional and shaped like the real vendor
formats: ``customer-ACME-cc-us-sessid-a1b2c3d4e5-sesstime-10`` is the Oxylabs
backconnect grammar, and ``1.2.3.4:12323:user:pass`` is the flat form ISP
providers hand out.
"""

from __future__ import annotations

import json
import os
import subprocess
from contextlib import nullcontext
from pathlib import Path

import pytest

import browser_core.network as network_module
import browser_core.gateway as gateway_module
from browser_core import proxy_import as proxy_import_module
from browser_core.control_files import canonical_json_bytes
from browser_core.contracts import ContractError, reject_sensitive_keys
from browser_core.network import (
    add_network_route,
    build_network_route,
    load_network_route,
    resolve_network_route,
)
from browser_core.proxy_import import (
    ParsedProxy,
    check_route,
    credential_env_names,
    delete_proxy_secret,
    describe_route,
    has_proxy_secret,
    import_proxy_file,
    import_proxy_route,
    load_proxy_secret,
    parse_proxy_line,
    parse_session_username,
    realign_route,
    resolve_route_credentials,
    sticky_session_id,
    store_proxy_secret,
    with_session,
)

RESIDENTIAL_USER = "customer-ACME-cc-us-sessid-a1b2c3d4e5-sesstime-10"
RESIDENTIAL_PASSWORD = "Sw0rdfish+Trombone"
RESIDENTIAL_LINE = f"{RESIDENTIAL_USER}:{RESIDENTIAL_PASSWORD}@pr.example-proxy.io:7777"
FLAT_LINE = "1.2.3.4:12323:14a35bed6f6b3:9c2f1ab77e"


def _valid_secret_body_for_route(tmp_path, route_id, *, source_id, password):
    parsed = ParsedProxy(
        protocol="http",
        host="pr.example-proxy.io",
        port=7777,
        username=RESIDENTIAL_USER,
        password=password,
    )
    store_proxy_secret(tmp_path, source_id, parsed)
    document = load_proxy_secret(tmp_path, source_id)
    document["route_id"] = route_id
    return canonical_json_bytes(document)


# --------------------------------------------------------------------------
# Parsing the formats providers actually hand out
# --------------------------------------------------------------------------


def test_the_backconnect_authority_form_parses():
    parsed = parse_proxy_line(RESIDENTIAL_LINE)
    assert parsed.host == "pr.example-proxy.io"
    assert parsed.port == 7777
    assert parsed.protocol == "http"
    assert parsed.username == RESIDENTIAL_USER
    assert parsed.password == RESIDENTIAL_PASSWORD


@pytest.mark.parametrize("host", ["bad-.example", "foo.-bar.example", "127.1", "foo.123"])
def test_proxy_parser_rejects_hosts_the_route_contract_rejects(host):
    with pytest.raises(ContractError, match="host or port"):
        parse_proxy_line(f"http://user:pass@{host}:8080")


def test_the_flat_four_field_form_parses():
    parsed = parse_proxy_line(FLAT_LINE)
    assert (parsed.host, parsed.port) == ("1.2.3.4", 12323)
    assert parsed.username == "14a35bed6f6b3"
    assert parsed.password == "9c2f1ab77e"


@pytest.mark.parametrize(
    "line,expected",
    [
        ("socks5://user:pass@host.example:1080", ("socks5", "host.example", 1080)),
        ("https://user:pass@host.example:443", ("https", "host.example", 443)),
        ("host.example:8080", ("http", "host.example", 8080)),
        ("http://host.example:8080", ("http", "host.example", 8080)),
        ("user:pass:host.example:9000", ("http", "host.example", 9000)),
    ],
)
def test_the_other_circulating_forms_parse(line, expected):
    parsed = parse_proxy_line(line)
    assert (parsed.protocol, parsed.host, parsed.port) == expected


@pytest.mark.parametrize(
    "line,expected",
    [
        ("http://user:pass@[2001:0db8::1]:8080", ("http", "2001:db8::1", 8080, "user", "pass")),
        ("socks5://[2001:db8::2]:1080", ("socks5", "2001:db8::2", 1080, None, None)),
        ("[2001:db8::3]:3128", ("http", "2001:db8::3", 3128, None, None)),
        ("[2001:db8::4]:3128:user:pass", ("http", "2001:db8::4", 3128, "user", "pass")),
        ("user:pass@[2001:db8::5]:3128", ("http", "2001:db8::5", 3128, "user", "pass")),
        ("user:pass:[2001:db8::6]:3128", ("http", "2001:db8::6", 3128, "user", "pass")),
    ],
)
def test_bracketed_ipv6_proxy_forms_parse(line, expected):
    parsed = parse_proxy_line(line)
    assert (
        parsed.protocol, parsed.host, parsed.port, parsed.username, parsed.password
    ) == expected


@pytest.mark.parametrize(
    "line",
    [
        "[127.0.0.1]:8080",
        "[example.com]:8080",
        "[fe80::1%zone]:8080",
        "[2001:db8::1:8080",
        "[2001:db8::1]:0",
        "2001:db8::1:8080",
    ],
)
def test_invalid_or_ambiguous_ipv6_proxy_forms_are_refused(line):
    with pytest.raises(ContractError):
        parse_proxy_line(line)


def test_a_password_containing_colons_survives_the_flat_form():
    parsed = parse_proxy_line("host.example:8080:user:a:b:c")
    assert parsed.password == "a:b:c", "only the first three colons are structural"


def test_percent_encoded_credentials_are_decoded():
    parsed = parse_proxy_line("http://user%40corp:p%3Ass@host.example:8080")
    assert parsed.username == "user@corp"
    assert parsed.password == "p:ss"


@pytest.mark.parametrize("encoded", ["%FF", "%C3%28"])
def test_percent_encoded_credentials_reject_invalid_utf8(encoded: str) -> None:
    with pytest.raises(ContractError, match="proxy credentials must be username:password") as failure:
        parse_proxy_line(f"http://user:{encoded}@host.example:8080")
    assert encoded not in str(failure.value)


def test_an_ambiguous_four_field_line_is_refused_rather_than_guessed():
    """Both orderings parse here; guessing sends the password to a hostname."""
    with pytest.raises(ContractError, match="ambiguous"):
        parse_proxy_line("10.0.0.1:8080:10.0.0.2:9090")


@pytest.mark.parametrize(
    "line",
    ["", "   ", "host.example", "host.example:99999", "host with space:80", "://host:80"],
)
def test_malformed_lines_are_refused(line):
    with pytest.raises(ContractError):
        parse_proxy_line(line)


def test_a_proxy_port_must_use_ascii_decimal_text() -> None:
    with pytest.raises(ContractError, match="host or port"):
        parse_proxy_line("host.example:٨٠٨٠")


def test_an_unsupported_scheme_is_refused():
    with pytest.raises(ContractError, match="unsupported"):
        parse_proxy_line("ftp://user:pass@host.example:21")


@pytest.mark.parametrize("protocol", [42, False, []])
@pytest.mark.parametrize("line", ["host.example:8080", "http://host.example:8080"])
def test_a_non_text_default_protocol_is_refused_even_with_an_explicit_scheme(
    line, protocol
) -> None:
    with pytest.raises(ContractError, match="proxy protocol is unsupported"):
        parse_proxy_line(line, default_protocol=protocol)


@pytest.mark.parametrize("edge", ["\u2028", "\u00a0"])
def test_a_unicode_whitespace_edge_is_not_silently_removed(edge: str) -> None:
    with pytest.raises(ContractError, match="whitespace"):
        parse_proxy_line(f"{edge}host.example:8080")
    with pytest.raises(ContractError, match="whitespace"):
        parse_proxy_line(f"host.example:8080{edge}")


def test_the_repr_never_shows_a_credential():
    parsed = parse_proxy_line(RESIDENTIAL_LINE)
    assert RESIDENTIAL_PASSWORD not in repr(parsed)
    assert RESIDENTIAL_USER not in repr(parsed)


def test_the_redacted_view_describes_the_shape_and_nothing_else():
    view = parse_proxy_line(RESIDENTIAL_LINE).redacted()
    assert view["country_hint"] == "us"
    assert view["session_grammar"] == "dash-token"
    assert view["session_minutes"] == 10
    assert view["authenticated"] is True
    assert RESIDENTIAL_PASSWORD not in json.dumps(view)
    assert RESIDENTIAL_USER not in json.dumps(view)


# --------------------------------------------------------------------------
# The residential username grammar
# --------------------------------------------------------------------------


def test_the_vendor_session_grammar_is_read_out_of_the_username():
    session = parse_session_username(RESIDENTIAL_USER)
    assert session["grammar"] == "dash-token"
    assert session["country"] == "us"
    assert session["session_id"] == "a1b2c3d4e5"
    assert session["session_minutes"] == 10
    assert session["session_key"] == "sessid"


def test_a_proxy_session_ttl_does_not_accept_unicode_decimal_aliases() -> None:
    session = parse_session_username(
        "customer-ACME-cc-us-sessid-a1b2c3d4e5-sesstime-١٠"
    )
    assert session["grammar"] == "dash-token"
    assert session["session_minutes"] is None


@pytest.mark.parametrize(
    "username",
    ["14a35bed6f6b3", "", "plainuser", "a-b", "one-two-three"],
)
def test_usernames_without_the_grammar_report_opaque(username):
    """ISP and datacenter credentials carry no structure; that is not an error."""
    session = parse_session_username(username)
    assert session["grammar"] == "opaque"
    assert session["session_id"] is None


def test_a_dash_username_with_no_session_or_country_field_is_opaque():
    assert parse_session_username("region-emea-tier-gold")["grammar"] == "dash-token"
    assert parse_session_username("plan-gold-tier-two")["grammar"] == "opaque"


def test_duplicate_vendor_labels_are_not_treated_as_rewritable() -> None:
    username = "customer-ACME-sessid-first-sessid-second"
    assert parse_session_username(username)["grammar"] == "opaque"
    with pytest.raises(ContractError, match="dash-token"):
        with_session(username, session_id="replacement")


@pytest.mark.parametrize(
    "username",
    [
        "customer-ACME-cc-us-country-gb-sessid-first",
        "customer-ACME-cc-us-sessid-first-session-second",
        "customer-ACME-cc-us-sessid-first-sesstime-10-ttl-20",
    ],
)
def test_duplicate_aliases_are_not_treated_as_rewritable(username: str) -> None:
    assert parse_session_username(username)["grammar"] == "opaque"
    with pytest.raises(ContractError, match="dash-token"):
        with_session(username, session_id="replacement")


def test_proxy_parser_rejects_non_utf8_credential_text() -> None:
    with pytest.raises(ContractError, match="proxy line"):
        parse_proxy_line("user:\ud800@proxy.example:8080")


def test_direct_proxy_credential_fingerprint_rejects_non_utf8_text() -> None:
    parsed = ParsedProxy(
        protocol="http",
        host="proxy.example",
        port=8080,
        username="user",
        password="\ud800",
    )

    with pytest.raises(ContractError, match="proxy credentials"):
        parsed.redacted()


# --------------------------------------------------------------------------
# Sticky sessions
# --------------------------------------------------------------------------


def test_the_same_identity_always_derives_the_same_session():
    assert sticky_session_id("profile-alpha") == sticky_session_id("profile-alpha")


def test_different_identities_derive_different_sessions():
    ids = {sticky_session_id(f"profile-{index}") for index in range(500)}
    assert len(ids) == 500, "collisions would silently share an exit IP"


def test_a_derived_session_is_alphanumeric_and_the_requested_width():
    value = sticky_session_id("profile-alpha", length=10)
    assert len(value) == 10
    assert value.isalnum() and value.islower()


def test_sticky_session_rejects_non_utf8_keys() -> None:
    with pytest.raises(ContractError, match="sticky session key"):
        sticky_session_id("\ud800")


def test_rewriting_a_session_touches_only_the_session_token():
    rewritten = with_session(RESIDENTIAL_USER, session_id="zzz9998887")
    assert rewritten == "customer-ACME-cc-us-sessid-zzz9998887-sesstime-10"


def test_rewriting_matches_a_label_position_not_an_earlier_value() -> None:
    username = "customer-sessid-sessid-old"
    assert with_session(username, session_id="new") == "customer-sessid-sessid-new"


def test_rewriting_can_change_country_and_lifetime():
    rewritten = with_session(RESIDENTIAL_USER, country="GB", session_minutes=30)
    assert rewritten == "customer-ACME-cc-gb-sessid-a1b2c3d4e5-sesstime-30"


def test_rewriting_an_opaque_username_is_refused_not_faked():
    """Inventing a -sessid- pair produces auth failures that look like outages."""
    with pytest.raises(ContractError, match="dash-token"):
        with_session("14a35bed6f6b3", session_id="abc123")


def test_missing_session_field_diagnostic_does_not_echo_session_id() -> None:
    private_session_id = "PrivateSessionMarker123"
    with pytest.raises(ContractError) as failure:
        with_session("region-emea-tier-gold", session_id=private_session_id)
    assert private_session_id not in str(failure.value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"session_id": "not-alphanumeric"},
        {"session_id": 0},
        {"country": "USA"},
        {"country": False},
        {"session_minutes": 0},
        {"session_minutes": 5000},
    ],
)
def test_invalid_session_rewrites_are_refused(kwargs):
    with pytest.raises(ContractError):
        with_session(RESIDENTIAL_USER, **kwargs)


# --------------------------------------------------------------------------
# Import: what lands on disk
# --------------------------------------------------------------------------


def test_importing_builds_a_route_whose_geography_came_from_the_proxy(tmp_path):
    result = import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    assert result["geography"] == {
        "country": "US",
        "locale": "en-US",
        "timezone": "America/Chicago",
    }
    assert result["sticky_capable"] is True
    assert result["credentials_stored"] is True


def test_import_detaches_caller_parsed_proxy_before_route_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed = ParsedProxy(protocol="http", host="first.example", port=3128)
    original_publish = proxy_import_module._publish_matching_route

    def mutate_after_publication(workspace, route):
        publication = original_publish(workspace, route)
        parsed.host = "changed.example"
        return publication

    monkeypatch.setattr(
        proxy_import_module, "_publish_matching_route", mutate_after_publication
    )
    result = import_proxy_route(
        tmp_path,
        parsed=parsed,
        route_id="detached-proxy",
        country="US",
        store_credentials=False,
    )
    saved = load_network_route(tmp_path, "detached-proxy")
    assert saved["endpoint"]["host"] == "first.example"
    assert result["endpoint"]["host"] == saved["endpoint"]["host"]


def test_importing_the_same_route_again_reuses_its_original_receipt(tmp_path, monkeypatch):
    first = import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    original = load_network_route(tmp_path, "res-us-1")
    monkeypatch.setattr(network_module, "_utc_now", lambda: "2099-01-01T00:00:00Z")

    repeated = import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")

    assert repeated["route_sha256_16"] == first["route_sha256_16"]
    assert repeated["credentials_stored"] is True
    assert load_network_route(tmp_path, "res-us-1") == original


def test_repeat_import_keeps_route_conflicts_and_requires_secret_overwrite(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    original = load_network_route(tmp_path, "res-us-1")
    replacement = RESIDENTIAL_LINE.replace(RESIDENTIAL_PASSWORD, "ReplacementSecret")

    with pytest.raises(ContractError, match="network route ID conflict"):
        import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1", name="Other")
    with pytest.raises(ContractError, match="different credential"):
        import_proxy_route(tmp_path, replacement, route_id="res-us-1")
    assert load_proxy_secret(tmp_path, "res-us-1")["secret"] == RESIDENTIAL_PASSWORD

    updated = import_proxy_route(
        tmp_path, replacement, route_id="res-us-1", overwrite_secret=True
    )
    assert updated["route_sha256_16"] == original["integrity_sha256"][:16]
    assert load_network_route(tmp_path, "res-us-1") == original
    assert load_proxy_secret(tmp_path, "res-us-1")["secret"] == "ReplacementSecret"


def test_a_long_valid_proxy_host_gets_a_bounded_default_route_name(tmp_path):
    host = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 60))
    result = import_proxy_route(
        tmp_path, f"{host}:8080", route_id="long-host", country="US"
    )
    route = load_network_route(tmp_path, result["route_id"])
    assert route["endpoint"]["host"] == host
    assert len(route["name"]) <= 128


def test_bracketed_ipv6_proxy_imports_as_an_unbracketed_route_host(tmp_path):
    result = import_proxy_route(
        tmp_path, "http://user:pass@[2001:0db8::1]:8080",
        route_id="ipv6-proxy", country="US", store_credentials=False,
    )
    route = load_network_route(tmp_path, result["route_id"])
    assert route["endpoint"]["host"] == "2001:db8::1"
    assert route["name"].startswith("http://[2001:db8::1]:8080")


@pytest.mark.parametrize(
    "username,password",
    [
        (RESIDENTIAL_USER, None),
        (None, RESIDENTIAL_PASSWORD),
        (RESIDENTIAL_USER, "bad\npassword"),
    ],
)
def test_direct_parsed_proxy_rejects_invalid_credentials_before_publication(
    tmp_path, username, password
):
    parsed = ParsedProxy(
        protocol="http", host="pr.example-proxy.io", port=7777,
        username=username, password=password,
    )
    with pytest.raises(ContractError, match="proxy credentials"):
        import_proxy_route(
            tmp_path, parsed=parsed, route_id="invalid-credential",
            country="US", store_credentials=False,
        )
    assert not (tmp_path / "network" / "routes" / "invalid-credential.json").exists()


@pytest.mark.parametrize(
    "line",
    [
        "http://alice%3Aother:pass@proxy.example:8080",
        f"socks5://{'u' * 256}:pass@proxy.example:1080",
        f"socks5://user:{'p' * 256}@proxy.example:1080",
        f"socks5://{'é' * 128}:pass@proxy.example:1080",
    ],
)
def test_import_rejects_relay_incompatible_credentials_before_publication(
    tmp_path, line
):
    with pytest.raises(ContractError, match="proxy credentials are invalid"):
        import_proxy_route(
            tmp_path, line, route_id="invalid-relay-auth", country="US",
            store_credentials=False,
        )
    assert not (tmp_path / "network" / "routes" / "invalid-relay-auth.json").exists()


def test_direct_secret_store_rejects_relay_incompatible_credentials(tmp_path):
    parsed = parse_proxy_line("http://alice%3Aother:pass@proxy.example:8080")
    with pytest.raises(ContractError, match="proxy credentials are invalid"):
        store_proxy_secret(tmp_path, "invalid-relay-auth", parsed)
    assert not (tmp_path / "network" / "secrets" / "invalid-relay-auth.json").exists()


def test_direct_secret_store_detaches_caller_credentials_before_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed = ParsedProxy(
        protocol="http", host="proxy.example", port=8080,
        username="alice", password="password",
    )
    original_validate = proxy_import_module._validate_relay_credentials

    def mutate_caller_after_validation(candidate):
        original_validate(candidate)
        parsed.username = "alice:other"

    monkeypatch.setattr(
        proxy_import_module, "_validate_relay_credentials",
        mutate_caller_after_validation,
    )
    store_proxy_secret(tmp_path, "detached-auth", parsed)
    secret = load_proxy_secret(tmp_path, "detached-auth")
    assert secret["username_template"] == "alice"
    assert secret["secret"] == "password"


def test_direct_parsed_proxy_rejects_invalid_endpoint_shape_before_publication(tmp_path):
    parsed = ParsedProxy(protocol="http", host=None, port=7777)
    with pytest.raises(ContractError, match="parsed proxy endpoint"):
        import_proxy_route(
            tmp_path, parsed=parsed, route_id="invalid-endpoint", country="US"
        )
    assert not (tmp_path / "network" / "routes" / "invalid-endpoint.json").exists()


def test_the_stored_route_document_contains_no_credential_material(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    raw = (tmp_path / "network" / "routes" / "res-us-1.json").read_text(encoding="utf-8")
    assert RESIDENTIAL_PASSWORD not in raw
    assert RESIDENTIAL_USER not in raw
    assert "ACME" not in raw
    route = load_network_route(tmp_path, "res-us-1")
    assert route["auth"] == {
        "username_env": "BROWSER_CORE_PROXY_RES_US_1_USERNAME",
        "password_env": "BROWSER_CORE_PROXY_RES_US_1_PASSWORD",
    }


def test_generated_credential_references_distinguish_valid_route_ids() -> None:
    route_ids = ["res-us-1", "res_us_1", "res.us.1", "RES-US-1", "res--us-1"]
    pairs = [credential_env_names(route_id) for route_id in route_ids]
    assert len(set(pairs)) == len(route_ids)
    for username_env, password_env in pairs:
        assert username_env != password_env
        assert len(username_env) <= 128
        assert len(password_env) <= 128
    long_pair = credential_env_names("A" * 64)
    assert all(len(name) <= 128 for name in long_pair)


@pytest.mark.parametrize("route_id", ["CON", "AUX.txt", "LPT1.foo"])
def test_credential_references_refuse_unusable_device_route_ids(route_id):
    with pytest.raises(ContractError, match="network route ID is invalid"):
        credential_env_names(route_id)


def test_distinct_route_ids_resolve_their_own_environment_credentials(tmp_path) -> None:
    first_id, second_id = "res-us-1", "res_us_1"
    for route_id in (first_id, second_id):
        import_proxy_route(
            tmp_path,
            RESIDENTIAL_LINE,
            route_id=route_id,
            store_credentials=False,
        )
    first_names = credential_env_names(first_id)
    second_names = credential_env_names(second_id)
    env = {
        first_names[0]: "first-user",
        first_names[1]: "first-password",
        second_names[0]: "second-user",
        second_names[1]: "second-password",
    }

    first = resolve_route_credentials(
        tmp_path, load_network_route(tmp_path, first_id), env=env
    )
    second = resolve_route_credentials(
        tmp_path, load_network_route(tmp_path, second_id), env=env
    )

    assert (first.username, first.password) == ("first-user", "first-password")
    assert (second.username, second.password) == ("second-user", "second-password")


def test_saved_legacy_credential_reference_still_resolves(tmp_path) -> None:
    route_id = "res_us_1"
    legacy_auth = {
        "username_env": "BROWSER_CORE_PROXY_RES_US_1_USERNAME",
        "password_env": "BROWSER_CORE_PROXY_RES_US_1_PASSWORD",
    }
    route = build_network_route(
        route_id=route_id,
        name="legacy proxy",
        geography={
            "country": "US",
            "locale": "en-US",
            "timezone": "America/Chicago",
        },
        mode="proxy",
        endpoint={"protocol": "http", "host": "pr.example-proxy.io", "port": 7777},
        auth=legacy_auth,
    )
    add_network_route(tmp_path, route)

    assert load_network_route(tmp_path, route_id)["auth"] == legacy_auth
    resolved = resolve_route_credentials(
        tmp_path,
        load_network_route(tmp_path, route_id),
        env={
            legacy_auth["username_env"]: RESIDENTIAL_USER,
            legacy_auth["password_env"]: RESIDENTIAL_PASSWORD,
        },
    )
    assert resolved.username == RESIDENTIAL_USER
    assert resolved.password == RESIDENTIAL_PASSWORD

def test_the_publishable_route_view_survives_the_sensitive_key_scanner(tmp_path):
    """``describe_route`` is the view that may leave the machine.

    The raw route cannot pass the scanner and is not meant to: ``auth`` holds
    ``password_env``, and the scanner rejects any key containing "password"
    without looking at whether the value is a secret or the *name* of one. That
    is the correct bias for a blunt guard, and it is why the summary drops
    ``auth`` entirely rather than trying to argue with it.
    """
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    reject_sensitive_keys(describe_route(tmp_path, "res-us-1"))
    with pytest.raises(ContractError, match="sensitive field"):
        reject_sensitive_keys(load_network_route(tmp_path, "res-us-1"))


def test_the_import_result_never_carries_the_secret(tmp_path):
    result = import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    body = json.dumps(result)
    assert RESIDENTIAL_PASSWORD not in body
    assert RESIDENTIAL_USER not in body
    assert result["credential_sha256_16"] is not None


def test_the_secret_file_holds_the_credential_and_the_route_does_not(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    secret_path = tmp_path / "network" / "secrets" / "res-us-1.json"
    assert secret_path.exists()
    stored = load_proxy_secret(tmp_path, "res-us-1")
    assert stored["username_template"] == RESIDENTIAL_USER
    assert stored["secret"] == RESIDENTIAL_PASSWORD
    assert stored["session"]["session_id_length"] == 10


def test_secret_loader_rebinds_selected_file_after_validation(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    source = tmp_path / "network" / "secrets" / "res-us-1.json"
    body = source.read_bytes()
    initial = source.stat()
    original_validate = proxy_import_module._validate_proxy_secret

    def rewrite_after_validation(*args, **kwargs):
        validated = original_validate(*args, **kwargs)
        source.write_bytes(b"X" + body[1:])
        os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        return validated

    with monkeypatch.context() as patch:
        patch.setattr(
            proxy_import_module,
            "_validate_proxy_secret",
            rewrite_after_validation,
        )
        with pytest.raises(ContractError, match="changed during validation"):
            load_proxy_secret(tmp_path, "res-us-1")
    assert len(source.read_bytes()) == len(body)
    source.write_bytes(body)
    assert load_proxy_secret(tmp_path, "res-us-1")["secret"] == RESIDENTIAL_PASSWORD


@pytest.mark.parametrize("consumer", ["has", "resolve"])
def test_secret_missing_result_rechecks_after_parent_validation(
    tmp_path, monkeypatch, consumer,
):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    route = load_network_route(tmp_path, "res-us-1")
    source = tmp_path / "network" / "secrets" / "res-us-1.json"
    held = tmp_path / "held-secret.json"
    source.replace(held)
    original_path = proxy_import_module._secret_path
    calls = 0

    def restore_after_parent_validation(workspace, route_id):
        nonlocal calls
        calls += 1
        selected = original_path(workspace, route_id)
        if calls == 3:
            held.replace(source)
        return selected

    with monkeypatch.context() as patch:
        patch.setattr(
            proxy_import_module, "_secret_path", restore_after_parent_validation,
        )
        with pytest.raises(ContractError, match="proxy secret changed during read"):
            if consumer == "has":
                has_proxy_secret(tmp_path, "res-us-1")
            else:
                username_env, password_env = credential_env_names("res-us-1")
                resolve_route_credentials(
                    tmp_path,
                    route,
                    env={username_env: "fallback-user", password_env: "fallback-secret"},
                )
    assert calls == 3
    assert source.exists()
    assert has_proxy_secret(tmp_path, "res-us-1") is True


@pytest.mark.parametrize("route_id", ["CON", "AUX.txt", "LPT1.foo"])
def test_store_secret_rejects_device_route_id_before_creating_parents(
    tmp_path, route_id,
):
    with pytest.raises(ContractError) as caught:
        store_proxy_secret(tmp_path, route_id, parse_proxy_line(RESIDENTIAL_LINE))
    assert not (tmp_path / "network").exists()
    assert "network route ID is invalid" in str(caught.value)


def test_describe_route_rechecks_route_after_secret_summary(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    route_path = tmp_path / "network" / "routes" / "res-us-1.json"
    real_load_secret = proxy_import_module._load_proxy_secret_snapshot
    replacement = None

    def load_secret_then_replace(workspace, route_id, **kwargs):
        nonlocal replacement
        loaded = real_load_secret(workspace, route_id, **kwargs)
        saved = load_network_route(workspace, route_id)
        replacement = build_network_route(
            route_id=route_id,
            name="competitor summary route",
            geography=saved["geography"],
            mode=saved["mode"],
            endpoint=saved["endpoint"],
            auth=saved["auth"],
            policies=saved["policies"],
            preflight_url=saved["preflight_url"],
        )
        candidate = route_path.with_suffix(".competitor")
        candidate.write_bytes(canonical_json_bytes(replacement))
        os.replace(candidate, route_path)
        return loaded

    monkeypatch.setattr(
        proxy_import_module, "_load_proxy_secret_snapshot", load_secret_then_replace,
    )
    with pytest.raises(ContractError, match="network route changed before summary"):
        describe_route(tmp_path, "res-us-1")
    assert load_network_route(tmp_path, "res-us-1") == replacement
    assert load_proxy_secret(tmp_path, "res-us-1")["secret"] == RESIDENTIAL_PASSWORD


def test_describe_route_rechecks_secret_after_summary(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    replacement = ParsedProxy(
        protocol="http",
        host="pr.example-proxy.io",
        port=7777,
        username=RESIDENTIAL_USER,
        password="Replacement+Secret",
    )
    original = proxy_import_module._load_proxy_secret_snapshot
    replaced = False

    def load_then_replace(workspace, route_id, **kwargs):
        nonlocal replaced
        document, snapshot = original(workspace, route_id, **kwargs)
        if document is not None and not replaced:
            replaced = True
            store_proxy_secret(workspace, route_id, replacement, overwrite=True)
        return document, snapshot

    monkeypatch.setattr(
        proxy_import_module, "_load_proxy_secret_snapshot", load_then_replace,
    )
    with pytest.raises(ContractError, match="proxy secret changed before summary"):
        describe_route(tmp_path, "res-us-1")
    assert load_proxy_secret(tmp_path, "res-us-1")["secret"] == replacement.password


def test_an_anonymous_proxy_imports_without_auth(tmp_path):
    result = import_proxy_route(
        tmp_path, "host.example:8080", route_id="open-1", country="DE"
    )
    assert result["credentials_stored"] is False
    assert load_network_route(tmp_path, "open-1")["auth"] is None


def test_a_country_the_proxy_does_not_declare_must_be_supplied(tmp_path):
    with pytest.raises(ContractError, match="country"):
        import_proxy_route(tmp_path, FLAT_LINE, route_id="isp-1")


def test_an_unknown_country_needs_an_explicit_locale_and_zone(tmp_path):
    """IS has no row in the shared geography table, so it must be spelled out.

    Deliberately a country the table does not cover: the point is the fallback
    path, and picking one that later gets a default turns this into a test that
    passes for the wrong reason.
    """
    with pytest.raises(ContractError, match="locale"):
        import_proxy_route(tmp_path, FLAT_LINE, route_id="isp-1", country="IS")
    result = import_proxy_route(
        tmp_path,
        FLAT_LINE,
        route_id="isp-1",
        country="IS",
        locale="is-IS",
        timezone_name="Atlantic/Reykjavik",
    )
    assert result["geography"]["country"] == "IS"
    assert result["sticky_capable"] is False, "an opaque username cannot be pinned"


def test_a_country_in_the_shared_table_needs_no_locale(tmp_path):
    """Route and persona geography come from one table, so they cannot disagree."""
    result = import_proxy_route(tmp_path, FLAT_LINE, route_id="isp-2", country="ZA")
    assert result["geography"] == {
        "country": "ZA",
        "locale": "en-ZA",
        "timezone": "Africa/Johannesburg",
    }


def test_reimporting_a_different_credential_is_refused(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    other = ParsedProxy(
        protocol="http",
        host="pr.example-proxy.io",
        port=7777,
        username=RESIDENTIAL_USER,
        password="a-different-password",
    )
    with pytest.raises(ContractError, match="already stored"):
        store_proxy_secret(tmp_path, "res-us-1", other)
    assert store_proxy_secret(tmp_path, "res-us-1", other, overwrite=True)["stored"] is True


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda document: document.__setitem__("unexpected", True), "fields"),
        (
            lambda document: document.__setitem__("credential_sha256_16", "0" * 16),
            "digest",
        ),
        (
            lambda document: document["session"].__setitem__("session_minutes", 11),
            "metadata",
        ),
    ],
)
def test_a_proxy_secret_is_exact_and_self_authenticating(tmp_path, mutation, message):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    path = tmp_path / "network" / "secrets" / "res-us-1.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    mutation(document)
    path.write_bytes(canonical_json_bytes(document))

    with pytest.raises(ContractError, match=message):
        has_proxy_secret(tmp_path, "res-us-1")


@pytest.mark.parametrize("field", ["session_minutes", "session_id_length"])
def test_a_proxy_secret_rejects_json_number_type_aliases(tmp_path, field):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    path = tmp_path / "network" / "secrets" / "res-us-1.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["session"][field] = float(document["session"][field])
    path.write_bytes(canonical_json_bytes(document))

    with pytest.raises(ContractError, match="metadata"):
        has_proxy_secret(tmp_path, "res-us-1")


def test_session_parser_treats_unbounded_ttl_digits_as_unknown():
    username = "customer-ACME-cc-us-sesstime-" + "9" * 5000
    parsed = parse_session_username(username)
    assert parsed["grammar"] == "dash-token"
    assert parsed["session_minutes"] is None


def test_a_proxy_secret_is_rejected_before_an_oversize_body_is_parsed(
    tmp_path, monkeypatch
):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    monkeypatch.setattr(proxy_import_module, "MAX_PROXY_SECRET_BYTES", 1)

    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        load_proxy_secret(tmp_path, "res-us-1")


def test_a_proxy_secret_with_an_additional_hard_link_is_rejected(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    path = tmp_path / "network" / "secrets" / "res-us-1.json"
    alias = tmp_path / "leaked-secret.json"
    try:
        alias.hardlink_to(path)
    except OSError as exc:
        pytest.skip(f"hard links unavailable on this test filesystem: {type(exc).__name__}")

    with pytest.raises(ContractError, match="hard links"):
        load_proxy_secret(tmp_path, "res-us-1")


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction regression')
def test_proxy_secret_loader_rejects_preexisting_file_behind_junction(tmp_path):
    source = tmp_path / 'source'
    body = _valid_secret_body_for_route(
        source, 'res-us-1', source_id='res-us-1', password=RESIDENTIAL_PASSWORD,
    )
    external = tmp_path / 'external-secrets'
    external.mkdir()
    secret = external / 'res-us-1.json'
    secret.write_bytes(body)
    network = tmp_path / 'network'
    network.mkdir()
    junction = network / 'secrets'
    result = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(junction), str(external)],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        pytest.skip('directory junction creation is unavailable')
    try:
        assert not junction.is_symlink()
        with pytest.raises(ContractError) as error:
            load_proxy_secret(tmp_path, 'res-us-1')
        assert RESIDENTIAL_PASSWORD not in str(error.value)
        assert secret.read_bytes() == body
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
@pytest.mark.parametrize("operation", ["load", "store"])
def test_proxy_secret_rejects_workspace_junction(tmp_path, operation):
    external = tmp_path / "external"
    external.mkdir()
    junction = tmp_path / "workspace"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
        capture_output=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        with pytest.raises(ContractError, match="proxy secret directory"):
            if operation == "load":
                load_proxy_secret(junction, "res-us-1")
            else:
                store_proxy_secret(junction, "res-us-1", parse_proxy_line(RESIDENTIAL_LINE))
        assert list(external.iterdir()) == []
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_proxy_secret_store_rechecks_workspace_after_path_admission(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hidden = tmp_path / "original-workspace"
    external = tmp_path / "external"
    external.mkdir()
    original_identity = proxy_import_module.directory_identity
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

    monkeypatch.setattr(proxy_import_module, "directory_identity", switch_after_workspace_check)
    try:
        with pytest.raises(ContractError, match="proxy secret directory"):
            store_proxy_secret(workspace, "res-us-1", parse_proxy_line(RESIDENTIAL_LINE))
        assert swapped
        assert list(external.iterdir()) == []
    finally:
        if swapped:
            workspace.rmdir()
            hidden.rename(workspace)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_proxy_secret_load_rechecks_workspace_after_path_admission(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hidden = tmp_path / "original-workspace"
    external = tmp_path / "external"
    store_proxy_secret(external, "res-us-1", parse_proxy_line(RESIDENTIAL_LINE))
    original_identity = proxy_import_module.directory_identity
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

    monkeypatch.setattr(proxy_import_module, "directory_identity", switch_after_workspace_check)
    try:
        with pytest.raises(ContractError, match="proxy secret directory"):
            load_proxy_secret(workspace, "res-us-1")
        assert swapped
    finally:
        if swapped:
            workspace.rmdir()
            hidden.rename(workspace)


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction regression')
def test_proxy_secret_store_does_not_create_child_through_new_parent_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    external = tmp_path / 'external'
    external.mkdir()
    network = workspace / 'network'
    original_mkdir = Path.mkdir
    inserted = False

    def insert_before_network_mkdir(path: Path, *args, **kwargs) -> None:
        nonlocal inserted
        if path == network and not inserted:
            created = subprocess.run(
                ['cmd', '/c', 'mklink', '/J', str(network), str(external)],
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                pytest.skip('directory junction creation is unavailable')
            inserted = True
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'mkdir', insert_before_network_mkdir)
    try:
        with pytest.raises(ContractError, match='proxy secret directory'):
            store_proxy_secret(workspace, 'owned-route', parse_proxy_line(FLAT_LINE))
        assert inserted
        assert list(external.iterdir()) == []
    finally:
        if inserted:
            network.rmdir()


def test_a_proxy_secret_rejects_duplicate_members_and_coerced_workspace(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    path = tmp_path / "network" / "secrets" / "res-us-1.json"
    body = path.read_text(encoding="utf-8")
    path.write_text(
        body.replace(
            '"route_id":"res-us-1",',
            '"route_id":"res-us-1","route_id":"private",',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="duplicate key") as failure:
        load_proxy_secret(tmp_path, "res-us-1")
    assert "private" not in str(failure.value)

    with pytest.raises(ContractError, match="workspace must be a Path"):
        load_proxy_secret(str(tmp_path), "res-us-1")  # type: ignore[arg-type]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not ACLs")
def test_a_proxy_secret_with_broad_permissions_is_rejected(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    path = tmp_path / "network" / "secrets" / "res-us-1.json"
    path.chmod(0o644)

    with pytest.raises(ContractError, match="permissions"):
        load_proxy_secret(tmp_path, "res-us-1")


def test_a_competing_secret_creation_wins_without_being_overwritten(
    tmp_path, monkeypatch
):
    competitor = _valid_secret_body_for_route(
        tmp_path,
        "res-us-1",
        source_id="race-source",
        password="competitor-password",
    )
    target = tmp_path / "network" / "secrets" / "res-us-1.json"
    intended = parse_proxy_line(RESIDENTIAL_LINE)
    real_publish = proxy_import_module.publish_json_exclusive

    def publish_after_competitor(path, document, **kwargs):
        path.write_bytes(competitor)
        return real_publish(path, document, **kwargs)

    monkeypatch.setattr(
        proxy_import_module, "publish_json_exclusive", publish_after_competitor
    )
    with pytest.raises(ContractError, match="different credential") as caught:
        store_proxy_secret(tmp_path, "res-us-1", intended)

    assert target.read_bytes() == competitor
    assert RESIDENTIAL_PASSWORD not in str(caught.value)
    assert "competitor-password" not in str(caught.value)
    assert not list(target.parent.glob(".res-us-1.json.tmp-*"))


def test_a_proxy_secret_overwrite_is_compare_and_swap(tmp_path, monkeypatch):
    original = parse_proxy_line(RESIDENTIAL_LINE)
    store_proxy_secret(tmp_path, "res-us-1", original)
    competitor = _valid_secret_body_for_route(
        tmp_path,
        "res-us-1",
        source_id="race-source",
        password="competitor-password",
    )
    target = tmp_path / "network" / "secrets" / "res-us-1.json"
    replacement = ParsedProxy(
        protocol="http",
        host="pr.example-proxy.io",
        port=7777,
        username=RESIDENTIAL_USER,
        password="replacement-password",
    )
    real_replace = proxy_import_module.replace_json_conditionally

    def replace_after_competitor(path, document, **kwargs):
        path.unlink()
        path.write_bytes(competitor)
        return real_replace(path, document, **kwargs)

    monkeypatch.setattr(
        proxy_import_module, "replace_json_conditionally", replace_after_competitor
    )
    with pytest.raises(ContractError, match="changed before transition") as caught:
        store_proxy_secret(tmp_path, "res-us-1", replacement, overwrite=True)

    assert target.read_bytes() == competitor
    error = str(caught.value)
    assert all(
        value not in error
        for value in (
            RESIDENTIAL_PASSWORD,
            "competitor-password",
            "replacement-password",
            str(target),
        )
    )


def test_proxy_secret_deletion_refuses_a_replaced_file(tmp_path, monkeypatch):
    original = parse_proxy_line(RESIDENTIAL_LINE)
    store_proxy_secret(tmp_path, "res-us-1", original)
    competitor = _valid_secret_body_for_route(
        tmp_path,
        "res-us-1",
        source_id="race-source",
        password="competitor-password",
    )
    target = tmp_path / "network" / "secrets" / "res-us-1.json"
    real_remove = proxy_import_module.remove_control_conditionally

    def remove_after_competitor(path, **kwargs):
        path.unlink()
        path.write_bytes(competitor)
        return real_remove(path, **kwargs)

    monkeypatch.setattr(
        proxy_import_module, "remove_control_conditionally", remove_after_competitor
    )
    with pytest.raises(ContractError, match="changed before removal"):
        delete_proxy_secret(tmp_path, "res-us-1")

    assert target.read_bytes() == competitor


def test_proxy_secret_deletion_rejects_disappearance_after_existing_snapshot(
    tmp_path, monkeypatch
):
    store_proxy_secret(tmp_path, "res-us-1", parse_proxy_line(RESIDENTIAL_LINE))
    target = tmp_path / "network" / "secrets" / "res-us-1.json"
    real_remove = proxy_import_module.remove_control_conditionally

    def remove_after_disappearance(path, **kwargs):
        path.unlink()
        return real_remove(path, **kwargs)

    monkeypatch.setattr(
        proxy_import_module, "remove_control_conditionally", remove_after_disappearance
    )
    with pytest.raises(ContractError, match="changed before removal"):
        delete_proxy_secret(tmp_path, "res-us-1")
    assert not target.exists()


def test_proxy_secret_deletion_rechecks_path_after_successful_remove(
    tmp_path, monkeypatch
):
    original = parse_proxy_line(RESIDENTIAL_LINE)
    store_proxy_secret(tmp_path, "res-us-1", original)
    target = tmp_path / "network" / "secrets" / "res-us-1.json"
    body = target.read_bytes()
    real_remove = proxy_import_module.remove_control_conditionally

    def remove_then_reappear(path, **kwargs):
        real_remove(path, **kwargs)
        path.write_bytes(body)
        os.chmod(path, 0o600)

    monkeypatch.setattr(
        proxy_import_module, "remove_control_conditionally", remove_then_reappear
    )
    with pytest.raises(ContractError, match="reappeared during removal"):
        delete_proxy_secret(tmp_path, "res-us-1")

    assert target.read_bytes() == body


def test_proxy_secret_storage_rechecks_publication_before_success(
    tmp_path, monkeypatch
):
    real_publish = proxy_import_module.publish_json_exclusive
    target = tmp_path / "network" / "secrets" / "res-us-1.json"

    def publish_then_disappear(path, document, **kwargs):
        body = real_publish(path, document, **kwargs)
        path.unlink()
        return body

    monkeypatch.setattr(
        proxy_import_module, "publish_json_exclusive", publish_then_disappear
    )
    with pytest.raises(ContractError, match="proxy secret changed before storage completed"):
        store_proxy_secret(tmp_path, "res-us-1", parse_proxy_line(RESIDENTIAL_LINE))
    assert not target.exists()


def test_idempotent_proxy_secret_storage_rechecks_before_success(
    tmp_path, monkeypatch
):
    parsed = parse_proxy_line(RESIDENTIAL_LINE)
    store_proxy_secret(tmp_path, "res-us-1", parsed)
    target = tmp_path / "network" / "secrets" / "res-us-1.json"
    real_load = proxy_import_module._load_proxy_secret_snapshot
    reads = 0

    def read_then_disappear(*args, **kwargs):
        nonlocal reads
        current = real_load(*args, **kwargs)
        reads += 1
        if reads == 1:
            target.unlink()
        return current

    monkeypatch.setattr(
        proxy_import_module, "_load_proxy_secret_snapshot", read_then_disappear
    )
    with pytest.raises(ContractError, match="proxy secret changed before storage completed"):
        store_proxy_secret(tmp_path, "res-us-1", parsed)
    assert not target.exists()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"store_credentials": "false"},
        {"overwrite_secret": 1},
        {"require_alignment": "true"},
    ],
)
def test_proxy_import_flags_are_exact_booleans_before_route_mutation(tmp_path, kwargs):
    with pytest.raises(ContractError, match="must be boolean"):
        import_proxy_route(
            tmp_path,
            RESIDENTIAL_LINE,
            route_id="res-us-1",
            **kwargs,
        )

    assert not (tmp_path / "network" / "routes" / "res-us-1.json").exists()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"country": False},
        {"country": True},
        {"locale": 0},
        {"timezone_name": False},
    ],
)
def test_proxy_import_rejects_nontext_geography_before_route_mutation(
    tmp_path, kwargs,
):
    with pytest.raises(ContractError, match="proxy import geography is invalid"):
        import_proxy_route(
            tmp_path, RESIDENTIAL_LINE, route_id="res-us-1", **kwargs
        )
    assert not (tmp_path / "network").exists()


@pytest.mark.parametrize("name", [False, 0, []])
def test_proxy_import_rejects_explicit_nontext_name_before_route_mutation(
    tmp_path, name,
):
    with pytest.raises(ContractError, match="proxy import name is invalid"):
        import_proxy_route(
            tmp_path, RESIDENTIAL_LINE, route_id="res-us-1", name=name
        )
    assert not (tmp_path / "network").exists()


def test_a_secret_conflict_rolls_back_only_the_newly_created_route(tmp_path):
    competitor = ParsedProxy(
        protocol="http",
        host="pr.example-proxy.io",
        port=7777,
        username=RESIDENTIAL_USER,
        password="competitor-password",
    )
    store_proxy_secret(tmp_path, "res-us-1", competitor)
    secret_path = tmp_path / "network" / "secrets" / "res-us-1.json"
    before = secret_path.read_bytes()

    with pytest.raises(ContractError, match="different credential"):
        import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")

    assert not (tmp_path / "network" / "routes" / "res-us-1.json").exists()
    assert secret_path.read_bytes() == before


def test_proxy_import_route_rollback_preserves_a_replacement(
    tmp_path, monkeypatch
):
    competitor = ParsedProxy(
        protocol="http",
        host="pr.example-proxy.io",
        port=7777,
        username=RESIDENTIAL_USER,
        password="competitor-password",
    )
    store_proxy_secret(tmp_path, "res-us-1", competitor)
    route_path = tmp_path / "network" / "routes" / "res-us-1.json"
    replacement = b"replacement route"
    real_rollback = network_module.rollback_network_route_publication

    def rollback_after_replacement(workspace, publication):
        route_path.unlink()
        route_path.write_bytes(replacement)
        return real_rollback(workspace, publication)

    monkeypatch.setattr(
        network_module,
        "rollback_network_route_publication",
        rollback_after_replacement,
    )
    with pytest.raises(ContractError, match="rollback incomplete") as caught:
        import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")

    assert route_path.read_bytes() == replacement
    assert RESIDENTIAL_PASSWORD not in str(caught.value)
    assert "competitor-password" not in str(caught.value)


def test_proxy_import_rechecks_route_receipt_after_secret_storage(tmp_path, monkeypatch):
    real_store = proxy_import_module.store_proxy_secret
    route_path = tmp_path / "network" / "routes" / "res-us-1.json"
    replacement = None

    def store_then_replace(workspace, route_id, parsed, **kwargs):
        nonlocal replacement
        result = real_store(workspace, route_id, parsed, **kwargs)
        saved = load_network_route(workspace, route_id)
        replacement = build_network_route(
            route_id=route_id,
            name="competitor route",
            geography=saved["geography"],
            mode=saved["mode"],
            endpoint=saved["endpoint"],
            auth=saved["auth"],
            policies=saved["policies"],
            preflight_url=saved["preflight_url"],
        )
        candidate = route_path.with_suffix(".competitor")
        candidate.write_bytes(canonical_json_bytes(replacement))
        os.replace(candidate, route_path)
        return result

    monkeypatch.setattr(proxy_import_module, "store_proxy_secret", store_then_replace)
    with pytest.raises(ContractError, match="network route changed before proxy receipt"):
        import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    assert load_network_route(tmp_path, "res-us-1") == replacement
    assert load_proxy_secret(tmp_path, "res-us-1")["secret"] == RESIDENTIAL_PASSWORD


# --------------------------------------------------------------------------
# Resolution: the credential reaching the socket, and only the socket
# --------------------------------------------------------------------------


def test_resolution_pins_a_sticky_session_for_the_given_identity(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    route = load_network_route(tmp_path, "res-us-1")
    resolved = resolve_route_credentials(tmp_path, route, session_key="profile-alpha")
    expected = sticky_session_id("profile-alpha", length=10)
    assert resolved.username == f"customer-ACME-cc-us-sessid-{expected}-sesstime-10"
    assert resolved.password == RESIDENTIAL_PASSWORD


@pytest.mark.parametrize("change", ["replace", "remove"])
def test_stored_credential_resolution_rechecks_secret_before_return(
    tmp_path, monkeypatch, change,
):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    route = load_network_route(tmp_path, "res-us-1")
    real_resolve = proxy_import_module.resolve_network_route
    replacement = ParsedProxy(
        protocol="http",
        host="pr.example-proxy.io",
        port=7777,
        username=RESIDENTIAL_USER,
        password="replacement-synthetic-password",
    )

    def change_secret_during_resolution(document, env=None):
        if change == "replace":
            store_proxy_secret(tmp_path, "res-us-1", replacement, overwrite=True)
        else:
            delete_proxy_secret(tmp_path, "res-us-1")
        return real_resolve(document, env)

    monkeypatch.setattr(
        proxy_import_module, "resolve_network_route", change_secret_during_resolution
    )
    with pytest.raises(ContractError, match="proxy secret changed before credential resolution"):
        resolve_route_credentials(tmp_path, route)

    if change == "replace":
        assert load_proxy_secret(tmp_path, "res-us-1")["secret"] == replacement.password
    else:
        assert not has_proxy_secret(tmp_path, "res-us-1")


def test_two_identities_resolve_to_two_different_exits(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    route = load_network_route(tmp_path, "res-us-1")
    first = resolve_route_credentials(tmp_path, route, session_key="alpha").username
    second = resolve_route_credentials(tmp_path, route, session_key="beta").username
    assert first != second


@pytest.mark.parametrize("first,second", [("aa", "bb"), ("a" * 65, "b" * 65)])
def test_unmintable_session_lengths_do_not_collapse_or_claim_sticky_routing(
    tmp_path, first, second
):
    path = tmp_path / "unmintable-sessions.txt"
    path.write_text(
        "\n".join(
            f"customer-ACME-cc-us-sessid-{session}:{RESIDENTIAL_PASSWORD}"
            "@pr.example-proxy.io:7777"
            for session in (first, second)
        ),
        encoding="utf-8",
    )
    result = import_proxy_file(tmp_path, path, prefix="short-session")
    assert result["imported_count"] == 2
    for item in result["imported"]:
        assert item["sticky_capable"] is False
        assert describe_route(tmp_path, item["route_id"])["sticky_capable"] is False
        route = load_network_route(tmp_path, item["route_id"])
        with pytest.raises(ContractError, match="not sticky-capable"):
            resolve_route_credentials(tmp_path, route, session_key="profile-alpha")


def test_the_same_identity_resolves_to_the_same_pin_across_calls(tmp_path):
    """The pin is stable; how long the vendor honours it is the vendor's call."""
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    route = load_network_route(tmp_path, "res-us-1")
    first = resolve_route_credentials(tmp_path, route, session_key="alpha").username
    second = resolve_route_credentials(tmp_path, route, session_key="alpha").username
    assert first == second, "a profile must present the same pin after a restart"


def test_without_a_session_key_the_providers_own_session_is_used(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    route = load_network_route(tmp_path, "res-us-1")
    assert resolve_route_credentials(tmp_path, route).username == RESIDENTIAL_USER


def test_country_only_username_remains_usable_with_a_profile_key(tmp_path):
    username = "customer-ACME-cc-us"
    line = f"{username}:{RESIDENTIAL_PASSWORD}@pr.example-proxy.io:7777"
    imported = import_proxy_route(tmp_path, line, route_id="country-only")
    assert imported["sticky_capable"] is False
    route = load_network_route(tmp_path, "country-only")
    assert describe_route(tmp_path, "country-only")["sticky_capable"] is False
    resolved = resolve_route_credentials(tmp_path, route, session_key="profile-alpha")
    assert resolved.username == username
    assert resolved.password == RESIDENTIAL_PASSWORD


def test_a_route_with_no_stored_secret_still_resolves_from_the_environment(tmp_path):
    """Everything that worked before the secret store existed must keep working."""
    imported = import_proxy_route(
        tmp_path, RESIDENTIAL_LINE, route_id="res-us-1", store_credentials=False
    )
    assert has_proxy_secret(tmp_path, "res-us-1") is False
    assert imported["sticky_capable"] is False
    assert describe_route(tmp_path, "res-us-1")["sticky_capable"] is False
    route = load_network_route(tmp_path, "res-us-1")
    username_env, password_env = credential_env_names("res-us-1")
    resolved = resolve_route_credentials(
        tmp_path, route, env={username_env: "env-user", password_env: "env-pass"}
    )
    assert resolved.username == "env-user"
    assert resolved.password == "env-pass"


def test_import_without_storing_reports_an_existing_sticky_secret(tmp_path):
    first = import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    repeated = import_proxy_route(
        tmp_path, RESIDENTIAL_LINE, route_id="res-us-1", store_credentials=False
    )
    summary = describe_route(tmp_path, "res-us-1")
    assert first["credentials_stored"] is True
    assert repeated["credentials_stored"] is True
    assert repeated["sticky_capable"] is True
    assert repeated["session"] == summary["session"]


def test_an_opaque_credential_is_never_rewritten_by_a_session_key(tmp_path):
    import_proxy_route(
        tmp_path,
        FLAT_LINE,
        route_id="isp-1",
        country="ZA",
        locale="en-ZA",
        timezone_name="Africa/Johannesburg",
    )
    route = load_network_route(tmp_path, "isp-1")
    resolved = resolve_route_credentials(tmp_path, route, session_key="alpha")
    assert resolved.username == "14a35bed6f6b3"


def test_resolution_does_not_touch_the_process_environment(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    username_env, password_env = credential_env_names("res-us-1")
    monkeypatch.delenv(username_env, raising=False)
    monkeypatch.delenv(password_env, raising=False)
    route = load_network_route(tmp_path, "res-us-1")
    resolve_route_credentials(tmp_path, route, session_key="alpha")
    assert username_env not in os.environ
    assert password_env not in os.environ


def test_the_plain_resolver_still_refuses_an_unset_environment(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    with pytest.raises(ContractError, match="unresolved"):
        resolve_network_route(load_network_route(tmp_path, "res-us-1"), {})


# --------------------------------------------------------------------------
# Description and bulk import
# --------------------------------------------------------------------------


def test_describing_a_route_reports_capability_without_the_credential(tmp_path):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    summary = describe_route(tmp_path, "res-us-1")
    assert summary["credentials_stored"] is True
    assert summary["sticky_capable"] is True
    assert summary["endpoint"]["port"] == 7777
    body = json.dumps(summary)
    assert RESIDENTIAL_PASSWORD not in body and RESIDENTIAL_USER not in body


def test_a_provider_list_collapses_to_one_route_per_endpoint(tmp_path):
    """A thousand pre-minted sessions are one route, not a thousand."""
    path = tmp_path / "provider.txt"
    path.write_text(
        "\n".join(
            f"customer-ACME-cc-us-sessid-{index:010d}-sesstime-10"
            f":{RESIDENTIAL_PASSWORD}@pr.example-proxy.io:7777"
            for index in range(50)
        )
        + "\n",
        encoding="utf-8",
    )
    result = import_proxy_file(tmp_path, path, prefix="res")
    assert result["lines_considered"] == 50
    assert result["distinct_endpoints"] == 1
    assert result["imported_count"] == 1
    assert result["imported"][0]["collapsed_lines"] == 50


def test_repeating_a_provider_file_import_keeps_the_existing_route(tmp_path, monkeypatch):
    path = tmp_path / "provider.txt"
    path.write_text(RESIDENTIAL_LINE + "\n", encoding="utf-8")
    first = import_proxy_file(tmp_path, path, prefix="repeat")
    monkeypatch.setattr(network_module, "_utc_now", lambda: "2099-01-01T00:00:00Z")

    repeated = import_proxy_file(tmp_path, path, prefix="repeat")

    assert repeated["imported_count"] == 1
    assert repeated["failed_count"] == 0
    assert repeated["imported"][0]["route_sha256_16"] == first["imported"][0][
        "route_sha256_16"
    ]


def test_bulk_import_collapses_dns_hosts_across_letter_case(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text(
        f"{RESIDENTIAL_USER}:{RESIDENTIAL_PASSWORD}@PROXY.Example:8080\n"
        f"{RESIDENTIAL_USER}:{RESIDENTIAL_PASSWORD}@proxy.example:8080\n",
        encoding="utf-8",
    )

    result = import_proxy_file(tmp_path, path, prefix="dns-case")

    assert result["distinct_endpoints"] == 1
    assert result["imported_count"] == 1
    assert result["imported"][0]["collapsed_lines"] == 2
    assert result["imported"][0]["endpoint"]["host"] == "proxy.example"


def test_bulk_import_keeps_distinct_passwords_and_non_session_fields(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text(
        "\n".join(
            [
                f"{RESIDENTIAL_USER}:{RESIDENTIAL_PASSWORD}@pr.example-proxy.io:7777",
                f"{RESIDENTIAL_USER}:AnotherPassword@pr.example-proxy.io:7777",
                f"{RESIDENTIAL_USER.replace('sesstime-10', 'sesstime-20')}:{RESIDENTIAL_PASSWORD}@pr.example-proxy.io:7777",
            ]
        ),
        encoding="utf-8",
    )

    result = import_proxy_file(tmp_path, path, prefix="distinct")

    assert result["distinct_endpoints"] == 1
    assert result["imported_count"] == 3
    assert result["failed_count"] == 0
    assert len({item["credential_sha256_16"] for item in result["imported"]}) == 3
    assert RESIDENTIAL_PASSWORD not in json.dumps(result)
    assert "AnotherPassword" not in json.dumps(result)


def test_bulk_import_reserves_route_id_suffix_for_long_host_labels(tmp_path):
    first_label = "a" * 63
    path = tmp_path / "provider.txt"
    path.write_text(
        "\n".join(
            [
                f"{RESIDENTIAL_USER}:{RESIDENTIAL_PASSWORD}@{first_label}.one.example:7777",
                f"{RESIDENTIAL_USER}:{RESIDENTIAL_PASSWORD}@{first_label}.two.example:7777",
            ]
        ),
        encoding="utf-8",
    )

    result = import_proxy_file(tmp_path, path, prefix="p" * 32)

    assert result["imported_count"] == 2
    assert result["failed_count"] == 0
    route_ids = {item["route_id"] for item in result["imported"]}
    assert len(route_ids) == 2
    assert all(len(route_id) <= 64 for route_id in route_ids)


def test_a_mixed_list_splits_by_country_and_endpoint(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text(
        "\n".join(
            [
                f"customer-ACME-cc-us-sessid-aaaaaaaaaa-sesstime-10:{RESIDENTIAL_PASSWORD}@pr.example-proxy.io:7777",
                f"customer-ACME-cc-gb-sessid-bbbbbbbbbb-sesstime-10:{RESIDENTIAL_PASSWORD}@pr.example-proxy.io:7777",
                "# a comment line",
                "",
                f"customer-ACME-cc-de-sessid-cccccccccc-sesstime-10:{RESIDENTIAL_PASSWORD}@eu.example-proxy.io:8000",
            ]
        ),
        encoding="utf-8",
    )
    result = import_proxy_file(tmp_path, path, prefix="res")
    assert result["distinct_endpoints"] == 3
    assert result["imported_count"] == 3
    assert {item["geography"]["country"] for item in result["imported"]} == {"US", "GB", "DE"}


def test_malformed_lines_are_reported_not_silently_dropped(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text(
        f"{RESIDENTIAL_LINE}\nnot-a-proxy\nhost.example\n", encoding="utf-8"
    )
    result = import_proxy_file(tmp_path, path)
    assert result["malformed_count"] == 2
    assert result["imported_count"] == 1
    assert {item["line"] for item in result["malformed"]} == {2, 3}
    assert {item["reason"] for item in result["malformed"]} == {
        "unrecognized-format"
    }


def test_bulk_import_does_not_treat_unicode_separator_as_a_physical_line(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text(
        f"{RESIDENTIAL_LINE}\u2028{RESIDENTIAL_LINE}", encoding="utf-8"
    )

    result = import_proxy_file(tmp_path, path)

    assert result["lines_considered"] == 1
    assert result["imported_count"] == 0
    assert result["malformed_count"] == 1


def test_bulk_import_does_not_strip_unicode_separator_at_line_end(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text(f"{RESIDENTIAL_LINE}\u2028\n", encoding="utf-8")

    result = import_proxy_file(tmp_path, path)

    assert result["lines_considered"] == 1
    assert result["imported_count"] == 0
    assert result["malformed_count"] == 1


def test_bulk_import_still_accepts_ascii_padding(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text(f" \t{RESIDENTIAL_LINE} \t\n", encoding="utf-8")

    result = import_proxy_file(tmp_path, path)

    assert result["lines_considered"] == 1
    assert result["imported_count"] == 1


def test_bulk_import_caps_physical_lines_including_comments(tmp_path, monkeypatch):
    path = tmp_path / "provider.txt"
    path.write_text("# comment\n\n# comment\n", encoding="utf-8")
    monkeypatch.setattr(proxy_import_module, "MAX_PROXY_IMPORT_PHYSICAL_LINES", 2)

    with pytest.raises(ContractError, match="too many physical lines"):
        import_proxy_file(tmp_path, path)


def test_bulk_import_output_carries_no_credentials(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text(f"{RESIDENTIAL_LINE}\n", encoding="utf-8")
    body = json.dumps(import_proxy_file(tmp_path, path))
    assert RESIDENTIAL_PASSWORD not in body
    assert RESIDENTIAL_USER not in body


def test_a_limit_stops_reading_the_file(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_text("\n".join([RESIDENTIAL_LINE] * 20), encoding="utf-8")
    assert import_proxy_file(tmp_path, path, limit=5)["lines_considered"] == 5


def test_a_limit_at_candidate_cap_stops_before_the_next_line(tmp_path, monkeypatch):
    path = tmp_path / "provider.txt"
    path.write_text(f"{RESIDENTIAL_LINE}\n{RESIDENTIAL_LINE}\n", encoding="utf-8")
    monkeypatch.setattr(proxy_import_module, "MAX_PROXY_IMPORT_LINES", 1)

    result = import_proxy_file(tmp_path, path, limit=1)

    assert result["lines_considered"] == 1
    assert result["imported_count"] == 1


def test_a_provider_file_is_byte_bounded_before_decoding(tmp_path, monkeypatch):
    path = tmp_path / "provider.txt"
    path.write_text(RESIDENTIAL_LINE, encoding="utf-8")
    monkeypatch.setattr(proxy_import_module, "MAX_PROXY_IMPORT_FILE_BYTES", 1)

    with pytest.raises(ContractError, match="exceeds 1 bytes"):
        import_proxy_file(tmp_path, path)


def test_a_provider_file_requires_strict_utf8(tmp_path):
    path = tmp_path / "provider.txt"
    path.write_bytes(b"\xff\xfe\xfd")

    with pytest.raises(ContractError, match="encoding"):
        import_proxy_file(tmp_path, path)


def test_a_provider_file_has_a_hard_candidate_line_cap(tmp_path, monkeypatch):
    path = tmp_path / "provider.txt"
    path.write_text(f"{RESIDENTIAL_LINE}\n{RESIDENTIAL_LINE}\n", encoding="utf-8")
    monkeypatch.setattr(proxy_import_module, "MAX_PROXY_IMPORT_LINES", 1)

    with pytest.raises(ContractError, match="too many candidate lines"):
        import_proxy_file(tmp_path, path)


def test_bulk_import_flags_are_validated_before_the_source_is_opened(tmp_path):
    with pytest.raises(ContractError, match="store_credentials must be boolean"):
        import_proxy_file(
            tmp_path,
            tmp_path / "missing-provider.txt",
            store_credentials="false",
        )


def test_bulk_import_requires_exact_paths_and_a_valid_protocol(tmp_path):
    with pytest.raises(ContractError, match="workspace must be a Path"):
        import_proxy_file(str(tmp_path), tmp_path / "missing.txt")  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="source must be a Path"):
        import_proxy_file(tmp_path, "missing.txt")  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="unsupported"):
        import_proxy_file(tmp_path, tmp_path / "missing.txt", default_protocol="ftp")


@pytest.mark.parametrize("protocol", [42, False, []])
def test_bulk_import_rejects_non_text_protocol_before_source_read(tmp_path, protocol):
    with pytest.raises(ContractError, match="proxy protocol is unsupported"):
        import_proxy_file(
            tmp_path,
            tmp_path / "missing.txt",
            default_protocol=protocol,
        )


def test_bulk_import_rejects_non_utf8_source_name_before_read(tmp_path, monkeypatch):
    monkeypatch.setattr(
        proxy_import_module,
        "read_bounded_control_snapshot_result",
        lambda *_args, **_kwargs: pytest.fail("invalid source name reached file read"),
    )

    with pytest.raises(ContractError, match="source name is invalid"):
        import_proxy_file(tmp_path, tmp_path / "\ud800")


def test_bulk_import_failure_receipts_do_not_echo_internal_diagnostics(
    tmp_path, monkeypatch
):
    path = tmp_path / "provider.txt"
    path.write_text(f"{RESIDENTIAL_LINE}\n", encoding="utf-8")
    sensitive = "operator-token@example.invalid:9443"

    def fail_import(*_args, **_kwargs):
        raise ContractError(sensitive)

    monkeypatch.setattr(proxy_import_module, "import_proxy_route", fail_import)
    result = import_proxy_file(tmp_path, path)
    assert result["failed_count"] == 1
    assert result["failed"][0]["failure"].startswith("contract-failure;")
    assert sensitive not in json.dumps(result)


def _realign_observation(workspace, route_id, *, timezone, country):
    route = load_network_route(workspace, route_id)
    return {
        "egress_timezone": timezone,
        "egress_country": country,
        "error": None,
        "realization": {"route_sha256_16": route["integrity_sha256"][:16]},
    }


@pytest.mark.parametrize("target_id", ["CON", "", False])
def test_realign_rejects_invalid_explicit_target_before_observation(
    tmp_path, monkeypatch, target_id,
):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")

    def unexpected_observation(*_args, **_kwargs):
        raise AssertionError("network observation started")

    monkeypatch.setattr(proxy_import_module, "check_route", unexpected_observation)
    with pytest.raises(ContractError, match="realigned route ID is invalid"):
        realign_route(tmp_path, "res-us-1", new_route_id=target_id)
    assert sorted(path.name for path in (tmp_path / "network" / "routes").iterdir()) == [
        "res-us-1.json"
    ]


def test_realign_rejects_nontext_locale_before_observation(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")

    def unexpected_observation(*_args, **_kwargs):
        raise AssertionError("network observation started")

    monkeypatch.setattr(proxy_import_module, "check_route", unexpected_observation)
    with pytest.raises(ContractError, match="realigned route locale is invalid"):
        realign_route(tmp_path, "res-us-1", locale=False)


def test_realigning_a_route_whose_exit_cannot_be_observed_is_refused(tmp_path):
    """Believing a measurement requires having one."""
    import_proxy_route(
        tmp_path,
        f"{RESIDENTIAL_USER}:{RESIDENTIAL_PASSWORD}@127.0.0.1:1",
        route_id="dead-1",
    )
    with pytest.raises(ContractError, match="could not be observed"):
        realign_route(tmp_path, "dead-1", timeout_seconds=1.0)


def test_realigning_writes_a_new_route_and_leaves_the_original_alone(
    tmp_path, monkeypatch
):
    """Routes are immutable by ID, so a correction is a second route."""
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    monkeypatch.setattr(
        proxy_import_module,
        "check_route",
        lambda workspace, route_id, **_kwargs: _realign_observation(
            workspace, route_id, timezone="America/New_York", country="US"
        ),
    )
    result = realign_route(tmp_path, "res-us-1", session_key="alpha")
    assert result["was"]["timezone"] == "America/Chicago"
    assert result["now"]["timezone"] == "America/New_York"
    assert result["credentials_copied"] is True
    assert result["session_key_supplied"] is True
    assert "alpha" not in json.dumps(result)
    original = load_network_route(tmp_path, "res-us-1")
    assert original["geography"]["timezone"] == "America/Chicago", "untouched"
    aligned = load_network_route(tmp_path, "res-us-1-aligned")
    assert aligned["endpoint"] == original["endpoint"]
    assert aligned["auth"]["username_env"].endswith("RES_US_1_ALIGNED_USERNAME")


def test_realigning_rejects_source_route_replaced_after_observation(
    tmp_path, monkeypatch
):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    observed = load_network_route(tmp_path, "res-us-1")
    replacement = build_network_route(
        route_id="res-us-1",
        name="replacement endpoint",
        geography=observed["geography"],
        mode="proxy",
        endpoint={**observed["endpoint"], "host": "replacement.example"},
        auth=observed["auth"],
        policies=observed["policies"],
        preflight_url=observed["preflight_url"],
    )
    source_path = tmp_path / "network" / "routes" / "res-us-1.json"

    def replace_during_check(*_args, **_kwargs):
        source_path.write_bytes(canonical_json_bytes(replacement))
        return {
            "egress_timezone": "America/New_York",
            "egress_country": "US",
            "realization": {
                "route_sha256_16": observed["integrity_sha256"][:16]
            },
        }

    monkeypatch.setattr(proxy_import_module, "check_route", replace_during_check)
    with pytest.raises(ContractError, match="source route changed during observation"):
        realign_route(tmp_path, "res-us-1")
    assert load_network_route(tmp_path, "res-us-1") == replacement
    assert not (tmp_path / "network" / "routes" / "res-us-1-aligned.json").exists()


@pytest.mark.parametrize(
    ("locale", "expected_locale"), [(None, "de-DE"), ("en-GB", "en-GB")]
)
def test_realigning_to_a_new_country_uses_that_countrys_locale(
    tmp_path, monkeypatch, locale, expected_locale
):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    monkeypatch.setattr(
        proxy_import_module,
        "check_route",
        lambda workspace, route_id, **_kwargs: _realign_observation(
            workspace, route_id, timezone="Europe/Berlin", country="DE"
        ),
    )

    result = realign_route(tmp_path, "res-us-1", locale=locale)

    assert result["now"] == {
        "country": "DE",
        "locale": expected_locale,
        "timezone": "Europe/Berlin",
    }
    assert load_network_route(tmp_path, result["route_id"])["geography"] == result["now"]


def test_repeating_a_realign_keeps_the_first_route_receipt(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    monkeypatch.setattr(
        proxy_import_module,
        "check_route",
        lambda workspace, route_id, **_kwargs: _realign_observation(
            workspace, route_id, timezone="America/New_York", country="US"
        ),
    )
    first = realign_route(tmp_path, "res-us-1")
    original = load_network_route(tmp_path, first["route_id"])
    monkeypatch.setattr(network_module, "_utc_now", lambda: "2099-01-01T00:00:00Z")

    repeated = realign_route(tmp_path, "res-us-1")

    assert repeated["route_sha256_16"] == first["route_sha256_16"]
    assert load_network_route(tmp_path, first["route_id"]) == original


def test_the_realigned_route_resolves_the_copied_credential(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    monkeypatch.setattr(
        proxy_import_module,
        "check_route",
        lambda workspace, route_id, **_kwargs: _realign_observation(
            workspace, route_id, timezone="America/New_York", country="US"
        ),
    )
    realign_route(tmp_path, "res-us-1", session_key="alpha")
    resolved = resolve_route_credentials(
        tmp_path, load_network_route(tmp_path, "res-us-1-aligned"), session_key="alpha"
    )
    assert resolved.password == RESIDENTIAL_PASSWORD
    expected = sticky_session_id("alpha", length=10)
    assert resolved.username == f"customer-ACME-cc-us-sessid-{expected}-sesstime-10"


def test_realigning_rolls_back_new_route_when_secret_copy_fails(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    monkeypatch.setattr(
        proxy_import_module,
        "check_route",
        lambda workspace, route_id, **_kwargs: _realign_observation(
            workspace, route_id, timezone="America/New_York", country="US"
        ),
    )
    monkeypatch.setattr(
        proxy_import_module,
        "store_proxy_secret",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ContractError("copy failed")),
    )

    with pytest.raises(ContractError, match="copy failed"):
        realign_route(tmp_path, "res-us-1", session_key="alpha")
    assert not (tmp_path / "network" / "routes" / "res-us-1-aligned.json").exists()
    assert load_network_route(tmp_path, "res-us-1")["id"] == "res-us-1"


def test_realigning_rechecks_route_receipt_after_secret_copy(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    monkeypatch.setattr(
        proxy_import_module,
        "check_route",
        lambda workspace, route_id, **_kwargs: _realign_observation(
            workspace, route_id, timezone="America/New_York", country="US"
        ),
    )
    target_id = "res-us-1-aligned"
    target_path = tmp_path / "network" / "routes" / f"{target_id}.json"
    real_store = proxy_import_module.store_proxy_secret
    replacement = None

    def store_then_replace(workspace, route_id, parsed, **kwargs):
        nonlocal replacement
        result = real_store(workspace, route_id, parsed, **kwargs)
        assert route_id == target_id
        saved = load_network_route(workspace, route_id)
        replacement = build_network_route(
            route_id=route_id,
            name="competitor aligned route",
            geography=saved["geography"],
            mode=saved["mode"],
            endpoint=saved["endpoint"],
            auth=saved["auth"],
            policies=saved["policies"],
            preflight_url=saved["preflight_url"],
        )
        candidate = target_path.with_suffix(".competitor")
        candidate.write_bytes(canonical_json_bytes(replacement))
        os.replace(candidate, target_path)
        return result

    monkeypatch.setattr(proxy_import_module, "store_proxy_secret", store_then_replace)
    with pytest.raises(ContractError, match="network route changed before proxy receipt"):
        realign_route(tmp_path, "res-us-1")
    assert load_network_route(tmp_path, target_id) == replacement
    assert load_proxy_secret(tmp_path, target_id)["secret"] == RESIDENTIAL_PASSWORD


def test_realigning_long_route_ids_keeps_distinct_default_destinations(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        proxy_import_module,
        "check_route",
        lambda workspace, route_id, **_kwargs: _realign_observation(
            workspace, route_id, timezone="America/New_York", country="US"
        ),
    )
    sources = ("r" * 63 + "a", "r" * 63 + "b")
    destinations = []
    for route_id in sources:
        import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id=route_id)
        result = realign_route(tmp_path, route_id)
        destinations.append(result["route_id"])
        assert len(result["route_id"]) <= 64
        assert load_network_route(tmp_path, result["route_id"])["id"] == result["route_id"]
    assert destinations[0] != destinations[1]


def test_realigning_a_long_route_name_preserves_the_observed_zone(
    tmp_path, monkeypatch
):
    import_proxy_route(
        tmp_path, RESIDENTIAL_LINE, route_id="res-us-1", name="N" * 128
    )
    monkeypatch.setattr(
        proxy_import_module,
        "check_route",
        lambda workspace, route_id, **_kwargs: _realign_observation(
            workspace, route_id, timezone="America/New_York", country="US"
        ),
    )
    result = realign_route(tmp_path, "res-us-1")
    name = load_network_route(tmp_path, result["route_id"])["name"]
    assert len(name) <= 128
    assert name.endswith(" @ America/New_York")


def test_checking_an_unreachable_route_reports_failure_without_raising(tmp_path):
    """A dead proxy is an answer, not a crash.

    This is how an operator finds out which of a hundred imported routes are
    still alive; one that raises stops the sweep at the first dead entry.
    """
    import_proxy_route(
        tmp_path,
        f"{RESIDENTIAL_USER}:{RESIDENTIAL_PASSWORD}@127.0.0.1:1",
        route_id="dead-1",
    )
    result = check_route(tmp_path, "dead-1", timeout_seconds=1.0)
    assert result["passed"] is False
    assert result["error"]
    assert RESIDENTIAL_PASSWORD not in json.dumps(result)


def test_proxy_check_rechecks_selected_route_after_preflight(tmp_path, monkeypatch):
    route = build_network_route(
        route_id="local-direct",
        name="Local direct",
        geography={
            "country": "US", "locale": "en-US", "timezone": "America/Chicago"
        },
    )
    add_network_route(tmp_path, route)
    selected = tmp_path / "network" / "routes" / "local-direct.json"
    replacement = build_network_route(
        route_id="local-direct",
        name="Replaced direct",
        geography=route["geography"],
    )

    def replace_during_preflight(*_args, **_kwargs):
        selected.write_bytes(canonical_json_bytes(replacement))
        return {"passed": True}

    monkeypatch.setattr(
        network_module, "preflight_network_route", replace_during_preflight
    )
    with pytest.raises(ContractError, match="network route changed before proxy check"):
        check_route(tmp_path, "local-direct")
    assert load_network_route(tmp_path, "local-direct") == replacement


def test_proxy_check_accepts_unchanged_direct_route(tmp_path, monkeypatch):
    route = build_network_route(
        route_id="local-direct",
        name="Local direct",
        geography={
            "country": "US", "locale": "en-US", "timezone": "America/Chicago"
        },
    )
    add_network_route(tmp_path, route)
    monkeypatch.setattr(
        network_module, "preflight_network_route", lambda *_args, **_kwargs: {"passed": True}
    )
    result = check_route(tmp_path, "local-direct")
    assert result["passed"] is True
    assert result["error"] is None


def test_proxy_check_hides_session_keys_and_exception_text(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    session_key = "private-identity-key"
    diagnostic = "connect failed via secret.gateway.example:9443/account-token"

    def fail_resolution(*_args, **_kwargs):
        raise OSError(diagnostic)

    monkeypatch.setattr(proxy_import_module, "resolve_route_credentials", fail_resolution)
    result = check_route(tmp_path, "res-us-1", session_key=session_key)
    body = json.dumps(result)
    assert result["session_key_supplied"] is True
    assert result["session_pinned"] is False
    assert result["error"].startswith("execution-failure;")
    assert session_key not in body
    assert diagnostic not in body


def test_proxy_check_validates_session_key_before_network_contact(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    contacted = False

    def resolve(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("must not contact")

    monkeypatch.setattr(proxy_import_module, "resolve_route_credentials", resolve)
    with pytest.raises(ContractError, match="session key"):
        check_route(tmp_path, "res-us-1", session_key="bad\nkey")
    assert contacted is False


def test_proxy_check_pinned_receipt_uses_credential_sent_before_secret_appears(
    tmp_path, monkeypatch
):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    route = load_network_route(tmp_path, "res-us-1")
    env_username = "customer-ACME-cc-us-sessid-zzzzzzzzzz-sesstime-10"
    assert env_username != with_session(
        RESIDENTIAL_USER, session_id=sticky_session_id("identity")
    )
    monkeypatch.setenv(route["auth"]["username_env"], env_username)
    monkeypatch.setenv(route["auth"]["password_env"], RESIDENTIAL_PASSWORD)
    original_has_secret = proxy_import_module.has_proxy_secret
    calls = 0

    def appears_after_resolution(*args, **kwargs):
        nonlocal calls
        calls += 1
        return False if calls == 1 else original_has_secret(*args, **kwargs)

    monkeypatch.setattr(proxy_import_module, "has_proxy_secret", appears_after_resolution)
    used = {}

    def fake_preflight(resolved, *_args, **_kwargs):
        used["username"] = resolved.username
        return {"passed": True}

    monkeypatch.setattr(network_module, "preflight_network_route", fake_preflight)
    monkeypatch.setattr(
        gateway_module,
        "serve_gateway",
        lambda *_args, **_kwargs: nullcontext(("127.0.0.1", 8080)),
    )
    monkeypatch.setattr(
        network_module,
        "observe_geo_alignment",
        lambda *_args, **_kwargs: {
            "passed": True,
            "observed": {"country": "US"},
            "egress_timezone": "America/Chicago",
        },
    )

    result = check_route(tmp_path, "res-us-1", session_key="identity")
    assert used["username"] == env_username
    assert result["passed"] is True
    assert result["session_pinned"] is False


def test_proxy_check_pinned_receipt_matches_used_stored_session(tmp_path, monkeypatch):
    import_proxy_route(tmp_path, RESIDENTIAL_LINE, route_id="res-us-1")
    used = {}

    def fake_preflight(resolved, *_args, **_kwargs):
        used["username"] = resolved.username
        return {"passed": True}

    monkeypatch.setattr(network_module, "preflight_network_route", fake_preflight)
    monkeypatch.setattr(
        gateway_module,
        "serve_gateway",
        lambda *_args, **_kwargs: nullcontext(("127.0.0.1", 8080)),
    )
    monkeypatch.setattr(
        network_module,
        "observe_geo_alignment",
        lambda *_args, **_kwargs: {
            "passed": True,
            "observed": {"country": "US"},
            "egress_timezone": "America/Chicago",
        },
    )

    result = check_route(tmp_path, "res-us-1", session_key="identity")
    assert used["username"] == with_session(
        RESIDENTIAL_USER, session_id=sticky_session_id("identity")
    )
    assert result["session_pinned"] is True


@pytest.mark.parametrize("change", ["replace", "appear"])
def test_proxy_check_rechecks_secret_after_preflight(tmp_path, monkeypatch, change):
    import_proxy_route(
        tmp_path,
        RESIDENTIAL_LINE,
        route_id="res-us-1",
        store_credentials=change == "replace",
    )
    route = load_network_route(tmp_path, "res-us-1")
    if change == "appear":
        monkeypatch.setenv(route["auth"]["username_env"], RESIDENTIAL_USER)
        monkeypatch.setenv(route["auth"]["password_env"], RESIDENTIAL_PASSWORD)
    replacement = ParsedProxy(
        protocol="http",
        host="pr.example-proxy.io",
        port=7777,
        username=RESIDENTIAL_USER,
        password="replacement-synthetic-password",
    )

    def change_secret_during_preflight(*_args, **_kwargs):
        store_proxy_secret(
            tmp_path,
            "res-us-1",
            replacement,
            overwrite=change == "replace",
        )
        return {"passed": True}

    monkeypatch.setattr(
        network_module, "preflight_network_route", change_secret_during_preflight
    )
    monkeypatch.setattr(
        gateway_module,
        "serve_gateway",
        lambda *_args, **_kwargs: nullcontext(("127.0.0.1", 8080)),
    )
    monkeypatch.setattr(
        network_module,
        "observe_geo_alignment",
        lambda *_args, **_kwargs: {
            "passed": True,
            "observed": {"country": "US"},
            "egress_timezone": "America/Chicago",
        },
    )

    with pytest.raises(ContractError, match="proxy secret changed before proxy check"):
        check_route(tmp_path, "res-us-1")
    assert load_proxy_secret(tmp_path, "res-us-1")["secret"] == replacement.password
