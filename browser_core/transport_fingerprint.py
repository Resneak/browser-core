"""Bind a bounded local TLS ClientHello fingerprint to the attested build.

The probe listens only on loopback and never completes the TLS handshake. It
records the transport fields visible to an edge while keeping the measurement
independent of a third-party service and external egress address.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .build import _hash_regular_file, load_build_attestation
from .control_files import (
    decode_strict_json_bytes,
    publish_json_exclusive,
    read_bounded_control_snapshot_result,
    require_bounded_control_snapshot_unchanged,
)
from .contracts import RUN_ID_RE, reject_sensitive_keys
from .profiles import has_windows_device_basename
from .errors import ContractError
from .numeric import is_finite_number
from .owned_paths import directory_ancestry_binding, prepare_owned_directory_parent
from .prepared_download import guarded_temporary_directory


TRANSPORT_FINGERPRINT_SCHEMA = "browser-core.transport-fingerprint/1"
TRANSPORT_BASELINE_SCHEMA = "browser-core.transport-baseline/1"
TRANSPORT_FINGERPRINT_COMPARISON_SCHEMA = (
    "browser-core.transport-fingerprint-comparison/1"
)

# RFC 8701 GREASE values. Chrome intentionally varies these values, so they are
# removed from the drift digest.
GREASE_VALUES = frozenset(
    (value << 8) | value
    for value in (
        0x0A,
        0x1A,
        0x2A,
        0x3A,
        0x4A,
        0x5A,
        0x6A,
        0x7A,
        0x8A,
        0x9A,
        0xAA,
        0xBA,
        0xCA,
        0xDA,
        0xEA,
        0xFA,
    )
)

_HANDSHAKE_RECORD = 0x16
_CLIENT_HELLO = 0x01
MAX_TLS_RECORD_BODY_BYTES = 16 * 1024
TRANSPORT_PROCESS_STOP_TIMEOUT_SECONDS = 10.0
MAX_TRANSPORT_VECTOR_ITEMS = 32 * 1024
MAX_TRANSPORT_FINGERPRINT_BYTES = 4 * 1024 * 1024


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ContractError("client hello is truncated")
    return (data[offset] << 8) | data[offset + 1]


def _take(data: bytes, offset: int, size: int, label: str) -> tuple[bytes, int]:
    if size < 0 or offset < 0 or offset + size > len(data):
        raise ContractError(f"client hello {label} is truncated")
    return data[offset : offset + size], offset + size


def _u16_vector(payload: bytes, label: str) -> list[int]:
    if len(payload) < 2:
        raise ContractError(f"client hello {label} vector is truncated")
    listed = _u16(payload, 0)
    if listed % 2 or listed != len(payload) - 2:
        raise ContractError(f"client hello {label} vector length is invalid")
    return [_u16(payload, 2 + index) for index in range(0, listed, 2)]


def _strip_grease(values: list[int]) -> list[int]:
    return [value for value in values if value not in GREASE_VALUES]


def _looks_like_grease_alpn(name: bytes | str) -> bool:
    """GREASE ALPN entries are two equal bytes with a low nibble of 0xa."""
    if len(name) != 2 or name[0] != name[1]:
        return False
    value = name[0] if isinstance(name, bytes) else ord(name[0])
    return value & 0x0F == 0x0A


def _valid_server_name(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        return False
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        return False
    labels = encoded.split(b".")
    return all(
        1 <= len(label) <= 63
        and bytes([label[0]]).isalnum()
        and bytes([label[-1]]).isalnum()
        and all(byte == 0x2D or chr(byte).isalnum() for byte in label)
        for label in labels
    )


def _protocol_name_list(payload: bytes, label: str) -> tuple[list[str], bool]:
    if len(payload) < 2 or _u16(payload, 0) != len(payload) - 2:
        raise ContractError(f"client hello {label} vector length is invalid")
    names: list[str] = []
    grease_present = False
    inner = 2
    while inner < len(payload):
        name_length = payload[inner]
        if name_length == 0:
            raise ContractError(f"client hello {label} name is empty")
        name, inner = _take(payload, inner + 1, name_length, f"{label} name")
        if _looks_like_grease_alpn(name):
            grease_present = True
            continue
        try:
            decoded = name.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            raise ContractError(f"client hello {label} name is not ASCII") from None
        if any(ord(character) < 0x21 or ord(character) > 0x7E for character in decoded):
            raise ContractError(f"client hello {label} name is not printable")
        names.append(decoded)
    return names, grease_present


def parse_client_hello(
    raw: bytes, *, expected_server_name: str | None = None
) -> dict[str, Any]:
    """Strictly parse one complete TLS handshake record containing one hello."""
    if not isinstance(raw, bytes):
        raise ContractError("client hello input must be bytes")
    if expected_server_name is not None and not _valid_server_name(
        expected_server_name
    ):
        raise ContractError("expected TLS server name is invalid")
    if len(raw) < 5 or raw[0] != _HANDSHAKE_RECORD:
        raise ContractError("not a TLS handshake record")
    record_length = _u16(raw, 3)
    if record_length > MAX_TLS_RECORD_BODY_BYTES:
        raise ContractError("TLS handshake record exceeds capture limit")
    if len(raw) != 5 + record_length:
        raise ContractError("TLS handshake record length is inconsistent")
    body = raw[5:]
    if len(body) < 4 or body[0] != _CLIENT_HELLO:
        raise ContractError("handshake record is not a client hello")
    if int.from_bytes(body[1:4], "big") != len(body) - 4:
        raise ContractError("client hello handshake length is inconsistent")
    hello = body[4:]

    cursor = 0
    legacy_bytes, cursor = _take(hello, cursor, 2, "legacy version")
    legacy_version = _u16(legacy_bytes, 0)
    _random, cursor = _take(hello, cursor, 32, "random")

    session_length_bytes, cursor = _take(hello, cursor, 1, "session id length")
    session_id_length = session_length_bytes[0]
    if session_id_length > 32:
        raise ContractError("client hello session id length is invalid")
    _session_id, cursor = _take(hello, cursor, session_id_length, "session id")

    cipher_length_bytes, cursor = _take(hello, cursor, 2, "cipher length")
    cipher_bytes = _u16(cipher_length_bytes, 0)
    if cipher_bytes < 2 or cipher_bytes % 2:
        raise ContractError("client hello cipher vector length is invalid")
    cipher_payload, cursor = _take(hello, cursor, cipher_bytes, "cipher vector")
    ciphers = [_u16(cipher_payload, index) for index in range(0, cipher_bytes, 2)]

    compression_length_bytes, cursor = _take(hello, cursor, 1, "compression length")
    compression_length = compression_length_bytes[0]
    if compression_length < 1:
        raise ContractError("client hello compression vector is empty")
    compression_payload, cursor = _take(
        hello, cursor, compression_length, "compression vector"
    )
    compression_methods = list(compression_payload)
    if len(compression_methods) != len(set(compression_methods)):
        raise ContractError("client hello repeats a compression method")

    extensions: list[int] = []
    groups: list[int] = []
    signature_algorithms: list[int] = []
    alpn: list[str] = []
    supported_versions: list[int] = []
    ec_point_formats: list[int] = []
    key_share_groups: list[int] = []
    certificate_compression_algorithms: list[int] = []
    psk_key_exchange_modes: list[int] = []
    application_settings_protocols: list[str] = []
    server_padding_request: int | None = None
    trust_anchor_identifiers: list[bytes] = []
    status_request_type: int | None = None
    status_responder_id_lengths: list[int] = []
    status_request_extensions_bytes: int | None = None
    session_ticket_bytes: int | None = None
    renegotiation_info_bytes: int | None = None
    server_names: list[str] = []
    grease_alpn_present = False

    if cursor < len(hello):
        extension_length_bytes, cursor = _take(hello, cursor, 2, "extensions length")
        extensions_length = _u16(extension_length_bytes, 0)
        end = cursor + extensions_length
        if end != len(hello):
            raise ContractError("client hello extensions length is inconsistent")
        seen_extensions: set[int] = set()
        while cursor < end:
            header, cursor = _take(hello, cursor, 4, "extension header")
            ext_type = _u16(header, 0)
            ext_length = _u16(header, 2)
            payload, cursor = _take(hello, cursor, ext_length, "extension payload")
            if ext_type in seen_extensions:
                raise ContractError("client hello repeats an extension")
            seen_extensions.add(ext_type)
            extensions.append(ext_type)
            if ext_type == 0:  # server_name
                if len(payload) < 2 or _u16(payload, 0) != len(payload) - 2:
                    raise ContractError("client hello server name list is invalid")
                inner = 2
                seen_name_types: set[int] = set()
                while inner < len(payload):
                    header, inner = _take(payload, inner, 3, "server name header")
                    name_type = header[0]
                    name_length = _u16(header, 1)
                    if name_type in seen_name_types:
                        raise ContractError("client hello repeats a server name type")
                    seen_name_types.add(name_type)
                    if name_length < 1:
                        raise ContractError("client hello server name is empty")
                    name, inner = _take(
                        payload, inner, name_length, "server name value"
                    )
                    if name_type == 0:
                        try:
                            decoded = name.decode("ascii", errors="strict").lower()
                        except UnicodeDecodeError:
                            raise ContractError(
                                "client hello server name is not ASCII"
                            ) from None
                        if not _valid_server_name(decoded):
                            raise ContractError("client hello server name is invalid")
                        server_names.append(decoded)
                if not seen_name_types:
                    raise ContractError("client hello server name list is empty")
            elif ext_type == 5:  # status_request
                if len(payload) < 5:
                    raise ContractError("client hello status request is invalid")
                status_request_type = payload[0]
                inner = 1
                responder_bytes = _u16(payload, inner)
                inner += 2
                responder_end = inner + responder_bytes
                if responder_end > len(payload) - 2:
                    raise ContractError("client hello status responder list is invalid")
                while inner < responder_end:
                    responder_length = _u16(payload, inner)
                    inner += 2
                    if responder_length < 1:
                        raise ContractError("client hello status responder ID is empty")
                    _responder, inner = _take(
                        payload, inner, responder_length, "status responder ID"
                    )
                    if inner > responder_end:
                        raise ContractError(
                            "client hello status responder list is invalid"
                        )
                    status_responder_id_lengths.append(responder_length)
                status_request_extensions_bytes = _u16(payload, inner)
                inner += 2
                _request_extensions, inner = _take(
                    payload,
                    inner,
                    status_request_extensions_bytes,
                    "status request extensions",
                )
                if inner != len(payload):
                    raise ContractError("client hello status request is inconsistent")
            elif ext_type == 10:  # supported_groups
                groups = _u16_vector(payload, "supported groups")
            elif ext_type == 11:  # ec_point_formats
                if not payload or payload[0] != len(payload) - 1:
                    raise ContractError(
                        "client hello EC point formats length is invalid"
                    )
                ec_point_formats = list(payload[1:])
            elif ext_type == 13:  # signature_algorithms
                signature_algorithms = _u16_vector(payload, "signature algorithms")
            elif ext_type == 16:  # ALPN
                alpn, protocol_grease = _protocol_name_list(payload, "ALPN")
                grease_alpn_present |= protocol_grease
            elif ext_type == 18:  # signed_certificate_timestamp
                if payload:
                    raise ContractError(
                        "client hello certificate timestamp extension is not empty"
                    )
            elif ext_type == 23:  # extended_master_secret
                if payload:
                    raise ContractError(
                        "client hello extended master secret extension is not empty"
                    )
            elif ext_type == 27:  # compress_certificate
                if (
                    not payload
                    or payload[0] < 2
                    or payload[0] % 2
                    or payload[0] != len(payload) - 1
                ):
                    raise ContractError(
                        "client hello certificate compression vector is invalid"
                    )
                certificate_compression_algorithms = [
                    _u16(payload, index) for index in range(1, len(payload), 2)
                ]
            elif ext_type == 35:  # session_ticket
                session_ticket_bytes = len(payload)
            elif ext_type == 43:  # supported_versions
                if not payload:
                    raise ContractError("client hello supported versions is empty")
                listed = payload[0]
                if listed % 2 or listed != len(payload) - 1:
                    raise ContractError(
                        "client hello supported versions length is invalid"
                    )
                supported_versions = [
                    _u16(payload, 1 + index) for index in range(0, listed, 2)
                ]
            elif ext_type == 45:  # psk_key_exchange_modes
                if not payload or payload[0] < 1 or payload[0] != len(payload) - 1:
                    raise ContractError(
                        "client hello PSK key exchange modes vector is invalid"
                    )
                psk_key_exchange_modes = list(payload[1:])
            elif ext_type == 51:  # key_share
                if len(payload) < 2 or _u16(payload, 0) != len(payload) - 2:
                    raise ContractError(
                        "client hello key share vector length is invalid"
                    )
                inner = 2
                while inner < len(payload):
                    header, inner = _take(payload, inner, 4, "key share header")
                    group = _u16(header, 0)
                    key_bytes = _u16(header, 2)
                    if key_bytes < 1:
                        raise ContractError("client hello key share is empty")
                    _key, inner = _take(payload, inner, key_bytes, "key share")
                    key_share_groups.append(group)
            elif ext_type in (17513, 17613):  # application_settings (ALPS)
                (
                    application_settings_protocols,
                    protocol_grease,
                ) = _protocol_name_list(payload, "application settings")
                grease_alpn_present |= protocol_grease
            elif ext_type == 4832:  # server_padding
                if len(payload) != 2:
                    raise ContractError(
                        "client hello server padding request is invalid"
                    )
                server_padding_request = _u16(payload, 0)
            elif ext_type == 51764:  # trust_anchors
                if len(payload) < 2 or _u16(payload, 0) != len(payload) - 2:
                    raise ContractError("client hello trust anchor list is invalid")
                inner = 2
                while inner < len(payload):
                    identifier_length = payload[inner]
                    if identifier_length < 1:
                        raise ContractError(
                            "client hello trust anchor identifier is empty"
                        )
                    _identifier, inner = _take(
                        payload,
                        inner + 1,
                        identifier_length,
                        "trust anchor identifier",
                    )
                    trust_anchor_identifiers.append(_identifier)
            elif ext_type == 65281:  # renegotiation_info
                if not payload or payload[0] != len(payload) - 1:
                    raise ContractError(
                        "client hello renegotiation info vector is invalid"
                    )
                renegotiation_info_bytes = payload[0]

    for label, values in (
        ("cipher", ciphers),
        ("supported group", groups),
        ("signature algorithm", signature_algorithms),
        ("supported version", supported_versions),
        ("EC point format", ec_point_formats),
        ("key share group", key_share_groups),
        ("certificate compression algorithm", certificate_compression_algorithms),
        ("PSK key exchange mode", psk_key_exchange_modes),
        ("ALPN name", alpn),
        ("application settings protocol", application_settings_protocols),
    ):
        if len(values) != len(set(values)):
            raise ContractError(f"client hello repeats a {label}")
    if 0 not in compression_methods:
        raise ContractError("client hello omits null compression")
    for extension, values, label in (
        (10, groups, "supported groups"),
        (11, ec_point_formats, "EC point formats"),
        (13, signature_algorithms, "signature algorithms"),
        (16, alpn, "ALPN"),
        (27, certificate_compression_algorithms, "certificate compression"),
        (43, supported_versions, "supported versions"),
        (45, psk_key_exchange_modes, "PSK key exchange modes"),
    ):
        if (extension in extensions) is not bool(values):
            raise ContractError(f"client hello {label} extension is inconsistent")
    if 11 in extensions and 0 not in ec_point_formats:
        raise ContractError("client hello omits uncompressed EC point format")
    if 51 not in extensions and key_share_groups:
        raise ContractError("client hello key share extension is inconsistent")
    if not set(_strip_grease(key_share_groups)) <= set(_strip_grease(groups)):
        raise ContractError("client hello key share group is unsupported")
    application_settings_extensions = {17513, 17613} & set(extensions)
    if len(application_settings_extensions) > 1 or bool(
        application_settings_extensions
    ) is not bool(application_settings_protocols):
        raise ContractError("client hello application settings are inconsistent")
    if not set(application_settings_protocols) <= set(alpn):
        raise ContractError("client hello application settings protocol is unsupported")
    if (4832 in extensions) is not (server_padding_request is not None):
        raise ContractError("client hello server padding request is inconsistent")
    if (5 in extensions) is not (status_request_type is not None):
        raise ContractError("client hello status request is inconsistent")
    if 5 not in extensions and (
        status_responder_id_lengths or status_request_extensions_bytes is not None
    ):
        raise ContractError("client hello status request is inconsistent")
    if (35 in extensions) is not (session_ticket_bytes is not None):
        raise ContractError("client hello session ticket is inconsistent")
    if (65281 in extensions) is not (renegotiation_info_bytes is not None):
        raise ContractError("client hello renegotiation info is inconsistent")
    trust_anchor_identifier_lengths = sorted(map(len, trust_anchor_identifiers))
    trust_anchor_set_sha256 = (
        hashlib.sha256(
            b"".join(
                bytes([len(value)]) + value
                for value in sorted(trust_anchor_identifiers)
            )
        ).hexdigest()
        if 51764 in extensions
        else None
    )
    if expected_server_name is not None and server_names != [
        expected_server_name.lower()
    ]:
        raise ContractError("client hello server name does not match capture target")

    grease_present = grease_alpn_present or any(
        value in GREASE_VALUES
        for values in (
            ciphers,
            extensions,
            groups,
            signature_algorithms,
            supported_versions,
            key_share_groups,
            certificate_compression_algorithms,
        )
        for value in values
    )
    return {
        "schema": TRANSPORT_FINGERPRINT_SCHEMA,
        "legacy_version": legacy_version,
        "ciphers": _strip_grease(ciphers),
        "extensions": _strip_grease(extensions),
        "supported_groups": _strip_grease(groups),
        "compression_methods": compression_methods,
        "ec_point_formats": ec_point_formats,
        "key_share_groups": _strip_grease(key_share_groups),
        "certificate_compression_algorithms": _strip_grease(
            certificate_compression_algorithms
        ),
        "psk_key_exchange_modes": psk_key_exchange_modes,
        "signature_algorithms": _strip_grease(signature_algorithms),
        "supported_versions": _strip_grease(supported_versions),
        "alpn": alpn,
        "application_settings_protocols": application_settings_protocols,
        "server_padding_request": server_padding_request,
        "trust_anchor_identifier_lengths": trust_anchor_identifier_lengths,
        "trust_anchor_set_sha256": trust_anchor_set_sha256,
        "status_request_type": status_request_type,
        "status_responder_id_lengths": status_responder_id_lengths,
        "status_request_extensions_bytes": status_request_extensions_bytes,
        "session_ticket_bytes": session_ticket_bytes,
        "renegotiation_info_bytes": renegotiation_info_bytes,
        "grease_present": grease_present,
    }


def _valid_alpn_name(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        return False
    return 1 <= len(encoded) <= 255 and all(0x21 <= byte <= 0x7E for byte in encoded)


def transport_digest(record: dict[str, Any]) -> str:
    """Return a stable digest, sorting only Chrome's permuted extensions."""
    if not isinstance(record, dict):
        raise ContractError("transport fingerprint must be an object")
    if not (_TRANSPORT_BASE_FIELDS - {"schema"}).issubset(record):
        raise ContractError("transport fingerprint fields are invalid")
    legacy_version = record.get("legacy_version")
    if (
        isinstance(legacy_version, bool)
        or not isinstance(legacy_version, int)
        or not 0 <= legacy_version <= 0xFFFF
    ):
        raise ContractError("transport fingerprint legacy version is invalid")
    integer_fields = {
        "ciphers": 0xFFFF,
        "extensions": 0xFFFF,
        "supported_groups": 0xFFFF,
        "compression_methods": 0xFF,
        "ec_point_formats": 0xFF,
        "key_share_groups": 0xFFFF,
        "certificate_compression_algorithms": 0xFFFF,
        "psk_key_exchange_modes": 0xFF,
        "signature_algorithms": 0xFFFF,
        "supported_versions": 0xFFFF,
    }
    for field, maximum in integer_fields.items():
        values = record.get(field)
        if (
            not isinstance(values, list)
            or len(values) > MAX_TRANSPORT_VECTOR_ITEMS
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= maximum
                for value in values
            )
            or len(values) != len(set(values))
        ):
            raise ContractError(f"transport fingerprint {field} is invalid")
    for field in (
        "ciphers",
        "extensions",
        "supported_groups",
        "key_share_groups",
        "certificate_compression_algorithms",
        "signature_algorithms",
        "supported_versions",
    ):
        if any(value in GREASE_VALUES for value in record[field]):
            raise ContractError(f"transport fingerprint {field} retains GREASE")
    for field in ("alpn", "application_settings_protocols"):
        names = record.get(field)
        if (
            not isinstance(names, list)
            or len(names) > 256
            or any(not _valid_alpn_name(name) for name in names)
            or len(names) != len(set(names))
        ):
            raise ContractError(f"transport fingerprint {field} is invalid")
        if any(_looks_like_grease_alpn(name) for name in names):
            raise ContractError(f"transport fingerprint {field} retains GREASE")
    alpn = record["alpn"]
    grease_present = record.get("grease_present")
    if type(grease_present) is not bool:
        raise ContractError("transport fingerprint GREASE receipt is invalid")
    server_padding_request = record.get("server_padding_request")
    if server_padding_request is not None and (
        isinstance(server_padding_request, bool)
        or not isinstance(server_padding_request, int)
        or not 0 <= server_padding_request <= 0xFFFF
    ):
        raise ContractError("transport fingerprint server padding request is invalid")
    trust_anchor_lengths = record.get("trust_anchor_identifier_lengths")
    if (
        not isinstance(trust_anchor_lengths, list)
        or len(trust_anchor_lengths) > MAX_TRANSPORT_VECTOR_ITEMS
        or any(
            isinstance(length, bool)
            or not isinstance(length, int)
            or not 1 <= length <= 0xFF
            for length in trust_anchor_lengths
        )
    ):
        raise ContractError("transport fingerprint trust anchor list is invalid")
    trust_anchor_set_sha256 = record.get("trust_anchor_set_sha256")
    if trust_anchor_set_sha256 is not None and (
        not isinstance(trust_anchor_set_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", trust_anchor_set_sha256) is None
    ):
        raise ContractError("transport fingerprint trust anchor digest is invalid")
    optional_integer_fields = {
        "status_request_type": 0xFF,
        "status_request_extensions_bytes": MAX_TLS_RECORD_BODY_BYTES,
        "session_ticket_bytes": MAX_TLS_RECORD_BODY_BYTES,
        "renegotiation_info_bytes": 0xFF,
    }
    for field, maximum in optional_integer_fields.items():
        value = record.get(field)
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= maximum
        ):
            raise ContractError(f"transport fingerprint {field} is invalid")
    status_responder_lengths = record.get("status_responder_id_lengths")
    if (
        not isinstance(status_responder_lengths, list)
        or len(status_responder_lengths) > MAX_TRANSPORT_VECTOR_ITEMS
        or any(
            isinstance(length, bool)
            or not isinstance(length, int)
            or not 1 <= length <= MAX_TLS_RECORD_BODY_BYTES
            for length in status_responder_lengths
        )
    ):
        raise ContractError("transport fingerprint status responder list is invalid")
    extensions = record["extensions"]
    if 0 not in record["compression_methods"]:
        raise ContractError("transport fingerprint compression methods are invalid")
    for extension, field in (
        (10, "supported_groups"),
        (11, "ec_point_formats"),
        (13, "signature_algorithms"),
        (16, "alpn"),
        (27, "certificate_compression_algorithms"),
        (43, "supported_versions"),
        (45, "psk_key_exchange_modes"),
    ):
        if (extension in extensions) is not bool(record[field]):
            raise ContractError(f"transport fingerprint {field} is inconsistent")
    if 11 in extensions and 0 not in record["ec_point_formats"]:
        raise ContractError("transport fingerprint EC point formats are invalid")
    if 51 not in extensions and record["key_share_groups"]:
        raise ContractError("transport fingerprint key shares are inconsistent")
    if not set(record["key_share_groups"]) <= set(record["supported_groups"]):
        raise ContractError("transport fingerprint key shares are unsupported")
    application_settings_extensions = {17513, 17613} & set(extensions)
    if len(application_settings_extensions) > 1 or bool(
        application_settings_extensions
    ) is not bool(record["application_settings_protocols"]):
        raise ContractError(
            "transport fingerprint application settings are inconsistent"
        )
    if not set(record["application_settings_protocols"]) <= set(alpn):
        raise ContractError(
            "transport fingerprint application settings protocol is unsupported"
        )
    if (4832 in extensions) is not (server_padding_request is not None):
        raise ContractError(
            "transport fingerprint server padding request is inconsistent"
        )
    if (51764 in extensions) is not (trust_anchor_set_sha256 is not None):
        raise ContractError("transport fingerprint trust anchor digest is inconsistent")
    if 51764 not in extensions and trust_anchor_lengths:
        raise ContractError("transport fingerprint trust anchor list is inconsistent")
    if (5 in extensions) is not (record["status_request_type"] is not None):
        raise ContractError("transport fingerprint status request is inconsistent")
    if 5 not in extensions and (
        status_responder_lengths
        or record["status_request_extensions_bytes"] is not None
    ):
        raise ContractError("transport fingerprint status request is inconsistent")
    if (35 in extensions) is not (record["session_ticket_bytes"] is not None):
        raise ContractError("transport fingerprint session ticket is inconsistent")
    if (65281 in extensions) is not (record["renegotiation_info_bytes"] is not None):
        raise ContractError("transport fingerprint renegotiation info is inconsistent")
    payload = {
        key: record[key]
        for key in (
            "legacy_version",
            "ciphers",
            "supported_groups",
            "compression_methods",
            "ec_point_formats",
            "key_share_groups",
            "certificate_compression_algorithms",
            "psk_key_exchange_modes",
            "signature_algorithms",
            "supported_versions",
            "alpn",
            "application_settings_protocols",
            "server_padding_request",
            "trust_anchor_identifier_lengths",
            "trust_anchor_set_sha256",
            "status_request_type",
            "status_responder_id_lengths",
            "status_request_extensions_bytes",
            "session_ticket_bytes",
            "renegotiation_info_bytes",
        )
    }
    payload["extensions_sorted"] = sorted(record["extensions"])
    payload["grease_present"] = grease_present
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


_TRANSPORT_BASE_FIELDS = {
    "schema",
    "legacy_version",
    "ciphers",
    "extensions",
    "supported_groups",
    "compression_methods",
    "ec_point_formats",
    "key_share_groups",
    "certificate_compression_algorithms",
    "psk_key_exchange_modes",
    "signature_algorithms",
    "supported_versions",
    "alpn",
    "application_settings_protocols",
    "server_padding_request",
    "trust_anchor_identifier_lengths",
    "trust_anchor_set_sha256",
    "status_request_type",
    "status_responder_id_lengths",
    "status_request_extensions_bytes",
    "session_ticket_bytes",
    "renegotiation_info_bytes",
    "grease_present",
}


def validate_transport_fingerprint(
    record: Any, *, require_build: bool = False
) -> dict[str, Any]:
    expected = _TRANSPORT_BASE_FIELDS | {"digest_sha256"}
    if require_build:
        expected = expected | {"core_build"}
    if type(record) is not dict or set(record) != expected:
        raise ContractError("transport fingerprint fields are invalid")
    if record.get("schema") != TRANSPORT_FINGERPRINT_SCHEMA:
        raise ContractError("transport fingerprint schema is invalid")
    if type(record.get("grease_present")) is not bool:
        raise ContractError("transport fingerprint GREASE receipt is invalid")
    digest = transport_digest(record)
    if record["trust_anchor_identifier_lengths"] != sorted(
        record["trust_anchor_identifier_lengths"]
    ):
        raise ContractError("transport fingerprint trust anchor list is invalid")
    if record.get("digest_sha256") != digest:
        raise ContractError("transport fingerprint digest is invalid")
    if require_build:
        build = record.get("core_build")
        if type(build) is not dict or set(build) != {
            "chromium_revision",
            "executable_sha256_16",
            "runtime_bundle_sha256_16",
        }:
            raise ContractError("transport fingerprint build receipt is invalid")
        if (
            not isinstance(build.get("chromium_revision"), str)
            or re.fullmatch(r"[0-9a-f]{40}", build["chromium_revision"]) is None
        ):
            raise ContractError("transport fingerprint build receipt is invalid")
        for field in ("executable_sha256_16", "runtime_bundle_sha256_16"):
            if (
                not isinstance(build.get(field), str)
                or re.fullmatch(r"[0-9a-f]{16}", build[field]) is None
            ):
                raise ContractError("transport fingerprint build receipt is invalid")
    return record


def load_transport_fingerprint(path: Path) -> dict[str, Any]:
    """Load one attested fingerprint through the stable strict-file boundary."""
    if not isinstance(path, Path):
        raise ContractError("transport fingerprint path must be a Path")
    selected = path.absolute()
    snapshot = read_bounded_control_snapshot_result(
        selected,
        maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
        label="transport fingerprint",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"transport fingerprint is {snapshot.state}")
    document = decode_strict_json_bytes(
        snapshot.body,
        label="transport fingerprint",
    )
    validated = validate_transport_fingerprint(document, require_build=True)
    require_bounded_control_snapshot_unchanged(
        selected,
        snapshot,
        maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
        label="transport fingerprint",
        require_single_link=True,
    )
    return validated


def validate_transport_baseline(document: Any) -> dict[str, Any]:
    expected = {
        "schema",
        "source_fingerprint_id",
        "baseline_fingerprint_id",
        "reviewed_digest_sha256",
        "fingerprint",
        "non_claim",
    }
    if type(document) is not dict or set(document) != expected:
        raise ContractError("transport baseline fields are invalid")
    if document.get("schema") != TRANSPORT_BASELINE_SCHEMA:
        raise ContractError("transport baseline schema is invalid")
    source_id = _require_transport_fingerprint_id(
        document.get("source_fingerprint_id"), "source fingerprint"
    )
    baseline_id = _require_transport_fingerprint_id(
        document.get("baseline_fingerprint_id"), "baseline fingerprint"
    )
    if source_id == baseline_id:
        raise ContractError("transport source and baseline ids must differ")
    reviewed_digest = document.get("reviewed_digest_sha256")
    if (
        not isinstance(reviewed_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", reviewed_digest) is None
    ):
        raise ContractError("transport baseline reviewed digest is invalid")
    fingerprint = validate_transport_fingerprint(
        document.get("fingerprint"), require_build=True
    )
    if fingerprint["digest_sha256"] != reviewed_digest:
        raise ContractError("transport baseline reviewed digest does not match")
    if document.get("non_claim") != (
        "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
        "or remote edge acceptance"
    ):
        raise ContractError("transport baseline non-claim is invalid")
    reject_sensitive_keys(document)
    return document


def load_transport_baseline(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path):
        raise ContractError("transport baseline path must be a Path")
    selected = path.absolute()
    snapshot = read_bounded_control_snapshot_result(
        selected,
        maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
        label="transport baseline",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"transport baseline is {snapshot.state}")
    document = decode_strict_json_bytes(snapshot.body, label="transport baseline")
    validated = validate_transport_baseline(document)
    require_bounded_control_snapshot_unchanged(
        selected,
        snapshot,
        maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
        label="transport baseline",
        require_single_link=True,
    )
    return validated


def install_transport_baseline(
    workspace: Path,
    baseline: Any,
) -> dict[str, Any]:
    """Install one already-approved wrapper without accepting an output path."""
    if not isinstance(workspace, Path):
        raise ContractError("transport baseline workspace must be a Path")
    baseline = validate_transport_baseline(baseline)
    registry = workspace.absolute() / "transport-fingerprints"
    prepare_owned_directory_parent(registry, label="transport baseline registry")
    registry_ancestry = directory_ancestry_binding(
        registry,
        label="transport baseline registry",
    )
    destination = registry / (
        f"{baseline['baseline_fingerprint_id']}.baseline.json"
    )
    if destination.exists() or destination.is_symlink():
        raise ContractError("transport baseline id already exists")
    publish_json_exclusive(
        destination,
        baseline,
        maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
        label="transport baseline",
    )
    published_baseline = load_transport_baseline(destination)
    registry_after_publication = directory_ancestry_binding(
        registry,
        label="transport baseline registry",
    )
    if (
        published_baseline != baseline
        or registry_after_publication != registry_ancestry
    ):
        raise ContractError("transport baseline changed after publication")
    return baseline


def _require_transport_fingerprint_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or RUN_ID_RE.fullmatch(value) is None
        or has_windows_device_basename(value)
    ):
        raise ContractError(f"transport {label} id is invalid")
    return value


def approve_transport_baseline(
    workspace: Path,
    *,
    current_id: str,
    baseline_id: str,
    expected_digest: str,
) -> dict[str, Any]:
    """Publish an immutable baseline only after explicit full-digest review."""
    if not isinstance(workspace, Path):
        raise ContractError("transport baseline workspace must be a Path")
    current_id = _require_transport_fingerprint_id(current_id, "source fingerprint")
    baseline_id = _require_transport_fingerprint_id(
        baseline_id, "baseline fingerprint"
    )
    if current_id == baseline_id:
        raise ContractError("transport source and baseline ids must differ")
    if (
        not isinstance(expected_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
    ):
        raise ContractError("transport reviewed digest is invalid")
    registry = workspace.absolute() / "transport-fingerprints"
    registry_ancestry = directory_ancestry_binding(
        registry,
        label="transport baseline registry",
    )
    source = registry / f"{current_id}.json"
    destination = registry / f"{baseline_id}.baseline.json"
    if source.is_symlink() or not source.is_file():
        raise ContractError("transport baseline source is unknown")
    if destination.exists() or destination.is_symlink():
        raise ContractError("transport baseline id already exists")
    record = load_transport_fingerprint(source)
    if record["digest_sha256"] != expected_digest:
        raise ContractError("transport baseline does not match reviewed digest")
    if (
        directory_ancestry_binding(registry, label="transport baseline registry")
        != registry_ancestry
    ):
        raise ContractError("transport baseline registry authority changed")
    baseline = {
        "schema": TRANSPORT_BASELINE_SCHEMA,
        "source_fingerprint_id": current_id,
        "baseline_fingerprint_id": baseline_id,
        "reviewed_digest_sha256": record["digest_sha256"],
        "fingerprint": record,
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }
    validate_transport_baseline(baseline)
    source_before_publication = load_transport_fingerprint(source)
    registry_before_publication = directory_ancestry_binding(
        registry,
        label="transport baseline registry",
    )
    if source_before_publication != record or registry_before_publication != registry_ancestry:
        raise ContractError("transport baseline source changed before publication")
    publish_json_exclusive(
        destination,
        baseline,
        maximum=MAX_TRANSPORT_FINGERPRINT_BYTES,
        label="transport baseline",
    )
    published_baseline = load_transport_baseline(destination)
    source_after_publication = load_transport_fingerprint(source)
    registry_after_publication = directory_ancestry_binding(
        registry,
        label="transport baseline registry",
    )
    if (
        registry_after_publication != registry_ancestry
        or published_baseline != baseline
        or source_after_publication != record
    ):
        raise ContractError("transport baseline source or publication changed")
    receipt = {
        "schema": "browser-core.transport-baseline-approval/1",
        "source_fingerprint_id": current_id,
        "baseline_fingerprint_id": baseline_id,
        "digest_sha256": record["digest_sha256"],
        "core_build": dict(record["core_build"]),
        "non_claim": (
            "Operator-approved local TLS ClientHello baseline only; not H2/H3 "
            "or remote edge acceptance"
        ),
    }
    reject_sensitive_keys(receipt)
    return receipt


def compare_transport_fingerprints(
    current: Any,
    baseline: Any,
) -> dict[str, Any]:
    """Compare two attested, normalized local ClientHello receipts."""
    current = validate_transport_fingerprint(current, require_build=True)
    baseline = validate_transport_fingerprint(baseline, require_build=True)
    compared_fields = _TRANSPORT_BASE_FIELDS - {"schema"}
    changed_fields = []
    for field in compared_fields:
        current_value = sorted(current[field]) if field == "extensions" else current[field]
        baseline_value = (
            sorted(baseline[field]) if field == "extensions" else baseline[field]
        )
        if current_value != baseline_value:
            changed_fields.append(field)
    changed_fields.sort()
    same_digest = current["digest_sha256"] == baseline["digest_sha256"]
    return {
        "schema": TRANSPORT_FINGERPRINT_COMPARISON_SCHEMA,
        "passed": same_digest and not changed_fields,
        "same_digest": same_digest,
        "changed_fields": changed_fields,
        "current_digest_sha256": current["digest_sha256"],
        "baseline_digest_sha256": baseline["digest_sha256"],
        "current_core_build": dict(current["core_build"]),
        "baseline_core_build": dict(baseline["core_build"]),
        "non_claim": (
            "Normalized local TLS ClientHello equality only; not H2/H3 parity "
            "or remote edge acceptance"
        ),
    }


def _remaining_capture_timeout(
    deadline: float,
    clock: Callable[[], float],
) -> float:
    if not is_finite_number(deadline) or not callable(clock):
        raise ContractError("transport capture deadline is invalid")
    try:
        now = clock()
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ContractError("transport capture clock failed") from None
    if not is_finite_number(now):
        raise ContractError("transport capture clock is invalid")
    remaining = float(deadline) - float(now)
    if remaining <= 0:
        raise ContractError("transport capture deadline expired")
    return remaining


def _apply_capture_deadline(
    connection: Any,
    deadline: float | None,
    clock: Callable[[], float],
) -> None:
    if deadline is None:
        return
    remaining = _remaining_capture_timeout(deadline, clock)
    try:
        connection.settimeout(remaining)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ContractError("transport timeout update failed") from None


def _read_tls_record(
    connection: socket.socket,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> bytes:
    def receive_exact(size: int) -> bytes:
        body = bytearray()
        while len(body) < size:
            remaining = size - len(body)
            requested = min(4096, remaining)
            _apply_capture_deadline(connection, deadline, clock)
            chunk = connection.recv(requested)
            if deadline is not None:
                _remaining_capture_timeout(deadline, clock)
            if type(chunk) is not bytes or len(chunk) > requested:
                raise ContractError(
                    "TLS record transport returned an invalid byte chunk"
                )
            if not chunk:
                raise ContractError("TLS peer closed before its record was complete")
            body.extend(chunk)
        return bytes(body)

    header = receive_exact(5)
    record_length = _u16(header, 3)
    if record_length > MAX_TLS_RECORD_BODY_BYTES:
        raise ContractError("TLS handshake record exceeds capture limit")
    return header + receive_exact(record_length)


def _stop_process(process: subprocess.Popen[Any]) -> None:
    try:
        process.terminate()
    except OSError:
        pass
    try:
        returncode = process.wait(timeout=TRANSPORT_PROCESS_STOP_TIMEOUT_SECONDS)
        if isinstance(returncode, bool) or not isinstance(returncode, int):
            raise ContractError("transport browser status is invalid")
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        raise ContractError("transport browser did not stop") from None
    try:
        returncode = process.wait(timeout=TRANSPORT_PROCESS_STOP_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        raise ContractError("transport browser did not stop") from None
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise ContractError("transport browser status is invalid")


def capture_client_hello(
    executable: Path,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    """Launch a browser against a local listener and capture one exact record."""
    if not isinstance(executable, Path):
        raise ContractError("browser executable must be a Path")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ContractError("transport capture timeout is invalid")
    path = executable.absolute()
    executable_before = _hash_regular_file(
        path,
        label="transport browser executable",
    )
    if executable_before[1] <= 0:
        raise ContractError("transport browser executable is empty")
    try:
        capture_nonce = secrets.token_hex(16)
    except (OSError, RuntimeError):
        raise ContractError("transport capture nonce generation failed") from None
    if re.fullmatch(r"[0-9a-f]{32}", capture_nonce) is None:
        raise ContractError("transport capture nonce is invalid")
    capture_hostname = f"bc-{capture_nonce}.invalid"
    deadline = time.monotonic() + float(timeout_seconds)
    captured: dict[str, bytes] = {}
    capture_failure: list[str] = []
    worker_cleanup_failures: list[str] = []

    try:
        with guarded_temporary_directory(
            tempfile.TemporaryDirectory(prefix="bc-tls-"),
            label="transport capture profile directory",
        ) as profile:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            process: subprocess.Popen[Any] | None = None
            thread: threading.Thread | None = None
            thread_started = False

            def accept_one() -> None:
                try:
                    _apply_capture_deadline(listener, deadline, time.monotonic)
                    connection, _peer = listener.accept()
                except (OSError, RuntimeError, TypeError, ValueError):
                    capture_failure.append("TLS listener accept failed")
                    return
                try:
                    captured["raw"] = _read_tls_record(
                        connection,
                        deadline=deadline,
                        clock=time.monotonic,
                    )
                except (OSError, ContractError, RuntimeError, TypeError, ValueError):
                    capture_failure.append("TLS record capture failed")
                finally:
                    try:
                        connection.close()
                    except (OSError, RuntimeError):
                        worker_cleanup_failures.append("connection-close")

            try:
                try:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    address = listener.getsockname()
                    if (
                        not isinstance(address, tuple)
                        or len(address) != 2
                        or address[0] != "127.0.0.1"
                        or isinstance(address[1], bool)
                        or not isinstance(address[1], int)
                        or not 1 <= address[1] <= 65535
                    ):
                        raise ContractError(
                            "transport capture listener address is invalid"
                        )
                    port = address[1]
                    thread = threading.Thread(
                        target=accept_one,
                        name="browser-core-tls-capture",
                        daemon=True,
                    )
                except ContractError:
                    raise
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    raise ContractError(
                        f"transport capture setup failed ({type(exc).__name__})"
                    ) from None
                try:
                    thread.start()
                except (OSError, RuntimeError) as exc:
                    raise ContractError(
                        f"transport capture worker could not start ({type(exc).__name__})"
                    ) from None
                thread_started = True
                try:
                    process = subprocess.Popen(
                        [
                            str(path),
                            "--headless=new",
                            "--no-sandbox",
                            "--disable-gpu",
                            f"--user-data-dir={profile}",
                            "--host-resolver-rules="
                            f"MAP {capture_hostname} 127.0.0.1, MAP * ^NOTFOUND",
                            f"https://{capture_hostname}:{port}/",
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    raise ContractError(
                        f"transport browser start failed ({type(exc).__name__})"
                    ) from None
                try:
                    thread.join(_remaining_capture_timeout(deadline, time.monotonic))
                except RuntimeError:
                    raise ContractError(
                        "transport capture worker join failed"
                    ) from None
            finally:
                cleanup_failures: list[str] = []
                try:
                    listener.close()
                except (OSError, RuntimeError):
                    cleanup_failures.append("listener-close")
                if process is not None:
                    try:
                        _stop_process(process)
                    except ContractError:
                        cleanup_failures.append("browser-stop")
                if thread is not None and (
                    thread_started or getattr(thread, "ident", None) is not None
                ):
                    try:
                        thread.join(timeout=5.0)
                        alive = thread.is_alive()
                        if type(alive) is not bool or alive:
                            cleanup_failures.append("worker-join")
                    except RuntimeError:
                        cleanup_failures.append("worker-join")
                cleanup_failures.extend(worker_cleanup_failures)
                if cleanup_failures:
                    phases = ",".join(dict.fromkeys(cleanup_failures))
                    cleanup_error = ContractError(
                        f"transport capture cleanup failed ({phases})"
                    )
                    active_error = sys.exc_info()[1]
                    if active_error is not None:
                        raise cleanup_error from active_error
                    raise cleanup_error from None
    except ContractError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ContractError(
            f"transport capture lifecycle failed ({type(exc).__name__})"
        ) from None

    raw = captured.get("raw")
    if not raw:
        reason = (
            capture_failure[0] if capture_failure else "transport capture timed out"
        )
        raise ContractError(reason)
    if (
        _hash_regular_file(path, label="transport browser executable")
        != executable_before
    ):
        raise ContractError("browser executable changed during transport capture")
    record = parse_client_hello(raw, expected_server_name=capture_hostname)
    record["digest_sha256"] = transport_digest(record)
    return validate_transport_fingerprint(record)


def capture_attested_client_hello(
    root: Path,
    executable: Path,
    *,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    """Capture one hello and bind it to one verified Browser Core runtime."""
    if not isinstance(root, Path) or not isinstance(executable, Path):
        raise ContractError("attested transport root and executable must be Paths")
    attestation = load_build_attestation(root, executable)
    record = capture_client_hello(executable, timeout_seconds=timeout_seconds)
    validate_transport_fingerprint(record)
    if load_build_attestation(root, executable) != attestation:
        raise ContractError(
            "Browser Core build attestation changed during transport capture"
        )
    record["core_build"] = {
        "chromium_revision": attestation["chromium_revision"],
        "executable_sha256_16": attestation["executable_sha256"][:16],
        "runtime_bundle_sha256_16": attestation["runtime_bundle_sha256"][:16],
    }
    return validate_transport_fingerprint(record, require_build=True)
