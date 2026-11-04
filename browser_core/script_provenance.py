"""What is actually known about where a captured script came from.

Why this module exists
----------------------
`observe product-script --label fedex-358eec4b` lets the operator assert a site
in a free-text label. That label is copied into every downstream artifact --
subtraction, baseline, digest -- and from there into prose. Nothing ever checks
it, and nothing marks it as an assertion rather than a measurement.

Measured 2026-08-06 against this monorepo's capture tree: **71 of 87** collector
scripts sitting in `captures/<name>/scripts/` appear in no capture manifest at
all, and scripts routinely sit in directories belonging to a capture that did not
fetch them -- `5323ff0ae7525aab` is served from a `www.homedepot.com` URL and is
physically present in two *FedEx* capture directories. Of eight site attributions
carried by two knowledge notes, **two** were manifest-backed and six rested on
directory naming.

So: directory layout is not provenance, and a label is not evidence. This module
answers the narrower question that *is* answerable -- "which origin does a
manifest actually record for these bytes?" -- and says UNVERIFIED when the honest
answer is that nothing does.

The pin is different in kind from the label. A script's SHA-256 is recomputed
from the bytes on every run and cannot be wrong; the label is whatever someone
typed. Wherever both appear, prefer the pin.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .contracts import ContractError
from .control_files import decode_strict_json_bytes, read_bounded_control_snapshot_result
from .errors import normalize_renderer_failures
from .owned_paths import DirectoryIdentity, directory_identity

PROVENANCE_SCHEMA = "browser-core.script-provenance/1"

# Fields a capture manifest may use for the fetched URL and content digest.
# Listed explicitly rather than guessed at, so an unrecognised manifest shape
# reports as unreadable instead of silently yielding zero hits.
_URL_KEYS = ("url", "src", "request_url")
_DIGEST_KEYS = ("sha256", "hash", "digest")

MAX_CAPTURE_DIRECTORIES = 10_000
MAX_CAPTURE_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CAPTURE_MANIFEST_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_MANIFEST_ENTRIES = 100_000
MAX_CAPTURE_SCRIPT_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_SCRIPT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_CAPTURE_SCRIPT_FILES = 100_000

_UNVERIFIED_RATIONALE = (
    "no capture manifest records these bytes. Any site attribution rests "
    "on directory naming, which is not provenance: scripts in this tree "
    "sit in directories belonging to captures that did not fetch them"
)
_PROVENANCE_NON_CLAIMS = [
    "VERIFIED means a manifest recorded this fetch, not that the origin is "
    "the site under study",
    "a label supplied by an operator is never evidence of origin",
]


def _bounded_text(value: Any, *, maximum: int, non_empty: bool = True) -> bool:
    if not isinstance(value, str) or (non_empty and not value):
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    # Report labels are printed as plain text. Unicode format controls and
    # line separators can visually insert or disguise a second verdict line.
    return len(encoded) <= maximum and not any(
        unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}
        for char in value
    )


def _read_regular_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=maximum,
        label=label,
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None:
        raise ContractError(f"{label} is {snapshot.state}")
    return snapshot.body


def _resolved_capture_root(root: Path) -> Path:
    try:
        return root.resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        raise ContractError("captures root path is invalid") from exc


def _capture_directories(root: Path) -> tuple[DirectoryIdentity, tuple[Path, ...]]:
    identity = directory_identity(root, label="capture provenance root")
    if identity is None:
        raise ContractError("capture provenance root is missing")
    try:
        with os.scandir(root) as entries:
            paths = []
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if (
                    not _bounded_text(entry.name, maximum=1_024)
                ):
                    raise ContractError("capture provenance directory name is invalid")
                paths.append(root / entry.name)
                if len(paths) > MAX_CAPTURE_DIRECTORIES:
                    raise ContractError("capture provenance directory inventory exceeds limit")
    except OSError:
        raise ContractError("capture provenance root scan failed") from None
    return identity, tuple(sorted(paths, key=lambda path: path.name))


def _capture_script_names(scripts: Path) -> tuple[str, ...]:
    names: list[str] = []
    try:
        with os.scandir(scripts) as entries:
            for entry in entries:
                if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(".js"):
                    continue
                if not _bounded_text(entry.name, maximum=1_024):
                    raise ContractError("capture script filename is invalid")
                names.append(entry.name)
                if len(names) > MAX_CAPTURE_SCRIPT_FILES:
                    raise ContractError("capture script inventory exceeds file limit")
    except ContractError:
        raise
    except OSError:
        raise ContractError("capture scripts directory scan failed") from None
    return tuple(sorted(names))


def _manifest_digest(entry: dict[str, Any]) -> str | None:
    provided = [entry[key] for key in _DIGEST_KEYS if key in entry]
    if not provided or any(
        not isinstance(value, str)
        or re.fullmatch(r"[0-9A-Fa-f]{64}", value) is None
        for value in provided
    ):
        return None
    values = {value.lower() for value in provided}
    return next(iter(values)) if len(values) == 1 else None


def _manifest_url(entry: dict[str, Any]) -> tuple[str, str] | None:
    provided = [entry[key] for key in _URL_KEYS if key in entry]
    if not provided or any(
        not _bounded_text(value, maximum=16_384) for value in provided
    ):
        return None
    values = set(provided)
    if len(values) != 1:
        return None
    url = next(iter(values))
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (UnicodeError, ValueError):
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "#" in url
        or any(char.isspace() or char in "\\%" for char in parsed.netloc)
        or any(ord(char) < 32 or ord(char) == 127 for char in url)
    ):
        return None
    hostname = parsed.hostname.lower()
    if ":" in hostname:
        try:
            hostname = str(ipaddress.IPv6Address(hostname))
        except ValueError:
            return None
    else:
        try:
            unicode_hostname = hostname
            hostname = hostname.encode("idna").decode("ascii").lower()
            if (
                not unicode_hostname.isascii()
                and hostname.encode("ascii").decode("idna") != unicode_hostname
            ):
                return None
        except UnicodeError:
            return None
        if len(hostname) > 253 or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
            for label in hostname.rstrip(".").split(".")
        ):
            return None
        # Special-scheme browser URLs interpret hosts ending in a number as
        # IPv4. Accept only the unambiguous four-part decimal spelling here.
        last_label = hostname.rstrip(".").split(".")[-1]
        if re.fullmatch(r"[0-9]+|0x[0-9a-f]*", last_label):
            try:
                if str(ipaddress.IPv4Address(hostname)) != hostname:
                    return None
            except ValueError:
                return None
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        host += f":{port}"
    return url, host


def script_pin(payload: bytes) -> str:
    """The 16-hex-char content pin used throughout this package."""
    if type(payload) is not bytes:
        raise ContractError("script payload must be bytes")
    return hashlib.sha256(payload).hexdigest()[:16]


def _iter_manifest_entries(
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], ...] | None:
    hits = manifest.get("script_hits")
    if hits is None:
        return None
    if not isinstance(hits, list) or len(hits) > MAX_CAPTURE_MANIFEST_ENTRIES:
        raise ContractError("capture manifest script_hits is invalid or exceeds limit")
    if any(not isinstance(hit, dict) for hit in hits):
        raise ContractError("capture manifest script_hits entries must be objects")
    return tuple(hits)


def index_capture_manifests(captures_root: Path) -> dict[str, Any]:
    """Build pin -> recorded-origin index from every capture manifest under a root.

    Reports how many capture directories carry no manifest, because that number
    is the real measure of how much of a capture tree is unattributable. A tree
    where most captures have no manifest cannot support origin claims about most
    of its scripts, and an index that silently omitted them would hide that.
    """
    if not isinstance(captures_root, Path):
        raise ContractError("captures root must be a Path")
    captures_root = _resolved_capture_root(captures_root)
    root_identity, capture_directories = _capture_directories(captures_root)

    index: dict[str, dict[str, Any]] = {}
    with_manifest = 0
    without_manifest: list[str] = []
    manifest_snapshots: list[
        tuple[Path, bytes, tuple[int, int, int, int, int, int]]
    ] = []
    missing_manifests: list[Path] = []
    capture_directory_states: list[tuple[Path, DirectoryIdentity]] = []
    manifest_total = 0
    entry_total = 0

    for capture_dir in capture_directories:
        capture_identity = directory_identity(
            capture_dir,
            label="capture provenance directory",
        )
        if capture_identity is None:
            raise ContractError("capture provenance directory disappeared during scan")
        capture_directory_states.append((capture_dir, capture_identity))
        manifest_path = capture_dir / "capture-summary.json"
        snapshot = read_bounded_control_snapshot_result(
            manifest_path,
            maximum=MAX_CAPTURE_MANIFEST_BYTES,
            label="capture provenance manifest",
            require_single_link=True,
        )
        if snapshot.state == "missing":
            without_manifest.append(capture_dir.name)
            missing_manifests.append(manifest_path)
            continue
        if snapshot.state != "complete" or snapshot.body is None:
            raise ContractError(f"capture provenance manifest is {snapshot.state}")
        manifest_total += len(snapshot.body)
        if manifest_total > MAX_CAPTURE_MANIFEST_TOTAL_BYTES:
            raise ContractError("capture provenance manifests exceed aggregate byte limit")
        assert snapshot.identity is not None
        manifest_snapshots.append((manifest_path, snapshot.body, snapshot.identity))
        try:
            manifest = decode_strict_json_bytes(
                snapshot.body,
                label="capture provenance manifest",
            )
        except ContractError:
            without_manifest.append(f"{capture_dir.name} (unreadable)")
            continue
        if not isinstance(manifest, dict):
            without_manifest.append(f"{capture_dir.name} (unreadable)")
            continue
        site = manifest.get("site")
        if site is not None and (
            not _bounded_text(site, maximum=1_024)
        ):
            site = None
        entries = _iter_manifest_entries(manifest)
        if entries is None:
            without_manifest.append(f"{capture_dir.name} (unreadable)")
            continue
        with_manifest += 1
        entry_total += len(entries)
        if entry_total > MAX_CAPTURE_MANIFEST_ENTRIES:
            raise ContractError("capture provenance entries exceed aggregate limit")
        for entry in entries:
            digest = _manifest_digest(entry)
            url_record = _manifest_url(entry)
            if digest is None or url_record is None:
                continue
            url, host = url_record
            record = index.setdefault(
                digest,
                {"hosts": set(), "sites": set(), "captures": set(), "urls": set()},
            )
            record["hosts"].add(host)
            if site:
                record["sites"].add(site)
            record["captures"].add(capture_dir.name)
            record["urls"].add(url)

    end_identity, end_directories = _capture_directories(captures_root)
    if end_identity != root_identity or end_directories != capture_directories:
        raise ContractError("capture provenance directory inventory changed during scan")
    for capture_dir, expected_identity in capture_directory_states:
        if directory_identity(
            capture_dir,
            label="capture provenance directory",
        ) != expected_identity:
            raise ContractError("capture provenance directory changed during scan")
    for manifest_path in missing_manifests:
        if read_bounded_control_snapshot_result(
            manifest_path,
            maximum=MAX_CAPTURE_MANIFEST_BYTES,
            label="capture provenance manifest",
            require_single_link=True,
        ).state != "missing":
            raise ContractError("capture provenance manifest inventory changed during scan")
    for manifest_path, expected_body, expected_identity in manifest_snapshots:
        if _read_regular_bytes(
            manifest_path,
            maximum=MAX_CAPTURE_MANIFEST_BYTES,
            label="capture provenance manifest",
        ) != expected_body:
            raise ContractError("capture provenance manifest changed during scan")
        final_snapshot = read_bounded_control_snapshot_result(
            manifest_path,
            maximum=MAX_CAPTURE_MANIFEST_BYTES,
            label="capture provenance manifest",
            require_single_link=True,
        )
        if (
            final_snapshot.state != "complete"
            or final_snapshot.body != expected_body
            or final_snapshot.identity != expected_identity
        ):
            raise ContractError("capture provenance manifest changed during scan")

    return {
        "index": index,
        "captures_with_manifest": with_manifest,
        "captures_without_manifest": without_manifest,
    }


def describe_provenance(
    script: Path,
    captures_root: Path,
    *,
    asserted_label: str | None = None,
    payload: bytes | None = None,
) -> dict[str, Any]:
    """Say what is verifiable about one script's origin, and what is not.

    ``asserted_label`` is echoed back and explicitly marked unverified rather than
    dropped. Silently discarding it would be its own dishonesty: the label is
    usually the only thing a downstream reader ever sees.
    """
    if not isinstance(script, Path) or not isinstance(captures_root, Path):
        raise ContractError("script provenance paths must be Paths")
    if not _bounded_text(script.name, maximum=1_024):
        raise ContractError("provenance script label is invalid")
    if asserted_label is not None and (
        not _bounded_text(asserted_label, maximum=4_096, non_empty=False)
    ):
        raise ContractError("asserted provenance label is invalid")
    path_read = payload is None
    if payload is None:
        payload = _read_regular_bytes(
            script,
            maximum=MAX_CAPTURE_SCRIPT_BYTES,
            label="provenance script",
        )
    elif type(payload) is not bytes or len(payload) > MAX_CAPTURE_SCRIPT_BYTES:
        raise ContractError("provenance script payload is invalid or exceeds limit")
    pin = script_pin(payload)
    digest = hashlib.sha256(payload).hexdigest()

    built = index_capture_manifests(captures_root)
    record = built["index"].get(digest)

    # Where the bytes physically sit, which is suggestive and nothing more.
    root = _resolved_capture_root(captures_root)
    root_identity, capture_directories = _capture_directories(root)
    candidates: list[Path] = []
    script_directory_states: list[tuple[Path, DirectoryIdentity, tuple[str, ...]]] = []
    missing_scripts: list[Path] = []
    for capture_dir in capture_directories:
        scripts = capture_dir / "scripts"
        scripts_identity = directory_identity(scripts, label="capture scripts directory")
        if scripts_identity is None:
            missing_scripts.append(scripts)
            continue
        names = _capture_script_names(scripts)
        if len(candidates) + len(names) > MAX_CAPTURE_SCRIPT_FILES:
            raise ContractError("capture script inventory exceeds file limit")
        script_directory_states.append((scripts, scripts_identity, names))
        candidates.extend(scripts / name for name in names)

    sits_in_set: set[str] = set()
    script_total = 0
    candidate_digests: list[tuple[Path, str]] = []
    for candidate in candidates:
        candidate_body = _read_regular_bytes(
            candidate,
            maximum=MAX_CAPTURE_SCRIPT_BYTES,
            label="capture script candidate",
        )
        script_total += len(candidate_body)
        if script_total > MAX_CAPTURE_SCRIPT_TOTAL_BYTES:
            raise ContractError("capture scripts exceed aggregate byte limit")
        candidate_digest = hashlib.sha256(candidate_body).hexdigest()
        candidate_digests.append((candidate, candidate_digest))
        if candidate_digest == digest:
            sits_in_set.add(candidate.parent.parent.name)

    end_identity, end_directories = _capture_directories(root)
    if end_identity != root_identity or end_directories != capture_directories:
        raise ContractError("capture script inventory changed during scan")
    for scripts in missing_scripts:
        if directory_identity(scripts, label="capture scripts directory") is not None:
            raise ContractError("capture script inventory changed during scan")
    for scripts, scripts_identity, names in script_directory_states:
        if directory_identity(scripts, label="capture scripts directory") != scripts_identity:
            raise ContractError("capture scripts directory changed during scan")
        end_names = _capture_script_names(scripts)
        if end_names != names:
            raise ContractError("capture script inventory changed during scan")
    for candidate, expected_digest in candidate_digests:
        if hashlib.sha256(
            _read_regular_bytes(
                candidate,
                maximum=MAX_CAPTURE_SCRIPT_BYTES,
                label="capture script candidate",
            )
        ).hexdigest() != expected_digest:
            raise ContractError("capture script candidate changed during scan")
    if index_capture_manifests(root) != built:
        raise ContractError("capture provenance manifest index changed during scan")
    if path_read and _read_regular_bytes(
        script,
        maximum=MAX_CAPTURE_SCRIPT_BYTES,
        label="provenance script",
    ) != payload:
        raise ContractError("provenance script changed during scan")
    sits_in = sorted(sits_in_set)

    if record:
        verdict = "VERIFIED"
        hosts = sorted(record["hosts"])
        rationale = (
            f"a capture manifest records these exact bytes fetched from "
            f"{', '.join(hosts)}"
        )
    else:
        verdict = "UNVERIFIED"
        hosts = []
        rationale = _UNVERIFIED_RATIONALE

    result: dict[str, Any] = {
        "schema": PROVENANCE_SCHEMA,
        "script": script.name,
        "script_sha256_16": pin,
        "bytes": len(payload),
        "verdict": verdict,
        "rationale": rationale,
        "recorded_hosts": hosts,
        "recorded_sites": sorted(record["sites"]) if record else [],
        "recorded_in_captures": sorted(record["captures"]) if record else [],
        "sits_in_directories": sits_in,
        "directory_disagrees_with_manifest": bool(
            record and sits_in and not set(sits_in) <= set(record["captures"])
        ),
        "asserted_label": asserted_label,
        "asserted_label_is_unverified": asserted_label is not None,
        "captures_with_manifest": built["captures_with_manifest"],
        "captures_without_manifest": len(built["captures_without_manifest"]),
        "non_claims": list(_PROVENANCE_NON_CLAIMS),
    }
    return result


_PROVENANCE_REPORT_FIELDS = {
    "schema",
    "script",
    "script_sha256_16",
    "bytes",
    "verdict",
    "rationale",
    "recorded_hosts",
    "recorded_sites",
    "recorded_in_captures",
    "sits_in_directories",
    "directory_disagrees_with_manifest",
    "asserted_label",
    "asserted_label_is_unverified",
    "captures_with_manifest",
    "captures_without_manifest",
    "non_claims",
}


def _validated_provenance_report(result: Any) -> dict[str, Any]:
    if type(result) is not dict or set(result) != _PROVENANCE_REPORT_FIELDS:
        raise ContractError("rendered script provenance structure is invalid")
    if result.get("schema") != PROVENANCE_SCHEMA:
        raise ContractError("rendered script provenance schema is invalid")
    if not _bounded_text(result.get("script"), maximum=1_024):
        raise ContractError("rendered script provenance structure is invalid")
    if not isinstance(result.get("script_sha256_16"), str) or re.fullmatch(
        r"[0-9a-f]{16}", result["script_sha256_16"]
    ) is None:
        raise ContractError("rendered script provenance structure is invalid")
    for field, maximum in (
        ("bytes", MAX_CAPTURE_SCRIPT_BYTES),
        ("captures_with_manifest", MAX_CAPTURE_DIRECTORIES),
        ("captures_without_manifest", MAX_CAPTURE_DIRECTORIES),
    ):
        value = result.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise ContractError("rendered script provenance structure is invalid")

    retained_lists: dict[str, list[str]] = {}
    for field in (
        "recorded_hosts",
        "recorded_sites",
        "recorded_in_captures",
        "sits_in_directories",
    ):
        values = result.get(field)
        if (
            type(values) is not list
            or len(values) > MAX_CAPTURE_MANIFEST_ENTRIES
            or any(not _bounded_text(value, maximum=1_024) for value in values)
            or values != sorted(values)
            or len(values) != len(set(values))
        ):
            raise ContractError("rendered script provenance structure is invalid")
        retained_lists[field] = values

    hosts = retained_lists["recorded_hosts"]
    sites = retained_lists["recorded_sites"]
    captures = retained_lists["recorded_in_captures"]
    sits_in = retained_lists["sits_in_directories"]
    if (
        len(captures) > result["captures_with_manifest"]
        or len(sites) > len(captures)
        or len(set(captures) | set(sits_in))
        > result["captures_with_manifest"] + result["captures_without_manifest"]
    ):
        raise ContractError("rendered script provenance coverage is inconsistent")
    for host in hosts:
        parsed_host = _manifest_url({"url": f"https://{host}/"})
        if parsed_host is None or parsed_host[1] != host:
            raise ContractError("rendered script provenance origin is invalid")
    expected_verdict = "VERIFIED" if hosts else "UNVERIFIED"
    if result.get("verdict") != expected_verdict:
        raise ContractError("rendered script provenance structure is invalid")
    if expected_verdict == "UNVERIFIED" and (sites or captures):
        raise ContractError("rendered script provenance structure is invalid")
    if expected_verdict == "VERIFIED" and not captures:
        raise ContractError("rendered script provenance structure is invalid")
    expected_rationale = (
        f"a capture manifest records these exact bytes fetched from {', '.join(hosts)}"
        if hosts
        else _UNVERIFIED_RATIONALE
    )
    if result.get("rationale") != expected_rationale:
        raise ContractError("rendered script provenance structure is invalid")

    expected_disagreement = bool(hosts and sits_in and not set(sits_in) <= set(captures))
    if (
        type(result.get("directory_disagrees_with_manifest")) is not bool
        or result["directory_disagrees_with_manifest"] is not expected_disagreement
    ):
        raise ContractError("rendered script provenance structure is invalid")
    asserted_label = result.get("asserted_label")
    if asserted_label is not None and not _bounded_text(
        asserted_label, maximum=4_096, non_empty=False
    ):
        raise ContractError("rendered script provenance structure is invalid")
    if (
        type(result.get("asserted_label_is_unverified")) is not bool
        or result["asserted_label_is_unverified"] is not (asserted_label is not None)
    ):
        raise ContractError("rendered script provenance structure is invalid")
    if result.get("non_claims") != _PROVENANCE_NON_CLAIMS:
        raise ContractError("rendered script provenance structure is invalid")
    return result


@normalize_renderer_failures("script provenance")
def render_provenance(result: dict[str, Any]) -> str:
    """Render a provenance verdict as short text."""
    result = _validated_provenance_report(result)
    out = [
        f"{result['script']}  ({result['bytes']:,} B)",
        f"pin       {result['script_sha256_16']}",
        f"VERDICT   {result['verdict']}",
        f"          {result['rationale']}",
    ]
    if result["recorded_hosts"]:
        out.append(f"origin    {', '.join(result['recorded_hosts'])}")
    if result["recorded_sites"]:
        out.append(f"site      {', '.join(result['recorded_sites'])}")
    if result["asserted_label"]:
        out.append(
            f"label     {result['asserted_label']!r} - operator-asserted, NOT verified"
        )
    if result["sits_in_directories"]:
        out.append(f"sits in   {', '.join(result['sits_in_directories'][:6])}")
    if result["directory_disagrees_with_manifest"]:
        out.append(
            "WARNING   these bytes sit in directories that no manifest says fetched "
            "them; do not read the directory name as a site"
        )
    out.append(
        f"coverage  {result['captures_with_manifest']} capture(s) with a manifest, "
        f"{result['captures_without_manifest']} without"
    )
    return "\n".join(out)
