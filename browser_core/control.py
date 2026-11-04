from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .contracts import ContractError, reject_sensitive_keys
from .control_files import (
    decode_strict_json_bytes,
    publish_bytes_exclusive,
    read_bounded_control_snapshot_result,
)
from .profiles import PROFILE_ID_RE, has_windows_device_basename
from .owned_paths import (
    directory_identity,
    prepare_owned_directory_parent,
    require_owned_directory_ancestors,
)


CONTROL_SCHEMA = "browser-core.control/2"
PREVIOUS_CONTROL_SCHEMA = "browser-core.control/1"
TOKEN_PREFIX = "bc1"
WORKER_TOKEN_PREFIX = "bcw1"
ROLES = {"owner", "operator", "viewer"}
ROLE_RANK = {"viewer": 1, "operator": 2, "owner": 3}
#: Job kinds a fleet may schedule. Membership here is necessary and not
#: sufficient: `execute_typed_job` must also implement the kind and validate its
#: payload field-for-field, so a kind added here alone would be accepted by the
#: scheduler and rejected by every worker.
#:
#: The reviewed set covers probing, evaluation, post-probe evidence workflows,
#: controlled multi-identity research, and passive local transport capture. The
#: control plane continues to refuse an arbitrary `shell` escape hatch.
JOB_KINDS = {
    "browser-eval",
    "kernel-probe",
    "physical-kernel-probe",
    "pinwatch-drift-check",
    "native-smoke",
    "network-preflight",
    "browser-fact-capture",
    "evidence-pack",
    "http2-baseline-install",
    "http2-check",
    "http2-evidence",
    "http2-evidence-baseline-install",
    "http2-evidence-check",
    "http2-fingerprint",
    "multi-identity-ops",
    "transport-baseline-install",
    "transport-check",
    "transport-evidence-suite-check",
    "transport-fingerprint",
    "transport-suite-check",
}
TERMINAL_JOB_STATES = {"succeeded", "failed", "cancelled"}
JOB_STATES = TERMINAL_JOB_STATES | {"queued", "running"}
_PUBLIC_JOB_COLUMNS = (
    "id,workspace_id,kind,requirements_json,priority,state,attempt,max_attempts,"
    "persona_id,profile_id,payload_sha256,result_sha256,created_at,updated_at"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{12,64}$")
TOKEN_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
CONTROL_TOKEN_VALUE_RE = re.compile(
    r"(?<![A-Za-z0-9])bc(?:1|w1)\.[A-Za-z0-9_-]{1,128}\.[A-Za-z0-9_-]{12,128}"
)
CONTROL_BEARER_VALUE_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])bearer[ \t]+\S{12,}", re.IGNORECASE
)
CONTROL_DEBUG_ENDPOINT_VALUE_RE = re.compile(r"wss?://[^\s\"'<>]*/devtools/", re.IGNORECASE)
CONTROL_RESTRICTED_KEYS = {
    "cdp",
    "cdp-endpoint",
    "cdp-url",
    "cookies",
    "debugger-address",
    "profile-dir",
    "profile-path",
    "remote-debugging-port",
    "storage-state",
    "user-data-dir",
    "websocket-debugger-url",
}
MAX_CONTROL_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_CONTROL_ROW_JSON_BYTES = 64 * 1024 * 1024
MAX_CONTROL_REVISION = (1 << 63) - 2
FLEET_STATUS_WORKER_LIMIT = 1000
_CONTROL_REQUIRED_TABLES = frozenset({
    "meta", "users", "workspaces", "memberships", "tokens", "records",
    "artifacts", "workers", "worker_scopes", "jobs", "audit",
})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ContractError("timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ContractError("timestamp is invalid")
        return parsed
    except (TypeError, ValueError):
        raise ContractError("timestamp is invalid") from None


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not PROFILE_ID_RE.fullmatch(value):
        raise ContractError(f"{label} is invalid")
    return value


def _safe_display_name(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ContractError(f"{label} is invalid")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} is invalid") from None
    try:
        _reject_control_restricted_keys(value)
    except ContractError:
        raise ContractError(f"{label} is invalid") from None
    return value


def _safe_bounded_int(value: Any, minimum: int, maximum: int, message: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError(message)
    return value


def _safe_stored_credential(value: Any, size: int) -> bytes:
    if not isinstance(value, bytes) or len(value) != size:
        raise ContractError("stored credential material is invalid")
    return value


def _safe_optional_revision(value: Any) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_CONTROL_REVISION
    ):
        raise ContractError("record expected revision is invalid")
    return value


def _safe_lease_duration(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 5 <= value <= 3600:
        raise ContractError(f"{label} is invalid")
    return value


def _safe_lease_token(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ContractError("job lease token is invalid")
    return value


def _safe_operation_time(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise ContractError("control operation time is invalid")
    try:
        offset = value.utcoffset()
    except (OverflowError, TypeError, ValueError):
        raise ContractError("control operation time is invalid") from None
    if value.tzinfo is None or offset is None:
        raise ContractError("control operation time is invalid")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, TypeError, ValueError):
        raise ContractError("control operation time is invalid") from None


def _lease_expiration(current: datetime, seconds: int) -> datetime:
    try:
        return current + timedelta(seconds=seconds)
    except OverflowError:
        raise ContractError("job lease expiration is out of range") from None


def _safe_payload(value: Any, label: str, *, maximum: int = 256 * 1024) -> str:
    try:
        reject_sensitive_keys(value)
        _reject_control_restricted_keys(value)
        encoded = _canonical(value)
        body = encoded.encode("utf-8", errors="strict")
    except ContractError:
        raise
    except (AttributeError, RuntimeError, TypeError, UnicodeEncodeError, ValueError):
        raise ContractError(f"{label} must be JSON serializable") from None
    if len(body) > maximum:
        raise ContractError(f"{label} exceeds {maximum} bytes")
    # A caller may mutate a container after the first scan. Check only the
    # detached bytes that will be stored or hashed, not its later live state.
    detached = _strict_json_bytes(body, label=label)
    reject_sensitive_keys(detached)
    _reject_control_restricted_keys(detached)
    return encoded


def _strict_json_bytes(body: bytes, *, label: str) -> Any:
    return decode_strict_json_bytes(body, label=label)


def _strict_canonical_json_text(
    value: Any,
    *,
    label: str,
    maximum: int,
) -> Any:
    if (
        not isinstance(value, str)
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= MAX_CONTROL_ROW_JSON_BYTES
    ):
        raise ContractError(f"{label} stored JSON is invalid")
    try:
        body = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError(f"{label} stored JSON is invalid") from None
    if len(body) > maximum:
        raise ContractError(f"{label} stored JSON exceeds {maximum} bytes")
    document = _strict_json_bytes(body, label=label)
    try:
        canonical = _canonical(document)
    except (TypeError, ValueError):
        raise ContractError(f"{label} stored JSON is invalid") from None
    if canonical != value:
        raise ContractError(f"{label} stored JSON is not canonical")
    return document


def _safe_database_payload(
    value: Any,
    *,
    label: str,
    maximum: int = 256 * 1024,
    expected_sha256: Any = None,
) -> Any:
    document = _strict_canonical_json_text(value, label=label, maximum=maximum)
    canonical = _safe_payload(document, label, maximum=maximum)
    if canonical != value:
        raise ContractError(f"{label} stored JSON is not canonical")
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or SHA256_RE.fullmatch(expected_sha256) is None
        or not hmac.compare_digest(
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            expected_sha256,
        )
    ):
        raise ContractError(f"{label} stored digest is invalid")
    return document


def _database_id_list(value: Any, *, label: str, allow_empty: bool) -> list[str]:
    document = _strict_canonical_json_text(value, label=label, maximum=64 * 1024)
    if (
        not isinstance(document, list)
        or (not allow_empty and not document)
        or any(
            not isinstance(item, str) or PROFILE_ID_RE.fullmatch(item) is None
            for item in document
        )
        or document != sorted(set(document))
    ):
        raise ContractError(f"{label} stored list is invalid")
    return document


def _reject_control_restricted_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            raw_key = re.sub(r"[\s_.:/]+", "-", key.strip())
            camel_split = re.sub(r"(.)([A-Z][a-z]+)", r"\1-\2", raw_key)
            normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", camel_split).lower()
            if normalized in CONTROL_RESTRICTED_KEYS:
                raise ContractError("restricted browser-control field is forbidden")
            _reject_control_restricted_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_control_restricted_keys(child)
    elif isinstance(value, str):
        if (CONTROL_TOKEN_VALUE_RE.search(value)
                or CONTROL_BEARER_VALUE_RE.search(value)
                or re.match(r"bearer[ \t]+\S", value.lstrip(), re.IGNORECASE)):
            raise ContractError("raw credential value is forbidden")
        if CONTROL_DEBUG_ENDPOINT_VALUE_RE.search(value):
            raise ContractError("browser debugging endpoint is forbidden")


@dataclass(frozen=True)
class Principal:
    user_id: str
    token_id: str
    scope_workspace_id: str | None = None


@dataclass(frozen=True)
class WorkerPrincipal:
    worker_id: str


class ControlStore:
    """Durable local-first collaboration and typed fleet control plane."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise ContractError("control database root must be a Path")
        if os.name == "nt" and any(
            component != root.anchor
            and component not in {".", ".."}
            and (
                component.endswith((".", " "))
                or has_windows_device_basename(component)
                or any(
                    character in '<>:"\\|?*' or ord(character) < 32
                    for character in component
                )
            )
            for component in root.parts
        ):
            raise ContractError("control database root has an invalid component")
        try:
            self.root = Path(os.path.abspath(root))
        except (OSError, ValueError):
            raise ContractError("control database root is invalid") from None
        prepare_owned_directory_parent(self.root, label="control database parent")
        self._root_identity = directory_identity(
            self.root, label="control database parent"
        )
        if self._root_identity is None:
            raise ContractError("control database parent is unavailable")
        self.database_path = self.root / "control.sqlite3"
        self.artifact_root = self.root / "artifacts" / "sha256"
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        self._require_owned_database_paths()
        connection = sqlite3.connect(
            self.database_path, timeout=30, isolation_level=None
        )
        try:
            self._require_owned_database_paths()
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            return connection
        except BaseException:
            connection.close()
            raise

    def _require_owned_database_paths(self) -> None:
        require_owned_directory_ancestors(self.root, label="control database parent")
        if (
            directory_identity(self.root, label="control database parent")
            != self._root_identity
        ):
            raise ContractError("control database parent changed")
        for suffix in ("", "-wal", "-shm", "-journal"):
            path = self.database_path.with_name(self.database_path.name + suffix)
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                continue
            except OSError:
                raise ContractError("control database path cannot be inspected") from None
            if (
                not stat.S_ISREG(metadata.st_mode)
                or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
                or metadata.st_nlink != 1
            ):
                raise ContractError("control database path is not an owned regular file")

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def _initialize(self) -> None:
        with self._transaction() as db:
            present_tables = {
                row["name"] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "meta" in present_tables:
                try:
                    previous_schema = db.execute(
                        "SELECT value FROM meta WHERE key='schema'"
                    ).fetchone()
                except sqlite3.DatabaseError:
                    raise ContractError("control-store schema metadata is invalid") from None
                if previous_schema is None:
                    raise ContractError("control-store schema metadata is missing")
                if previous_schema is not None and previous_schema["value"] not in {
                    PREVIOUS_CONTROL_SCHEMA,
                    CONTROL_SCHEMA,
                }:
                    raise ContractError("unsupported control-store schema")
                if not _CONTROL_REQUIRED_TABLES.issubset(present_tables):
                    raise ContractError("control-store schema table is missing")
            elif present_tables - {"sqlite_sequence"}:
                raise ContractError("control-store schema metadata is missing")
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workspaces (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1,
                    max_running INTEGER NOT NULL,
                    max_queued INTEGER NOT NULL,
                    last_dispatched_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS memberships (
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    user_id TEXT NOT NULL REFERENCES users(id),
                    role TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY(workspace_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id),
                    scope_workspace_id TEXT REFERENCES workspaces(id),
                    scope_version INTEGER NOT NULL DEFAULT 0 CHECK(scope_version IN (0,1)),
                    salt BLOB NOT NULL,
                    verifier BLOB NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS records (
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    kind TEXT NOT NULL,
                    id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    updated_by TEXT NOT NULL REFERENCES users(id),
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(workspace_id, kind, id)
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    media_type TEXT NOT NULL,
                    visibility TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(workspace_id, sha256)
                );
                CREATE TABLE IF NOT EXISTS workers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    max_slots INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    token_salt BLOB NOT NULL,
                    token_verifier BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS worker_scopes (
                    worker_id TEXT NOT NULL REFERENCES workers(id),
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    PRIMARY KEY(worker_id, workspace_id)
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    requirements_json TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    lease_worker_id TEXT REFERENCES workers(id),
                    lease_token_sha256 TEXT,
                    lease_expires_at TEXT,
                    persona_id TEXT,
                    profile_id TEXT,
                    idempotency_key_sha256 TEXT NOT NULL,
                    result_json TEXT,
                    result_sha256 TEXT,
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(workspace_id, idempotency_key_sha256)
                );
                CREATE INDEX IF NOT EXISTS jobs_dispatch
                    ON jobs(state, priority DESC, created_at);
                CREATE INDEX IF NOT EXISTS jobs_workspace_state
                    ON jobs(workspace_id, state);
                CREATE INDEX IF NOT EXISTS jobs_running_worker
                    ON jobs(lease_worker_id) WHERE state='running';
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS audit_workspace_seq
                    ON audit(workspace_id, seq);
                CREATE INDEX IF NOT EXISTS audit_action_resource
                    ON audit(action, resource);
                """
            )
            # executescript commits the enclosing transaction before running DDL.
            # Keep the schema pin and any saved-time repair in one write transaction.
            if not db.in_transaction:
                db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            if current is None:
                db.execute(
                    "INSERT INTO meta(key,value) VALUES('schema',?)", (CONTROL_SCHEMA,)
                )
            elif current["value"] == PREVIOUS_CONTROL_SCHEMA:
                self._migrate_token_scopes(db)
                db.execute(
                    "UPDATE meta SET value=? WHERE key='schema'", (CONTROL_SCHEMA,)
                )
            elif current["value"] != CONTROL_SCHEMA:
                raise ContractError("unsupported control-store schema")
            token_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(tokens)")
            }
            if not {"scope_workspace_id", "scope_version"}.issubset(token_columns):
                raise ContractError("control-store token scope column is missing")
            self._normalize_dispatch_times(db)

    @staticmethod
    def _migrate_token_scopes(db: sqlite3.Connection) -> None:
        """Pin v1 tokens to their issuing workspace; retain root self-renewals."""
        db.execute(
            "ALTER TABLE tokens ADD COLUMN scope_workspace_id TEXT REFERENCES workspaces(id)"
        )
        db.execute(
            "ALTER TABLE tokens ADD COLUMN scope_version INTEGER NOT NULL DEFAULT 0 "
            "CHECK(scope_version IN (0,1))"
        )
        bootstrap = db.execute(
            "SELECT actor_id,workspace_id FROM audit "
            "WHERE action='workspace.bootstrap' ORDER BY seq LIMIT 2"
        ).fetchall()
        if len(bootstrap) != 1:
            raise ContractError("legacy token bootstrap provenance is invalid")
        root_owner = _safe_id(bootstrap[0]["actor_id"], "legacy bootstrap owner")
        last_id = ""
        while True:
            rows = db.execute(
                "SELECT id,user_id FROM tokens WHERE id>? ORDER BY id LIMIT 256",
                (last_id,),
            ).fetchall()
            if not rows:
                break
            for row in rows:
                token_id = row["id"]
                user_id = row["user_id"]
                if not isinstance(token_id, str) or TOKEN_ID_RE.fullmatch(token_id) is None:
                    raise ContractError("legacy token ID is invalid")
                _safe_id(user_id, "legacy token user")
                issued = db.execute(
                    "SELECT workspace_id,actor_id,details_json FROM audit "
                    "WHERE action='token.issue' AND resource=? ORDER BY seq LIMIT 2",
                    (f"token:{token_id}",),
                ).fetchall()
                if len(issued) != 1:
                    raise ContractError("legacy token issue provenance is invalid")
                event = issued[0]
                scope_workspace_id = _safe_id(
                    event["workspace_id"], "legacy token workspace"
                )
                actor_id = _safe_id(event["actor_id"], "legacy token actor")
                details = _safe_database_payload(
                    event["details_json"], label="legacy token issue", maximum=64 * 1024
                )
                if (
                    not isinstance(details, dict)
                    or details.get("user_id") != user_id
                    or set(details) not in (
                        {"user_id", "ttl_hours"},
                        {"user_id", "ttl_hours", "scope"},
                    )
                    or isinstance(details.get("ttl_hours"), bool)
                    or not isinstance(details.get("ttl_hours"), int)
                    or not 1 <= details["ttl_hours"] <= 24 * 365
                    or (
                        "scope" in details
                        and (
                            not isinstance(details["scope"], str)
                            or details["scope"] not in {"global", "workspace"}
                        )
                    )
                ):
                    raise ContractError("legacy token issue provenance is invalid")
                if "scope" in details and (
                    (details["scope"] == "global") != (actor_id == user_id == root_owner)
                ):
                    raise ContractError("legacy token issue scope is invalid")
                db.execute(
                    "UPDATE tokens SET scope_workspace_id=?,scope_version=1 WHERE id=?",
                    (
                        None if actor_id == user_id == root_owner else scope_workspace_id,
                        token_id,
                    ),
                )
                last_id = token_id

    @staticmethod
    def _normalize_dispatch_times(db: sqlite3.Connection) -> None:
        last_id = ""
        while True:
            rows = db.execute(
                "SELECT id,last_dispatched_at FROM workspaces "
                "WHERE last_dispatched_at IS NOT NULL AND id>? ORDER BY id LIMIT 256",
                (last_id,),
            ).fetchall()
            if not rows:
                break
            for row in rows:
                last_id = row["id"]
                instant = _safe_operation_time(_parse_time(row["last_dispatched_at"]))
                canonical = instant.isoformat(timespec="microseconds").replace("+00:00", "Z")
                if canonical != row["last_dispatched_at"]:
                    db.execute(
                        "UPDATE workspaces SET last_dispatched_at=? WHERE id=?",
                        (canonical, row["id"]),
                    )

    def _audit(
        self,
        db: sqlite3.Connection,
        workspace_id: str,
        actor_id: str,
        action: str,
        resource: str,
        details: Any,
    ) -> None:
        details_json = _safe_payload(details, "audit details", maximum=64 * 1024)
        previous = db.execute(
            "SELECT event_sha256 FROM audit WHERE workspace_id=? ORDER BY seq DESC LIMIT 1",
            (workspace_id,),
        ).fetchone()
        previous_sha256 = previous["event_sha256"] if previous else "0" * 64
        if not isinstance(previous_sha256, str) or SHA256_RE.fullmatch(previous_sha256) is None:
            raise ContractError("stored audit head digest is invalid")
        created_at = utc_now()
        body = {
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "action": action,
            "resource": resource,
            "details": _safe_database_payload(
                details_json,
                label="audit details",
                maximum=64 * 1024,
            ),
            "created_at": created_at,
            "previous_sha256": previous_sha256,
        }
        event_sha256 = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        db.execute(
            "INSERT INTO audit(workspace_id,actor_id,action,resource,details_json,created_at,previous_sha256,event_sha256) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                workspace_id,
                actor_id,
                action,
                resource,
                details_json,
                created_at,
                previous_sha256,
                event_sha256,
            ),
        )

    def bootstrap(
        self,
        *,
        workspace_id: str,
        workspace_name: str,
        owner_id: str,
        owner_name: str,
        token_ttl_hours: int = 24,
        max_running: int = 4,
        max_queued: int = 100,
        publish_secret: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        _safe_id(workspace_id, "workspace ID")
        _safe_id(owner_id, "owner ID")
        _safe_display_name(workspace_name, "workspace name")
        _safe_display_name(owner_name, "owner name")
        _safe_bounded_int(max_running, 1, 1000, "workspace quotas are invalid")
        _safe_bounded_int(max_queued, 1, 100000, "workspace quotas are invalid")
        _safe_bounded_int(token_ttl_hours, 1, 24 * 365, "token TTL is invalid")
        if publish_secret is not None and not callable(publish_secret):
            raise ContractError("secret publisher is invalid")
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM workspaces LIMIT 1").fetchone() is not None:
                raise ContractError("control store is already bootstrapped")
            now = utc_now()
            db.execute(
                "INSERT INTO users(id,display_name,created_at) VALUES(?,?,?)",
                (owner_id, owner_name, now),
            )
            db.execute(
                "INSERT INTO workspaces(id,name,max_running,max_queued,created_at) VALUES(?,?,?,?,?)",
                (workspace_id, workspace_name, max_running, max_queued, now),
            )
            db.execute(
                "INSERT INTO memberships(workspace_id,user_id,role) VALUES(?,?,?)",
                (workspace_id, owner_id, "owner"),
            )
            self._audit(
                db,
                workspace_id,
                owner_id,
                "workspace.bootstrap",
                f"workspace:{workspace_id}",
                {},
            )
            token = self._insert_token(
                db,
                owner_id,
                ttl_hours=token_ttl_hours,
                audit_workspace_id=workspace_id,
                audit_actor_id=owner_id,
                scope_workspace_id=None,
            )
            if publish_secret is not None:
                publish_secret(token)
        return {"workspace_id": workspace_id, "owner_id": owner_id, "token": token}

    def _insert_token(
        self,
        db: sqlite3.Connection,
        user_id: str,
        *,
        ttl_hours: int,
        audit_workspace_id: str,
        audit_actor_id: str,
        scope_workspace_id: str | None,
    ) -> str:
        _safe_id(user_id, "user ID")
        _safe_bounded_int(ttl_hours, 1, 24 * 365, "token TTL is invalid")
        if scope_workspace_id is not None and scope_workspace_id != audit_workspace_id:
            raise ContractError("token scope is invalid")
        token_id = secrets.token_urlsafe(12)
        secret = secrets.token_urlsafe(32)
        salt = secrets.token_bytes(16)
        verifier = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 240_000)
        now = datetime.now(timezone.utc)
        if (
            db.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone()
            is None
        ):
            raise ContractError("token user does not exist")
        db.execute(
            "INSERT INTO tokens(id,user_id,scope_workspace_id,scope_version,salt,verifier,expires_at,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                token_id,
                user_id,
                scope_workspace_id,
                1,
                salt,
                verifier,
                (now + timedelta(hours=ttl_hours))
                .isoformat()
                .replace("+00:00", "Z"),
                now.isoformat().replace("+00:00", "Z"),
            ),
        )
        self._audit(
            db,
            audit_workspace_id,
            audit_actor_id,
            "token.issue",
            f"token:{token_id}",
            {
                "user_id": user_id,
                "ttl_hours": ttl_hours,
                "scope": "global" if scope_workspace_id is None else "workspace",
            },
        )
        return f"{TOKEN_PREFIX}.{token_id}.{secret}"

    def _issue_token(
        self,
        user_id: str,
        *,
        ttl_hours: int,
        audit_workspace_id: str,
        audit_actor_id: str,
        scope_workspace_id: str | None,
        publish_secret: Callable[[str], None] | None = None,
    ) -> str:
        with self._transaction() as db:
            token = self._insert_token(
                db,
                user_id,
                ttl_hours=ttl_hours,
                audit_workspace_id=audit_workspace_id,
                audit_actor_id=audit_actor_id,
                scope_workspace_id=scope_workspace_id,
            )
            if publish_secret is not None:
                publish_secret(token)
            return token

    def issue_token(
        self,
        principal: Principal,
        workspace_id: str,
        user_id: str,
        *,
        ttl_hours: int = 24,
        publish_secret: Callable[[str], None] | None = None,
    ) -> str:
        _safe_id(user_id, "user ID")
        _safe_bounded_int(ttl_hours, 1, 24 * 365, "token TTL is invalid")
        if publish_secret is not None and not callable(publish_secret):
            raise ContractError("secret publisher is invalid")
        with self._read_connection() as db:
            self.require_role(db, principal, workspace_id, "owner")
            membership = db.execute(
                "SELECT 1 FROM memberships WHERE workspace_id=? AND user_id=?",
                (workspace_id, user_id),
            ).fetchone()
        if membership is None:
            raise ContractError("token user is not a workspace member")
        return self._issue_token(
            user_id,
            ttl_hours=ttl_hours,
            audit_workspace_id=workspace_id,
            audit_actor_id=principal.user_id,
            scope_workspace_id=(
                None
                if principal.scope_workspace_id is None and user_id == principal.user_id
                else workspace_id
            ),
            publish_secret=publish_secret,
        )

    def authenticate(self, token: str, *, now: datetime | None = None) -> Principal:
        if not isinstance(token, str) or len(token) > 256:
            raise ContractError("bearer token is invalid")
        parts = token.split(".")
        if (
            len(parts) != 3
            or parts[0] != TOKEN_PREFIX
            or not TOKEN_ID_RE.fullmatch(parts[1])
            or not TOKEN_SECRET_RE.fullmatch(parts[2])
        ):
            raise ContractError("bearer token is invalid")
        with self._read_connection() as db:
            row = db.execute("SELECT * FROM tokens WHERE id=?", (parts[1],)).fetchone()
            if (
                row is None
                or row["revoked_at"] is not None
                or row["scope_version"] != 1
            ):
                raise ContractError("bearer token is invalid")
            current = _safe_operation_time(now)
            if _parse_time(row["expires_at"]) <= current:
                raise ContractError("bearer token has expired")
            salt = _safe_stored_credential(row["salt"], 16)
            verifier = _safe_stored_credential(row["verifier"], 32)
            observed = hashlib.pbkdf2_hmac(
                "sha256", parts[2].encode("utf-8"), salt, 240_000
            )
            if not hmac.compare_digest(observed, verifier):
                raise ContractError("bearer token is invalid")
            scope = row["scope_workspace_id"]
            if scope is not None and (
                not isinstance(scope, str) or PROFILE_ID_RE.fullmatch(scope) is None
            ):
                raise ContractError("stored token scope is invalid")
            return Principal(row["user_id"], row["id"], scope)

    def revoke_token(
        self, principal: Principal, workspace_id: str, token_id: str
    ) -> None:
        _safe_id(workspace_id, "workspace ID")
        if not isinstance(token_id, str) or not TOKEN_ID_RE.fullmatch(token_id):
            raise ContractError("token ID is invalid")
        with self._transaction() as db:
            row = db.execute(
                "SELECT user_id,scope_workspace_id,revoked_at FROM tokens WHERE id=?",
                (token_id,),
            ).fetchone()
            if row is None:
                raise ContractError("token does not exist")
            if row["user_id"] == principal.user_id:
                self.require_role(db, principal, workspace_id, "viewer")
                if row["scope_workspace_id"] != workspace_id and (
                    row["scope_workspace_id"] is not None
                    or principal.scope_workspace_id is not None
                ):
                    raise ContractError("token scope does not permit this workspace")
            else:
                self.require_role(db, principal, workspace_id, "owner")
                if row["scope_workspace_id"] != workspace_id:
                    raise ContractError("token scope does not permit this workspace")
                membership = db.execute(
                    "SELECT 1 FROM memberships WHERE workspace_id=? AND user_id=?",
                    (workspace_id, row["user_id"]),
                ).fetchone()
                if membership is None:
                    raise ContractError("token user is not a workspace member")
            if row["revoked_at"] is None:
                db.execute(
                    "UPDATE tokens SET revoked_at=? WHERE id=?", (utc_now(), token_id)
                )
                self._audit(
                    db,
                    workspace_id,
                    principal.user_id,
                    "token.revoke",
                    f"token:{token_id}",
                    {"user_id": row["user_id"]},
                )

    def _role(
        self, db: sqlite3.Connection, principal: Principal, workspace_id: str
    ) -> str:
        row = db.execute(
            "SELECT role FROM memberships WHERE workspace_id=? AND user_id=?",
            (workspace_id, principal.user_id),
        ).fetchone()
        if row is None:
            raise ContractError("principal is not a workspace member")
        role = row["role"]
        if not isinstance(role, str) or role not in ROLES:
            raise ContractError("stored workspace role is invalid")
        return role

    def require_role(
        self,
        db: sqlite3.Connection,
        principal: Principal,
        workspace_id: str,
        minimum: str,
    ) -> str:
        if minimum not in ROLES:
            raise RuntimeError("unknown minimum role")
        if (
            principal.scope_workspace_id is not None
            and principal.scope_workspace_id != workspace_id
        ):
            raise ContractError("token scope does not permit this workspace")
        role = self._role(db, principal, workspace_id)
        if ROLE_RANK[role] < ROLE_RANK[minimum]:
            raise ContractError(f"workspace role {minimum} is required")
        return role

    def add_member(
        self,
        principal: Principal,
        workspace_id: str,
        *,
        user_id: str,
        display_name: str,
        role: str,
    ) -> None:
        _safe_id(user_id, "user ID")
        if not isinstance(role, str) or role not in ROLES:
            raise ContractError("workspace role is invalid")
        _safe_display_name(display_name, "display name")
        with self._transaction() as db:
            self.require_role(db, principal, workspace_id, "owner")
            if db.execute(
                "SELECT 1 FROM memberships WHERE workspace_id=? AND user_id=?",
                (workspace_id, user_id),
            ).fetchone() is not None:
                raise ContractError("user is already a workspace member")
            existing_user = db.execute(
                "SELECT display_name FROM users WHERE id=?", (user_id,)
            ).fetchone()
            if existing_user is None:
                db.execute(
                    "INSERT INTO users(id,display_name,created_at) VALUES(?,?,?)",
                    (user_id, display_name, utc_now()),
                )
            elif existing_user["display_name"] != display_name:
                raise ContractError("user display name conflict")
            db.execute(
                "INSERT INTO memberships(workspace_id,user_id,role) VALUES(?,?,?)",
                (workspace_id, user_id, role),
            )
            self._audit(
                db,
                workspace_id,
                principal.user_id,
                "member.add",
                f"user:{user_id}",
                {"role": role},
            )

    def create_workspace(
        self,
        principal: Principal,
        *,
        workspace_id: str,
        name: str,
        max_running: int = 4,
        max_queued: int = 100,
    ) -> dict[str, Any]:
        _safe_id(workspace_id, "workspace ID")
        _safe_display_name(name, "workspace name")
        _safe_bounded_int(max_running, 1, 1000, "workspace quotas are invalid")
        _safe_bounded_int(max_queued, 1, 100000, "workspace quotas are invalid")
        if principal.scope_workspace_id is not None:
            raise ContractError("token scope does not permit workspace creation")
        with self._transaction() as db:
            if db.execute(
                "SELECT 1 FROM workspaces WHERE id=?", (workspace_id,)
            ).fetchone() is not None:
                raise ContractError("workspace already exists")
            if (
                db.execute(
                    "SELECT 1 FROM users WHERE id=?", (principal.user_id,)
                ).fetchone()
                is None
            ):
                raise ContractError("workspace creator does not exist")
            now = utc_now()
            db.execute(
                "INSERT INTO workspaces(id,name,max_running,max_queued,created_at) VALUES(?,?,?,?,?)",
                (workspace_id, name, max_running, max_queued, now),
            )
            db.execute(
                "INSERT INTO memberships(workspace_id,user_id,role) VALUES(?,?,?)",
                (workspace_id, principal.user_id, "owner"),
            )
            self._audit(
                db,
                workspace_id,
                principal.user_id,
                "workspace.create",
                f"workspace:{workspace_id}",
                {"max_running": max_running, "max_queued": max_queued},
            )
        return {"id": workspace_id, "name": name, "role": "owner"}

    def put_record(
        self,
        principal: Principal,
        workspace_id: str,
        *,
        kind: str,
        record_id: str,
        payload: Any,
        expected_revision: int | None,
    ) -> dict[str, Any]:
        _safe_id(kind, "record kind")
        _safe_id(record_id, "record ID")
        expected_revision = _safe_optional_revision(expected_revision)
        payload_json = _safe_payload(payload, "record payload")
        digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        with self._transaction() as db:
            self.require_role(db, principal, workspace_id, "operator")
            existing = db.execute(
                "SELECT revision FROM records WHERE workspace_id=? AND kind=? AND id=?",
                (workspace_id, kind, record_id),
            ).fetchone()
            if existing is None:
                if expected_revision not in {None, 0}:
                    raise ContractError("record revision conflict")
                revision = 1
                db.execute(
                    "INSERT INTO records VALUES(?,?,?,?,?,?,?,?)",
                    (
                        workspace_id,
                        kind,
                        record_id,
                        revision,
                        payload_json,
                        digest,
                        principal.user_id,
                        utc_now(),
                    ),
                )
                action = "record.create"
            else:
                if expected_revision != existing["revision"]:
                    raise ContractError("record revision conflict")
                revision = _safe_bounded_int(
                    existing["revision"],
                    1,
                    MAX_CONTROL_REVISION - 1,
                    "stored record revision cannot advance",
                ) + 1
                db.execute(
                    "UPDATE records SET revision=?,payload_json=?,payload_sha256=?,updated_by=?,updated_at=? "
                    "WHERE workspace_id=? AND kind=? AND id=?",
                    (
                        revision,
                        payload_json,
                        digest,
                        principal.user_id,
                        utc_now(),
                        workspace_id,
                        kind,
                        record_id,
                    ),
                )
                action = "record.update"
            self._audit(
                db,
                workspace_id,
                principal.user_id,
                action,
                f"record:{kind}:{record_id}",
                {"revision": revision, "payload_sha256": digest},
            )
        return {
            "kind": kind,
            "id": record_id,
            "revision": revision,
            "payload_sha256": digest,
        }

    def get_record(
        self, principal: Principal, workspace_id: str, *, kind: str, record_id: str
    ) -> dict[str, Any]:
        with self._read_connection() as db:
            self.require_role(db, principal, workspace_id, "viewer")
            row = db.execute(
                "SELECT * FROM records WHERE workspace_id=? AND kind=? AND id=?",
                (workspace_id, kind, record_id),
            ).fetchone()
        if row is None:
            raise ContractError("record does not exist")
        revision = _safe_bounded_int(
            row["revision"], 1, MAX_CONTROL_REVISION, "stored record revision is invalid"
        )
        _parse_time(row["updated_at"])
        return {
            "kind": row["kind"],
            "id": row["id"],
            "revision": revision,
            "payload": _safe_database_payload(
                row["payload_json"],
                label="record payload",
                expected_sha256=row["payload_sha256"],
            ),
            "payload_sha256": row["payload_sha256"],
            "updated_at": row["updated_at"],
        }

    def put_artifact(
        self,
        principal: Principal,
        workspace_id: str,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
        visibility: str = "operator",
    ) -> dict[str, Any]:
        if not isinstance(content, bytes) or len(content) > MAX_CONTROL_ARTIFACT_BYTES:
            raise ContractError("artifact must be bytes no larger than 64 MiB")
        if not isinstance(visibility, str) or visibility not in {
            "viewer",
            "operator",
            "owner",
        }:
            raise ContractError("artifact visibility is invalid")
        if (
            not isinstance(media_type, str)
            or not 1 <= len(media_type) <= 128
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in media_type
            )
        ):
            raise ContractError("artifact media type is invalid")
        if visibility == "viewer":
            if media_type != "application/json":
                raise ContractError(
                    "viewer-visible artifacts must use application/json"
                )
            shared_document = _strict_json_bytes(
                content,
                label="viewer-visible artifact",
            )
            _safe_payload(shared_document, "viewer artifact", maximum=64 * 1024 * 1024)
        digest = hashlib.sha256(content).hexdigest()
        path = self.artifact_root / digest[:2] / digest
        with self._transaction() as db:
            self.require_role(db, principal, workspace_id, "operator")
            existing = db.execute(
                "SELECT size,media_type,visibility FROM artifacts WHERE workspace_id=? AND sha256=?",
                (workspace_id, digest),
            ).fetchone()
            if existing is not None and (
                existing["size"] != len(content)
                or existing["media_type"] != media_type
                or existing["visibility"] != visibility
            ):
                raise ContractError("content-addressed artifact metadata conflict")
            prepare_owned_directory_parent(
                path.parent, label="content-addressed artifact parent"
            )
            require_owned_directory_ancestors(
                path.parent, label="content-addressed artifact parent"
            )
            parent_identity = directory_identity(
                path.parent, label="content-addressed artifact parent"
            )
            if parent_identity is None:
                raise ContractError("content-addressed artifact parent is unavailable")
            snapshot = read_bounded_control_snapshot_result(
                path,
                maximum=MAX_CONTROL_ARTIFACT_BYTES,
                label="content-addressed artifact",
                require_single_link=True,
            )
            if snapshot.state == "missing":
                try:
                    publish_bytes_exclusive(
                        path,
                        content,
                        maximum=MAX_CONTROL_ARTIFACT_BYTES,
                        label="content-addressed artifact",
                    )
                except ContractError:
                    # An idempotent concurrent publisher may have won. Re-read
                    # the final object and accept only the exact digest body.
                    snapshot = read_bounded_control_snapshot_result(
                        path,
                        maximum=MAX_CONTROL_ARTIFACT_BYTES,
                        label="content-addressed artifact",
                        require_single_link=True,
                    )
                    if snapshot.state != "complete" or snapshot.body != content:
                        raise ContractError(
                            "content-addressed artifact publication conflicted"
                        ) from None
            elif snapshot.state != "complete" or snapshot.body != content:
                raise ContractError("content-addressed artifact path is corrupt")
            require_owned_directory_ancestors(
                path.parent, label="content-addressed artifact parent"
            )
            if (
                directory_identity(
                    path.parent, label="content-addressed artifact parent"
                )
                != parent_identity
            ):
                raise ContractError("content-addressed artifact parent changed")
            db.execute(
                "INSERT INTO artifacts(workspace_id,sha256,size,media_type,visibility,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(workspace_id,sha256) DO NOTHING",
                (
                    workspace_id,
                    digest,
                    len(content),
                    media_type,
                    visibility,
                    principal.user_id,
                    utc_now(),
                ),
            )
            self._audit(
                db,
                workspace_id,
                principal.user_id,
                "artifact.put",
                f"artifact:{digest}",
                {
                    "sha256": digest,
                    "size": len(content),
                    "media_type": media_type,
                    "visibility": visibility,
                },
            )
            require_owned_directory_ancestors(
                path.parent, label="content-addressed artifact parent"
            )
            if (
                directory_identity(
                    path.parent, label="content-addressed artifact parent"
                )
                != parent_identity
            ):
                raise ContractError("content-addressed artifact parent changed")
            final_snapshot = read_bounded_control_snapshot_result(
                path,
                maximum=MAX_CONTROL_ARTIFACT_BYTES,
                label="content-addressed artifact",
                require_single_link=True,
            )
            if final_snapshot.state != "complete" or final_snapshot.body != content:
                raise ContractError("content-addressed artifact changed before metadata commit")
            if (
                directory_identity(
                    path.parent, label="content-addressed artifact parent"
                )
                != parent_identity
            ):
                raise ContractError("content-addressed artifact parent changed")
        return {
            "sha256": digest,
            "size": len(content),
            "media_type": media_type,
            "visibility": visibility,
        }

    def get_artifact(
        self, principal: Principal, workspace_id: str, digest: str
    ) -> bytes:
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ContractError("artifact digest is invalid")
        with self._read_connection() as db:
            role = self.require_role(db, principal, workspace_id, "viewer")
            row = db.execute(
                "SELECT * FROM artifacts WHERE workspace_id=? AND sha256=?",
                (workspace_id, digest),
            ).fetchone()
        if row is None:
            raise ContractError("artifact does not exist")
        visibility = row["visibility"]
        if not isinstance(visibility, str) or visibility not in ROLE_RANK:
            raise ContractError("stored artifact visibility is invalid")
        if ROLE_RANK[role] < ROLE_RANK[visibility]:
            raise ContractError("artifact visibility denies access")
        path = self.artifact_root / digest[:2] / digest
        require_owned_directory_ancestors(
            path.parent, label="content-addressed artifact parent"
        )
        parent_identity = directory_identity(
            path.parent, label="content-addressed artifact parent"
        )
        if parent_identity is None:
            raise ContractError("content-addressed artifact parent is unavailable")
        snapshot = read_bounded_control_snapshot_result(
            path,
            maximum=MAX_CONTROL_ARTIFACT_BYTES,
            label="artifact content",
            require_single_link=True,
        )
        require_owned_directory_ancestors(
            path.parent, label="content-addressed artifact parent"
        )
        if (
            directory_identity(
                path.parent, label="content-addressed artifact parent"
            )
            != parent_identity
        ):
            raise ContractError("content-addressed artifact parent changed")
        if snapshot.state != "complete" or snapshot.body is None:
            raise ContractError("artifact content is missing") from None
        content = snapshot.body
        if len(content) != row["size"] or hashlib.sha256(content).hexdigest() != digest:
            raise ContractError("artifact content integrity failed")
        return content

    def verify_audit(self, principal: Principal, workspace_id: str) -> dict[str, Any]:
        previous = "0" * 64
        events = 0
        with self._read_connection() as db:
            self.require_role(db, principal, workspace_id, "viewer")
            for row in db.execute(
                "SELECT * FROM audit WHERE workspace_id=? ORDER BY seq", (workspace_id,)
            ):
                if row["previous_sha256"] != previous:
                    raise ContractError(
                        f"audit chain predecessor mismatch at sequence {row['seq']}"
                    )
                body = {
                    "workspace_id": row["workspace_id"],
                    "actor_id": row["actor_id"],
                    "action": row["action"],
                    "resource": row["resource"],
                    "details": _safe_database_payload(
                        row["details_json"],
                        label="audit details",
                        maximum=64 * 1024,
                    ),
                    "created_at": row["created_at"],
                    "previous_sha256": row["previous_sha256"],
                }
                expected = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
                if row["event_sha256"] != expected:
                    raise ContractError(
                        f"audit chain event mismatch at sequence {row['seq']}"
                    )
                previous = expected
                events += 1
        return {"events": events, "head_sha256": previous, "valid": True}

    def register_worker(
        self,
        principal: Principal,
        workspace_id: str,
        worker_id: str,
        *,
        name: str,
        capabilities: list[str],
        max_slots: int,
        publish_secret: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        _safe_id(worker_id, "worker ID")
        _safe_display_name(name, "worker name")
        if not isinstance(capabilities, list):
            raise ContractError(
                "worker capabilities must be sorted unique safe identifiers"
            )
        capability_snapshot = tuple(capabilities)
        if (
            not capability_snapshot
            or any(
                not isinstance(item, str) or not PROFILE_ID_RE.fullmatch(item)
                for item in capability_snapshot
            )
            or capability_snapshot != tuple(sorted(set(capability_snapshot)))
        ):
            raise ContractError(
                "worker capabilities must be sorted unique safe identifiers"
            )
        if (
            isinstance(max_slots, bool)
            or not isinstance(max_slots, int)
            or not 1 <= max_slots <= 256
        ):
            raise ContractError("worker slot count is invalid")
        if publish_secret is not None and not callable(publish_secret):
            raise ContractError("secret publisher is invalid")
        now = utc_now()
        secret = secrets.token_urlsafe(32)
        worker_token = f"{WORKER_TOKEN_PREFIX}.{worker_id}.{secret}"
        salt = secrets.token_bytes(16)
        verifier = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 240_000)
        with self._transaction() as db:
            self.require_role(db, principal, workspace_id, "owner")
            existing = db.execute(
                "SELECT revision FROM workers WHERE id=?", (worker_id,)
            ).fetchone()
            if existing is not None:
                registration = db.execute(
                    "SELECT workspace_id FROM audit WHERE action='worker.register' AND resource=? "
                    "ORDER BY seq ASC LIMIT 1",
                    (f"worker:{worker_id}",),
                ).fetchone()
                if registration is None or registration["workspace_id"] != workspace_id:
                    raise ContractError("worker registration workspace does not own this worker")
            revision = (
                _safe_bounded_int(
                    existing["revision"],
                    1,
                    MAX_CONTROL_REVISION - 1,
                    "stored worker revision cannot advance",
                ) + 1
                if existing
                else 1
            )
            db.execute(
                "INSERT INTO workers(id,name,capabilities_json,max_slots,state,last_seen_at,revision,token_salt,token_verifier) "
                "VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name,capabilities_json=excluded.capabilities_json,"
                "max_slots=excluded.max_slots,state='online',last_seen_at=excluded.last_seen_at,revision=excluded.revision,"
                "token_salt=excluded.token_salt,token_verifier=excluded.token_verifier",
                (
                    worker_id,
                    name,
                    _canonical(capability_snapshot),
                    max_slots,
                    "online",
                    now,
                    revision,
                    salt,
                    verifier,
                ),
            )
            db.execute(
                "INSERT INTO worker_scopes(worker_id,workspace_id) VALUES(?,?) "
                "ON CONFLICT(worker_id,workspace_id) DO NOTHING",
                (worker_id, workspace_id),
            )
            self._audit(
                db,
                workspace_id,
                principal.user_id,
                "worker.register",
                f"worker:{worker_id}",
                {
                    "capabilities": capability_snapshot,
                    "max_slots": max_slots,
                    "revision": revision,
                },
            )
            if publish_secret is not None:
                publish_secret(worker_token)
        return {
            "id": worker_id,
            "capabilities": list(capability_snapshot),
            "max_slots": max_slots,
            "revision": revision,
            "worker_token": worker_token,
        }

    def authenticate_worker(self, token: str) -> WorkerPrincipal:
        if not isinstance(token, str) or len(token) > 256:
            raise ContractError("worker token is invalid")
        parts = token.split(".")
        if (
            len(parts) != 3
            or parts[0] != WORKER_TOKEN_PREFIX
            or not PROFILE_ID_RE.fullmatch(parts[1])
            or not TOKEN_SECRET_RE.fullmatch(parts[2])
        ):
            raise ContractError("worker token is invalid")
        with self._read_connection() as db:
            row = db.execute(
                "SELECT token_salt,token_verifier,state FROM workers WHERE id=?",
                (parts[1],),
            ).fetchone()
        if row is None or row["state"] != "online":
            raise ContractError("worker token is invalid")
        salt = _safe_stored_credential(row["token_salt"], 16)
        verifier = _safe_stored_credential(row["token_verifier"], 32)
        observed = hashlib.pbkdf2_hmac(
            "sha256", parts[2].encode("utf-8"), salt, 240_000
        )
        if not hmac.compare_digest(observed, verifier):
            raise ContractError("worker token is invalid")
        return WorkerPrincipal(parts[1])

    def add_worker_scope(
        self,
        principal: Principal,
        workspace_id: str,
        worker_id: str,
    ) -> None:
        _safe_id(worker_id, "worker ID")
        with self._transaction() as db:
            self.require_role(db, principal, workspace_id, "owner")
            if (
                db.execute("SELECT 1 FROM workers WHERE id=?", (worker_id,)).fetchone()
                is None
            ):
                raise ContractError("worker does not exist")
            registration = db.execute(
                "SELECT workspace_id FROM audit WHERE action='worker.register' AND resource=? "
                "ORDER BY seq ASC LIMIT 1",
                (f"worker:{worker_id}",),
            ).fetchone()
            if registration is None:
                raise ContractError("worker registration workspace is unavailable")
            self.require_role(db, principal, registration["workspace_id"], "owner")
            db.execute(
                "INSERT INTO worker_scopes(worker_id,workspace_id) VALUES(?,?) "
                "ON CONFLICT(worker_id,workspace_id) DO NOTHING",
                (worker_id, workspace_id),
            )
            self._audit(
                db,
                workspace_id,
                principal.user_id,
                "worker.scope-add",
                f"worker:{worker_id}",
                {},
            )

    def enqueue_job(
        self,
        principal: Principal,
        workspace_id: str,
        *,
        kind: str,
        payload: Any,
        requirements: list[str],
        idempotency_key: str,
        priority: int = 0,
        max_attempts: int = 3,
        persona_id: str | None = None,
        profile_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(kind, str) or kind not in JOB_KINDS:
            raise ContractError("job kind is not in the reviewed allowlist")
        payload_json = _safe_payload(payload, "job payload")
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        if not isinstance(requirements, list):
            raise ContractError(
                "job requirements must be sorted unique safe identifiers"
            )
        requirement_snapshot = tuple(requirements)
        if (
            any(
                not isinstance(item, str) or not PROFILE_ID_RE.fullmatch(item)
                for item in requirement_snapshot
            )
            or requirement_snapshot != tuple(sorted(set(requirement_snapshot)))
        ):
            raise ContractError(
                "job requirements must be sorted unique safe identifiers"
            )
        requirements_json = _canonical(requirement_snapshot)
        if (
            not isinstance(idempotency_key, str)
            or not idempotency_key
            or len(idempotency_key) > 512
        ):
            raise ContractError("job idempotency key is invalid")
        try:
            idempotency_bytes = idempotency_key.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ContractError("job idempotency key is invalid") from None
        idempotency_sha256 = hashlib.sha256(idempotency_bytes).hexdigest()
        if (
            isinstance(priority, bool)
            or not isinstance(priority, int)
            or not -100 <= priority <= 100
        ):
            raise ContractError("job priority is invalid")
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or not 1 <= max_attempts <= 20
        ):
            raise ContractError("job max attempts is invalid")
        for value, label in ((persona_id, "persona ID"), (profile_id, "profile ID")):
            if value is not None:
                _safe_id(value, label)
        with self._transaction() as db:
            self.require_role(db, principal, workspace_id, "operator")
            existing = db.execute(
                "SELECT * FROM jobs WHERE workspace_id=? AND idempotency_key_sha256=?",
                (workspace_id, idempotency_sha256),
            ).fetchone()
            if existing is not None:
                if (
                    existing["payload_sha256"] != payload_sha256
                    or existing["kind"] != kind
                    or existing["requirements_json"] != requirements_json
                    or existing["priority"] != priority
                    or existing["max_attempts"] != max_attempts
                    or existing["persona_id"] != persona_id
                    or existing["profile_id"] != profile_id
                ):
                    raise ContractError(
                        "job idempotency key conflicts with different work"
                    )
                _safe_database_payload(
                    existing["payload_json"],
                    label="job payload",
                    expected_sha256=existing["payload_sha256"],
                )
                return self._job_public(existing)
            workspace = db.execute(
                "SELECT * FROM workspaces WHERE id=?", (workspace_id,)
            ).fetchone()
            queued = db.execute(
                "SELECT COUNT(*) AS count FROM jobs WHERE workspace_id=? AND state='queued'",
                (workspace_id,),
            ).fetchone()["count"]
            max_queued = _safe_bounded_int(
                workspace["max_queued"], 1, 100000, "stored workspace queued quota is invalid"
            )
            if queued >= max_queued:
                raise ContractError("workspace queued-job quota is exhausted")
            job_id = f"job-{secrets.token_hex(8)}"
            now = utc_now()
            db.execute(
                "INSERT INTO jobs(id,workspace_id,kind,payload_json,payload_sha256,requirements_json,priority,state,"
                "attempt,max_attempts,persona_id,profile_id,idempotency_key_sha256,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,'queued',0,?,?,?,?,?,?,?)",
                (
                    job_id,
                    workspace_id,
                    kind,
                    payload_json,
                    payload_sha256,
                    requirements_json,
                    priority,
                    max_attempts,
                    persona_id,
                    profile_id,
                    idempotency_sha256,
                    principal.user_id,
                    now,
                    now,
                ),
            )
            self._audit(
                db,
                workspace_id,
                principal.user_id,
                "job.enqueue",
                f"job:{job_id}",
                {
                    "kind": kind,
                    "requirements": requirement_snapshot,
                    "payload_sha256": payload_sha256,
                },
            )
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._job_public(row)

    def _job_public(self, row: sqlite3.Row) -> dict[str, Any]:
        _safe_id(row["id"], "stored job ID")
        _safe_id(row["workspace_id"], "stored job workspace ID")
        kind = row["kind"]
        if not isinstance(kind, str) or kind not in JOB_KINDS:
            raise ContractError("stored job kind is invalid")
        state = row["state"]
        if not isinstance(state, str) or state not in JOB_STATES:
            raise ContractError("stored job state is invalid")
        _safe_bounded_int(row["priority"], -100, 100, "stored job priority is invalid")
        attempts = _safe_bounded_int(row["attempt"], 0, 20, "stored job attempt is invalid")
        max_attempts = _safe_bounded_int(
            row["max_attempts"], 1, 20, "stored job max attempts is invalid"
        )
        if attempts > max_attempts:
            raise ContractError("stored job attempt is invalid")
        for field in ("persona_id", "profile_id"):
            if row[field] is not None:
                _safe_id(row[field], f"stored job {field}")
        for field in ("payload_sha256", "result_sha256"):
            value = row[field]
            if value is None and field == "result_sha256":
                continue
            if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
                raise ContractError(f"stored job {field} is invalid")
        _parse_time(row["created_at"])
        _parse_time(row["updated_at"])
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "kind": kind,
            "requirements": _database_id_list(
                row["requirements_json"],
                label="job requirements",
                allow_empty=True,
            ),
            "priority": row["priority"],
            "state": state,
            "attempt": row["attempt"],
            "max_attempts": row["max_attempts"],
            "persona_id": row["persona_id"],
            "profile_id": row["profile_id"],
            "payload_sha256": row["payload_sha256"],
            "result_sha256": row["result_sha256"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_jobs(self, principal: Principal, workspace_id: str) -> dict[str, Any]:
        limit = 100
        with self._read_connection() as db:
            self.require_role(db, principal, workspace_id, "viewer")
            rows = db.execute(
                f"SELECT {_PUBLIC_JOB_COLUMNS} FROM jobs WHERE workspace_id=? "
                "ORDER BY created_at DESC,id DESC LIMIT ?",
                (workspace_id, limit + 1),
            ).fetchall()
        return {
            "schema": "browser-core.job-list/1",
            "workspace_id": workspace_id,
            "jobs": [self._job_public(row) for row in rows[:limit]],
            "limit": limit,
            "jobs_truncated": len(rows) > limit,
        }

    def get_job(
        self, principal: Principal, workspace_id: str, job_id: str
    ) -> dict[str, Any]:
        _safe_id(job_id, "job ID")
        with self._read_connection() as db:
            role = self.require_role(db, principal, workspace_id, "viewer")
            columns = "*" if ROLE_RANK[role] >= ROLE_RANK["operator"] else _PUBLIC_JOB_COLUMNS
            row = db.execute(
                f"SELECT {columns} FROM jobs WHERE workspace_id=? AND id=?",
                (workspace_id, job_id),
            ).fetchone()
        if row is None:
            raise ContractError("job does not exist")
        document = self._job_public(row)
        if ROLE_RANK[role] >= ROLE_RANK["operator"]:
            document["payload"] = _safe_database_payload(
                row["payload_json"],
                label="job payload",
                expected_sha256=row["payload_sha256"],
            )
            if row["result_json"] is not None:
                document["result"] = _safe_database_payload(
                    row["result_json"],
                    label="job result",
                    expected_sha256=row["result_sha256"],
                )
        return document

    def _expire_leases(self, db: sqlite3.Connection, now: datetime) -> None:
        last_id = ""
        while True:
            rows = db.execute(
                "SELECT id,workspace_id,attempt,max_attempts,lease_expires_at FROM jobs "
                "WHERE state='running' AND lease_expires_at IS NOT NULL AND id>? "
                "ORDER BY id LIMIT 256",
                (last_id,),
            ).fetchall()
            if not rows:
                break
            for row in rows:
                last_id = row["id"]
                if _parse_time(row["lease_expires_at"]) > now:
                    continue
                attempt = _safe_bounded_int(row["attempt"], 1, 20, "stored job attempt is invalid")
                max_attempts = _safe_bounded_int(
                    row["max_attempts"], 1, 20, "stored job attempt limit is invalid"
                )
                if attempt > max_attempts:
                    raise ContractError("stored job attempt exceeds its limit")
                next_state = "queued" if attempt < max_attempts else "failed"
                result_json = None
                result_sha256 = None
                if next_state == "failed":
                    result_json = _canonical(
                        {"reason": "lease-expired", "attempts": attempt}
                    )
                    result_sha256 = hashlib.sha256(result_json.encode("utf-8")).hexdigest()
                db.execute(
                    "UPDATE jobs SET state=?,lease_worker_id=NULL,lease_token_sha256=NULL,lease_expires_at=NULL,"
                    "result_json=?,result_sha256=?,updated_at=? WHERE id=?",
                    (
                        next_state,
                        result_json,
                        result_sha256,
                        now.isoformat().replace("+00:00", "Z"),
                        row["id"],
                    ),
                )
                self._audit(
                    db,
                    row["workspace_id"],
                    "scheduler",
                    "job.lease-expired",
                    f"job:{row['id']}",
                    {"attempt": attempt, "next_state": next_state},
                )

    def lease_job(
        self,
        worker: WorkerPrincipal,
        *,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        lease_seconds = _safe_lease_duration(lease_seconds, "job lease duration")
        current = _safe_operation_time(now)
        current_timestamp = current.isoformat(timespec="microseconds").replace("+00:00", "Z")
        worker_id = _safe_id(worker.worker_id, "worker ID")
        with self._transaction() as db:
            worker = db.execute(
                "SELECT * FROM workers WHERE id=?", (worker_id,)
            ).fetchone()
            if worker is None or worker["state"] != "online":
                raise ContractError("worker is not registered online")
            self._expire_leases(db, current)
            running_slots = db.execute(
                "SELECT COUNT(*) AS count FROM jobs WHERE state='running' AND lease_worker_id=?",
                (worker_id,),
            ).fetchone()["count"]
            max_slots = _safe_bounded_int(worker["max_slots"], 1, 256, "stored worker slots are invalid")
            if running_slots >= max_slots:
                return None
            worker_capabilities = set(
                _database_id_list(
                    worker["capabilities_json"],
                    label="worker capabilities",
                    allow_empty=False,
                )
            )
            selected = None
            workspace_running_counts: dict[str, int] = {}
            persona_conflicts: dict[str, bool] = {}
            profile_conflicts: dict[str, bool] = {}
            with closing(
                db.execute(
                    "SELECT jobs.id,jobs.workspace_id,jobs.requirements_json,jobs.persona_id,"
                    "jobs.profile_id,workspaces.max_running FROM jobs "
                    "JOIN workspaces ON workspaces.id=jobs.workspace_id "
                    "JOIN worker_scopes ON worker_scopes.workspace_id=jobs.workspace_id "
                    "WHERE jobs.state='queued' AND worker_scopes.worker_id=? "
                    "ORDER BY COALESCE(workspaces.last_dispatched_at,'') ASC,jobs.priority DESC,jobs.created_at ASC",
                    (worker_id,),
                )
            ) as candidates:
                for row in candidates:
                    requirements = _database_id_list(
                        row["requirements_json"],
                        label="job requirements",
                        allow_empty=True,
                    )
                    if not set(requirements).issubset(worker_capabilities):
                        continue
                    workspace_id = row["workspace_id"]
                    workspace_running = workspace_running_counts.get(workspace_id)
                    if workspace_running is None:
                        workspace_running = db.execute(
                            "SELECT COUNT(*) AS count FROM jobs WHERE workspace_id=? AND state='running'",
                            (workspace_id,),
                        ).fetchone()["count"]
                        workspace_running_counts[workspace_id] = workspace_running
                    max_running = _safe_bounded_int(
                        row["max_running"], 1, 1000, "stored workspace running quota is invalid"
                    )
                    if workspace_running >= max_running:
                        continue
                    persona_id = row["persona_id"]
                    if persona_id is not None:
                        if persona_id not in persona_conflicts:
                            persona_conflicts[persona_id] = db.execute(
                                "SELECT 1 FROM jobs WHERE state='running' AND persona_id=? LIMIT 1",
                                (persona_id,),
                            ).fetchone() is not None
                        if persona_conflicts[persona_id]:
                            continue
                    profile_id = row["profile_id"]
                    if profile_id is not None:
                        if profile_id not in profile_conflicts:
                            profile_conflicts[profile_id] = db.execute(
                                "SELECT 1 FROM jobs WHERE state='running' AND profile_id=? LIMIT 1",
                                (profile_id,),
                            ).fetchone() is not None
                        if profile_conflicts[profile_id]:
                            continue
                    selected = db.execute(
                        "SELECT * FROM jobs WHERE id=?", (row["id"],)
                    ).fetchone()
                    break
            if selected is None:
                return None
            selected_payload = _safe_database_payload(
                selected["payload_json"],
                label="job payload",
                expected_sha256=selected["payload_sha256"],
            )
            selected_public = self._job_public(selected)
            if selected_public["attempt"] >= selected_public["max_attempts"]:
                raise ContractError("queued job has exhausted its attempt limit")
            db.execute(
                "UPDATE workers SET last_seen_at=? WHERE id=?",
                (current_timestamp, worker_id),
            )
            lease_token = secrets.token_urlsafe(32)
            lease_hash = hashlib.sha256(lease_token.encode("utf-8")).hexdigest()
            expires = _lease_expiration(current, lease_seconds)
            db.execute(
                "UPDATE jobs SET state='running',attempt=attempt+1,lease_worker_id=?,lease_token_sha256=?,"
                "lease_expires_at=?,updated_at=? WHERE id=? AND state='queued'",
                (
                    worker_id,
                    lease_hash,
                    expires.isoformat().replace("+00:00", "Z"),
                    current_timestamp,
                    selected["id"],
                ),
            )
            db.execute(
                "UPDATE workspaces SET last_dispatched_at=? WHERE id=?",
                (current_timestamp, selected["workspace_id"]),
            )
            self._audit(
                db,
                selected["workspace_id"],
                f"worker:{worker_id}",
                "job.lease",
                f"job:{selected['id']}",
                {"attempt": selected["attempt"] + 1, "lease_seconds": lease_seconds},
            )
            leased = db.execute(
                "SELECT * FROM jobs WHERE id=?", (selected["id"],)
            ).fetchone()
            leased_public = self._job_public(leased)
        return {
            **leased_public,
            "payload": selected_payload,
            "lease_token": lease_token,
        }

    def heartbeat_lease(
        self,
        worker: WorkerPrincipal,
        job_id: str,
        lease_token: str,
        *,
        extend_seconds: int = 60,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        extend_seconds = _safe_lease_duration(extend_seconds, "job lease extension")
        job_id = _safe_id(job_id, "job ID")
        lease_token = _safe_lease_token(lease_token)
        current = _safe_operation_time(now)
        worker_id = _safe_id(worker.worker_id, "worker ID")
        with self._transaction() as db:
            row = self._verified_lease(db, worker_id, job_id, lease_token, current)
            expires = _lease_expiration(current, extend_seconds)
            db.execute(
                "UPDATE jobs SET lease_expires_at=?,updated_at=? WHERE id=?",
                (
                    expires.isoformat().replace("+00:00", "Z"),
                    current.isoformat().replace("+00:00", "Z"),
                    job_id,
                ),
            )
            db.execute(
                "UPDATE workers SET last_seen_at=? WHERE id=?",
                (current.isoformat().replace("+00:00", "Z"), worker_id),
            )
            self._audit(
                db,
                row["workspace_id"],
                f"worker:{worker_id}",
                "job.heartbeat",
                f"job:{job_id}",
                {"extend_seconds": extend_seconds},
            )
        return {
            "job_id": row["id"],
            "lease_expires_at": expires.isoformat().replace("+00:00", "Z"),
        }

    def _verified_lease(
        self,
        db: sqlite3.Connection,
        worker_id: str,
        job_id: str,
        lease_token: str,
        now: datetime,
    ) -> sqlite3.Row:
        job_id = _safe_id(job_id, "job ID")
        lease_token = _safe_lease_token(lease_token)
        row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if (
            row is None
            or row["state"] != "running"
            or row["lease_worker_id"] != worker_id
        ):
            raise ContractError("job lease is not owned by this worker")
        observed = hashlib.sha256(lease_token.encode("utf-8")).hexdigest()
        stored_digest = row["lease_token_sha256"]
        if (
            not isinstance(stored_digest, str)
            or SHA256_RE.fullmatch(stored_digest) is None
            or not hmac.compare_digest(observed, stored_digest)
        ):
            raise ContractError("job lease token is invalid")
        if _parse_time(row["lease_expires_at"]) <= now:
            raise ContractError("job lease has expired")
        return row

    def complete_job(
        self,
        worker: WorkerPrincipal,
        job_id: str,
        lease_token: str,
        *,
        succeeded: bool,
        result: Any,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        job_id = _safe_id(job_id, "job ID")
        lease_token = _safe_lease_token(lease_token)
        if not isinstance(succeeded, bool):
            raise ContractError("job completion success flag is invalid")
        current = _safe_operation_time(now)
        worker_id = _safe_id(worker.worker_id, "worker ID")
        result_json = _safe_payload(result, "job result")
        result_sha256 = hashlib.sha256(result_json.encode("utf-8")).hexdigest()
        with self._transaction() as db:
            existing = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if existing is None:
                raise ContractError("job does not exist")
            self._job_public(existing)
            if existing["state"] in TERMINAL_JOB_STATES:
                if existing["result_sha256"] == result_sha256 and existing["state"] == (
                    "succeeded" if succeeded else "failed"
                ):
                    completion = db.execute(
                        "SELECT actor_id,details_json FROM audit "
                        "WHERE workspace_id=? AND action='job.complete' AND resource=? "
                        "ORDER BY seq DESC LIMIT 1",
                        (existing["workspace_id"], f"job:{job_id}"),
                    ).fetchone()
                    if completion is None or completion["actor_id"] != f"worker:{worker_id}":
                        raise ContractError("job completion lease is not owned by this worker")
                    details = _safe_database_payload(
                        completion["details_json"],
                        label="job completion audit",
                        maximum=64 * 1024,
                    )
                    proof = details.get("lease_token_sha256") if isinstance(details, dict) else None
                    observed = hashlib.sha256(lease_token.encode("utf-8")).hexdigest()
                    if (
                        not isinstance(proof, str)
                        or SHA256_RE.fullmatch(proof) is None
                        or not hmac.compare_digest(observed, proof)
                    ):
                        raise ContractError("job completion lease token is invalid")
                    _safe_database_payload(
                        existing["result_json"],
                        label="job result",
                        expected_sha256=existing["result_sha256"],
                    )
                    return self._job_public(existing)
                raise ContractError("job already has a different terminal result")
            row = self._verified_lease(db, worker_id, job_id, lease_token, current)
            state = "succeeded" if succeeded else "failed"
            db.execute(
                "UPDATE jobs SET state=?,result_json=?,result_sha256=?,lease_worker_id=NULL,lease_token_sha256=NULL,"
                "lease_expires_at=NULL,updated_at=? WHERE id=?",
                (
                    state,
                    result_json,
                    result_sha256,
                    current.isoformat().replace("+00:00", "Z"),
                    job_id,
                ),
            )
            self._audit(
                db,
                row["workspace_id"],
                f"worker:{worker_id}",
                "job.complete",
                f"job:{job_id}",
                {
                    "state": state,
                    "result_sha256": result_sha256,
                    "lease_token_sha256": hashlib.sha256(
                        lease_token.encode("utf-8")
                    ).hexdigest(),
                },
            )
            completed = db.execute(
                "SELECT * FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            completed_public = self._job_public(completed)
        return completed_public

    def cancel_job(
        self, principal: Principal, workspace_id: str, job_id: str
    ) -> dict[str, Any]:
        with self._transaction() as db:
            self.require_role(db, principal, workspace_id, "operator")
            row = db.execute(
                "SELECT * FROM jobs WHERE id=? AND workspace_id=?",
                (job_id, workspace_id),
            ).fetchone()
            if row is None:
                raise ContractError("job does not exist")
            self._job_public(row)
            if row["state"] in TERMINAL_JOB_STATES:
                return self._job_public(row)
            result_json = _canonical({"reason": "operator-cancelled"})
            result_sha256 = hashlib.sha256(result_json.encode("utf-8")).hexdigest()
            db.execute(
                "UPDATE jobs SET state='cancelled',result_json=?,result_sha256=?,lease_worker_id=NULL,"
                "lease_token_sha256=NULL,lease_expires_at=NULL,updated_at=? WHERE id=?",
                (result_json, result_sha256, utc_now(), job_id),
            )
            self._audit(
                db, workspace_id, principal.user_id, "job.cancel", f"job:{job_id}", {}
            )
            cancelled = db.execute(
                "SELECT * FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            cancelled_public = self._job_public(cancelled)
        return cancelled_public

    def fleet_status(self, principal: Principal, workspace_id: str) -> dict[str, Any]:
        with self._read_connection() as db:
            self.require_role(db, principal, workspace_id, "viewer")
            rows = db.execute(
                "SELECT state,COUNT(*) AS count FROM jobs WHERE workspace_id=? GROUP BY state",
                (workspace_id,),
            ).fetchall()
            workers = db.execute(
                "SELECT workers.id,workers.state,workers.max_slots,workers.last_seen_at FROM workers "
                "JOIN worker_scopes ON worker_scopes.worker_id=workers.id "
                "WHERE worker_scopes.workspace_id=? ORDER BY workers.id LIMIT ?",
                (workspace_id, FLEET_STATUS_WORKER_LIMIT + 1),
            ).fetchall()
        job_counts: dict[str, int] = {}
        for row in rows:
            state = row["state"]
            if not isinstance(state, str) or state not in JOB_STATES:
                raise ContractError("stored job state is invalid")
            job_counts[state] = _safe_bounded_int(
                row["count"], 0, MAX_CONTROL_REVISION, "stored job count is invalid"
            )
        worker_rows: list[dict[str, Any]] = []
        for row in workers[:FLEET_STATUS_WORKER_LIMIT]:
            _safe_id(row["id"], "stored worker ID")
            if row["state"] != "online":
                raise ContractError("stored worker state is invalid")
            _safe_bounded_int(row["max_slots"], 1, 256, "stored worker slots are invalid")
            _parse_time(row["last_seen_at"])
            worker_rows.append(dict(row))
        return {
            "workspace_id": workspace_id,
            "jobs": job_counts,
            "workers": worker_rows,
            "worker_limit": FLEET_STATUS_WORKER_LIMIT,
            "workers_truncated": len(workers) > FLEET_STATUS_WORKER_LIMIT,
        }
