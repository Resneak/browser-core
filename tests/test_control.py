from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import browser_core.control as control_module
from browser_core.contracts import ContractError
from browser_core.control import ControlStore


def bootstrapped(tmp_path: Path):
    store = ControlStore(tmp_path)
    result = store.bootstrap(
        workspace_id="lab",
        workspace_name="Research Lab",
        owner_id="alice",
        owner_name="Alice",
        max_running=2,
        max_queued=10,
    )
    owner = store.authenticate(result["token"])
    return store, owner, result["token"]


def test_unsupported_control_schema_does_not_create_current_tables(tmp_path: Path) -> None:
    root = tmp_path / "future-store"
    root.mkdir()
    database = root / "control.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.execute("INSERT INTO meta(key,value) VALUES('schema','browser-core.control/999')")
        before = set(db.execute("SELECT type,name FROM sqlite_master").fetchall())
    with pytest.raises(ContractError, match="unsupported control-store schema"):
        ControlStore(root)
    with sqlite3.connect(database) as db:
        after = set(db.execute("SELECT type,name FROM sqlite_master").fetchall())
    assert after == before


@pytest.mark.parametrize(
    "damage", ["missing-jobs", "missing-schema-pin", "missing-meta-table"]
)
def test_existing_control_store_rejects_incomplete_schema_before_repair(
    tmp_path: Path, damage: str,
) -> None:
    store, _, _ = bootstrapped(tmp_path)
    with sqlite3.connect(store.database_path) as db:
        if damage == "missing-jobs":
            db.execute("DROP TABLE jobs")
        elif damage == "missing-schema-pin":
            db.execute("DELETE FROM meta WHERE key='schema'")
        else:
            db.execute("DROP TABLE meta")
        before = set(db.execute("SELECT type,name FROM sqlite_master").fetchall())

    with pytest.raises(ContractError, match="control-store schema"):
        ControlStore(tmp_path)

    with sqlite3.connect(store.database_path) as db:
        after = set(db.execute("SELECT type,name FROM sqlite_master").fetchall())
    assert after == before


def test_control_store_rejects_hard_linked_database_before_sqlite_access(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.sqlite3"
    with sqlite3.connect(outside) as db:
        db.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
        db.execute("INSERT INTO sentinel(value) VALUES('preserve')")
    before = outside.read_bytes()
    root = tmp_path / "store"
    root.mkdir()
    try:
        os.link(outside, root / "control.sqlite3")
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {type(exc).__name__}")
    with pytest.raises(ContractError, match="database path"):
        ControlStore(root)
    assert outside.read_bytes() == before


@pytest.mark.skipif(os.name != "nt", reason="Win32 directory-name normalization")
@pytest.mark.parametrize("suffix", [".", " "])
def test_control_store_rejects_normalized_root_alias_before_sqlite_creation(
    tmp_path: Path, suffix: str,
) -> None:
    root = tmp_path / "store"
    root.mkdir()
    selected = tmp_path / f"store{suffix}"
    assert selected.is_dir() and os.path.samefile(selected, root)

    with pytest.raises(ContractError, match="control database root"):
        ControlStore(selected)
    assert not (root / "control.sqlite3").exists()

    assert ControlStore(root).database_path.is_file()


@pytest.mark.skipif(os.name != "nt", reason="Win32 invalid directory components")
@pytest.mark.parametrize("leaf", ["bad?name", "bad<name", "CON", "AUX.txt"])
def test_control_store_rejects_invalid_root_before_parent_creation(
    tmp_path: Path, leaf: str,
) -> None:
    selected = tmp_path / "new-parent" / leaf
    with pytest.raises(ContractError, match="control database root has an invalid component"):
        ControlStore(selected)
    assert not selected.parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
@pytest.mark.parametrize("nested", [False, True])
def test_control_store_rejects_junction_root_before_sqlite_creation(
    tmp_path: Path, nested: bool,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = tmp_path / "linked"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        root = junction / "control" if nested else junction
        with pytest.raises(ContractError, match="regular directory"):
            ControlStore(root)
        assert list(outside.iterdir()) == []
    finally:
        junction.rmdir()


def test_control_store_rejects_replaced_root_before_sqlite_contact(
    tmp_path: Path,
) -> None:
    root = tmp_path / "control"
    store = ControlStore(root)
    root.rename(tmp_path / "original-control")
    root.mkdir()
    with pytest.raises(ContractError, match="database parent changed"):
        store._connect().close()
    assert list(root.iterdir()) == []


def test_expiring_one_way_tokens_and_roles(tmp_path: Path) -> None:
    store, owner, raw_token = bootstrapped(tmp_path)
    store.add_member(owner, "lab", user_id="bob", display_name="Bob", role="operator")
    store.add_member(owner, "lab", user_id="eve", display_name="Eve", role="viewer")
    bob_token = store.issue_token(owner, "lab", "bob")
    eve_token = store.issue_token(owner, "lab", "eve")
    bob = store.authenticate(bob_token)
    eve = store.authenticate(eve_token)
    assert owner.user_id == "alice" and bob.user_id == "bob"
    database_bytes = store.database_path.read_bytes()
    assert raw_token.encode() not in database_bytes and bob_token.encode() not in database_bytes
    with pytest.raises(ContractError, match="operator"):
        store.put_record(eve, "lab", kind="persona", record_id="p1", payload={"digest": "x"}, expected_revision=0)
    created = store.put_record(bob, "lab", kind="persona", record_id="p1", payload={"digest": "x"}, expected_revision=0)
    assert created["revision"] == 1
    assert store.get_record(eve, "lab", kind="persona", record_id="p1")["payload"] == {"digest": "x"}
    expired = datetime.now(timezone.utc) + timedelta(days=2)
    with pytest.raises(ContractError, match="expired"):
        store.authenticate(eve_token, now=expired)
    with pytest.raises(ContractError, match="owner"):
        store.revoke_token(eve, "lab", raw_token.split(".", 2)[1])
    store.revoke_token(owner, "lab", bob_token.split(".", 2)[1])
    with pytest.raises(ContractError, match="invalid"):
        store.authenticate(bob_token)
    assert store.verify_audit(owner, "lab")["valid"] is True


def test_duplicate_member_and_workspace_are_contract_errors(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.add_member(owner, "lab", user_id="bob", display_name="Bob", role="viewer")
    with pytest.raises(ContractError, match="already a workspace member"):
        store.add_member(owner, "lab", user_id="bob", display_name="Bob", role="viewer")

    store.create_workspace(owner, workspace_id="lab2", name="Lab 2")
    with pytest.raises(ContractError, match="workspace already exists"):
        store.create_workspace(owner, workspace_id="lab2", name="New Name")
    assert store.verify_audit(owner, "lab")["valid"] is True
    assert store.verify_audit(owner, "lab2")["valid"] is True


def test_issued_token_is_limited_to_its_workspace(tmp_path: Path) -> None:
    store, alice, _ = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    store.add_member(alice, "lab", user_id="bob", display_name="Bob", role="owner")
    store.add_member(alice, "lab2", user_id="bob", display_name="Bob", role="owner")
    bob = store.authenticate(store.issue_token(alice, "lab", "bob"))

    assert store.fleet_status(bob, "lab")["workspace_id"] == "lab"
    with pytest.raises(ContractError, match="token scope"):
        store.fleet_status(bob, "lab2")
    with pytest.raises(ContractError, match="token scope"):
        store.create_workspace(bob, workspace_id="lab3", name="Lab 3")
    renewed = store.authenticate(store.issue_token(bob, "lab", "bob"))
    with pytest.raises(ContractError, match="token scope"):
        store.fleet_status(renewed, "lab2")


def test_bootstrap_owner_self_renewal_keeps_global_workspace_access(tmp_path: Path) -> None:
    store, alice, _ = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    renewed = store.authenticate(store.issue_token(alice, "lab", "alice"))

    assert store.fleet_status(renewed, "lab2")["workspace_id"] == "lab2"


def test_workspace_owner_cannot_revoke_another_workspaces_token(tmp_path: Path) -> None:
    store, alice, _ = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    store.add_member(alice, "lab", user_id="bob", display_name="Bob", role="viewer")
    store.add_member(alice, "lab2", user_id="bob", display_name="Bob", role="viewer")
    token = store.issue_token(alice, "lab", "bob")
    token_id = token.split(".", 2)[1]

    with pytest.raises(ContractError, match="token scope"):
        store.revoke_token(alice, "lab2", token_id)
    assert store.authenticate(token).user_id == "bob"


def test_scoped_token_cannot_revoke_own_other_scope_or_global_token(
    tmp_path: Path,
) -> None:
    store, alice, bootstrap_token = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    store.add_member(alice, "lab", user_id="bob", display_name="Bob", role="owner")
    store.add_member(alice, "lab2", user_id="bob", display_name="Bob", role="owner")
    bob_lab = store.authenticate(store.issue_token(alice, "lab", "bob"))
    bob_lab2_token = store.issue_token(alice, "lab2", "bob")

    with pytest.raises(ContractError, match="token scope"):
        store.revoke_token(bob_lab, "lab", bob_lab2_token.split(".", 2)[1])
    assert store.authenticate(bob_lab2_token).scope_workspace_id == "lab2"

    scoped_alice = store.authenticate(store.issue_token(bob_lab, "lab", "alice"))
    with pytest.raises(ContractError, match="token scope"):
        store.revoke_token(scoped_alice, "lab", bootstrap_token.split(".", 2)[1])
    assert store.authenticate(bootstrap_token).scope_workspace_id is None


def test_legacy_tokens_gain_workspace_scopes_on_upgrade(tmp_path: Path) -> None:
    store, alice, bootstrap_token = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    store.add_member(alice, "lab", user_id="bob", display_name="Bob", role="owner")
    store.add_member(alice, "lab2", user_id="bob", display_name="Bob", role="owner")
    bob_token = store.issue_token(alice, "lab", "bob")
    bob = store.authenticate(bob_token)
    bob_renewal = store.issue_token(bob, "lab", "bob")
    alice_renewal = store.issue_token(alice, "lab", "alice")

    # Recreate a valid v1 audit chain and token table in the old on-disk shape.
    with sqlite3.connect(store.database_path) as db:
        db.row_factory = sqlite3.Row
        previous_by_workspace: dict[str, str] = {}
        for row in db.execute("SELECT * FROM audit ORDER BY seq").fetchall():
            details = json.loads(row["details_json"])
            if row["action"] == "token.issue":
                details.pop("scope")
            details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
            previous = previous_by_workspace.get(row["workspace_id"], "0" * 64)
            body = {
                "workspace_id": row["workspace_id"],
                "actor_id": row["actor_id"],
                "action": row["action"],
                "resource": row["resource"],
                "details": details,
                "created_at": row["created_at"],
                "previous_sha256": previous,
            }
            digest = hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            db.execute(
                "UPDATE audit SET details_json=?,previous_sha256=?,event_sha256=? "
                "WHERE seq=?",
                (details_json, previous, digest, row["seq"]),
            )
            previous_by_workspace[row["workspace_id"]] = digest
        db.execute("ALTER TABLE tokens DROP COLUMN scope_workspace_id")
        db.execute("ALTER TABLE tokens DROP COLUMN scope_version")
        db.execute(
            "UPDATE meta SET value='browser-core.control/1' WHERE key='schema'"
        )

    upgraded = ControlStore(tmp_path)
    assert upgraded.authenticate(bootstrap_token).scope_workspace_id is None
    assert upgraded.authenticate(alice_renewal).scope_workspace_id is None
    for token in (bob_token, bob_renewal):
        principal = upgraded.authenticate(token)
        assert principal.scope_workspace_id == "lab"
        with pytest.raises(ContractError, match="token scope"):
            upgraded.fleet_status(principal, "lab2")
    assert upgraded.verify_audit(upgraded.authenticate(bootstrap_token), "lab")["valid"]
    with sqlite3.connect(upgraded.database_path) as db:
        assert db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0] == control_module.CONTROL_SCHEMA
    assert ControlStore(tmp_path).authenticate(bob_token).scope_workspace_id == "lab"


def test_legacy_scope_upgrade_rolls_back_on_missing_issue(tmp_path: Path) -> None:
    store, alice, _ = bootstrapped(tmp_path)
    store.add_member(alice, "lab", user_id="bob", display_name="Bob", role="viewer")
    bob_token = store.issue_token(alice, "lab", "bob")
    token_id = bob_token.split(".", 2)[1]
    with sqlite3.connect(store.database_path) as db:
        db.execute("ALTER TABLE tokens DROP COLUMN scope_workspace_id")
        db.execute("ALTER TABLE tokens DROP COLUMN scope_version")
        db.execute("UPDATE meta SET value='browser-core.control/1' WHERE key='schema'")
        db.execute(
            "DELETE FROM audit WHERE action='token.issue' AND resource=?",
            (f"token:{token_id}",),
        )

    with pytest.raises(ContractError, match="legacy token issue provenance"):
        ControlStore(tmp_path)
    with sqlite3.connect(store.database_path) as db:
        assert db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0] == "browser-core.control/1"
        columns = {row[1] for row in db.execute("PRAGMA table_info(tokens)")}
        assert "scope_workspace_id" not in columns


@pytest.mark.parametrize("column", ["scope_workspace_id", "scope_version"])
def test_current_schema_rejects_missing_token_scope_column(
    tmp_path: Path, column: str
) -> None:
    store, _, _ = bootstrapped(tmp_path)
    with sqlite3.connect(store.database_path) as db:
        db.execute(f"ALTER TABLE tokens DROP COLUMN {column}")
    with pytest.raises(ContractError, match="token scope column"):
        ControlStore(tmp_path)


def test_old_writer_token_after_upgrade_cannot_authenticate(tmp_path: Path) -> None:
    store, alice, _ = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    store.add_member(alice, "lab", user_id="bob", display_name="Bob", role="owner")
    store.add_member(alice, "lab2", user_id="bob", display_name="Bob", role="owner")
    token_id = "oldwriter000001"
    secret = "oldwritersecret00000000000000000000"
    salt = b"x" * 16
    verifier = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 240_000)
    now = datetime.now(timezone.utc)
    with store._transaction() as db:
        db.execute(
            "INSERT INTO tokens(id,user_id,salt,verifier,expires_at,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                token_id,
                "bob",
                salt,
                verifier,
                (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                now.isoformat().replace("+00:00", "Z"),
            ),
        )
        store._audit(
            db,
            "lab",
            "alice",
            "token.issue",
            f"token:{token_id}",
            {"user_id": "bob", "ttl_hours": 1},
        )

    with pytest.raises(ContractError, match="bearer token is invalid"):
        store.authenticate(f"bc1.{token_id}.{secret}")


def test_legacy_scope_upgrade_rejects_unhashable_saved_scope(tmp_path: Path) -> None:
    store, _, token = bootstrapped(tmp_path)
    token_id = token.split(".", 2)[1]
    with sqlite3.connect(store.database_path) as db:
        db.execute("ALTER TABLE tokens DROP COLUMN scope_workspace_id")
        db.execute("ALTER TABLE tokens DROP COLUMN scope_version")
        db.execute("UPDATE meta SET value='browser-core.control/1' WHERE key='schema'")
        db.execute(
            "UPDATE audit SET details_json=? WHERE action='token.issue' AND resource=?",
            ('{"scope":[],"ttl_hours":24,"user_id":"alice"}', f"token:{token_id}"),
        )
    with pytest.raises(ContractError, match="legacy token issue provenance"):
        ControlStore(tmp_path)


def test_workspace_owner_cannot_rename_an_existing_global_user(tmp_path: Path) -> None:
    store, alice, _ = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    store.add_member(alice, "lab", user_id="bob", display_name="Bob", role="viewer")
    store.add_member(
        alice, "lab2", user_id="charlie", display_name="Charlie", role="owner"
    )
    charlie = store.authenticate(store.issue_token(alice, "lab2", "charlie"))

    with pytest.raises(ContractError, match="display name conflict"):
        store.add_member(
            charlie, "lab2", user_id="bob", display_name="Mallory", role="viewer"
        )
    with sqlite3.connect(store.database_path) as db:
        assert db.execute("SELECT display_name FROM users WHERE id='bob'").fetchone()[0] == "Bob"
        assert db.execute(
            "SELECT 1 FROM memberships WHERE workspace_id='lab2' AND user_id='bob'"
        ).fetchone() is None


def test_corrupt_saved_membership_role_fails_as_contract_error(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE memberships SET role=? WHERE workspace_id=? AND user_id=?",
            ("unknown", "lab", "alice"),
        )
    with pytest.raises(ContractError, match="stored workspace role is invalid"):
        store.fleet_status(owner, "lab")


@pytest.mark.parametrize(
    "method,bad",
    [
        ("authenticate", "bc1.abcdefghijkl." + "a" * 4096),
        ("authenticate", "bc1.abcdefghijkl.\ud800"),
        ("authenticate_worker", "bcw1.worker-a." + "a" * 4096),
        ("authenticate_worker", "bcw1.worker-a.\ud800"),
    ],
    ids=["user-overlong", "user-surrogate", "worker-overlong", "worker-surrogate"],
)
def test_authentication_rejects_malformed_tokens_before_database_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, bad: str
) -> None:
    store, _, _ = bootstrapped(tmp_path)
    monkeypatch.setattr(store, "_connect", lambda: pytest.fail("invalid token reached database"))
    with pytest.raises(ContractError, match="token is invalid"):
        getattr(store, method)(bad)


def test_authentication_rejects_naive_comparison_time(tmp_path: Path) -> None:
    store, _, token = bootstrapped(tmp_path)
    with pytest.raises(ContractError, match="operation time"):
        store.authenticate(token, now=datetime(2026, 10, 24))


@pytest.mark.parametrize(
    "credential,field",
    [
        ("user", "salt"),
        ("user", "verifier"),
        ("worker", "token_salt"),
        ("worker", "token_verifier"),
    ],
)
def test_authentication_rejects_corrupt_saved_credential_material(
    tmp_path: Path, credential: str, field: str,
) -> None:
    store, owner, user_token = bootstrapped(tmp_path)
    registration = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    table = "tokens" if credential == "user" else "workers"
    identity = user_token.split(".", 2)[1] if credential == "user" else "worker-a"
    token = user_token if credential == "user" else registration["worker_token"]
    private_marker = "private-route-marker"
    with sqlite3.connect(store.database_path) as db:
        db.execute(f"UPDATE {table} SET {field}=? WHERE id=?", (private_marker, identity))
    method = store.authenticate if credential == "user" else store.authenticate_worker
    with pytest.raises(ContractError) as failure:
        method(token)
    assert private_marker not in str(failure.value)


def test_bootstrap_rolls_back_when_token_issuance_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ControlStore(tmp_path)
    original_audit = store._audit

    def fail_token_audit(*args: object, **kwargs: object) -> None:
        if args[3] == "token.issue":
            raise ContractError("injected token issuance failure")
        original_audit(*args, **kwargs)

    monkeypatch.setattr(store, "_audit", fail_token_audit)
    with pytest.raises(ContractError, match="injected token issuance failure"):
        store.bootstrap(
            workspace_id="lab", workspace_name="Lab", owner_id="alice", owner_name="Alice"
        )
    with sqlite3.connect(store.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0
    monkeypatch.setattr(store, "_audit", original_audit)
    result = store.bootstrap(
        workspace_id="lab", workspace_name="Lab", owner_id="alice", owner_name="Alice"
    )
    assert store.authenticate(result["token"]).user_id == "alice"


def test_optimistic_revision_and_audit_tamper_detection(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    first = store.put_record(owner, "lab", kind="route", record_id="us", payload={"country": "US"}, expected_revision=0)
    assert first["revision"] == 1
    with pytest.raises(ContractError, match="revision conflict"):
        store.put_record(owner, "lab", kind="route", record_id="us", payload={"country": "CA"}, expected_revision=0)
    second = store.put_record(owner, "lab", kind="route", record_id="us", payload={"country": "CA"}, expected_revision=1)
    assert second["revision"] == 2
    assert store.verify_audit(owner, "lab")["valid"] is True
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE audit SET details_json='{}' WHERE seq=(SELECT MAX(seq) FROM audit)")
        db.commit()
    with pytest.raises(ContractError, match="event mismatch"):
        store.verify_audit(owner, "lab")


@pytest.mark.parametrize("digest", [b"private-route-marker", "private-route-marker"])
def test_mutation_rejects_corrupt_saved_audit_head(
    tmp_path: Path, digest: object,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE audit SET event_sha256=? WHERE seq=(SELECT MAX(seq) FROM audit)", (digest,))
    with pytest.raises(ContractError, match="audit head"):
        store.put_record(
            owner, "lab", kind="result", record_id="receipt", payload={}, expected_revision=0
        )
    with sqlite3.connect(store.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 0


@pytest.mark.parametrize("field", ["revision", "updated_at"])
def test_record_view_rejects_corrupt_saved_scalar_fields(tmp_path: Path, field: str) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.put_record(
        owner, "lab", kind="result", record_id="receipt", payload={}, expected_revision=0
    )
    private_marker = "private-route-marker"
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            f"UPDATE records SET {field}=? WHERE workspace_id=? AND kind=? AND id=?",
            (private_marker, "lab", "result", "receipt"),
        )
    with pytest.raises(ContractError) as failure:
        store.get_record(owner, "lab", kind="result", record_id="receipt")
    assert private_marker not in str(failure.value)


def test_record_revision_cannot_advance_past_public_limit(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.put_record(
        owner, "lab", kind="result", record_id="receipt", payload={}, expected_revision=0
    )
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE records SET revision=? WHERE workspace_id=? AND kind=? AND id=?",
            (control_module.MAX_CONTROL_REVISION, "lab", "result", "receipt"),
        )
    with pytest.raises(ContractError, match="revision"):
        store.put_record(
            owner,
            "lab",
            kind="result",
            record_id="receipt",
            payload={"new": True},
            expected_revision=control_module.MAX_CONTROL_REVISION,
        )
    with sqlite3.connect(store.database_path) as db:
        assert db.execute(
            "SELECT revision FROM records WHERE workspace_id=? AND kind=? AND id=?",
            ("lab", "result", "receipt"),
        ).fetchone()[0] == control_module.MAX_CONTROL_REVISION


def test_audit_verification_releases_read_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    opened: list[sqlite3.Connection] = []
    original_connect = store._connect

    def tracked_connect() -> sqlite3.Connection:
        connection = original_connect()
        opened.append(connection)
        return connection

    monkeypatch.setattr(store, "_connect", tracked_connect)
    assert store.verify_audit(owner, "lab")["valid"] is True
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")


def test_control_store_rejects_non_finite_direct_api_payloads(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)

    with pytest.raises(ContractError, match="JSON serializable"):
        store.put_record(
            owner,
            "lab",
            kind="result",
            record_id="nan",
            payload={"score": float("nan")},
            expected_revision=0,
        )


@pytest.mark.parametrize("field", ["workspace_name", "owner_name"])
def test_bootstrap_rejects_unencodable_names_as_contract_errors(
    tmp_path: Path, field: str,
) -> None:
    store = ControlStore(tmp_path)
    arguments = {
        "workspace_id": "lab",
        "workspace_name": "Lab",
        "owner_id": "alice",
        "owner_name": "Alice",
    }
    arguments[field] = "\ud800"
    with pytest.raises(ContractError, match="name is invalid"):
        store.bootstrap(**arguments)


@pytest.mark.parametrize("field", ["workspace_name", "owner_name"])
@pytest.mark.parametrize(
    "value",
    [
        "Bearer abcdefghijklmnop",
        "wss://127.0.0.1/devtools/page/private",
        "line one\nline two",
    ],
)
def test_bootstrap_rejects_credential_or_control_text_in_display_names(
    tmp_path: Path, field: str, value: str,
) -> None:
    store = ControlStore(tmp_path)
    arguments = {
        "workspace_id": "lab",
        "workspace_name": "Lab",
        "owner_id": "alice",
        "owner_name": "Alice",
    }
    arguments[field] = value
    with pytest.raises(ContractError, match="name is invalid"):
        store.bootstrap(**arguments)


@pytest.mark.parametrize(
    "operation",
    [
        "workspace-name",
        "member-name",
        "worker-name",
        "member-role",
        "job-kind",
        "job-idempotency",
    ],
)
def test_control_store_rejects_malformed_text_and_types_before_database_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    monkeypatch.setattr(store, "_connect", lambda: pytest.fail("invalid input reached database"))
    diagnostics = {
        "workspace-name": "workspace name is invalid",
        "member-name": "display name is invalid",
        "worker-name": "worker name is invalid",
        "member-role": "workspace role is invalid",
        "job-kind": "job kind is not in the reviewed allowlist",
        "job-idempotency": "job idempotency key is invalid",
    }

    def call() -> None:
        if operation == "workspace-name":
            store.create_workspace(owner, workspace_id="other", name="\ud800")
        elif operation == "member-name":
            store.add_member(owner, "lab", user_id="bob", display_name="\ud800", role="viewer")
        elif operation == "worker-name":
            store.register_worker(
                owner, "lab", "worker-b", name="\ud800", capabilities=["chromium"], max_slots=1
            )
        elif operation == "member-role":
            store.add_member(owner, "lab", user_id="bob", display_name="Bob", role=[])
        elif operation == "job-kind":
            store.enqueue_job(
                owner, "lab", kind=[], payload={}, requirements=[], idempotency_key="bad-kind"
            )
        else:
            store.enqueue_job(
                owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="\ud800"
            )

    with pytest.raises(ContractError, match=diagnostics[operation]):
        call()


def test_control_store_rejects_naive_saved_timestamp_before_comparison() -> None:
    with pytest.raises(ContractError, match="timestamp is invalid"):
        control_module._parse_time("2026-10-24T12:00:00")


@pytest.mark.parametrize("field,value", [("max_running", True), ("max_queued", "10"), ("max_running", [])])
def test_workspace_quotas_reject_nonintegers_before_database_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    store = ControlStore(tmp_path)
    monkeypatch.setattr(store, "_connect", lambda: pytest.fail("invalid quota reached database"))
    bootstrap_args = {
        "workspace_id": "lab",
        "workspace_name": "Lab",
        "owner_id": "alice",
        "owner_name": "Alice",
        field: value,
    }
    with pytest.raises(ContractError, match="workspace quotas are invalid"):
        store.bootstrap(**bootstrap_args)

    store, owner, _ = bootstrapped(tmp_path / "created")
    monkeypatch.setattr(store, "_connect", lambda: pytest.fail("invalid quota reached database"))
    with pytest.raises(ContractError, match="workspace quotas are invalid"):
        store.create_workspace(owner, workspace_id="another", name="Another", **{field: value})


@pytest.mark.parametrize("identifiers", [["chromium", []], ["chromium", 1]])
def test_worker_and_job_identifier_lists_reject_mixed_types_before_database_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identifiers: list[object]
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    monkeypatch.setattr(store, "_connect", lambda: pytest.fail("invalid identifiers reached database"))
    with pytest.raises(ContractError, match="worker capabilities"):
        store.register_worker(
            owner, "lab", "worker-a", name="A", capabilities=identifiers, max_slots=1
        )
    with pytest.raises(ContractError, match="job requirements"):
        store.enqueue_job(
            owner,
            "lab",
            kind="browser-eval",
            payload={},
            requirements=identifiers,
            idempotency_key="bad-identifiers",
        )


@pytest.mark.parametrize("value", [True, "24", []])
def test_token_ttl_rejects_nonintegers_before_database_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    store = ControlStore(tmp_path)
    monkeypatch.setattr(store, "_connect", lambda: pytest.fail("invalid TTL reached database"))
    with pytest.raises(ContractError, match="token TTL is invalid"):
        store.bootstrap(
            workspace_id="lab",
            workspace_name="Lab",
            owner_id="alice",
            owner_name="Alice",
            token_ttl_hours=value,
        )


def test_control_store_operation_intent_rejects_before_database_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(
        owner,
        "lab",
        "worker-a",
        name="A",
        capabilities=["chromium"],
        max_slots=1,
    )
    worker = store.authenticate_worker(registered["worker_token"])
    monkeypatch.setattr(
        store,
        "_connect",
        lambda: pytest.fail("invalid operation reached database contact"),
    )

    cases = [
        (
            lambda: store.issue_token(owner, "lab", ["bob"]),  # type: ignore[arg-type]
            "user ID",
        ),
        (
            lambda: store.issue_token(owner, "lab", "alice", ttl_hours=True),
            "token TTL",
        ),
        (
            lambda: store.revoke_token(owner, "lab", ["token-id"]),  # type: ignore[arg-type]
            "token ID",
        ),
        (
            lambda: store.get_artifact(owner, "lab", ["digest"]),  # type: ignore[arg-type]
            "artifact digest",
        ),
        (
            lambda: store.put_record(
                owner,
                "lab",
                kind="persona",
                record_id="owned",
                payload={},
                expected_revision=[],  # type: ignore[arg-type]
            ),
            "revision",
        ),
        (
            lambda: store.lease_job(worker, lease_seconds="30"),  # type: ignore[arg-type]
            "lease duration",
        ),
        (
            lambda: store.lease_job(
                worker,
                lease_seconds=30,
                now=datetime(2026, 8, 11),
            ),
            "operation time",
        ),
        (
            lambda: store.heartbeat_lease(
                worker,
                "job-one",
                ["private-token"],  # type: ignore[arg-type]
                extend_seconds=60,
            ),
            "lease token",
        ),
        (
            lambda: store.heartbeat_lease(
                worker,
                "job-one",
                "lease-token",
                extend_seconds=True,
            ),
            "lease extension",
        ),
        (
            lambda: store.complete_job(
                worker,
                "job-one",
                "lease-token",
                succeeded=1,  # type: ignore[arg-type]
                result={},
            ),
            "success flag",
        ),
    ]
    for operation, message in cases:
        with pytest.raises(ContractError, match=message):
            operation()


def test_record_reads_strictly_decode_and_digest_bind_database_json(
    tmp_path: Path,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.put_record(
        owner,
        "lab",
        kind="result",
        record_id="receipt",
        payload={"verdict": "pass"},
        expected_revision=0,
    )
    duplicate = '{"verdict":"pass","verdict":"fail"}'
    duplicate_digest = control_module.hashlib.sha256(duplicate.encode()).hexdigest()
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE records SET payload_json=?,payload_sha256=? WHERE id='receipt'",
            (duplicate, duplicate_digest),
        )
        db.commit()
    with pytest.raises(ContractError, match="duplicate key"):
        store.get_record(owner, "lab", kind="result", record_id="receipt")

    canonical = '{"verdict":"changed"}'
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE records SET payload_json=? WHERE id='receipt'",
            (canonical,),
        )
        db.commit()
    with pytest.raises(ContractError, match="stored digest"):
        store.get_record(owner, "lab", kind="result", record_id="receipt")


def test_scheduler_rejects_corrupt_requirement_and_capability_rows(
    tmp_path: Path,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(
        owner,
        "lab",
        "worker-a",
        name="A",
        capabilities=["chromium"],
        max_slots=1,
    )
    worker = store.authenticate_worker(registered["worker_token"])
    job = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"arm": "core"},
        requirements=["chromium"],
        idempotency_key="corrupt-row",
    )
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE jobs SET requirements_json='[\"chromium\",\"chromium\"]' WHERE id=?",
            (job["id"],),
        )
        db.commit()
    with pytest.raises(ContractError, match="stored list"):
        store.lease_job(worker)

    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE jobs SET requirements_json='[\"chromium\"]' WHERE id=?",
            (job["id"],),
        )
        db.execute(
            "UPDATE workers SET capabilities_json='[\"chromium\",\"chromium\"]' WHERE id='worker-a'"
        )
        db.commit()
    with pytest.raises(ContractError, match="stored list"):
        store.lease_job(worker)


@pytest.mark.parametrize("field", ["worker-slots", "workspace-running"])
def test_scheduler_rejects_corrupt_saved_capacity_fields(
    tmp_path: Path, field: str,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registration = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registration["worker_token"])
    store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="capacity"
    )
    private_marker = "private-route-marker"
    with sqlite3.connect(store.database_path) as db:
        if field == "worker-slots":
            db.execute("UPDATE workers SET max_slots=? WHERE id=?", (private_marker, "worker-a"))
        else:
            db.execute("UPDATE workspaces SET max_running=? WHERE id=?", (private_marker, "lab"))
    with pytest.raises(ContractError) as failure:
        store.lease_job(worker)
    assert private_marker not in str(failure.value)


@pytest.mark.parametrize("transition", ["lease", "complete", "cancel"])
def test_job_transition_rejects_corrupt_saved_row_before_commit(
    tmp_path: Path, transition: str,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registration = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registration["worker_token"])
    job = store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="transition"
    )
    lease = store.lease_job(worker) if transition == "complete" else None
    expected_state = "running" if lease is not None else "queued"
    expected_attempt = 1 if lease is not None else 0
    private_marker = "private-route-marker"
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE jobs SET priority=? WHERE id=?", (private_marker, job["id"]))
    with pytest.raises(ContractError) as failure:
        if transition == "lease":
            store.lease_job(worker)
        elif transition == "complete":
            assert lease is not None
            store.complete_job(
                worker, job["id"], lease["lease_token"], succeeded=True, result={}
            )
        else:
            store.cancel_job(owner, "lab", job["id"])
    assert private_marker not in str(failure.value)
    with sqlite3.connect(store.database_path) as db:
        state, attempt = db.execute(
            "SELECT state,attempt FROM jobs WHERE id=?", (job["id"],)
        ).fetchone()
    assert (state, attempt) == (expected_state, expected_attempt)


def test_scheduler_does_not_commit_lease_at_saved_attempt_limit(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registration = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registration["worker_token"])
    job = store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="attempt-limit"
    )
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE jobs SET attempt=max_attempts WHERE id=?", (job["id"],))
    with pytest.raises(ContractError, match="attempt"):
        store.lease_job(worker)
    with sqlite3.connect(store.database_path) as db:
        assert db.execute(
            "SELECT state,attempt FROM jobs WHERE id=?", (job["id"],)
        ).fetchone() == ("queued", 3)


def test_enqueue_rejects_corrupt_saved_queued_quota(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    private_marker = "private-route-marker"
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE workspaces SET max_queued=? WHERE id=?", (private_marker, "lab"))
    with pytest.raises(ContractError) as failure:
        store.enqueue_job(
            owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="quota"
        )
    assert private_marker not in str(failure.value)


def test_scheduler_does_not_lease_an_undeliverable_payload(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registration = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registration["worker_token"])
    job = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"arm": "original"},
        requirements=["chromium"],
        idempotency_key="payload-corrupt",
    )
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE jobs SET payload_json=? WHERE id=?", ('{"arm":"changed"}', job["id"]))
        db.commit()
    with pytest.raises(ContractError, match="stored digest"):
        store.lease_job(worker)
    with sqlite3.connect(store.database_path) as db:
        state, attempt, lease_worker = db.execute(
            "SELECT state,attempt,lease_worker_id FROM jobs WHERE id=?", (job["id"],)
        ).fetchone()
    assert (state, attempt, lease_worker) == ("queued", 0, None)


@pytest.mark.parametrize(
    "field",
    ["kind", "payload_sha256", "result_sha256", "state", "priority", "created_at"],
)
def test_job_public_view_rejects_corrupt_saved_scalar_fields(
    tmp_path: Path, field: str,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    job = store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="scalar"
    )
    private_marker = "private-route-marker"
    with sqlite3.connect(store.database_path) as db:
        db.execute(f"UPDATE jobs SET {field}=? WHERE id=?", (private_marker, job["id"]))
    with pytest.raises(ContractError) as failure:
        store.list_jobs(owner, "lab")
    assert private_marker not in str(failure.value)


def test_job_list_marks_when_saved_population_exceeds_page(tmp_path: Path) -> None:
    store = ControlStore(tmp_path)
    owner = store.authenticate(store.bootstrap(
        workspace_id="lab", workspace_name="Lab", owner_id="alice",
        owner_name="Alice", max_queued=200,
    )["token"])
    for index in range(100):
        store.enqueue_job(
            owner, "lab", kind="browser-eval", payload={}, requirements=[],
            idempotency_key=f"job-{index}",
        )
    exact_page = store.list_jobs(owner, "lab")
    assert exact_page["limit"] == len(exact_page["jobs"]) == 100
    assert exact_page["jobs_truncated"] is False

    store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[],
        idempotency_key="job-over-page",
    )
    overflow = store.list_jobs(owner, "lab")
    assert overflow["limit"] == len(overflow["jobs"]) == 100
    assert overflow["jobs_truncated"] is True


def test_idempotent_enqueue_rejects_a_corrupt_saved_payload(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    request = {
        "kind": "browser-eval",
        "payload": {"arm": "original"},
        "requirements": ["chromium"],
        "idempotency_key": "saved-payload-corrupt",
    }
    job = store.enqueue_job(owner, "lab", **request)
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE jobs SET payload_json=? WHERE id=?",
            ('{"arm":"changed"}', job["id"]),
        )
        db.commit()

    with pytest.raises(ContractError, match="stored digest"):
        store.enqueue_job(owner, "lab", **request)


def test_shared_worker_can_only_be_reregistered_from_its_origin_workspace(
    tmp_path: Path,
) -> None:
    store, alice, _ = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    store.add_member(
        alice, "lab2", user_id="bob", display_name="Bob", role="owner"
    )
    bob = store.authenticate(store.issue_token(alice, "lab2", "bob"))
    original = store.register_worker(
        alice, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    store.add_worker_scope(alice, "lab2", "worker-a")

    with pytest.raises(ContractError, match="registration workspace"):
        store.register_worker(
            bob, "lab2", "worker-a", name="Taken Over", capabilities=["chromium"], max_slots=1
        )
    assert store.authenticate_worker(original["worker_token"]).worker_id == "worker-a"

    rotated = store.register_worker(
        alice, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    assert rotated["revision"] == 2
    with pytest.raises(ContractError, match="worker token is invalid"):
        store.authenticate_worker(original["worker_token"])
    assert store.authenticate_worker(rotated["worker_token"]).worker_id == "worker-a"


def test_other_workspace_owner_cannot_attach_foreign_worker(tmp_path: Path) -> None:
    store, alice, _ = bootstrapped(tmp_path)
    store.create_workspace(alice, workspace_id="lab2", name="Lab 2")
    store.add_member(alice, "lab2", user_id="bob", display_name="Bob", role="owner")
    bob = store.authenticate(store.issue_token(alice, "lab2", "bob"))
    store.register_worker(
        alice, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )

    with pytest.raises(ContractError):
        store.add_worker_scope(bob, "lab2", "worker-a")
    with sqlite3.connect(store.database_path) as db:
        scoped = db.execute(
            "SELECT 1 FROM worker_scopes WHERE worker_id=? AND workspace_id=?",
            ("worker-a", "lab2"),
        ).fetchone()
    assert scoped is None


@pytest.mark.parametrize("revision", ["private-route-marker", control_module.MAX_CONTROL_REVISION])
def test_worker_reregistration_rejects_invalid_saved_revision(
    tmp_path: Path, revision: object,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    original = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE workers SET revision=? WHERE id=?", (revision, "worker-a"))
    with pytest.raises(ContractError, match="revision"):
        store.register_worker(
            owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
        )
    assert store.authenticate_worker(original["worker_token"]).worker_id == "worker-a"


def test_content_addressed_artifact_visibility_and_integrity(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.add_member(owner, "lab", user_id="viewer", display_name="Viewer", role="viewer")
    viewer = store.authenticate(store.issue_token(owner, "lab", "viewer"))
    public_evidence = b'{"schema":"browser-core.shared-evidence/1","verdict":"pass"}'
    artifact = store.put_artifact(
        owner, "lab", public_evidence, visibility="viewer", media_type="application/json"
    )
    assert store.get_artifact(viewer, "lab", artifact["sha256"]) == public_evidence
    with pytest.raises(ContractError, match="application/json"):
        store.put_artifact(owner, "lab", b"opaque", visibility="viewer", media_type="application/octet-stream")
    with pytest.raises(ContractError, match="restricted browser-control"):
        store.put_artifact(
            owner,
            "lab",
            b'{"cdp_endpoint":"http://127.0.0.1:9222"}',
            visibility="viewer",
            media_type="application/json",
        )
    private = store.put_artifact(owner, "lab", b"operator-evidence", visibility="operator")
    with pytest.raises(ContractError, match="visibility"):
        store.get_artifact(viewer, "lab", private["sha256"])
    path = store.artifact_root / artifact["sha256"][:2] / artifact["sha256"]
    path.write_bytes(b"tampered")
    with pytest.raises(ContractError, match="integrity"):
        store.get_artifact(owner, "lab", artifact["sha256"])


def test_corrupt_saved_artifact_visibility_fails_as_contract_error(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    artifact = store.put_artifact(owner, "lab", b"owned-content")
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE artifacts SET visibility=? WHERE workspace_id=? AND sha256=?",
            ("unknown", "lab", artifact["sha256"]),
        )
    with pytest.raises(ContractError, match="stored artifact visibility is invalid"):
        store.get_artifact(owner, "lab", artifact["sha256"])


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_artifact_put_rejects_junction_before_creating_external_directories(
    tmp_path: Path,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    target = tmp_path / "outside-artifacts"
    target.mkdir()
    junction = tmp_path / "artifacts"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        assert not junction.is_symlink()
        with pytest.raises(ContractError):
            store.put_artifact(owner, "lab", b"owned-content")
        assert list(target.iterdir()) == []
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_artifact_put_rejects_parent_swapped_after_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    content = b"owned-content"
    digest = control_module.hashlib.sha256(content).hexdigest()
    parent = store.artifact_root / digest[:2]
    unrelated = tmp_path / "unrelated-artifacts"
    unrelated.mkdir()
    foreign_artifact = unrelated / digest
    foreign_artifact.write_bytes(content)
    moved_parent = tmp_path / "moved-artifact-parent"
    original_prepare = control_module.prepare_owned_directory_parent
    junction_created = False

    def swap_after_preparation(path: Path, *, label: str) -> None:
        nonlocal junction_created
        original_prepare(path, label=label)
        if label != "content-addressed artifact parent":
            return
        path.rename(moved_parent)
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(path), str(unrelated)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("directory junction creation is unavailable")
        junction_created = True

    monkeypatch.setattr(
        control_module, "prepare_owned_directory_parent", swap_after_preparation
    )
    try:
        with pytest.raises(ContractError, match="regular directory"):
            store.put_artifact(owner, "lab", content)
        with store._connect() as db:
            saved = db.execute(
                "SELECT 1 FROM artifacts WHERE workspace_id=? AND sha256=?",
                ("lab", digest),
            ).fetchone()
        assert saved is None
        assert foreign_artifact.read_bytes() == content
    finally:
        if junction_created:
            parent.rmdir()


def test_artifact_put_rejects_parent_swapped_after_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    content = b"owned-content"
    digest = hashlib.sha256(content).hexdigest()
    parent = store.artifact_root / digest[:2]
    moved_parent = tmp_path / "moved-artifact-parent"
    original_audit = store._audit

    def swap_after_audit(*args: object, **kwargs: object) -> None:
        original_audit(*args, **kwargs)
        if args[3] == "artifact.put":
            parent.rename(moved_parent)
            parent.mkdir()
            (parent / digest).write_bytes(b"foreign-content")

    monkeypatch.setattr(store, "_audit", swap_after_audit)
    with pytest.raises(ContractError, match="artifact parent changed"):
        store.put_artifact(owner, "lab", content)
    with sqlite3.connect(store.database_path) as db:
        saved = db.execute(
            "SELECT 1 FROM artifacts WHERE workspace_id=? AND sha256=?",
            ("lab", digest),
        ).fetchone()
    assert saved is None
    assert (moved_parent / digest).read_bytes() == content
    assert (parent / digest).read_bytes() == b"foreign-content"


def test_artifact_put_rejects_content_replaced_after_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    content = b"owned-content"
    digest = hashlib.sha256(content).hexdigest()
    path = store.artifact_root / digest[:2] / digest
    original_audit = store._audit

    def replace_after_audit(*args: object, **kwargs: object) -> None:
        original_audit(*args, **kwargs)
        if args[3] == "artifact.put":
            path.write_bytes(b"foreign-content")

    monkeypatch.setattr(store, "_audit", replace_after_audit)
    with pytest.raises(ContractError, match="artifact changed before metadata commit"):
        store.put_artifact(owner, "lab", content)
    with sqlite3.connect(store.database_path) as db:
        saved = db.execute(
            "SELECT 1 FROM artifacts WHERE workspace_id=? AND sha256=?",
            ("lab", digest),
        ).fetchone()
    assert saved is None
    assert path.read_bytes() == b"foreign-content"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_artifact_get_rejects_junction_ancestor(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    artifact = store.put_artifact(owner, "lab", b"owned-content")
    junction = tmp_path / "artifacts"
    target = tmp_path / "outside-artifacts"
    junction.rename(target)
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        pytest.skip("directory junction creation is unavailable")
    try:
        assert not junction.is_symlink()
        with pytest.raises(ContractError):
            store.get_artifact(owner, "lab", artifact["sha256"])
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction regression")
def test_artifact_get_rejects_parent_swapped_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    content = b"owned-content"
    artifact = store.put_artifact(owner, "lab", content)
    parent = store.artifact_root / artifact["sha256"][:2]
    moved_parent = tmp_path / "moved-artifact-parent"
    original_read = control_module.read_bounded_control_snapshot_result
    junction_created = False

    def swap_before_read(path: Path, **kwargs: object):
        nonlocal junction_created
        if kwargs.get("label") == "artifact content":
            parent.rename(moved_parent)
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(parent), str(moved_parent)],
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                pytest.skip("directory junction creation is unavailable")
            junction_created = True
        return original_read(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(control_module, "read_bounded_control_snapshot_result", swap_before_read)
    try:
        with pytest.raises(ContractError, match="regular directory"):
            store.get_artifact(owner, "lab", artifact["sha256"])
        assert (moved_parent / artifact["sha256"]).read_bytes() == content
    finally:
        if junction_created:
            parent.rmdir()


@pytest.mark.parametrize(
    "payload",
    [
        {"private-location-marker": {"cdp_endpoint": "http://127.0.0.1:9222"}},
        {"private-location-marker": "Bearer private-credential-marker"},
        {"private-location-marker": "ws://localhost/devtools/private-endpoint-marker"},
    ],
)
def test_restricted_control_diagnostics_do_not_echo_untrusted_paths(
    payload: dict,
) -> None:
    with pytest.raises(ContractError) as failure:
        control_module._safe_payload(payload, "control payload")
    assert "private-location-marker" not in str(failure.value)


@pytest.mark.parametrize(
    "payload",
    [
        {"evidence": ({"cdp_endpoint": "http://127.0.0.1:9222"},)},
        {"evidence": ("ws://localhost/devtools/private-endpoint-marker",)},
    ],
)
def test_restricted_control_values_inside_json_serializable_tuples_are_rejected(
    payload: dict,
) -> None:
    with pytest.raises(ContractError) as failure:
        control_module._safe_payload(payload, "control payload")
    assert "private-endpoint-marker" not in str(failure.value)


@pytest.mark.parametrize(
    "field",
    ["profile dir", "ProfileDir", "remote.debugging.port", "storage/state"],
)
def test_restricted_control_field_aliases_are_rejected(field: str) -> None:
    with pytest.raises(ContractError, match="restricted browser-control"):
        control_module._safe_payload({field: "private-location-marker"}, "control payload")


@pytest.mark.parametrize(
    "value",
    ["bearer private-credential-marker", " WSS://localhost/devtools/private-endpoint-marker"],
)
def test_restricted_control_value_case_and_padding_are_rejected(value: str) -> None:
    with pytest.raises(ContractError):
        control_module._safe_payload({"note": value}, "control payload")


@pytest.mark.parametrize(
    "value",
    [
        "memo_bc1.abcdefghijklmnop.abcdefghijklmnopqrstuvwxyz123456",
        "memo_bcw1.w.abcdefghijklmnopqrstuvwxyz123456",
        "memo: Bearer private-credential-marker",
        "debug at ws://localhost/devtools/browser/private-endpoint-marker",
    ],
)
def test_restricted_control_values_embedded_in_notes_are_rejected(value: str) -> None:
    with pytest.raises(ContractError) as failure:
        control_module._safe_payload({"note": value}, "control payload")
    assert value not in str(failure.value)


def test_control_note_accepts_noncredential_browser_context() -> None:
    value = "A Bearer token was discussed; ws://localhost/ordinary-path is a local example"
    assert control_module._safe_payload({"note": value}, "control payload") == (
        json.dumps({"note": value}, sort_keys=True, separators=(",", ":"))
    )


@pytest.mark.parametrize(
    "first,second",
    [
        ("viewer", "operator"),
        ("operator", "viewer"),
        ("viewer", "owner"),
    ],
)
def test_artifact_republication_rejects_conflicting_visibility(
    tmp_path: Path, first: str, second: str
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    body = b'{"verdict":"pass"}'
    first_record = store.put_artifact(
        owner, "lab", body, visibility=first, media_type="application/json"
    )
    assert store.put_artifact(
        owner, "lab", body, visibility=first, media_type="application/json"
    ) == first_record
    with pytest.raises(ContractError, match="metadata conflict"):
        store.put_artifact(
            owner, "lab", body, visibility=second, media_type="application/json"
        )


def test_artifact_republication_rejects_conflicting_media_type(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.put_artifact(owner, "lab", b"body", media_type="application/octet-stream")
    with pytest.raises(ContractError, match="metadata conflict"):
        store.put_artifact(owner, "lab", b"body", media_type="text/plain")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b'{"value":1,"value":2}', "duplicate key"),
        (b'{"value":NaN}', "non-finite"),
        (b'{"value":1e400}', "non-finite"),
    ],
)
def test_viewer_artifacts_require_strict_unambiguous_json(
    tmp_path: Path,
    content: bytes,
    message: str,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)

    with pytest.raises(ContractError, match=message):
        store.put_artifact(
            owner,
            "lab",
            content,
            visibility="viewer",
            media_type="application/json",
        )


@pytest.mark.parametrize(
    ("visibility", "media_type"),
    [
        (True, "application/octet-stream"),
        ("operator", "application/json\nprivate"),
        ("operator", ["application/json"]),
    ],
)
def test_artifact_metadata_requires_exact_safe_strings(
    tmp_path: Path,
    visibility,
    media_type,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)

    with pytest.raises(ContractError, match="visibility|media type"):
        store.put_artifact(
            owner,
            "lab",
            b"body",
            visibility=visibility,
            media_type=media_type,
        )


def test_artifact_reader_rejects_an_additional_hard_link(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    artifact = store.put_artifact(owner, "lab", b"immutable")
    path = store.artifact_root / artifact["sha256"][:2] / artifact["sha256"]
    alias = tmp_path / "external-alias"
    try:
        alias.hardlink_to(path)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {type(exc).__name__}")

    with pytest.raises(ContractError, match="hard links"):
        store.get_artifact(owner, "lab", artifact["sha256"])


def test_idempotent_artifact_publication_accepts_only_an_exact_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    real_publish = control_module.publish_bytes_exclusive
    raced = False

    def exact_race(path: Path, body: bytes, **kwargs: object) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            path.write_bytes(body)
        return real_publish(path, body, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(control_module, "publish_bytes_exclusive", exact_race)
    artifact = store.put_artifact(owner, "lab", b"same-content")
    assert store.get_artifact(owner, "lab", artifact["sha256"]) == b"same-content"


def test_artifact_publication_preserves_and_rejects_a_corrupt_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    competitor = b"competitor"

    def corrupt_race(path: Path, _body: bytes, **_kwargs: object) -> bytes:
        path.write_bytes(competitor)
        raise ContractError("injected publication conflict")

    monkeypatch.setattr(control_module, "publish_bytes_exclusive", corrupt_race)

    with pytest.raises(ContractError, match="publication conflicted"):
        store.put_artifact(owner, "lab", b"intended")

    digest = control_module.hashlib.sha256(b"intended").hexdigest()
    path = store.artifact_root / digest[:2] / digest
    assert path.read_bytes() == competitor


def test_job_allowlist_idempotency_and_sensitive_payload_rejection(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    with pytest.raises(ContractError, match="allowlist"):
        store.enqueue_job(owner, "lab", kind="shell", payload={"command": "whoami"}, requirements=[], idempotency_key="1")
    with pytest.raises(ContractError, match="sensitive"):
        store.enqueue_job(
            owner,
            "lab",
            kind="browser-eval",
            payload={"proxy_password": "secret"},
            requirements=["chromium"],
            idempotency_key="2",
        )
    with pytest.raises(ContractError, match="restricted browser-control"):
        store.put_record(
            owner,
            "lab",
            kind="session",
            record_id="unsafe",
            payload={"cdp_endpoint": "http://127.0.0.1:9222"},
            expected_revision=0,
        )
    with pytest.raises(ContractError, match="raw credential"):
        store.put_record(
            owner,
            "lab",
            kind="result",
            record_id="unsafe-token",
            payload={"value": "bc1.tokenidentifier.abcdefghijklmnopqrstuvwxyz"},
            expected_revision=0,
        )
    with pytest.raises(ContractError, match="debugging endpoint"):
        store.put_record(
            owner,
            "lab",
            kind="result",
            record_id="unsafe-cdp",
            payload={"value": "ws://127.0.0.1:9222/devtools/browser/opaque"},
            expected_revision=0,
        )
    first = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"evaluators": ["controlled_coherence"]},
        requirements=["chromium"],
        idempotency_key="same-work",
    )
    second = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"evaluators": ["controlled_coherence"]},
        requirements=["chromium"],
        idempotency_key="same-work",
    )
    assert first["id"] == second["id"]
    with pytest.raises(ContractError, match="different work"):
        store.enqueue_job(
            owner,
            "lab",
            kind="browser-eval",
            payload={"evaluators": ["peet"]},
            requirements=["chromium"],
            idempotency_key="same-work",
        )


@pytest.mark.parametrize(
    "added,reason",
    [
        ({"proxy_password": "secret"}, "sensitive"),
        ({"debuggerAddress": "ws://127.0.0.1/devtools/browser/x"}, "restricted browser-control"),
    ],
)
def test_control_payload_checks_exact_serialized_snapshot(
    monkeypatch: pytest.MonkeyPatch, added: dict[str, str], reason: str
) -> None:
    payload = {"safe": True}
    original = control_module._canonical

    def mutate_while_serializing(value: object) -> str:
        if value is payload:
            payload.update(added)
        return original(value)

    monkeypatch.setattr(control_module, "_canonical", mutate_while_serializing)
    with pytest.raises(ContractError, match=reason):
        control_module._safe_payload(payload, "job payload")


def test_worker_registration_uses_validated_capability_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    capabilities = ["chromium"]
    original = control_module._canonical
    mutated = False

    def mutate_while_serializing(value: object) -> str:
        nonlocal mutated
        if not mutated and isinstance(value, (list, tuple)) and list(value) == ["chromium"]:
            capabilities[:] = ["webgpu"]
            mutated = True
        return original(value)

    monkeypatch.setattr(control_module, "_canonical", mutate_while_serializing)
    registered = store.register_worker(
        owner, "lab", "worker-a", name="Worker", capabilities=capabilities, max_slots=1
    )
    assert mutated
    assert registered["capabilities"] == ["chromium"]
    with sqlite3.connect(store.database_path) as db:
        assert db.execute(
            "SELECT capabilities_json FROM workers WHERE id='worker-a'"
        ).fetchone()[0] == '["chromium"]'


def test_job_enqueue_uses_validated_requirement_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    requirements = ["chromium"]
    original = control_module._canonical
    mutated = False

    def mutate_while_serializing(value: object) -> str:
        nonlocal mutated
        if not mutated and isinstance(value, (list, tuple)) and list(value) == ["chromium"]:
            requirements[:] = ["webgpu"]
            mutated = True
        return original(value)

    monkeypatch.setattr(control_module, "_canonical", mutate_while_serializing)
    job = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"n": 1},
        requirements=requirements,
        idempotency_key="immutable-requirements",
    )
    assert mutated
    assert job["requirements"] == ["chromium"]
    with sqlite3.connect(store.database_path) as db:
        assert db.execute(
            "SELECT requirements_json FROM jobs WHERE id=?", (job["id"],)
        ).fetchone()[0] == '["chromium"]'


@pytest.mark.parametrize(
    "changed",
    [
        {"requirements": ["webkit"]},
        {"priority": 10},
        {"max_attempts": 2},
        {"persona_id": "persona-one"},
        {"profile_id": "profile-one"},
    ],
)
def test_job_idempotency_rejects_changed_scheduling_contract(
    tmp_path: Path, changed: dict[str, object]
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    original = {
        "kind": "browser-eval",
        "payload": {"evaluators": ["controlled_coherence"]},
        "requirements": ["chromium"],
        "idempotency_key": "same-work",
    }
    store.enqueue_job(owner, "lab", **original)
    with pytest.raises(ContractError, match="different work"):
        store.enqueue_job(owner, "lab", **{**original, **changed})


def test_capability_leasing_exclusivity_heartbeat_and_idempotent_completion(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(owner, "lab", "worker-a", name="A", capabilities=["chromium", "windows"], max_slots=2)
    worker = store.authenticate_worker(registered["worker_token"])
    first = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"arm": "core"},
        requirements=["chromium"],
        idempotency_key="a",
        persona_id="persona-one",
    )
    store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"arm": "core-2"},
        requirements=["chromium"],
        idempotency_key="b",
        persona_id="persona-one",
    )
    incompatible = store.enqueue_job(
        owner,
        "lab",
        kind="kernel-probe",
        payload={"engine": "webkit"},
        requirements=["webkit"],
        idempotency_key="c",
    )
    lease = store.lease_job(worker, lease_seconds=30)
    assert lease and lease["id"] == first["id"] and "lease_token" in lease
    # Persona exclusivity blocks the second Chromium job and the worker lacks WebKit.
    assert store.lease_job(worker, lease_seconds=30) is None
    heartbeat = store.heartbeat_lease(worker, lease["id"], lease["lease_token"], extend_seconds=60)
    assert heartbeat["job_id"] == lease["id"]
    completed = store.complete_job(
        worker, lease["id"], lease["lease_token"], succeeded=True, result={"verdict": "pass"}
    )
    assert completed["state"] == "succeeded"
    repeated = store.complete_job(
        worker, lease["id"], lease["lease_token"], succeeded=True, result={"verdict": "pass"}
    )
    assert repeated["state"] == "succeeded"
    with pytest.raises(ContractError, match="lease"):
        store.complete_job(
            worker, lease["id"], "wrong-lease-token", succeeded=True, result={"verdict": "pass"}
        )
    other_registration = store.register_worker(
        owner, "lab", "worker-b", name="B", capabilities=["chromium"], max_slots=1
    )
    other_worker = store.authenticate_worker(other_registration["worker_token"])
    with pytest.raises(ContractError, match="lease"):
        store.complete_job(
            other_worker, lease["id"], lease["lease_token"],
            succeeded=True, result={"verdict": "pass"},
        )
    with pytest.raises(ContractError, match="different terminal"):
        store.complete_job(
            worker, lease["id"], lease["lease_token"], succeeded=True, result={"verdict": "fail"}
        )
    assert incompatible["state"] == "queued"


def test_lease_heartbeat_rejects_corrupt_saved_token_digest(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registered["worker_token"])
    job = store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="lease-hash"
    )
    lease = store.lease_job(worker)
    assert lease is not None
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE jobs SET lease_token_sha256=? WHERE id=?", (b"private-route-marker", job["id"]))
    with pytest.raises(ContractError, match="lease token"):
        store.heartbeat_lease(worker, job["id"], lease["lease_token"])
    with sqlite3.connect(store.database_path) as db:
        assert db.execute("SELECT state FROM jobs WHERE id=?", (job["id"],)).fetchone()[0] == "running"


def test_repeated_completion_rejects_a_corrupt_saved_result(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registered["worker_token"])
    job = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"arm": "core"},
        requirements=["chromium"],
        idempotency_key="saved-result-corrupt",
    )
    lease = store.lease_job(worker, lease_seconds=30)
    assert lease is not None and lease["id"] == job["id"]
    store.complete_job(
        worker, job["id"], lease["lease_token"], succeeded=True, result={"verdict": "pass"}
    )
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE jobs SET result_json=? WHERE id=?",
            ('{"verdict":"fail"}', job["id"]),
        )
        db.commit()

    with pytest.raises(ContractError, match="stored digest"):
        store.complete_job(
            worker,
            job["id"],
            lease["lease_token"],
            succeeded=True,
            result={"verdict": "pass"},
        )


def test_idempotent_artifact_put_rejects_corrupt_saved_size(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    content = b"same-content"
    artifact = store.put_artifact(owner, "lab", content)
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "UPDATE artifacts SET size=? WHERE workspace_id='lab' AND sha256=?",
            (len(content) + 1, artifact["sha256"]),
        )
        db.commit()

    with pytest.raises(ContractError, match="metadata conflict"):
        store.put_artifact(owner, "lab", content)


def test_expired_lease_recovers_then_fails_at_attempt_limit(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1)
    worker = store.authenticate_worker(registered["worker_token"])
    job = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"arm": "core"},
        requirements=["chromium"],
        idempotency_key="recover",
        max_attempts=2,
    )
    start = datetime(2026, 8, 3, tzinfo=timezone.utc)
    first = store.lease_job(worker, lease_seconds=5, now=start)
    assert first and first["attempt"] == 1
    second = store.lease_job(worker, lease_seconds=5, now=start + timedelta(seconds=6))
    assert second and second["id"] == job["id"] and second["attempt"] == 2
    assert store.lease_job(worker, lease_seconds=5, now=start + timedelta(seconds=12)) is None
    status = store.fleet_status(owner, "lab")
    assert status["jobs"]["failed"] == 1


@pytest.mark.parametrize("field", ["attempt", "max_attempts"])
def test_expired_lease_rejects_corrupt_saved_attempts(
    tmp_path: Path, field: str,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registered["worker_token"])
    job = store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="expiry"
    )
    start = datetime(2026, 8, 3, tzinfo=timezone.utc)
    lease = store.lease_job(worker, lease_seconds=5, now=start)
    assert lease is not None
    private_marker = "private-route-marker"
    with sqlite3.connect(store.database_path) as db:
        db.execute(f"UPDATE jobs SET {field}=? WHERE id=?", (private_marker, job["id"]))
    with pytest.raises(ContractError) as failure:
        store.lease_job(worker, lease_seconds=5, now=start + timedelta(seconds=6))
    assert private_marker not in str(failure.value)


def test_lease_expiration_rejects_out_of_range_operation_time(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registered["worker_token"])
    job = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"arm": "core"},
        requirements=["chromium"],
        idempotency_key="overflow-time",
    )
    impossible_expiry = datetime.max.replace(tzinfo=timezone.utc)
    with pytest.raises(ContractError, match="lease expiration"):
        store.lease_job(worker, lease_seconds=5, now=impossible_expiry)
    assert store.get_job(owner, "lab", job["id"])["state"] == "queued"

    lease = store.lease_job(worker, lease_seconds=5)
    assert lease is not None
    with store._transaction() as db:
        db.execute(
            "UPDATE jobs SET lease_expires_at=? WHERE id=?",
            (impossible_expiry.isoformat(), job["id"]),
        )
    with pytest.raises(ContractError, match="lease expiration"):
        store.heartbeat_lease(
            worker, job["id"], lease["lease_token"],
            extend_seconds=5, now=impossible_expiry - timedelta(seconds=1),
        )
    assert store.get_job(owner, "lab", job["id"])["state"] == "running"


def test_expired_lease_scan_covers_multiple_pages(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    seed = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"arm": "core"},
        requirements=["chromium"],
        idempotency_key="lease-seed",
    )
    current = datetime(2026, 8, 3, tzinfo=timezone.utc)
    expired_at = (current - timedelta(seconds=1)).isoformat()
    future_at = (current + timedelta(hours=1)).isoformat()
    with store._transaction() as db:
        db.executemany(
            "INSERT INTO jobs(id,workspace_id,kind,payload_json,payload_sha256,"
            "requirements_json,priority,state,attempt,max_attempts,lease_worker_id,"
            "lease_token_sha256,lease_expires_at,persona_id,profile_id,"
            "idempotency_key_sha256,result_json,result_sha256,created_by,created_at,updated_at) "
            "SELECT ?,workspace_id,kind,payload_json,payload_sha256,requirements_json,"
            "priority,'running',1,?,'worker-a',?, ?,persona_id,profile_id,?,"
            "NULL,NULL,created_by,created_at,updated_at FROM jobs WHERE id=?",
            [
                (
                    f"job-bulk-{index:04d}",
                    2 if index % 3 == 0 else 1,
                    "a" * 64,
                    future_at if index % 3 == 2 else expired_at,
                    hashlib.sha256(f"bulk-{index}".encode()).hexdigest(),
                    seed["id"],
                )
                for index in range(260)
            ],
        )
        store._expire_leases(db, current)
        counts = dict(
            db.execute(
                "SELECT state,COUNT(*) FROM jobs WHERE id LIKE 'job-bulk-%' GROUP BY state"
            ).fetchall()
        )
    assert counts == {"queued": 87, "failed": 87, "running": 86}
    assert store.verify_audit(owner, "lab")["valid"] is True


def test_lease_job_can_select_after_many_incompatible_queued_jobs(
    tmp_path: Path,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    registered = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    worker = store.authenticate_worker(registered["worker_token"])
    eligible = store.enqueue_job(
        owner,
        "lab",
        kind="browser-eval",
        payload={"chosen": "payload"},
        requirements=["chromium"],
        idempotency_key="eligible",
    )
    with store._transaction() as db:
        db.executemany(
            "INSERT INTO jobs(id,workspace_id,kind,payload_json,payload_sha256,"
            "requirements_json,priority,state,attempt,max_attempts,lease_worker_id,"
            "lease_token_sha256,lease_expires_at,persona_id,profile_id,"
            "idempotency_key_sha256,result_json,result_sha256,created_by,created_at,updated_at) "
            "SELECT ?,workspace_id,kind,payload_json,payload_sha256,'[\"firefox\"]',"
            "priority,'queued',0,max_attempts,NULL,NULL,NULL,persona_id,profile_id,?,"
            "NULL,NULL,created_by,?,updated_at FROM jobs WHERE id=?",
            [
                (
                    f"job-incompatible-{index:04d}",
                    hashlib.sha256(f"incompatible-{index}".encode()).hexdigest(),
                    "2020-01-01T00:00:00Z",
                    eligible["id"],
                )
                for index in range(260)
            ],
        )
    leased = store.lease_job(worker)
    assert leased is not None
    assert leased["id"] == eligible["id"]
    assert leased["payload"] == {"chosen": "payload"}


def test_fair_dispatch_across_workspaces(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.create_workspace(owner, workspace_id="lab2", name="Lab 2", max_running=2, max_queued=10)
    registered = store.register_worker(owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=2)
    store.add_worker_scope(owner, "lab2", "worker-a")
    worker = store.authenticate_worker(registered["worker_token"])
    first = store.enqueue_job(owner, "lab", kind="browser-eval", payload={"n": 1}, requirements=["chromium"], idempotency_key="1")
    second = store.enqueue_job(owner, "lab", kind="browser-eval", payload={"n": 2}, requirements=["chromium"], idempotency_key="2")
    other = store.enqueue_job(owner, "lab2", kind="browser-eval", payload={"n": 3}, requirements=["chromium"], idempotency_key="3")
    lease1 = store.lease_job(worker)
    lease2 = store.lease_job(worker)
    assert lease1["id"] == first["id"]
    assert lease2["id"] == other["id"]
    assert second["id"] not in {lease1["id"], lease2["id"]}


def test_fair_dispatch_orders_equivalent_zone_timestamps_by_instant(
    tmp_path: Path,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.create_workspace(
        owner, workspace_id="lab2", name="Lab 2", max_running=2, max_queued=10
    )
    registered = store.register_worker(
        owner,
        "lab",
        "worker-a",
        name="A",
        capabilities=["chromium"],
        max_slots=4,
    )
    store.add_worker_scope(owner, "lab2", "worker-a")
    worker = store.authenticate_worker(registered["worker_token"])
    jobs = [
        store.enqueue_job(
            owner,
            workspace_id,
            kind="browser-eval",
            payload={"n": index},
            requirements=["chromium"],
            idempotency_key=str(index),
        )
        for index, workspace_id in enumerate(("lab", "lab2", "lab", "lab2"))
    ]
    first = store.lease_job(worker, now=datetime(2030, 1, 1, 10, tzinfo=timezone.utc))
    second = store.lease_job(
        worker,
        now=datetime(
            2030, 1, 1, 5, 0, 0, 1, tzinfo=timezone(timedelta(hours=-5))
        ),
    )
    third = store.lease_job(worker, now=datetime(2030, 1, 1, 10, 0, 1, tzinfo=timezone.utc))
    assert [lease["id"] for lease in (first, second, third)] == [
        jobs[0]["id"],
        jobs[1]["id"],
        jobs[2]["id"],
    ]
    with sqlite3.connect(store.database_path) as db:
        saved = dict(db.execute("SELECT id,last_dispatched_at FROM workspaces"))
    assert saved == {
        "lab": "2030-01-01T10:00:01.000000Z",
        "lab2": "2030-01-01T10:00:00.000001Z",
    }


def test_reopened_store_orders_legacy_dispatch_timestamps_by_instant(
    tmp_path: Path,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.create_workspace(owner, workspace_id="lab2", name="Lab 2")
    registration = store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=2
    )
    store.add_worker_scope(owner, "lab2", "worker-a")
    earlier = store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="a"
    )
    store.enqueue_job(
        owner, "lab2", kind="browser-eval", payload={}, requirements=[], idempotency_key="b"
    )
    with sqlite3.connect(store.database_path) as db:
        db.executemany(
            "UPDATE workspaces SET last_dispatched_at=? WHERE id=?",
            [
                ("2030-01-01T10:00:00Z", "lab"),
                ("2030-01-01T05:00:00.000001-05:00", "lab2"),
            ],
        )
    reopened = ControlStore(tmp_path)
    worker = reopened.authenticate_worker(registration["worker_token"])
    leased = reopened.lease_job(worker, now=datetime(2030, 1, 1, 10, 0, 1, tzinfo=timezone.utc))
    assert leased["id"] == earlier["id"]


def test_fleet_status_exposes_only_workers_scoped_to_the_workspace(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.create_workspace(owner, workspace_id="unscoped", name="Unscoped")
    store.register_worker(owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1)

    assert [item["id"] for item in store.fleet_status(owner, "lab")["workers"]] == ["worker-a"]
    assert store.fleet_status(owner, "unscoped")["workers"] == []


def test_fleet_status_bounds_worker_rows_and_marks_incomplete_list(tmp_path: Path) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    with sqlite3.connect(store.database_path) as db:
        db.executemany(
            "INSERT INTO workers(id,name,capabilities_json,max_slots,state,last_seen_at,"
            "revision,token_salt,token_verifier) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                (f"worker-{index:04d}", "Worker", "[]", 1, "online", "2026-10-25T00:00:00Z", 1, b"a" * 16, b"b" * 32)
                for index in range(1001)
            ),
        )
        db.executemany(
            "INSERT INTO worker_scopes(worker_id,workspace_id) VALUES(?,?)",
            ((f"worker-{index:04d}", "lab") for index in range(1001)),
        )

    status = store.fleet_status(owner, "lab")
    assert status["worker_limit"] == 1000
    assert status["workers_truncated"] is True
    assert len(status["workers"]) == 1000
    assert status["workers"][0]["id"] == "worker-0000"
    assert status["workers"][-1]["id"] == "worker-0999"

    with sqlite3.connect(store.database_path) as db:
        db.execute("DELETE FROM worker_scopes WHERE worker_id=?", ("worker-1000",))
    exact_limit = store.fleet_status(owner, "lab")
    assert len(exact_limit["workers"]) == 1000
    assert exact_limit["workers_truncated"] is False


@pytest.mark.parametrize(
    "field",
    ["job-state", "worker-state", "worker-slots", "worker-last-seen"],
)
def test_fleet_status_rejects_corrupt_saved_scalar_fields(
    tmp_path: Path, field: str,
) -> None:
    store, owner, _ = bootstrapped(tmp_path)
    store.register_worker(
        owner, "lab", "worker-a", name="A", capabilities=["chromium"], max_slots=1
    )
    job = store.enqueue_job(
        owner, "lab", kind="browser-eval", payload={}, requirements=[], idempotency_key="fleet"
    )
    private_marker = "private-route-marker"
    with sqlite3.connect(store.database_path) as db:
        if field == "job-state":
            db.execute("UPDATE jobs SET state=? WHERE id=?", (private_marker, job["id"]))
        elif field == "worker-state":
            db.execute("UPDATE workers SET state=? WHERE id=?", (private_marker, "worker-a"))
        elif field == "worker-slots":
            db.execute("UPDATE workers SET max_slots=? WHERE id=?", (private_marker, "worker-a"))
        else:
            db.execute("UPDATE workers SET last_seen_at=? WHERE id=?", (private_marker, "worker-a"))
    with pytest.raises(ContractError) as failure:
        store.fleet_status(owner, "lab")
    assert private_marker not in str(failure.value)
