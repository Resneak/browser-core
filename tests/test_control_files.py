from __future__ import annotations

import os
import json
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import browser_core.control_files as control_files
from browser_core.contracts import ContractError
from browser_core.control_files import (
    JsonPublicationCursor,
    canonical_json_bytes,
    decode_strict_json_bytes,
    inventory_bounded_json_directory,
    load_canonical_json_document,
    publish_bytes_exclusive_result,
    publish_json_exclusive,
    publish_json_exclusive_result,
    read_bounded_control_snapshot,
    read_bounded_control_snapshot_result,
    remove_control_conditionally,
    replace_bytes_conditionally,
    replace_json_conditionally,
    replace_json_conditionally_result,
)


@pytest.mark.skipif(os.name != "nt", reason="Win32 selected-file aliases")
@pytest.mark.parametrize("part", ["parent", "leaf"])
def test_bounded_snapshot_rejects_normalized_selected_path_alias(
    tmp_path: Path, part: str,
) -> None:
    parent = tmp_path / "evidence"
    parent.mkdir()
    ordinary = parent / "receipt.json"
    ordinary.write_bytes(b"fixture")
    selected = (
        tmp_path / "evidence." / "receipt.json"
        if part == "parent"
        else parent / "receipt.json."
    )
    assert selected.is_file() and os.path.samefile(selected, ordinary)

    with pytest.raises(ContractError, match="path is invalid"):
        read_bounded_control_snapshot_result(selected, maximum=16, label="fixture")
    assert read_bounded_control_snapshot_result(
        ordinary, maximum=16, label="fixture",
    ).body == b"fixture"


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data stream path syntax")
def test_bounded_snapshot_rejects_alternate_stream_selection(tmp_path: Path) -> None:
    holder = tmp_path / "holder.txt"
    holder.write_bytes(b"unrelated")
    selected = Path(str(holder) + ":receipt")
    try:
        selected.write_bytes(b"fixture")
    except OSError:
        pytest.skip("host filesystem does not support alternate data streams")
    assert selected.read_bytes() == b"fixture"

    with pytest.raises(ContractError, match="path is invalid"):
        read_bounded_control_snapshot_result(selected, maximum=16, label="fixture")
    assert holder.read_bytes() == b"unrelated"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_bounded_snapshot_rejects_preexisting_parent_junction(
    tmp_path: Path,
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    source = foreign / "receipt.json"
    source.write_bytes(b"foreign")
    junction = tmp_path / "linked"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="owned regular directory"):
            read_bounded_control_snapshot_result(
                junction / "receipt.json", maximum=16, label="fixture",
            )
        with pytest.raises(ContractError, match="owned regular directory"):
            read_bounded_control_snapshot_result(
                junction / "missing.json", maximum=16, label="fixture",
            )
        assert read_bounded_control_snapshot_result(
            source, maximum=16, label="fixture",
        ).body == b"foreign"
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows file identity and parent move")
def test_bounded_snapshot_detects_parent_replacement_with_same_file_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "owned"
    parent.mkdir()
    selected = parent / "receipt.json"
    selected.write_bytes(b"owned")
    original_identity = control_files._identity(os.lstat(selected))
    held = tmp_path / "held"
    real_lstat = control_files.os.lstat
    selected_lookups = 0

    def move_parent_at_final_lookup(path: Path):
        nonlocal selected_lookups
        if Path(path) == selected:
            selected_lookups += 1
            if selected_lookups == 2:
                parent.rename(held)
                parent.mkdir()
                os.link(held / "receipt.json", selected)
        return real_lstat(path)

    with monkeypatch.context() as patch:
        patch.setattr(control_files.os, "lstat", move_parent_at_final_lookup)
        snapshot = read_bounded_control_snapshot_result(
            selected, maximum=16, label="fixture",
        )
    assert selected_lookups == 2
    assert control_files._identity(os.lstat(selected)) == original_identity
    assert snapshot.state == "changed"
    assert (held / "receipt.json").read_bytes() == b"owned"


def test_bounded_snapshot_does_not_report_missing_after_parent_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "selected"
    parent.mkdir()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "receipt.json").write_bytes(b"replacement")
    parked = tmp_path / "parked"
    selected = parent / "receipt.json"
    real_lstat = control_files.os.lstat
    moved = False

    def replace_parent_at_missing_lookup(path: Path):
        nonlocal moved
        if Path(path) == selected and not moved:
            moved = True
            parent.rename(parked)
            replacement.rename(parent)
            raise FileNotFoundError
        return real_lstat(path)

    with monkeypatch.context() as patch:
        patch.setattr(control_files.os, "lstat", replace_parent_at_missing_lookup)
        snapshot = read_bounded_control_snapshot_result(
            selected, maximum=32, label="fixture",
        )
    assert moved
    assert selected.read_bytes() == b"replacement"
    assert snapshot.state == "changed"
    assert read_bounded_control_snapshot_result(
        parked / "receipt.json", maximum=32, label="fixture",
    ).state == "missing"


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_exclusive_publication_rejects_preexisting_parent_ancestor_junction(
    tmp_path: Path,
) -> None:
    target = tmp_path / "unrelated"
    inner = target / "inner"
    inner.mkdir(parents=True)
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            publish_bytes_exclusive_result(
                junction / "inner" / "control.json", b"owned\n",
                maximum=4096, label="owned control",
            )
        assert list(inner.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
@pytest.mark.parametrize("operation", ["replace", "remove"])
def test_control_mutation_rejects_preexisting_parent_ancestor_junction(
    tmp_path: Path, operation: str,
) -> None:
    target = tmp_path / "unrelated"
    inner = target / "inner"
    inner.mkdir(parents=True)
    original = inner / "control.json"
    original.write_bytes(b"owned\n")
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    path = junction / "inner" / "control.json"
    try:
        snapshot = read_bounded_control_snapshot_result(
            original, maximum=4096, label="owned control"
        )
        assert snapshot.body == b"owned\n" and snapshot.identity is not None
        with pytest.raises(ContractError):
            if operation == "replace":
                replace_bytes_conditionally(
                    path, b"changed\n", expected_body=snapshot.body,
                    expected_identity=snapshot.identity, maximum=4096, label="owned control",
                )
            else:
                remove_control_conditionally(
                    path, expected_body=snapshot.body,
                    expected_identity=snapshot.identity, maximum=4096, label="owned control",
                )
        assert original.read_bytes() == b"owned\n"
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.parametrize('codepoint', [0xD800, 0xDBFF, 0xDC00, 0xDFFF])
@pytest.mark.parametrize('as_key', [False, True])
@pytest.mark.parametrize('position', ['start', 'middle', 'end'])
def test_strict_json_rejects_surrogate_boundaries_inside_keys_and_values(codepoint, as_key, position):
    padding='profile-description-'*100
    char=chr(codepoint)
    text={'start':char+padding, 'middle':padding+char+padding, 'end':padding+char}[position]
    document={text: 'ordinary value'} if as_key else {'ordinary key': text}
    with pytest.raises(ContractError, match='unpaired Unicode surrogate'):
        decode_strict_json_bytes(json.dumps(document).encode('ascii'),label='test profile')


def test_strict_json_preserves_multilingual_text_and_supplementary_characters():
    text='English العربية 日本語 '+chr(0xD7FF)+chr(0xE000)+'😀'+chr(0x10FFFF)
    document={text: [text, {'nested':text}]}
    for ascii_only in [False,True]:
        body=json.dumps(document,ensure_ascii=ascii_only).encode('utf-8')
        assert decode_strict_json_bytes(body,label='test profile')==document
    assert load_canonical_json_document(canonical_json_bytes(document),label='test profile')==document


def test_conditional_byte_replacement_supports_non_json_artifacts(
    tmp_path: Path,
) -> None:
    target = tmp_path / "ledger.md"
    target.write_bytes(b"# old\n")
    source = read_bounded_control_snapshot_result(
        target, maximum=4096, label="ledger", require_single_link=True
    )
    assert source.body is not None and source.identity is not None
    body = replace_bytes_conditionally(
        target,
        b"# new\n",
        expected_body=source.body,
        expected_identity=source.identity,
        maximum=4096,
        label="ledger",
    )
    assert body == b"# new\n"
    assert target.read_bytes() == body


def test_conditional_byte_replacement_rejects_non_bytes_before_mutation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "ledger.md"
    original = b"# old\n"
    target.write_bytes(original)
    source = read_bounded_control_snapshot_result(target, maximum=4096, label="ledger")
    assert source.body is not None and source.identity is not None
    with pytest.raises(ContractError, match="must be bytes"):
        replace_bytes_conditionally(
            target,
            "# new\n",  # type: ignore[arg-type]
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="ledger",
        )
    assert target.read_bytes() == original


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b'{"value":1,"value":2}', "duplicate key"),
        (b'{"value":NaN}', "non-finite"),
        (b'{"value":1e400}', "non-finite"),
        (b'{"value":' + b"9" * 1025 + b"}", "integer is too large"),
        (b'{"value":"\\ud800"}', "unpaired Unicode surrogate"),
        (b"[" * 129 + b"0" + b"]" * 129, "nesting limit"),
        (b"\xff", "UTF-8 JSON"),
    ],
)
def test_strict_json_decoder_rejects_ambiguous_documents(
    body: bytes,
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        decode_strict_json_bytes(body, label="fixture document")


def test_strict_json_decoder_rejects_untyped_inputs() -> None:
    with pytest.raises(ContractError, match="must be bytes"):
        decode_strict_json_bytes("{}", label="fixture document")  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="label"):
        decode_strict_json_bytes(b"{}", label="")


def test_bounded_json_directory_inventory_binds_sorted_single_link_files(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "registry"
    directory.mkdir()
    (directory / "b.json").write_text("{}", encoding="utf-8")
    (directory / "a.json").write_text("{}", encoding="utf-8")
    (directory / "notes.txt").write_text("ignored but counted", encoding="utf-8")
    inventory = inventory_bounded_json_directory(
        directory,
        maximum_entries=4,
        maximum_files=2,
        maximum_file_bytes=16,
        maximum_total_bytes=32,
        label="fixture registry",
    )
    assert inventory.state == "complete"
    assert [name for name, _identity in inventory.files] == ["a.json", "b.json"]


def test_bounded_json_directory_inventory_rejects_noncanonical_extension(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "registry"
    directory.mkdir()
    candidate = directory / "entry.JSON"
    candidate.write_text("{}", encoding="utf-8")
    with pytest.raises(ContractError, match="noncanonical JSON entry"):
        inventory_bounded_json_directory(
            directory,
            maximum_entries=2,
            maximum_files=2,
            maximum_file_bytes=16,
            maximum_total_bytes=32,
            label="fixture registry",
        )
    assert candidate.read_text(encoding="utf-8") == "{}"


def test_bounded_json_inventory_stops_scanning_at_entry_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "registry"
    directory.mkdir()

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
                pytest.fail("inventory scanned beyond its entry limit")
            return SimpleNamespace(name=f"{self.requests}.json")

    entries = Entries()
    monkeypatch.setattr(control_files.os, "scandir", lambda _: entries)
    with pytest.raises(ContractError, match="too many entries"):
        inventory_bounded_json_directory(
            directory, maximum_entries=2, maximum_files=2,
            maximum_file_bytes=16, maximum_total_bytes=32,
            label="fixture registry",
        )
    assert entries.requests == 3


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_bounded_json_inventory_rejects_parent_ancestor_junction(
    tmp_path: Path,
) -> None:
    foreign = tmp_path / "foreign"
    registry = foreign / "registry"
    registry.mkdir(parents=True)
    (registry / "entry.json").write_text("{}", encoding="utf-8")
    junction = tmp_path / "linked"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(foreign)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError, match="owned regular directory"):
            inventory_bounded_json_directory(
                junction / "registry",
                maximum_entries=2, maximum_files=2,
                maximum_file_bytes=16, maximum_total_bytes=32,
                label="fixture registry",
            )
    finally:
        if junction.exists():
            junction.rmdir()


def test_bounded_json_inventory_keeps_missing_nested_directory_status(
    tmp_path: Path,
) -> None:
    inventory = inventory_bounded_json_directory(
        tmp_path / "new" / "registry",
        maximum_entries=2, maximum_files=2,
        maximum_file_bytes=16, maximum_total_bytes=32,
        label="fixture registry",
    )
    assert inventory.state == "missing"
    assert inventory.files == ()


@pytest.mark.skipif(os.name != "nt", reason="Windows catalog move retains root stat fields")
def test_bounded_json_inventory_detects_parent_relocation_with_same_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "selected"
    parent.mkdir()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    parked = tmp_path / "parked"
    directory = parent / "catalog"
    directory.mkdir()
    (directory / "a.json").write_bytes(b"{}\n")
    real_scandir = control_files.os.scandir
    moved = False

    def replace_parent_during_inventory(path: Path):
        nonlocal moved
        if Path(path) == directory and not moved:
            moved = True
            parent.rename(parked)
            replacement.rename(parent)
            (parked / "catalog").rename(directory)
        return real_scandir(path)

    with monkeypatch.context() as patch:
        patch.setattr(control_files.os, "scandir", replace_parent_during_inventory)
        with pytest.raises(ContractError, match="changed during inventory"):
            inventory_bounded_json_directory(
                directory, maximum_entries=2, maximum_files=2,
                maximum_file_bytes=16, maximum_total_bytes=32,
                label="fixture registry",
            )
    assert moved
    assert (directory / "a.json").read_bytes() == b"{}\n"


def test_bounded_json_inventory_does_not_report_missing_after_parent_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "selected"
    parent.mkdir()
    replacement = tmp_path / "replacement"
    (replacement / "catalog").mkdir(parents=True)
    parked = tmp_path / "parked"
    directory = parent / "catalog"
    real_lstat = control_files.os.lstat
    moved = False

    def replace_parent_at_missing_lookup(path: Path):
        nonlocal moved
        if Path(path) == directory and not moved:
            moved = True
            parent.rename(parked)
            replacement.rename(parent)
            raise FileNotFoundError
        return real_lstat(path)

    with monkeypatch.context() as patch:
        patch.setattr(control_files.os, "lstat", replace_parent_at_missing_lookup)
        with pytest.raises(ContractError, match="changed during inventory"):
            inventory_bounded_json_directory(
                directory, maximum_entries=2, maximum_files=2,
                maximum_file_bytes=16, maximum_total_bytes=32,
                label="fixture registry",
            )
    assert moved
    assert directory.is_dir()
    assert inventory_bounded_json_directory(
        parked / "catalog", maximum_entries=2, maximum_files=2,
        maximum_file_bytes=16, maximum_total_bytes=32,
        label="fixture registry",
    ).state == "missing"


def test_bounded_json_directory_inventory_rejects_hard_links_and_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "registry"
    directory.mkdir()
    first = directory / "a.json"
    first.write_text("{}", encoding="utf-8")
    control_files.os.link(first, directory / "linked.json")
    with pytest.raises(ContractError, match="hard links"):
        inventory_bounded_json_directory(
            directory,
            maximum_entries=4,
            maximum_files=4,
            maximum_file_bytes=16,
            maximum_total_bytes=64,
            label="fixture registry",
        )
    with pytest.raises(ContractError, match="limits are inconsistent"):
        inventory_bounded_json_directory(
            directory,
            maximum_entries=1,
            maximum_files=2,
            maximum_file_bytes=16,
            maximum_total_bytes=64,
            label="fixture registry",
        )


def test_json_publication_cursor_exclusively_publishes_then_owned_replaces(
    tmp_path: Path,
) -> None:
    target = tmp_path / "progress.json"
    cursor = JsonPublicationCursor(
        target,
        maximum=4096,
        label="progress report",
    )

    first = cursor.publish({"step": 1})
    second = cursor.publish({"step": 2})

    assert first == b'{"step":1}\n'
    assert second == b'{"step":2}\n'
    assert target.read_bytes() == second
    assert not list(tmp_path.glob(".*progress.json*"))


def test_json_publication_cursor_preserves_competing_replacement(
    tmp_path: Path,
) -> None:
    target = tmp_path / "progress.json"
    cursor = JsonPublicationCursor(
        target,
        maximum=4096,
        label="progress report",
    )
    cursor.publish({"step": 1})
    target.unlink()
    competitor = b'{"competitor":true}\n'
    target.write_bytes(competitor)

    with pytest.raises(ContractError, match="changed before transition"):
        cursor.publish({"step": 2})

    assert target.read_bytes() == competitor


@pytest.mark.parametrize(
    ("path", "maximum", "label"),
    [
        ("progress.json", 4096, "progress"),
        (Path("progress.json"), True, "progress"),
        (Path("progress.json"), 0, "progress"),
        (Path("progress.json"), 4096, ""),
    ],
)
def test_json_publication_cursor_rejects_invalid_configuration_without_io(
    tmp_path: Path,
    path,
    maximum,
    label,
) -> None:
    candidate = tmp_path / path if isinstance(path, Path) else path
    with pytest.raises(ContractError, match="publication"):
        JsonPublicationCursor(candidate, maximum=maximum, label=label)
    assert list(tmp_path.iterdir()) == []


def test_exclusive_json_publication_is_canonical_complete_and_no_replace(
    tmp_path: Path,
) -> None:
    target = tmp_path / "ready.json"
    document = {"schema": "owned/1", "port": 9222}
    expected = b'{"port":9222,"schema":"owned/1"}\n'

    assert (
        publish_json_exclusive(
            target,
            document,
            maximum=4096,
            label="owned control",
        )
        == expected
    )
    assert target.read_bytes() == expected
    assert not list(tmp_path.glob(".ready.json.tmp-*"))

    with pytest.raises(ContractError, match="publication failed") as raised:
        publish_json_exclusive(
            target,
            {"replacement": True},
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert target.read_bytes() == expected
    assert not list(tmp_path.glob(".ready.json.tmp-*"))


def test_exclusive_json_publication_returns_the_final_verified_identity(
    tmp_path: Path,
) -> None:
    target = tmp_path / "ready.json"
    published = publish_json_exclusive_result(
        target,
        {"schema": "owned/1", "port": 9222},
        maximum=4096,
        label="owned control",
    )
    observed = read_bounded_control_snapshot_result(
        target,
        maximum=4096,
        label="owned control",
    )

    assert observed.state == "complete"
    assert published.body == observed.body
    assert published.identity == observed.identity
    assert not list(tmp_path.glob(".ready.json.tmp-*"))


def test_exclusive_json_publication_rejects_oversize_before_filesystem_change(
    tmp_path: Path,
) -> None:
    target = tmp_path / "ready.json"
    with pytest.raises(ContractError, match="exceeds 8 bytes"):
        publish_json_exclusive(
            target,
            {"value": "too large"},
            maximum=8,
            label="owned control",
        )
    assert not target.exists()
    assert not list(tmp_path.iterdir())


def test_exclusive_json_publication_cleans_a_partial_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private-ready.json"
    real_write = control_files.os.write
    calls = 0

    def partial_then_fail(descriptor: int, body: memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, body[:3])
        raise OSError(5, str(target))

    monkeypatch.setattr(control_files.os, "write", partial_then_fail)
    with pytest.raises(ContractError, match="publication failed") as raised:
        publish_json_exclusive(
            target,
            {"schema": "owned/1"},
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert not target.exists()
    assert not list(tmp_path.glob(".private-ready.json.tmp-*"))


def test_exclusive_json_publication_rolls_back_after_final_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private-ready.json"
    real_link = control_files.os.link
    real_unlink = control_files.os.unlink
    published = False
    failed = False

    def recording_link(source: Path, destination: Path, **kwargs: object) -> None:
        nonlocal published
        real_link(source, destination, **kwargs)
        published = True

    def fail_first_temporary_unlink(path: Path) -> None:
        nonlocal failed
        if published and not failed and ".tmp-" in Path(path).name:
            failed = True
            raise OSError(5, str(path))
        real_unlink(path)

    monkeypatch.setattr(control_files.os, "link", recording_link)
    monkeypatch.setattr(control_files.os, "unlink", fail_first_temporary_unlink)
    with pytest.raises(ContractError, match="publication failed") as raised:
        publish_json_exclusive(
            target,
            {"schema": "owned/1"},
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert not target.exists()
    assert not list(tmp_path.glob(".private-ready.json.tmp-*"))


def test_exclusive_json_publication_preserves_final_replacement_during_temp_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private-ready.json"
    competitor = b'{"owner":"competitor"}\n'
    real_unlink = control_files.os.unlink
    injected = False

    def replace_final_before_temp_quarantine_unlink(path: Path) -> None:
        nonlocal injected
        candidate = Path(path)
        if not injected and ".tmp-" in candidate.name and ".removed-" in candidate.name:
            injected = True
            replacement = tmp_path / "replacement"
            replacement.write_bytes(competitor)
            control_files.os.replace(replacement, target)
            raise OSError(5, str(path))
        real_unlink(path)

    monkeypatch.setattr(
        control_files.os, "unlink", replace_final_before_temp_quarantine_unlink
    )
    with pytest.raises(ContractError, match="publication failed") as raised:
        publish_json_exclusive_result(
            target,
            {"schema": "owned/1"},
            maximum=4096,
            label="owned control",
        )

    assert str(target) not in str(raised.value)
    assert target.read_bytes() == competitor
    assert not list(tmp_path.glob(".private-ready.json.tmp-*"))
    assert not list(tmp_path.glob("*.removed-*"))


def test_exclusive_publication_can_require_a_single_final_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "strict.json"
    alias = tmp_path / "strict-alias.json"
    body = b'{"schema":"strict/1"}\n'
    real_link = control_files.os.link

    def publish_then_alias(source: Path, destination: Path, **kwargs: object) -> None:
        real_link(source, destination, **kwargs)
        real_link(destination, alias)

    monkeypatch.setattr(control_files.os, "link", publish_then_alias)
    with pytest.raises(ContractError, match="publication failed"):
        publish_bytes_exclusive_result(
            target,
            body,
            maximum=4096,
            label="strict control",
            require_single_link=True,
        )

    assert not target.exists()
    assert alias.read_bytes() == body


def test_exclusive_publication_rejects_an_invalid_link_policy(tmp_path: Path) -> None:
    target = tmp_path / "strict.json"
    with pytest.raises(ContractError, match="link policy is invalid"):
        publish_bytes_exclusive_result(
            target,
            b"{}\n",
            maximum=4096,
            label="strict control",
            require_single_link="yes",  # type: ignore[arg-type]
        )
    assert not target.exists()


def test_exclusive_publication_rejects_parent_replacement_after_final_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "workspace"
    parent.mkdir()
    target = parent / "control.json"
    displaced = tmp_path / "displaced-workspace"
    competitor = b"competitor"
    real_read = control_files.read_bounded_control_snapshot_result
    target_reads = 0

    def read_then_replace(path: Path, **kwargs: object):  # noqa: ANN202
        nonlocal target_reads
        result = real_read(path, **kwargs)
        if path == target:
            target_reads += 1
            if target_reads == 2:
                parent.rename(displaced)
                parent.mkdir()
                (parent / "competitor.bin").write_bytes(competitor)
        return result

    monkeypatch.setattr(
        control_files,
        "read_bounded_control_snapshot_result",
        read_then_replace,
    )
    with pytest.raises(ContractError, match="publication failed; cleanup incomplete"):
        publish_bytes_exclusive_result(
            target,
            b'{"schema":"owned/1"}\n',
            maximum=4096,
            label="owned control",
        )

    assert (displaced / "control.json").is_file()
    assert (parent / "competitor.bin").read_bytes() == competitor
    assert not target.exists()


def test_exclusive_publication_rejects_ancestor_relocation_after_final_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    parent = authority / "controls"
    parent.mkdir(parents=True)
    target = parent / "control.json"
    retained = tmp_path / "retained-authority"
    body = b'{"schema":"owned/1"}\n'
    real_read = control_files.read_bounded_control_snapshot_result
    target_reads = 0

    def read_then_relocate(path: Path, **kwargs: object):  # noqa: ANN202
        nonlocal target_reads
        result = real_read(path, **kwargs)
        if path == target:
            target_reads += 1
            if target_reads == 2:
                authority.rename(retained)
                authority.mkdir()
                (retained / "controls").rename(parent)
        return result

    monkeypatch.setattr(control_files, "read_bounded_control_snapshot_result", read_then_relocate)
    with pytest.raises(ContractError, match="publication failed; cleanup incomplete"):
        publish_bytes_exclusive_result(target, body, maximum=4096, label="owned control")

    assert target.read_bytes() == body
    assert not list(parent.glob(".control.json.tmp-*"))


def test_publication_cleanup_never_mutates_a_replacement_parent_hard_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "workspace"
    parent.mkdir()
    target = parent / "control.json"
    displaced = tmp_path / "displaced-workspace"
    body = b'{"schema":"owned/1"}\n'
    real_read = control_files.read_bounded_control_snapshot_result
    target_reads = 0

    def read_then_replace(path: Path, **kwargs: object):  # noqa: ANN202
        nonlocal target_reads
        result = real_read(path, **kwargs)
        if path == target:
            target_reads += 1
            if target_reads == 2:
                parent.rename(displaced)
                parent.mkdir()
                os.link(displaced / "control.json", target)
                (parent / "competitor.bin").write_bytes(b"competitor")
        return result

    monkeypatch.setattr(
        control_files,
        "read_bounded_control_snapshot_result",
        read_then_replace,
    )
    with pytest.raises(ContractError, match="publication failed; cleanup incomplete"):
        publish_bytes_exclusive_result(
            target,
            body,
            maximum=4096,
            label="owned control",
        )

    assert (displaced / "control.json").read_bytes() == body
    assert target.read_bytes() == body
    assert (parent / "competitor.bin").read_bytes() == b"competitor"


def test_exclusive_json_publication_preserves_temp_replacement_during_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private-ready.json"
    competitor = b'{"owner":"competitor"}\n'
    real_rename = control_files.os.rename
    injected = False

    def replace_temp_before_quarantine(source: Path, destination: Path) -> None:
        nonlocal injected
        source_path = Path(source)
        destination_path = Path(destination)
        if (
            not injected
            and ".tmp-" in source_path.name
            and ".removed-" in destination_path.name
        ):
            injected = True
            replacement = tmp_path / "replacement"
            replacement.write_bytes(competitor)
            control_files.os.replace(replacement, source_path)
        real_rename(source, destination)

    monkeypatch.setattr(control_files.os, "rename", replace_temp_before_quarantine)
    with pytest.raises(ContractError, match="publication failed") as raised:
        publish_json_exclusive_result(
            target,
            {"schema": "owned/1"},
            maximum=4096,
            label="owned control",
        )

    assert str(target) not in str(raised.value)
    assert not target.exists()
    temporary_replacements = list(tmp_path.glob(".private-ready.json.tmp-*"))
    assert len(temporary_replacements) == 1
    assert temporary_replacements[0].read_bytes() == competitor
    assert not list(tmp_path.glob("*.removed-*"))


def test_bounded_control_snapshot_uses_one_handle_and_retries_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "control"
    target.write_bytes(b"owned")
    real_fstat = control_files.os.fstat
    descriptors: list[int] = []
    identities = iter(
        [
            (1, 1, 1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (1, 1, 1, 2, 1, 1),
        ]
    )

    def recording_fstat(descriptor: int):  # type: ignore[no-untyped-def]
        descriptors.append(descriptor)
        return real_fstat(descriptor)

    monkeypatch.setattr(control_files.os, "fstat", recording_fstat)
    monkeypatch.setattr(control_files, "_identity", lambda _metadata: next(identities))

    assert (
        read_bounded_control_snapshot(
            target,
            maximum=16,
            label="owned control",
        )
        is None
    )
    assert len(descriptors) == 2 and descriptors[0] == descriptors[1]


@pytest.mark.skipif(os.name != "nt", reason="Windows filename executable bits")
@pytest.mark.parametrize("name", ["tool.bat", "tool.cmd", "tool.exe"])
def test_bounded_snapshot_accepts_stable_windows_executable_filename(
    tmp_path: Path, name: str,
) -> None:
    target = tmp_path / name
    target.write_bytes(b"owned")
    snapshot = read_bounded_control_snapshot_result(
        target, maximum=16, label="owned control", require_single_link=True,
    )
    assert snapshot.state == "complete"
    assert snapshot.body == b"owned"
    assert snapshot.identity == control_files._identity(os.lstat(target))
    writable_mode = snapshot.identity[2]
    try:
        os.chmod(target, stat.S_IREAD)
        readonly_mode = control_files._identity(os.lstat(target))[2]
        assert readonly_mode != writable_mode
        assert readonly_mode & stat.S_IWUSR == 0
        assert read_bounded_control_snapshot_result(
            target, maximum=16, label="owned control", require_single_link=True,
        ).state == "complete"
    finally:
        os.chmod(target, stat.S_IREAD | stat.S_IWRITE)


@pytest.mark.skipif(os.name != "nt", reason="Windows creation time is not change time")
def test_bounded_snapshot_rejects_same_size_edit_with_restored_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "control"
    target.write_bytes(b"AAAA")
    stamp = target.stat()
    real_fstat = control_files.os.fstat
    calls = 0

    def write_after_first_read(descriptor: int):
        nonlocal calls
        calls += 1
        if calls == 2:
            with target.open("r+b") as writer:
                writer.write(b"BBBB")
            os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return real_fstat(descriptor)

    monkeypatch.setattr(control_files.os, "fstat", write_after_first_read)
    snapshot = read_bounded_control_snapshot_result(
        target, maximum=4, label="owned control"
    )
    assert snapshot.state == "changed"
    assert snapshot.body is None
    assert target.read_bytes() == b"BBBB"


def test_bounded_control_snapshot_exposes_stable_retry_classes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "control"
    assert (
        read_bounded_control_snapshot_result(
            target,
            maximum=16,
            label="owned control",
        ).state
        == "missing"
    )
    target.write_bytes(b"owned")
    monkeypatch.setattr(
        Path,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError(13, "private")),
    )
    assert (
        read_bounded_control_snapshot_result(
            target,
            maximum=16,
            label="owned control",
        ).state
        == "locked"
    )


def test_bounded_snapshot_distinguishes_final_disappearance_from_initial_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "owned.json"
    assert read_bounded_control_snapshot_result(
        target, maximum=16, label="owned control",
    ).state == "missing"
    target.write_bytes(b"owned")
    real_lstat = control_files.os.lstat
    selected_calls = 0

    def disappear_after_open(path: Path, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal selected_calls
        if Path(path) == target:
            selected_calls += 1
            if selected_calls == 2:
                raise FileNotFoundError(2, "synthetic final lookup", str(target))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(control_files.os, "lstat", disappear_after_open)
    snapshot = read_bounded_control_snapshot_result(
        target, maximum=16, label="owned control",
    )
    assert selected_calls == 2
    assert snapshot.state == "changed"
    assert snapshot.body is None


def test_publication_cleanup_does_not_call_postread_disappearance_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "owned.json"
    target.write_bytes(b"owned")
    owned_identity = control_files._identity(os.lstat(target))
    real_lstat = control_files.os.lstat
    selected_calls = 0

    def disappear_after_open(path: Path, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal selected_calls
        if Path(path) == target:
            selected_calls += 1
            if selected_calls == 2:
                raise FileNotFoundError(2, "synthetic final lookup", str(target))
        return real_lstat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(control_files.os, "lstat", disappear_after_open)
        clean = control_files._cleanup_publication_name(
            target, expected_body=b"owned", owned_identity=owned_identity,
            maximum=16, label="owned control",
        )
    assert selected_calls == 2
    assert clean is False
    assert target.read_bytes() == b"owned"


def test_bounded_control_snapshot_retries_missing_and_writer_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private" / "control"
    assert (
        read_bounded_control_snapshot(
            target,
            maximum=16,
            label="owned control",
        )
        is None
    )

    monkeypatch.setattr(
        Path,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PermissionError(13, "private writer path")
        ),
    )
    assert (
        read_bounded_control_snapshot(
            target,
            maximum=16,
            label="owned control",
        )
        is None
    )


def test_bounded_control_snapshot_rejects_overflow_and_nonregular_path_free(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "private-oversized"
    oversized.write_bytes(b"x" * 17)
    with pytest.raises(ContractError, match="exceeds 16 bytes") as raised:
        read_bounded_control_snapshot(
            oversized,
            maximum=16,
            label="owned control",
        )
    assert str(oversized) not in str(raised.value)

    directory = tmp_path / "private-directory"
    directory.mkdir()
    with pytest.raises(ContractError, match="not a regular file") as raised:
        read_bounded_control_snapshot(
            directory,
            maximum=16,
            label="owned control",
        )
    assert str(directory) not in str(raised.value)


@pytest.mark.parametrize("invalid", ["bad\x00file", "bad\ud800file"])
def test_bounded_control_snapshot_rejects_invalid_path_text(invalid: str) -> None:
    with pytest.raises(ContractError, match="owned control path is invalid") as raised:
        read_bounded_control_snapshot_result(
            Path(invalid), maximum=16, label="owned control"
        )
    assert invalid not in str(raised.value)


@pytest.mark.parametrize("invalid", ["bad\x00dir", "bad\ud800dir"])
def test_bounded_json_inventory_rejects_invalid_path_text(invalid: str) -> None:
    with pytest.raises(ContractError, match="fixture catalog path is invalid") as raised:
        inventory_bounded_json_directory(
            Path(invalid), maximum_entries=1, maximum_files=1,
            maximum_file_bytes=16, maximum_total_bytes=16,
            label="fixture catalog",
        )
    assert invalid not in str(raised.value)


@pytest.mark.parametrize("invalid", ["bad\x00control", "bad\ud800control"])
@pytest.mark.parametrize("operation", ["publish", "replace", "remove"])
def test_control_mutation_rejects_invalid_path_text(
    invalid: str, operation: str,
) -> None:
    path = Path(invalid)
    identity = (1, 1, 0o100666, 1, 1, 1)
    with pytest.raises(ContractError, match="owned control path is invalid") as raised:
        if operation == "publish":
            publish_bytes_exclusive_result(path, b"new", maximum=16, label="owned control")
        elif operation == "replace":
            control_files.replace_bytes_conditionally_result(
                path, b"new", expected_body=b"old", expected_identity=identity,
                maximum=16, label="owned control",
            )
        else:
            remove_control_conditionally(
                path, expected_body=b"old", expected_identity=identity,
                maximum=16, label="owned control",
            )
    assert invalid not in str(raised.value)


def test_canonical_json_loader_rejects_encoding_whitespace_and_duplicates() -> None:
    document = {"schema": "owned/1", "port": 9222}
    body = canonical_json_bytes(document)
    assert load_canonical_json_document(body, label="owned control") == document

    for malformed in (
        b'{"port":9222, "schema":"owned/1"}\n',
        b'{"port":9222,"port":9223,"schema":"owned/1"}\n',
        b'{"schema":"owned/1","value":"\xff"}\n',
        b"[]\n",
    ):
        with pytest.raises(ContractError, match="not canonical JSON"):
            load_canonical_json_document(malformed, label="owned control")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_control_json_rejects_nonfinite_numbers(value: float) -> None:
    with pytest.raises(ContractError, match="not strict JSON"):
        canonical_json_bytes({"value": value})

    with pytest.raises(ContractError, match="not canonical JSON"):
        load_canonical_json_document(
            ('{"value":' + str(value) + "}\n").encode("ascii"),
            label="owned control",
        )


def test_canonical_json_loader_rejects_exponent_overflow() -> None:
    with pytest.raises(ContractError, match="not canonical JSON"):
        load_canonical_json_document(b'{"value":1e400}\n', label="owned control")


@pytest.mark.parametrize(
    "document",
    [
        {"value": "\ud800"},
        {"value": int("9" * 1025)},
    ],
)
def test_canonical_json_writer_refuses_values_its_loader_cannot_accept(
    document,
) -> None:
    with pytest.raises(ContractError):
        canonical_json_bytes(document)


def test_canonical_json_writer_refuses_excessive_nesting() -> None:
    value: object = 0
    for _ in range(129):
        value = [value]
    with pytest.raises(ContractError, match="nesting limit"):
        canonical_json_bytes({"value": value})


def test_canonical_json_writer_normalizes_encoder_recursion() -> None:
    value: object = 0
    for _ in range(2_000):
        value = [value]

    with pytest.raises(ContractError, match="not strict JSON"):
        canonical_json_bytes({"value": value})


def _complete_snapshot(path: Path):  # type: ignore[no-untyped-def]
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=4096,
        label="owned control",
    )
    assert snapshot.state == "complete"
    assert snapshot.body is not None and snapshot.identity is not None
    return snapshot


def test_conditional_json_replacement_commits_complete_canonical_bytes(
    tmp_path: Path,
) -> None:
    target = tmp_path / "session.json"
    target.write_bytes(b'{"state": "active"}')
    source = _complete_snapshot(target)

    body = replace_json_conditionally(
        target,
        {"state": "stopped"},
        expected_body=source.body,
        expected_identity=source.identity,
        maximum=4096,
        label="owned control",
    )

    assert body == canonical_json_bytes({"state": "stopped"})
    assert target.read_bytes() == body
    assert not list(tmp_path.glob(".session.json.previous-*"))
    assert not list(tmp_path.glob(".session.json.tmp-*"))


def test_conditional_json_replacement_returns_the_final_verified_identity(
    tmp_path: Path,
) -> None:
    target = tmp_path / "session.json"
    target.write_bytes(b'{"state": "active"}')
    source = _complete_snapshot(target)

    publication = replace_json_conditionally_result(
        target,
        {"state": "stopped"},
        expected_body=source.body,
        expected_identity=source.identity,
        maximum=4096,
        label="owned control",
    )
    observed = _complete_snapshot(target)

    assert publication.body == canonical_json_bytes({"state": "stopped"})
    assert publication.body == observed.body
    assert publication.identity == observed.identity
    assert not list(tmp_path.glob(".session.json.previous-*"))
    assert not list(tmp_path.glob(".session.json.tmp-*"))


def test_conditional_replacement_rechecks_output_after_quarantine_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "session.json"
    target.write_bytes(b'{"state":"active"}\n')
    source = _complete_snapshot(target)
    competitor = b'{"owner":"competitor"}\n'
    real_remove = control_files.remove_control_conditionally

    def replace_after_cleanup(path: Path, **kwargs: object) -> None:
        real_remove(path, **kwargs)
        if ".previous-" in path.name:
            replacement = tmp_path / "replacement"
            replacement.write_bytes(competitor)
            control_files.os.replace(replacement, target)

    monkeypatch.setattr(
        control_files, "remove_control_conditionally", replace_after_cleanup
    )
    with pytest.raises(ContractError, match="transition committed; output changed"):
        replace_json_conditionally_result(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert target.read_bytes() == competitor


def test_conditional_json_replacement_rejects_oversize_before_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    original = b'{"state":"active"}\n'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    renamed = False

    def must_not_rename(*_args: object, **_kwargs: object) -> None:
        nonlocal renamed
        renamed = True
        raise AssertionError("oversize replacement reached rename")

    monkeypatch.setattr(control_files.os, "rename", must_not_rename)

    with pytest.raises(ContractError, match="exceeds"):
        replace_json_conditionally_result(
            target,
            {"large": "x" * 100},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=16,
            label="owned control",
        )

    assert renamed is False
    assert target.read_bytes() == original


def test_conditional_json_replacement_preserves_racing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    target.write_bytes(b'{"state": "active"}')
    source = _complete_snapshot(target)
    competitor = b'{"owner":"competitor"}\n'
    real_rename = control_files.os.rename

    def replace_before_rename(source_path: Path, quarantine: Path) -> None:
        injected = tmp_path / "injected"
        injected.write_bytes(competitor)
        control_files.os.replace(injected, source_path)
        real_rename(source_path, quarantine)

    monkeypatch.setattr(control_files.os, "rename", replace_before_rename)
    with pytest.raises(ContractError, match="changed during transition") as raised:
        replace_json_conditionally(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert target.read_bytes() == competitor
    assert not list(tmp_path.glob(".session.json.previous-*"))


def test_conditional_json_replacement_preserves_competing_publish_and_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    original = b'{"state": "active"}'
    competitor = b'{"owner":"competitor"}\n'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_publish = control_files.publish_bytes_exclusive_result

    def publish_after_competitor(
        path: Path,
        body: bytes,
        *,
        maximum: int,
        label: str,
    ):  # type: ignore[no-untyped-def]
        path.write_bytes(competitor)
        return real_publish(path, body, maximum=maximum, label=label)

    monkeypatch.setattr(
        control_files,
        "publish_bytes_exclusive_result",
        publish_after_competitor,
    )
    with pytest.raises(ContractError, match="rollback incomplete") as raised:
        replace_json_conditionally(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert target.read_bytes() == competitor
    quarantines = list(tmp_path.glob(".session.json.previous-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == original


def test_conditional_json_replacement_restores_source_after_partial_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    original = b'{"state": "active"}'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_write = control_files.os.write
    calls = 0

    def partial_then_fail(descriptor: int, body: memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, body[:3])
        raise OSError(5, str(target))

    monkeypatch.setattr(control_files.os, "write", partial_then_fail)
    with pytest.raises(ContractError, match="publication failed") as raised:
        replace_json_conditionally(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert target.read_bytes() == original
    assert not list(tmp_path.glob(".session.json.previous-*"))
    assert not list(tmp_path.glob(".session.json.tmp-*"))


def test_conditional_replacement_never_restores_a_replaced_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    original = b'{"state":"active"}\n'
    competitor = b'{"owner":"competitor"}\n'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    holding = tmp_path / "held-original.json"

    def replace_quarantine_then_fail(
        _path: Path,
        _body: bytes,
        *,
        maximum: int,
        label: str,
    ):  # noqa: ANN202
        del maximum, label
        quarantines = list(tmp_path.glob(".session.json.previous-*"))
        assert len(quarantines) == 1
        quarantines[0].rename(holding)
        quarantines[0].write_bytes(competitor)
        raise ContractError("synthetic publication failure")

    monkeypatch.setattr(
        control_files,
        "publish_bytes_exclusive_result",
        replace_quarantine_then_fail,
    )
    with pytest.raises(ContractError, match="rollback incomplete") as failure:
        replace_json_conditionally_result(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )

    assert isinstance(failure.value.__cause__, ContractError)
    assert not target.exists()
    assert holding.read_bytes() == original
    quarantines = list(tmp_path.glob(".session.json.previous-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == competitor


def test_conditional_json_replacement_retains_unverified_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    original = b'{"state": "active"}'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_read = control_files.read_bounded_control_snapshot_result

    def fail_quarantine_read(path: Path, *, maximum: int, label: str):  # type: ignore[no-untyped-def]
        if ".previous-" in path.name:
            raise ContractError("owned control quarantined source read failed")
        return real_read(path, maximum=maximum, label=label)

    monkeypatch.setattr(
        control_files,
        "read_bounded_control_snapshot_result",
        fail_quarantine_read,
    )
    with pytest.raises(ContractError, match="rollback incomplete") as failure:
        replace_json_conditionally(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert isinstance(failure.value.__cause__, ContractError)
    assert not target.exists()
    quarantines = list(tmp_path.glob(".session.json.previous-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == original


def test_conditional_json_replacement_reports_cleanup_failure_after_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    original = b'{"state": "active"}'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_unlink = control_files.os.unlink
    failed = False

    def fail_quarantine_unlink(path: Path) -> None:
        nonlocal failed
        if not failed and ".previous-" in Path(path).name:
            failed = True
            raise OSError(5, str(path))
        real_unlink(path)

    monkeypatch.setattr(control_files.os, "unlink", fail_quarantine_unlink)
    with pytest.raises(
        ContractError, match="transition committed; cleanup failed"
    ) as raised:
        replace_json_conditionally(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert target.read_bytes() == canonical_json_bytes({"state": "stopped"})
    quarantines = list(tmp_path.glob(".session.json.previous-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == original


def test_conditional_json_replacement_preserves_quarantine_replacement_after_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    original = b'{"state": "active"}'
    competitor = b'{"owner":"competitor"}\n'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_publish = control_files.publish_bytes_exclusive_result

    def publish_then_replace_quarantine(
        path: Path,
        body: bytes,
        *,
        maximum: int,
        label: str,
    ):  # type: ignore[no-untyped-def]
        publication = real_publish(path, body, maximum=maximum, label=label)
        quarantines = list(tmp_path.glob(".session.json.previous-*"))
        assert len(quarantines) == 1
        replacement = tmp_path / "replacement"
        replacement.write_bytes(competitor)
        control_files.os.replace(replacement, quarantines[0])
        return publication

    monkeypatch.setattr(
        control_files,
        "publish_bytes_exclusive_result",
        publish_then_replace_quarantine,
    )
    with pytest.raises(ContractError, match="transition committed; cleanup failed"):
        replace_json_conditionally_result(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )

    assert target.read_bytes() == canonical_json_bytes({"state": "stopped"})
    quarantines = list(tmp_path.glob(".session.json.previous-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == competitor


def test_conditional_json_replacement_preserves_quarantine_race_during_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "session.json"
    original = b'{"state": "active"}'
    competitor = b'{"owner":"competitor"}\n'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_rename = control_files.os.rename
    injected = False

    def replace_before_cleanup_rename(source_path: Path, quarantine: Path) -> None:
        nonlocal injected
        source_name = Path(source_path).name
        quarantine_name = Path(quarantine).name
        if (
            not injected
            and ".previous-" in source_name
            and ".removed-" in quarantine_name
        ):
            injected = True
            replacement = tmp_path / "replacement"
            replacement.write_bytes(competitor)
            control_files.os.replace(replacement, source_path)
        real_rename(source_path, quarantine)

    monkeypatch.setattr(control_files.os, "rename", replace_before_cleanup_rename)
    with pytest.raises(ContractError, match="transition committed; cleanup failed"):
        replace_json_conditionally_result(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )

    assert injected
    assert target.read_bytes() == canonical_json_bytes({"state": "stopped"})
    quarantines = list(tmp_path.glob(".session.json.previous-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == competitor
    assert not list(tmp_path.glob("*.removed-*"))


def test_conditional_replacement_rejects_parent_swap_after_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "workspace"
    parent.mkdir()
    target = parent / "session.json"
    target.write_bytes(b'{"state":"active"}\n')
    source = _complete_snapshot(target)
    displaced = tmp_path / "displaced-workspace"
    competitor = b"competitor"
    real_remove = control_files.remove_control_conditionally

    def remove_then_replace_parent(path: Path, **kwargs: object) -> None:
        real_remove(path, **kwargs)
        if ".previous-" in path.name:
            parent.rename(displaced)
            parent.mkdir()
            (parent / "competitor.bin").write_bytes(competitor)

    monkeypatch.setattr(
        control_files,
        "remove_control_conditionally",
        remove_then_replace_parent,
    )
    with pytest.raises(
        ContractError, match="transition committed; output parent changed"
    ):
        replace_json_conditionally_result(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )

    assert (displaced / "session.json").read_bytes() == canonical_json_bytes(
        {"state": "stopped"}
    )
    assert (parent / "competitor.bin").read_bytes() == competitor
    assert not target.exists()


def test_conditional_replacement_rejects_ancestor_relocation_after_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    parent = authority / "controls"
    parent.mkdir(parents=True)
    target = parent / "session.json"
    target.write_bytes(b'{"state":"active"}\n')
    source = _complete_snapshot(target)
    retained = tmp_path / "retained-authority"
    real_remove = control_files.remove_control_conditionally

    def remove_then_relocate(path: Path, **kwargs: object) -> None:
        real_remove(path, **kwargs)
        if ".previous-" in path.name:
            authority.rename(retained)
            authority.mkdir()
            (retained / "controls").rename(parent)

    monkeypatch.setattr(control_files, "remove_control_conditionally", remove_then_relocate)
    with pytest.raises(ContractError, match="transition committed; output parent changed"):
        replace_json_conditionally_result(
            target,
            {"state": "stopped"},
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )

    assert target.read_bytes() == canonical_json_bytes({"state": "stopped"})


def test_conditional_control_removal_deletes_only_the_accepted_entry(
    tmp_path: Path,
) -> None:
    target = tmp_path / "lease.json"
    target.write_bytes(b'{"owner": "accepted"}')
    source = _complete_snapshot(target)

    remove_control_conditionally(
        target,
        expected_body=source.body,
        expected_identity=source.identity,
        maximum=4096,
        label="owned control",
    )

    assert not target.exists()
    assert not list(tmp_path.glob(".lease.json.removed-*"))


def test_conditional_removal_rejects_parent_swap_after_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "workspace"
    parent.mkdir()
    target = parent / "lease.json"
    target.write_bytes(b'{"owner":"accepted"}\n')
    source = _complete_snapshot(target)
    displaced = tmp_path / "displaced-workspace"
    competitor = b"competitor"
    real_unlink = control_files.os.unlink

    def unlink_then_replace_parent(path: Path) -> None:
        real_unlink(path)
        if ".removed-" in Path(path).name:
            parent.rename(displaced)
            parent.mkdir()
            (parent / "competitor.bin").write_bytes(competitor)

    monkeypatch.setattr(control_files.os, "unlink", unlink_then_replace_parent)
    with pytest.raises(ContractError, match="removal committed; parent changed"):
        remove_control_conditionally(
            target,
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )

    assert not (displaced / "lease.json").exists()
    assert (parent / "competitor.bin").read_bytes() == competitor
    assert not target.exists()


def test_conditional_removal_retains_quarantine_after_ancestor_relocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    parent = authority / "controls"
    parent.mkdir(parents=True)
    target = parent / "lease.json"
    body = b'{"owner":"accepted"}\n'
    target.write_bytes(body)
    source = _complete_snapshot(target)
    retained = tmp_path / "retained-authority"
    real_rename = control_files.os.rename

    def rename_then_relocate(source_path: Path, destination: Path) -> None:
        real_rename(source_path, destination)
        if ".removed-" in Path(destination).name:
            authority.rename(retained)
            authority.mkdir()
            (retained / "controls").rename(parent)

    monkeypatch.setattr(control_files.os, "rename", rename_then_relocate)
    with pytest.raises(ContractError, match="rollback incomplete"):
        remove_control_conditionally(
            target,
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )

    quarantines = list(parent.glob(".lease.json.removed-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == body
    assert not target.exists()


def test_conditional_control_removal_accepts_owned_source_disappearance_when_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "lease.json"
    target.write_bytes(b'{"owner": "accepted"}')
    source = _complete_snapshot(target)
    real_rename = control_files.os.rename
    real_unlink = control_files.os.unlink

    def disappear_after_quarantine(source_path: Path, quarantine: Path) -> None:
        real_rename(source_path, quarantine)
        real_unlink(quarantine)

    monkeypatch.setattr(control_files.os, "rename", disappear_after_quarantine)
    remove_control_conditionally(
        target,
        expected_body=source.body,
        expected_identity=source.identity,
        maximum=4096,
        label="owned control",
        missing_ok=True,
    )

    assert not target.exists()
    assert not list(tmp_path.glob(".lease.json.removed-*"))


def test_conditional_control_removal_preserves_replacement_before_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "lease.json"
    original = b'{"owner": "accepted"}'
    competitor = b'{"owner":"competitor"}\n'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_rename = control_files.os.rename

    def replace_before_rename(source_path: Path, quarantine: Path) -> None:
        injected = tmp_path / "injected"
        injected.write_bytes(competitor)
        control_files.os.replace(injected, source_path)
        real_rename(source_path, quarantine)

    monkeypatch.setattr(control_files.os, "rename", replace_before_rename)
    with pytest.raises(ContractError, match="changed during removal") as raised:
        remove_control_conditionally(
            target,
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert target.read_bytes() == competitor
    assert not list(tmp_path.glob(".lease.json.removed-*"))


def test_conditional_control_removal_leaves_later_competitor_public(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "lease.json"
    original = b'{"owner": "accepted"}'
    competitor = b'{"owner":"competitor"}\n'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_read = control_files.read_bounded_control_snapshot_result
    injected = False

    def inject_during_verification(
        path: Path,
        *,
        maximum: int,
        label: str,
    ):  # type: ignore[no-untyped-def]
        nonlocal injected
        if ".removed-" in path.name and not injected:
            injected = True
            target.write_bytes(competitor)
        return real_read(path, maximum=maximum, label=label)

    monkeypatch.setattr(
        control_files,
        "read_bounded_control_snapshot_result",
        inject_during_verification,
    )
    remove_control_conditionally(
        target,
        expected_body=source.body,
        expected_identity=source.identity,
        maximum=4096,
        label="owned control",
    )

    assert target.read_bytes() == competitor
    assert not list(tmp_path.glob(".lease.json.removed-*"))


def test_conditional_control_removal_retains_unverified_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "lease.json"
    original = b'{"owner": "accepted"}'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_read = control_files.read_bounded_control_snapshot_result

    def fail_quarantine_read(
        path: Path,
        *,
        maximum: int,
        label: str,
    ):  # type: ignore[no-untyped-def]
        if ".removed-" in path.name:
            raise ContractError("owned control quarantined source read failed")
        return real_read(path, maximum=maximum, label=label)

    monkeypatch.setattr(
        control_files,
        "read_bounded_control_snapshot_result",
        fail_quarantine_read,
    )
    with pytest.raises(ContractError, match="rollback incomplete") as failure:
        remove_control_conditionally(
            target,
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert isinstance(failure.value.__cause__, ContractError)
    assert not target.exists()
    quarantines = list(tmp_path.glob(".lease.json.removed-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == original


def test_conditional_control_removal_restores_after_unlink_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "lease.json"
    original = b'{"owner": "accepted"}'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    real_unlink = control_files.os.unlink
    failed = False

    def fail_first_quarantine_unlink(path: Path) -> None:
        nonlocal failed
        if ".removed-" in Path(path).name and not failed:
            failed = True
            raise OSError(5, str(path))
        real_unlink(path)

    monkeypatch.setattr(control_files.os, "unlink", fail_first_quarantine_unlink)
    with pytest.raises(ContractError, match="removal failed") as raised:
        remove_control_conditionally(
            target,
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )
    assert str(target) not in str(raised.value)
    assert target.read_bytes() == original
    assert not list(tmp_path.glob(".lease.json.removed-*"))


def test_conditional_removal_never_restores_a_replaced_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "lease.json"
    original = b'{"owner":"accepted"}\n'
    competitor = b'{"owner":"competitor"}\n'
    target.write_bytes(original)
    source = _complete_snapshot(target)
    holding = tmp_path / "held-original.json"
    real_unlink = control_files.os.unlink

    def replace_quarantine_before_unlink(path: Path) -> None:
        candidate = Path(path)
        if ".removed-" in candidate.name:
            candidate.rename(holding)
            candidate.write_bytes(competitor)
            raise OSError(5, str(candidate))
        real_unlink(path)

    monkeypatch.setattr(
        control_files.os,
        "unlink",
        replace_quarantine_before_unlink,
    )
    with pytest.raises(ContractError, match="rollback incomplete") as failure:
        remove_control_conditionally(
            target,
            expected_body=source.body,
            expected_identity=source.identity,
            maximum=4096,
            label="owned control",
        )

    assert isinstance(failure.value.__cause__, ContractError)
    assert not target.exists()
    assert holding.read_bytes() == original
    quarantines = list(tmp_path.glob(".lease.json.removed-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == competitor


@pytest.mark.parametrize(
    "override",
    [
        {"path": "lease.json"},
        {"expected_body": "body"},
        {"expected_body": b"too-long", "maximum": 1},
        {"expected_identity": [0, 0, 0, 0, 0, 0]},
        {"expected_identity": (0, 0, 0, 0, 0, True)},
        {"maximum": True},
        {"maximum": 0},
        {"label": "private\nlabel"},
        {"missing_ok": 1},
    ],
)
def test_conditional_control_removal_validates_before_filesystem_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict,
) -> None:
    touched = False

    def fail_if_touched(_path: Path):
        nonlocal touched
        touched = True
        raise AssertionError("filesystem must not be inspected")

    monkeypatch.setattr(control_files.os, "lstat", fail_if_touched)
    arguments = {
        "path": tmp_path / "lease.json",
        "expected_body": b"body",
        "expected_identity": (0, 0, 0, 0, 0, 0),
        "maximum": 4096,
        "label": "owned control",
        "missing_ok": False,
    }
    arguments.update(override)
    with pytest.raises(ContractError):
        remove_control_conditionally(**arguments)
    assert touched is False


@pytest.mark.parametrize(
    "override",
    [
        {"path": "lease.json"},
        {"body": "body"},
        {"body": b"too-long", "maximum": 1},
        {"maximum": True},
        {"maximum": 0},
        {"label": "private\nlabel"},
    ],
)
def test_exclusive_publication_validates_before_opening_a_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict,
) -> None:
    touched = False

    def fail_if_touched(*_args, **_kwargs):
        nonlocal touched
        touched = True
        raise AssertionError("temporary must not be opened")

    monkeypatch.setattr(control_files.os, "open", fail_if_touched)
    arguments = {
        "path": tmp_path / "lease.json",
        "body": b"body",
        "maximum": 4096,
        "label": "owned control",
    }
    arguments.update(override)
    with pytest.raises(ContractError) as failure:
        control_files.publish_bytes_exclusive_result(**arguments)
    assert "private\nlabel" not in str(failure.value)
    assert touched is False


@pytest.mark.parametrize(
    "override",
    [
        {"path": "lease.json"},
        {"replacement_body": "body"},
        {"replacement_body": b"too-long", "maximum": 1},
        {"expected_body": "body"},
        {"expected_body": b"too-long", "maximum": 1},
        {"expected_identity": [0, 0, 0, 0, 0, 0]},
        {"expected_identity": (0, 0, 0, 0, 0, True)},
        {"maximum": True},
        {"maximum": 0},
        {"label": "private\nlabel"},
    ],
)
def test_conditional_replacement_validates_before_filesystem_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict,
) -> None:
    touched = False

    def fail_if_touched(_path: Path):
        nonlocal touched
        touched = True
        raise AssertionError("filesystem must not be inspected")

    monkeypatch.setattr(control_files.os, "lstat", fail_if_touched)
    arguments = {
        "path": tmp_path / "lease.json",
        "replacement_body": b"replacement",
        "expected_body": b"body",
        "expected_identity": (0, 0, 0, 0, 0, 0),
        "maximum": 4096,
        "label": "owned control",
    }
    arguments.update(override)
    with pytest.raises(ContractError) as failure:
        control_files.replace_bytes_conditionally_result(**arguments)
    assert "private\nlabel" not in str(failure.value)
    assert touched is False


@pytest.mark.parametrize("operation", ["replace", "remove"])
def test_conditional_control_mutation_never_quarantines_a_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    target = tmp_path / "control.json"
    target.mkdir()
    identity = control_files._identity(control_files.os.lstat(target))
    renamed = False

    def must_not_rename(*_args: object, **_kwargs: object) -> None:
        nonlocal renamed
        renamed = True
        raise AssertionError("directory reached quarantine")

    monkeypatch.setattr(control_files.os, "rename", must_not_rename)
    with pytest.raises(ContractError, match="expected identity is invalid"):
        if operation == "replace":
            control_files.replace_bytes_conditionally_result(
                target,
                b"replacement",
                expected_body=b"body",
                expected_identity=identity,
                maximum=4096,
                label="owned control",
            )
        else:
            remove_control_conditionally(
                target,
                expected_body=b"body",
                expected_identity=identity,
                maximum=4096,
                label="owned control",
            )

    assert target.is_dir()
    assert renamed is False


@pytest.mark.parametrize(
    "override",
    [
        {"path": "lease.json"},
        {"maximum": True},
        {"maximum": "4096"},
        {"maximum": -1},
        {"maximum": 1024 * 1024 * 1024 + 1},
        {"label": "private\nlabel"},
        {"require_private": 1},
        {"require_single_link": 0},
    ],
)
def test_bounded_control_read_validates_before_filesystem_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict,
) -> None:
    touched = False

    def fail_if_touched(_path: Path):
        nonlocal touched
        touched = True
        raise AssertionError("filesystem must not be inspected")

    monkeypatch.setattr(control_files.os, "lstat", fail_if_touched)
    arguments = {
        "path": tmp_path / "lease.json",
        "maximum": 4096,
        "label": "owned control",
        "require_private": False,
        "require_single_link": False,
    }
    arguments.update(override)
    with pytest.raises(ContractError) as failure:
        read_bounded_control_snapshot_result(**arguments)
    assert "private\nlabel" not in str(failure.value)
    assert touched is False


@pytest.mark.parametrize(
    "override",
    [
        {"directory": "catalog"},
        {"maximum_entries": True},
        {"maximum_files": "10"},
        {"maximum_file_bytes": 0},
        {"maximum_total_bytes": 1024 * 1024 * 1024 + 1},
        {"label": "private\nlabel"},
        {"require_json_only": 1},
    ],
)
def test_json_directory_inventory_validates_before_filesystem_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict,
) -> None:
    touched = False

    def fail_if_touched(_path: Path):
        nonlocal touched
        touched = True
        raise AssertionError("directory must not be inspected")

    monkeypatch.setattr(control_files.os, "lstat", fail_if_touched)
    arguments = {
        "directory": tmp_path / "catalog",
        "maximum_entries": 10,
        "maximum_files": 10,
        "maximum_file_bytes": 4096,
        "maximum_total_bytes": 40960,
        "label": "catalog",
        "require_json_only": False,
    }
    arguments.update(override)
    with pytest.raises(ContractError) as failure:
        inventory_bounded_json_directory(**arguments)
    assert "private\nlabel" not in str(failure.value)
    assert touched is False
