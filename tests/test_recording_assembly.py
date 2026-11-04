from pathlib import Path
from contextlib import contextmanager
import hashlib
import os
import subprocess
import tempfile

import pytest

from browser_core.contracts import ContractError
from browser_core.recording_assembly import assemble_recording
from browser_core.recording_parts import part_path, done_marker_path
from browser_core.recording_interruption import interruption_marker_path
from browser_core.recording_limits import MIB, limit_marker_path
from browser_core.recording_source import bind_recording_file
from test_recording_recovery import source
from test_recording_parts import SIZE, packet


@pytest.fixture
def split(source):
    body=packet(b'a'*(SIZE-6))+packet(b'b'*901)
    source.path.write_bytes(body[:SIZE]);part_path(source.path,2).write_bytes(body[SIZE:])
    source.session['live_trace'].update(byte_limit=SIZE,
        parts={'schema':'browser-core.recording-parts/1','max_parts':3},
        file_binding=bind_recording_file(source.path))
    source.save();done_marker_path(source.final).write_bytes(b'')
    source.body=body
    return source


def test_assembly_publishes_exact_complete_stream_and_preserves_original_files(split):
    output=split.document.parent/'joined.pftrace'
    old=[(p,p.stat().st_ino,p.read_bytes()) for p in (split.path,part_path(split.path,2),split.document)]
    receipt=assemble_recording(split.document,split.document.parent,output)
    assert receipt['complete'] and receipt['bytes']==len(split.body)
    assert receipt['sha256']==hashlib.sha256(split.body).hexdigest() and output.read_bytes()==split.body
    assert output.stat().st_nlink==1 and not list(output.parent.glob('.browser-core-assemble-*'))
    assert all(p.stat().st_ino==identity and p.read_bytes()==body for p,identity,body in old)


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_assembly_rejects_preexisting_output_parent_junction(source):
    outside = source.document.parent / "unrelated"
    outside.mkdir()
    junction = source.document.parent / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip("host could not create an unprivileged directory junction")
    try:
        with pytest.raises(ContractError):
            assemble_recording(
                source.document, source.document.parent,
                junction / "joined.pftrace", allow_incomplete=True,
            )
        assert list(outside.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_assembly_rechecks_output_parent_before_staging(source, monkeypatch):
    import browser_core.recording_assembly as module

    parent = source.document.parent / "output"
    parent.mkdir()
    outside = source.document.parent / "unrelated"
    original_snapshot = module.snapshot_live_trace

    @contextmanager
    def swap_during_snapshot(*args, **kwargs):
        with original_snapshot(*args, **kwargs) as snapshot:
            parent.rename(outside)
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(parent), str(outside)],
                capture_output=True, check=False,
            )
            assert created.returncode == 0
            yield snapshot

    monkeypatch.setattr(module, "snapshot_live_trace", swap_during_snapshot)
    try:
        with pytest.raises(ContractError):
            assemble_recording(
                source.document, source.document.parent,
                parent / "joined.pftrace", allow_incomplete=True,
            )
        assert list(outside.iterdir()) == []
    finally:
        if parent.exists():
            parent.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_assembly_rejects_transient_parent_junction_during_resolution(source, monkeypatch):
    import browser_core.recording_assembly as module

    owned = source.document.parent / "owned"
    (owned / "leaf").mkdir(parents=True)
    retired = source.document.parent / "retired-owned"
    foreign = source.document.parent / "foreign"
    (foreign / "leaf").mkdir(parents=True)
    output = owned / "leaf" / "joined.pftrace"
    original_resolve = Path.resolve

    def resolve_during_switch(path, *args, **kwargs):
        if path != output:
            return original_resolve(path, *args, **kwargs)
        owned.rename(retired)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(owned), str(foreign)],
            capture_output=True, check=False,
        )
        if created.returncode:
            retired.rename(owned)
            pytest.skip("host could not create an unprivileged directory junction")
        try:
            return original_resolve(path, *args, **kwargs)
        finally:
            owned.rmdir()
            retired.rename(owned)

    attempted_staging = []

    def observe_staging(*args, **kwargs):
        attempted_staging.append(Path(kwargs["dir"]))
        raise ContractError("staging reached redirected parent")

    monkeypatch.setattr(Path, "resolve", resolve_during_switch)
    monkeypatch.setattr(module, "TemporaryDirectory", observe_staging)
    with pytest.raises(ContractError):
        assemble_recording(
            source.document, source.document.parent, output, allow_incomplete=True,
        )
    assert attempted_staging == []
    assert list((foreign / "leaf").iterdir()) == []


def test_assembly_rejects_a_postlink_destination_replacement(split, monkeypatch):
    import browser_core.recording_assembly as module

    output=split.document.parent/'joined-replaced.pftrace'
    replacement=split.document.parent/'competitor.pftrace'
    replacement.write_bytes(b'competing output')
    original_link=module.os.link

    def link_then_replace(source, destination):
        original_link(source, destination)
        replacement.replace(destination)

    monkeypatch.setattr(module.os, 'link', link_then_replace)
    with pytest.raises(ContractError, match='assembly output changed after publication'):
        assemble_recording(split.document, split.document.parent, output)
    assert output.read_bytes()==b'competing output'
    assert split.path.read_bytes()==split.body[:SIZE]


def test_assembly_preserves_replaced_staging_directory_after_publication(source, monkeypatch):
    import browser_core.recording_assembly as module

    output = source.document.parent / 'joined.pftrace'
    folder = tempfile.TemporaryDirectory(dir=output.parent)
    original_name = Path(folder.name)
    retained = output.parent / 'retained-staging'
    sentinel = original_name / 'unrelated.txt'
    cleanup = folder.cleanup
    calls = []
    original_link = module.os.link
    monkeypatch.setattr(folder, 'cleanup', lambda: calls.append('cleanup'))
    monkeypatch.setattr(module, 'TemporaryDirectory', lambda **kwargs: folder)

    def link_then_replace(staged, destination):
        original_link(staged, destination)
        original_name.rename(retained)
        original_name.mkdir()
        sentinel.write_text('preserve', encoding='utf-8')

    monkeypatch.setattr(module.os, 'link', link_then_replace)
    try:
        with pytest.raises(ContractError):
            assemble_recording(
                source.document, source.document.parent, output, allow_incomplete=True,
            )
        assert calls == []
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
        assert output.read_bytes() == source.path.read_bytes()
    finally:
        monkeypatch.setattr(folder, 'cleanup', cleanup)
        sentinel.unlink(missing_ok=True)
        if original_name.exists():
            original_name.rmdir()
        retained.rename(original_name)
        cleanup()


def test_assembly_rejects_changed_output_ancestor_and_preserves_staging(
        source, monkeypatch):
    import browser_core.recording_assembly as module

    private_parent = source.document.parent / 'private-parent'
    output_parent = private_parent / 'output'
    output_parent.mkdir(parents=True)
    retained_parent = source.document.parent / 'retained-parent'
    output = output_parent / 'joined.pftrace'
    folder = tempfile.TemporaryDirectory(dir=output_parent)
    name = Path(folder.name).name
    current_folder = output_parent / name
    sentinel = current_folder / 'unrelated.txt'
    original_link = module.os.link
    swapped = False

    def link_then_move_ancestor(staged, destination):
        nonlocal swapped
        original_link(staged, destination)
        private_parent.rename(retained_parent)
        private_parent.mkdir()
        (retained_parent / 'output').rename(output_parent)
        swapped = True
        sentinel.write_text('preserve', encoding='utf-8')

    monkeypatch.setattr(module, 'TemporaryDirectory', lambda **kwargs: folder)
    monkeypatch.setattr(module.os, 'link', link_then_move_ancestor)
    try:
        with pytest.raises(ContractError, match='assembly staging directory.*cleanup'):
            assemble_recording(
                source.document, source.document.parent, output,
                allow_incomplete=True,
            )
        assert output.read_bytes() == source.path.read_bytes()
        assert sentinel.read_text(encoding='utf-8') == 'preserve'
    finally:
        sentinel.unlink(missing_ok=True)
        if swapped:
            output_parent.rename(retained_parent / 'output')
            private_parent.rmdir()
            retained_parent.rename(private_parent)
        folder.cleanup()


def test_assembly_rebinds_output_after_final_source_check(split, monkeypatch):
    import browser_core.recording_assembly as module

    output=split.document.parent/'changed-during-source-check.pftrace'
    original_binding=module._stable_file_binding
    original_resolve=module.RecordingSource.resolve
    output_bound=False
    changed=False

    def bind_output(*args, **kwargs):
        nonlocal output_bound
        result=original_binding(*args, **kwargs)
        if args[0]==output:
            output_bound=True
        return result

    def resolve_then_change_output(source):
        nonlocal changed
        location=original_resolve(source)
        if output_bound and not changed:
            with output.open('r+b') as stream:
                stream.write(b'X')
            changed=True
        return location

    monkeypatch.setattr(module,'_stable_file_binding',bind_output)
    monkeypatch.setattr(module.RecordingSource,'resolve',resolve_then_change_output)
    with pytest.raises(ContractError,match='assembly output changed after publication'):
        assemble_recording(split.document,split.document.parent,output)
    assert changed
    assert output.read_bytes().startswith(b'X')


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junction boundary")
def test_assembly_rechecks_parent_after_final_output_binding(split, monkeypatch):
    import browser_core.recording_assembly as module

    parent = split.document.parent / "owned"
    parent.mkdir()
    retired = split.document.parent / "retired-owned"
    foreign = split.document.parent / "foreign"
    foreign.mkdir()
    output = parent / "joined.pftrace"
    original_binding = module._stable_file_binding
    bindings = 0

    def bind_then_redirect(path, *args, **kwargs):
        nonlocal bindings
        result = original_binding(path, *args, **kwargs)
        if path == output:
            bindings += 1
            if bindings == 2:
                parent.rename(retired)
                created = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(parent), str(foreign)],
                    capture_output=True, check=False,
                )
                if created.returncode:
                    retired.rename(parent)
                    pytest.skip("host could not create an unprivileged directory junction")
        return result

    monkeypatch.setattr(module, "_stable_file_binding", bind_then_redirect)
    try:
        with pytest.raises(ContractError):
            assemble_recording(split.document, split.document.parent, output)
        assert bindings == 2
        assert list(foreign.iterdir()) == []
        assert (retired / output.name).read_bytes() == split.body
    finally:
        if parent.exists() and parent.resolve() == foreign:
            parent.rmdir()
        if retired.exists():
            retired.rename(parent)


def test_assembly_never_overwrites_existing_output(split):
    output=split.document.parent/'existing';output.write_bytes(b'keep')
    with pytest.raises(ContractError,match='already exists'):assemble_recording(split.document,split.document.parent,output)
    assert output.read_bytes()==b'keep'


def test_assembly_rejects_dangling_symlink_output_name(split, monkeypatch):
    import browser_core.recording_assembly as module

    requested=split.document.parent/'dangling-link'
    target=split.document.parent/'link-target'
    original_resolve=Path.resolve
    original_lexists=os.path.lexists

    # Simulate a dangling link without relying on Windows symlink privileges.
    def resolve(path, *args, **kwargs):
        return target if path==requested else original_resolve(path, *args, **kwargs)

    def lexists(path):
        return True if Path(path)==requested else original_lexists(path)

    monkeypatch.setattr(Path, 'resolve', resolve)
    monkeypatch.setattr(module.os.path, 'lexists', lexists)
    with pytest.raises(ContractError, match='already exists'):
        assemble_recording(split.document, split.document.parent, requested)
    assert not target.exists()


def test_assembly_rejects_output_occupied_before_resolution_even_if_removed(split, monkeypatch):
    import browser_core.recording_assembly as module

    requested=split.document.parent/'vanishing-link'
    target=split.document.parent/'old-link-target'
    original_resolve=Path.resolve
    original_lexists=os.path.lexists
    occupied=True

    def resolve(path, *args, **kwargs):
        nonlocal occupied
        if path==requested:
            occupied=False
            return target
        return original_resolve(path, *args, **kwargs)

    def lexists(path):
        return occupied if Path(path)==requested else original_lexists(path)

    monkeypatch.setattr(Path, 'resolve', resolve)
    monkeypatch.setattr(module.os.path, 'lexists', lexists)
    with pytest.raises(ContractError, match='already exists'):
        assemble_recording(split.document, split.document.parent, requested)
    assert not target.exists()


def test_assembly_rejects_a_short_staging_write(split, monkeypatch):
    output = split.document.parent / 'short-write.pftrace'
    original_open = Path.open

    class ShortWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, body):
            return 0

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def open_with_short_write(path, mode='r', *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        if path.name == 'recording.pftrace' and mode == 'xb':
            return ShortWriter(stream)
        return stream

    monkeypatch.setattr(Path, 'open', open_with_short_write)

    with pytest.raises(ContractError, match='short write'):
        assemble_recording(split.document, split.document.parent, output)
    assert not output.exists()


def test_assembly_cannot_claim_complete_after_completion_marker_disappears(split,monkeypatch):
    import browser_core.recording_assembly as module

    output=split.document.parent/'marker-lost.pftrace'
    original=module.snapshot_live_trace
    @contextmanager
    def remove_marker_before_copy(*args,**kwargs):
        with original(*args,**kwargs) as snapshot:
            done_marker_path(split.final).unlink()
            yield snapshot

    monkeypatch.setattr(module,'snapshot_live_trace',remove_marker_before_copy)
    with pytest.raises(ContractError,match='marker changed'):
        assemble_recording(split.document,split.document.parent,output)
    assert not output.exists()


def test_assembly_cannot_claim_complete_when_marker_disappears_during_output_binding(split, monkeypatch):
    import browser_core.recording_assembly as module

    output = split.document.parent / 'late-marker-loss.pftrace'
    original = module._stable_file_binding

    def bind_then_remove_marker(*args, **kwargs):
        binding = original(*args, **kwargs)
        done_marker_path(split.final).unlink()
        return binding

    monkeypatch.setattr(module, '_stable_file_binding', bind_then_remove_marker)
    with pytest.raises(ContractError, match='marker changed'):
        assemble_recording(split.document, split.document.parent, output)


@pytest.mark.parametrize('marker_kind,phase', [
    ('limit', 'limited-recording'),
    ('interrupted', 'interrupted-recording'),
])
def test_incomplete_assembly_rechecks_terminal_marker_after_output_binding(
        source, monkeypatch, marker_kind, phase):
    import browser_core.recording_assembly as module

    source.session['live_trace']['byte_limit'] = 4 * MIB
    source.save()
    marker = (limit_marker_path(source.final) if marker_kind == 'limit'
              else interruption_marker_path(source.final))
    marker.write_bytes(b'')

    stable_output = source.document.parent / f'stable-{marker_kind}.pftrace'
    stable = assemble_recording(source.document, source.document.parent,
                                stable_output, allow_incomplete=True)
    assert stable['source_phase'] == phase and stable['complete'] is False
    assert stable_output.read_bytes() == source.path.read_bytes()

    output = source.document.parent / f'lost-{marker_kind}.pftrace'
    original_binding = module._stable_file_binding
    removed = False

    def bind_then_remove_marker(*args, **kwargs):
        nonlocal removed
        binding = original_binding(*args, **kwargs)
        if args[0] == output and not removed:
            marker.unlink()
            removed = True
        return binding

    monkeypatch.setattr(module, '_stable_file_binding', bind_then_remove_marker)
    with pytest.raises(ContractError, match='marker changed|phase changed'):
        assemble_recording(source.document, source.document.parent,
                           output, allow_incomplete=True)
    assert removed
    assert output.read_bytes() == source.path.read_bytes()


def test_single_file_assembly_cannot_claim_complete_after_final_name_is_lost(source,monkeypatch):
    import browser_core.recording_assembly as module

    source.status.update(state='stale',running=False)
    source.path.rename(source.final)
    output=source.document.parent/'renamed-away.pftrace'
    original=module.snapshot_live_trace
    @contextmanager
    def rename_final_before_copy(*args,**kwargs):
        with original(*args,**kwargs) as snapshot:
            source.final.rename(source.path)
            yield snapshot

    monkeypatch.setattr(module,'snapshot_live_trace',rename_final_before_copy)
    with pytest.raises(ContractError,match='phase changed'):
        assemble_recording(source.document,source.document.parent,output)
    assert not output.exists()


@pytest.mark.parametrize('which',['session','first','next','final','done','limit'])
def test_assembly_output_cannot_conflict_with_original_artifact_names(split,which):
    from browser_core.recording_limits import limit_marker_path
    targets={'session':split.document,'first':split.path,'next':part_path(split.path,3),
             'final':split.final,'done':done_marker_path(split.final),'limit':limit_marker_path(split.final)}
    with pytest.raises(ContractError,match='original recording'):assemble_recording(split.document,split.document.parent,targets[which])


def test_assembly_refuses_unsupported_part_name_before_publication(split):
    # The part reader treats part17 as an unsupported continuation. Publishing
    # the assembled copy there would make the original recording unreadable.
    output=Path(str(split.path)+'.part17')
    assert not os.path.lexists(output)
    with pytest.raises(ContractError):
        assemble_recording(split.document,split.document.parent,output)
    assert not os.path.lexists(output)

    ordinary=split.document.parent/'joined-after-refusal.pftrace'
    receipt=assemble_recording(split.document,split.document.parent,ordinary)
    assert receipt['complete'] and ordinary.read_bytes()==split.body


def test_incomplete_copy_requires_explicit_option_and_excludes_partial_tail(source):
    source.path.write_bytes(source.path.read_bytes()+b'\x0a\x03a')
    output=source.document.parent/'prefix'
    with pytest.raises(ContractError,match='allow-incomplete'):assemble_recording(source.document,source.document.parent,output)
    assert not output.exists()
    receipt=assemble_recording(source.document,source.document.parent,output,allow_incomplete=True)
    assert not receipt['complete'] and receipt['excluded_tail_bytes']==3
    assert output.read_bytes()==b'\x0a\x03abc' and source.path.read_bytes()==b'\x0a\x03abc\x0a\x03a'


def test_cli_assembly_passes_only_explicit_output_and_recovery_policy(source,monkeypatch):
    from browser_core.cli import build_parser
    calls=[]
    monkeypatch.setattr('browser_core.recording_assembly.assemble_recording',lambda *a,**k:calls.append((a,k)) or {'complete':False})
    output=source.document.parent/'prefix'
    args=build_parser().parse_args(['trace','assemble','--session',str(source.document),'--output',str(output),'--allow-incomplete'])
    assert args.func(args)==0
    assert calls[0][0][0]==source.document and calls[0][0][2]==output
    assert calls[0][1]=={'allow_incomplete':True,'reader_executable':None}
