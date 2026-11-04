"""Publish a new flat Perfetto prefix without modifying the original recording."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from .contracts import ContractError
from .live_trace import snapshot_live_trace
from .recording_source import RecordingSource
from .recording_parts import MAX_PARTS, part_path, done_marker_path
from .recording_limits import MIB, limit_marker_path
from .recording_interruption import interruption_marker_path
from .perfetto import _stable_file_binding
from .owned_paths import (
    directory_ancestry_binding,
    directory_identity,
    require_owned_directory_ancestors,
)
from .prepared_download import require_temporary_cleanup_authority


def assemble_recording(session_path: Path, repository_root: Path, destination: Path, *,
                       allow_incomplete=False, reader_executable=None):
    if not isinstance(destination, Path) or type(allow_incomplete) is not bool:
        raise ContractError('invalid recording assembly options')
    requested_destination = destination
    requested_occupied = os.path.lexists(requested_destination)
    require_owned_directory_ancestors(
        requested_destination.parent, label='recording assembly output parent'
    )
    requested_parent = Path(os.path.normpath(requested_destination.parent.absolute()))
    parent_ancestry = directory_ancestry_binding(
        requested_parent, label='recording assembly output parent'
    )
    parent_identity = directory_identity(
        requested_destination.parent, label='recording assembly output parent'
    )
    if parent_identity is None:
        raise ContractError('assembly output parent is unavailable')
    destination = destination.resolve()
    require_owned_directory_ancestors(
        requested_destination.parent, label='recording assembly output parent'
    )
    if directory_identity(
        destination.parent, label='recording assembly output parent'
    ) != parent_identity:
        raise ContractError('assembly output parent changed during resolution')
    if directory_ancestry_binding(
        destination.parent, label='recording assembly output parent'
    ) != parent_ancestry:
        raise ContractError('assembly output parent changed during resolution')

    def require_output_parent_authority() -> None:
        require_owned_directory_ancestors(
            requested_destination.parent, label='recording assembly output parent'
        )
        if directory_identity(
            requested_destination.parent, label='recording assembly output parent'
        ) != parent_identity:
            raise ContractError('assembly output parent changed')
        if directory_ancestry_binding(
            requested_parent, label='recording assembly output parent'
        ) != parent_ancestry:
            raise ContractError('assembly output parent changed')

    source = RecordingSource(session_path, repository_root, reader_executable)
    location = source.resolve()
    session = location.session
    original = Path(session['live_trace']['path'])
    final = Path(session['trace_path'])
    reserved = [session_path, final, done_marker_path(final), limit_marker_path(final), interruption_marker_path(final)]
    reserved.extend(part_path(original, number) for number in range(1, MAX_PARTS+1))
    # The parts reader also probes the first unsupported continuation. Do not
    # publish an assembly there and make its original source invalid.
    reserved.append(Path(str(original) + f'.part{MAX_PARTS + 1}'))
    if destination in {path.resolve() for path in reserved}:
        raise ContractError('assembly output cannot replace any original recording artifact')
    if requested_occupied or os.path.lexists(requested_destination) or os.path.lexists(destination):
        raise ContractError('assembly output already exists')
    if location.phase != 'finalized-recording' and not allow_incomplete:
        raise ContractError('unfinished recording requires --allow-incomplete')
    try:
        with snapshot_live_trace(location.path, **({'parts': source.parts} if source.parts else {})) as snapshot:
            if location.phase == 'finalized-recording' and snapshot.incomplete_tail_bytes:
                raise ContractError('finalized recording has an incomplete packet')
            require_output_parent_authority()
            folder = TemporaryDirectory(prefix='.browser-core-assemble-', dir=destination.parent)
            root = Path(folder.name)
            authority = None
            try:
                ancestry = directory_ancestry_binding(root, label='assembly staging directory')
                authority = (root, ancestry[-1], ancestry)
                require_temporary_cleanup_authority(
                    folder, authority, label='assembly staging directory',
                )
                staged = root / 'recording.pftrace'
                digest = hashlib.sha256()
                written = 0
                with snapshot.path.open('rb') as origin, staged.open('xb') as output:
                    for body in iter(lambda: origin.read(MIB), b''):
                        written += len(body)
                        if written > snapshot.bytes:
                            raise ContractError('assembly snapshot changed')
                        if output.write(body) != len(body):
                            raise ContractError('recording assembly short write')
                        digest.update(body)
                    output.flush()
                    os.fsync(output.fileno())
                if written != snapshot.bytes or digest.hexdigest() != snapshot.sha256:
                    raise ContractError('assembly snapshot changed')
                # Any completion marker can disappear after the first
                # resolution while the flat snapshot is being copied. A
                # single final file can also move back to its live name.
                if source.resolve().phase != location.phase:
                    raise ContractError('assembly source phase changed')
                # A same-filesystem hard link publishes complete bytes without
                # replacing an existing destination. The staging link is gone
                # before the command returns; originals are never renamed.
                require_temporary_cleanup_authority(
                    folder, authority, label='assembly staging directory',
                )
                require_output_parent_authority()
                os.link(staged, destination)
            finally:
                require_temporary_cleanup_authority(
                    folder, authority, label='assembly staging directory',
                )
                folder.cleanup()
            try:
                published = _stable_file_binding(
                    destination,
                    label='assembly output',
                    maximum=max(written, 1),
                )
            except ContractError:
                raise ContractError('assembly output changed after publication') from None
            if published != {'bytes': written, 'sha256': snapshot.sha256}:
                raise ContractError('assembly output changed after publication')
            # Output hashing can outlast the marker that justified the source
            # phase. Recheck after that final publication work.
            if source.resolve().phase != location.phase:
                raise ContractError('assembly source phase changed')
            require_output_parent_authority()
            # Resolving the source after publication can outlast the output
            # digest check. Bind the returned receipt to the bytes still at
            # the published path after that final source check.
            try:
                final_binding = _stable_file_binding(
                    destination,
                    label='assembly output',
                    maximum=max(written, 1),
                )
            except ContractError:
                raise ContractError('assembly output changed after publication') from None
            if final_binding != published:
                raise ContractError('assembly output changed after publication')
            require_output_parent_authority()
            return {'schema': 'browser-core.recording-assembly/1', 'run_id': session['run_id'],
                    'output': str(destination), 'source_phase': location.phase,
                    'complete': location.phase == 'finalized-recording', 'bytes': written,
                    'packets': snapshot.packets, 'source_bytes': snapshot.source_bytes,
                    'excluded_tail_bytes': snapshot.incomplete_tail_bytes,
                    'sha256': snapshot.sha256, 'originals_unchanged': True}
    except OSError:
        raise ContractError('recording assembly could not publish its new output') from None
