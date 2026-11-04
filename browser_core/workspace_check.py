"""Reversible admission check of the exact profile and recording directories."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from .contracts import ContractError
from .control_files import _identity, remove_control_conditionally
from .launcher import validate_workspace
from .native_paths import native_browser_path
from .owned_paths import directory_ancestry_binding, directory_identity
from .profiles import validate_profile_id

SCHEMA = 'browser-core.workspace-check/1'


def check_workspace(workspace: Path, root: Path, profile_id: str) -> dict:
    """No browser/profile registry is created. Remove only our empty probe paths.

    Success is a point-in-time host check, not a grant of write authority or a
    promise that the later launch sees unchanged paths/permissions.
    """
    created=[]
    code='workspace-invalid'
    cleanup=True
    workspace_binding=None
    try:
        if not isinstance(workspace, Path) or not workspace.is_absolute():
            raise ContractError('absolute workspace required')
        workspace=validate_workspace(workspace,root)
        if directory_identity(workspace,label='workspace admission root') is not None:
            workspace_binding=directory_ancestry_binding(workspace,label='workspace admission root')
        validate_profile_id(profile_id)
        profile=workspace/'profiles'/'data'/profile_id
        directories=(profile, workspace/'profiles'/'registry', workspace/'sessions', workspace/'traces')
        for directory in directories:
            missing=[]
            current=directory
            while not os.path.lexists(current):
                missing.append(current)
                current=current.parent
            directory_identity(current,label='workspace admission parent')
            for path in reversed(missing):
                path.mkdir()
                try:
                    created_identity=directory_identity(path,label='workspace admission directory')
                    created_binding=directory_ancestry_binding(path,label='workspace admission directory')
                except (OSError,ContractError):
                    # mkdir succeeded, but we cannot prove custody of the new
                    # path. Keep the residue and report incomplete cleanup.
                    cleanup=False
                    raise
                if created_identity is None:
                    cleanup=False
                    raise ContractError('workspace admission directory disappeared')
                created.append((path,created_identity,created_binding))
                if path==workspace and workspace_binding is None:
                    workspace_binding=created_binding
            if workspace_binding is None:
                workspace_binding=directory_ancestry_binding(workspace,label='workspace admission root')
            elif directory_ancestry_binding(workspace,label='workspace admission root')!=workspace_binding:
                raise ContractError('workspace changed during admission')
            identity=directory_identity(directory,label='workspace admission directory')
            directory_binding=directory_ancestry_binding(directory,label='workspace admission directory')
            descriptor,name=tempfile.mkstemp(prefix='.browser-core-admission-',dir=directory)
            probe_identity=None
            try:
                with os.fdopen(descriptor,'w+b') as probe:
                    probe.write(b'browser-core-workspace-check\n')
                    probe.flush()
                    os.fsync(probe.fileno())
                    probe.seek(0)
                    if probe.read()!=b'browser-core-workspace-check\n':
                        raise OSError('workspace readback failed')
                    # Retain the created object, never adopt a later pathname
                    # occupant (even if its bytes happen to be identical).
                    probe_identity=_identity(os.fstat(probe.fileno()))
                if (directory_identity(directory,label='workspace admission directory')!=identity
                        or directory_ancestry_binding(directory,label='workspace admission directory')!=directory_binding):
                    raise ContractError('workspace changed during admission')
            finally:
                try:
                    if (probe_identity is None or
                            directory_identity(directory,label='workspace admission cleanup')!=identity or
                            directory_ancestry_binding(directory,label='workspace admission cleanup')!=directory_binding):
                        raise ContractError('workspace probe custody unavailable')
                    remove_control_conditionally(Path(name),
                        expected_body=b'browser-core-workspace-check\n',
                        expected_identity=probe_identity,maximum=4096,
                        label='workspace admission probe',require_handle_delete=True)
                except (OSError,ContractError):
                    cleanup=False
            if not cleanup:
                raise ContractError('workspace probe cleanup incomplete')
        code='native-path-unavailable'
        native_browser_path(profile,profile=True)
        # Exactly the launcher's fixed run-id shape; no run/session is created.
        native_browser_path(workspace/'traces'/'core-20000101T000000Z-00000000.perfetto-trace',profile=False)
        if (workspace_binding is None or
                directory_ancestry_binding(workspace,label='workspace admission root')!=workspace_binding):
            raise ContractError('workspace changed during admission')
        code='ready'
    except PermissionError:
        code='workspace-permission-denied'
    except OSError:
        code='workspace-io-unavailable'
    except ContractError:
        pass
    finally:
        workspace_authority_ok=True
        if workspace_binding is not None:
            try:
                workspace_authority_ok=(
                    directory_ancestry_binding(workspace,label='workspace admission cleanup')
                    ==workspace_binding
                )
            except (OSError,ContractError):
                workspace_authority_ok=False
            if not workspace_authority_ok:
                cleanup=False
        for path,identity,binding in reversed(created):
            try:
                if (not workspace_authority_ok or
                        directory_identity(path,label='workspace admission cleanup')!=identity or
                        directory_ancestry_binding(path,label='workspace admission cleanup')!=binding):
                    cleanup=False
                    continue
                path.rmdir()  # Only an empty directory whose creation we retained.
            except (OSError,ContractError):
                cleanup=False
    if not cleanup:
        code='workspace-cleanup-incomplete'
    return {'schema':SCHEMA,'status':'ok' if code=='ready' else 'error','code':code,
            'workspace_ready':code=='ready','cleanup_verified':cleanup,
            'browser_launched':False,'profile_created':False,'grants_authority':False,
            'path_and_permission_snapshot_only':True}
