"""Publish complete downloads before retiring old, owned temporary directories."""
from __future__ import annotations
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

from .contracts import ContractError
from .owned_paths import (
    directory_ancestry_binding,
    directory_identity,
    require_owned_directory_ancestors,
)


class ExportCleanupPending(ContractError):
    """A held temporary directory must be released before another preparation."""


def require_temporary_cleanup_authority(folder, authority, *, label):
    """Refuse path-based cleanup after a private directory name changes owner."""
    try:
        if authority is None:
            raise ContractError(f'{label} has no directory authority')
        if type(authority) is not tuple or len(authority) not in (2, 3):
            raise ContractError(f'{label} has no directory authority')
        expected_path, expected_identity = authority[:2]
        if Path(folder.name) != expected_path:
            raise ContractError(f'{label} path changed')
        if len(authority) == 3:
            if directory_ancestry_binding(expected_path, label=label) != authority[2]:
                raise ContractError(f'{label} ancestor changed')
        else:
            require_owned_directory_ancestors(expected_path.parent, label=label)
        if directory_identity(expected_path, label=label) != expected_identity:
            raise ContractError(f'{label} identity changed')
    except (AttributeError, ContractError, OSError, TypeError, ValueError):
        # TemporaryDirectory's finalizer otherwise removes the replacement
        # later, even when explicit cleanup correctly refuses it now.
        finalizer = getattr(folder, '_finalizer', None)
        if finalizer is not None:
            try:
                finalizer.detach()
            except Exception:
                pass
        raise ContractError(f'{label} changed before cleanup') from None


@contextmanager
def guarded_temporary_directory_with_check(folder, *, label):
    """Yield a private directory and a check for subsequent path operations."""
    root = Path(folder.name)
    authority = None
    try:
        ancestry = directory_ancestry_binding(root, label=label)
        authority = (root, ancestry[-1], ancestry)

        def check():
            require_temporary_cleanup_authority(folder, authority, label=label)

        check()
        yield root, check
    finally:
        require_temporary_cleanup_authority(folder, authority, label=label)
        folder.cleanup()


@contextmanager
def guarded_temporary_directory(folder, *, label):
    """Yield a private directory and clean it only while its name is still owned."""
    with guarded_temporary_directory_with_check(folder, label=label) as (root, _check):
        yield root


class PreparedDownload:
    """One published artifact and at most one directory awaiting cleanup.

    The panel's read lock serializes preparation, download and close. Directory
    cleanup can remove files before failing, so it must never precede publication
    of the replacement. A failed cleanup is retained and retried before any new
    preparation; repeated failures cannot accumulate directories or large exports.
    """
    def __init__(self):
        self.folder=self.path=self.receipt=None
        self._retired=None
        self._folder_authority=None
        self._retired_authority=None

    def _ensure_cleanup(self):
        if self._retired is None:return
        try:
            require_temporary_cleanup_authority(
                self._retired, self._retired_authority,
                label='retired prepared download directory',
            )
            self._retired.cleanup()
        except (ContractError,OSError,RecursionError):
            # Python 3.10 TemporaryDirectory can recursively retry a held Windows
            # directory until RecursionError. Retain the owner for a later retry.
            raise ExportCleanupPending('previous export cleanup is pending') from None
        self._retired=None
        self._retired_authority=None

    def _discard(self,folder,*,authority=None):
        if self._retired is not None:
            raise RuntimeError('export cleanup must precede another preparation')
        self._retired=folder
        self._retired_authority=authority
        try:self._ensure_cleanup()
        except ExportCleanupPending:pass

    def _publish(self,folder,path,receipt,*,validate_source=None,
                 expected_directory_ancestry=None):
        from .perfetto import _stable_file_binding

        authority=None
        try:
            private_root=Path(folder.name)
            if expected_directory_ancestry is not None:
                if type(expected_directory_ancestry) is not tuple or not expected_directory_ancestry:
                    raise ContractError('prepared download directory authority is invalid')
                authority=(private_root,expected_directory_ancestry[-1],
                           expected_directory_ancestry)
            if (type(receipt) is not dict or type(receipt.get('bytes')) is not int
                    or receipt['bytes'] < 1 or type(receipt.get('sha256')) is not str):
                raise ContractError('prepared download receipt is invalid')
            # Retain the exact claim being checked before the source callback
            # can mutate a caller-owned receipt or one of its nested summaries.
            retained=deepcopy(receipt)
            if path.parent!=private_root:
                raise ContractError('prepared download path escaped its private directory')
            private_ancestry=directory_ancestry_binding(
                private_root,label='prepared download directory')
            if (expected_directory_ancestry is not None
                    and private_ancestry!=expected_directory_ancestry):
                raise ContractError('prepared download directory changed')
            private_identity=private_ancestry[-1]
            authority=(private_root,private_identity,private_ancestry)
            binding=_stable_file_binding(path,label='prepared download',maximum=retained['bytes'])
            if directory_ancestry_binding(private_root,label='prepared download directory')!=private_ancestry:
                raise ContractError('prepared download directory changed')
            if binding!={'bytes':retained['bytes'],'sha256':retained['sha256']}:
                raise ContractError('prepared download digest disagrees with its receipt')
            if validate_source is not None:
                validate_source()
                # Source validation can run after a long export and must not
                # leave a receipt for bytes changed during that final check.
                if directory_ancestry_binding(private_root,label='prepared download directory')!=private_ancestry:
                    raise ContractError('prepared download directory changed')
                if _stable_file_binding(path,label='prepared download',maximum=retained['bytes'])!=binding:
                    raise ContractError('prepared download changed during source validation')
                if directory_ancestry_binding(private_root,label='prepared download directory')!=private_ancestry:
                    raise ContractError('prepared download directory changed')
        except ContractError:
            self._discard(folder,authority=authority)
            raise ContractError('prepared download changed before publication') from None
        except BaseException:
            self._discard(folder,authority=authority)
            raise
        returned=deepcopy(retained)
        previous=self.folder
        previous_authority=self._folder_authority
        self.folder,self.path,self.receipt=folder,path,retained
        self._folder_authority=(private_root,private_identity,private_ancestry)
        if previous is not None:
            self._discard(previous,authority=previous_authority)
        # Comparison receipts contain a nested report. Keep callers from
        # changing the retained receipt after the file has been published.
        return returned

    def close(self):
        failed=False
        if self.folder is not None:
            try:
                require_temporary_cleanup_authority(
                    self.folder, self._folder_authority,
                    label='prepared download directory',
                )
                self.folder.cleanup()
            except (ContractError,OSError,RecursionError):
                failed=True
            else:
                self.folder=self.path=self.receipt=None
                self._folder_authority=None
        try:self._ensure_cleanup()
        except ExportCleanupPending:failed=True
        if failed:
            raise ExportCleanupPending('temporary export cleanup is pending') from None
