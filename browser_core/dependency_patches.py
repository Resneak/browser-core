"""Pinned patch scopes for Chromium Git dependencies, without relaxing root checks."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import hashlib
import os
import re
import stat

from .contracts import ContractError
from .owned_paths import directory_ancestry_binding


def dependency_scopes(series: dict) -> dict[str, str]:
    items = series.get('dependencies', [])
    if not isinstance(items, list) or len(items) > 8 or ('dependencies' in series and not items):
        raise ContractError('patch dependencies must be a nonempty bounded list')
    scopes = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {'path', 'revision'}:
            raise ContractError('patch dependency fields are invalid')
        name, revision = item['path'], item['revision']
        if (not isinstance(name, str) or len(name) > 512
                or not re.fullmatch(r'[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)*', name)
                or any(part in ('.', '..', '.git') for part in name.split('/'))
                or not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}', revision)):
            raise ContractError('patch dependency pin is invalid')
        if any(name.lower() == other.lower() or name.lower().startswith(other.lower()+'/')
               or other.lower().startswith(name.lower()+'/') for other in scopes):
            raise ContractError('patch dependency scopes overlap')
        scopes[name] = revision
    for patch in series.get('patches', []):
        if 'checkout' in patch and (not isinstance(patch['checkout'], str) or patch['checkout'] not in scopes):
            raise ContractError('patch checkout is not a declared dependency')
    for name in scopes:
        if not any(patch.get('checkout') == name for patch in series.get('patches', [])):
            raise ContractError('patch dependency has no declared patches')
        if not any(image['path'].startswith(name+'/') for image in series.get('postimages', [])):
            raise ContractError('patch dependency has no declared postimages')
    return scopes


def grouped_bodies(bundle) -> dict[str, list[bytes]]:
    groups = {'': []}
    groups.update({name: [] for name in dependency_scopes(bundle.series)})
    by_name = dict(bundle.patch_bodies)
    for patch in bundle.series['patches']:
        groups[patch.get('checkout', '')].append(by_name[patch['file']])
    return groups


def verify_dependency_roots(checkout: Path, series: dict) -> None:
    try:
        _verify_dependency_roots(checkout, series)
    except OSError:
        raise ContractError('patch dependency filesystem check failed') from None


def _verify_dependency_roots(checkout: Path, series: dict) -> None:
    from . import upstream as up

    for scope, expected in dependency_scopes(series).items():
        # Every directory component must be ordinary; resolving a linked scope
        # first would conceal the redirection from the checkout-shape check.
        target = checkout
        for component in PurePosixPath(scope).parts:
            target = target / component
            if target.is_symlink() or getattr(target.lstat(), 'st_file_attributes', 0) & 0x400:
                raise ContractError('patch dependency path is redirected')
        up._require_git_worktree_shape(target)
        code, root = up._run_git_capture(target, ['rev-parse', '--show-toplevel'], maximum=8192)
        try:
            actual_root = Path(root.decode('utf-8').strip()).resolve()
        except (UnicodeError, ValueError, OSError):
            raise ContractError('patch dependency worktree root is invalid') from None
        if code or actual_root != target.resolve():
            raise ContractError('patch dependency is not its own worktree')
        code, body = up._run_git_capture(checkout, ['ls-tree', 'HEAD', '--', scope], maximum=4096)
        if code or body.rstrip(b'\r\n') != f'160000 commit {expected}\t{scope}'.encode('ascii'):
            raise ContractError('patch dependency differs from the Chromium Git pin')
        code, body = up._run_git_capture(target, ['rev-parse', 'HEAD'], maximum=128)
        if code or body.strip() != expected.encode('ascii'):
            raise ContractError('patch dependency checkout differs from its pin')


def verify_dependency_deltas(checkout: Path, bundle) -> dict[str, bytes]:
    from . import upstream as up

    verify_dependency_roots(checkout, bundle.series)
    states = {}
    for scope, bodies in grouped_bodies(bundle).items():
        if not scope:
            continue
        target = checkout / scope
        if not up._reverse_patch_population(target, bodies):
            raise ContractError('declared dependency patches are not fully applied')
        if up._run_git_no_output(target, ['diff', '--check', 'HEAD', '--']):
            raise ContractError('patch dependency has an invalid tracked delta')
        code, body = up._run_git_capture(target,
            ['diff', '--name-only', '-z', '--ignore-submodules=none', 'HEAD', '--'],
            maximum=up.MAX_CHANGED_PATH_BYTES)
        try:
            names = [name.decode('utf-8') for name in body.split(b'\0') if name]
        except UnicodeError:
            raise ContractError('patch dependency change inventory is invalid') from None
        expected = {image['path'][len(scope)+1:] for image in bundle.series['postimages']
                    if image['path'].startswith(scope+'/')}
        if code or len(names) != len(set(names)) or set(names) != expected:
            raise ContractError('patch dependency tracked delta differs from its postimages')
        states[scope] = body
    return states


def _normalize_dependency_postimage(
    target: Path, *, expected_body: bytes,
    expected_identity: tuple[int, int, int, int, int, int] | None,
    normalized: bytes, maximum: int,
) -> None:
    """Write through the verified source handle, never a later path replacement."""
    from . import upstream as up

    def changed() -> None:
        raise ContractError('dependency postimage changed before normalization')

    if expected_identity is None or len(expected_body) > maximum or len(normalized) > maximum:
        changed()
    try:
        path_before = os.lstat(target)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or bool(getattr(path_before, 'st_file_attributes', 0) & 0x400)
            or path_before.st_nlink != 1
            or up._file_identity(path_before) != expected_identity
        ):
            changed()
        with target.open('r+b', buffering=0) as source:
            held = os.fstat(source.fileno())
            if held.st_nlink != 1 or up._file_identity(held) != expected_identity:
                changed()
            offset = 0
            while offset < len(expected_body):
                block = source.read(min(1024 * 1024, len(expected_body) - offset))
                if not block or block != expected_body[offset:offset + len(block)]:
                    changed()
                offset += len(block)
            if source.read(1):
                changed()
            held_before_write = os.fstat(source.fileno())
            path_before_write = os.lstat(target)
            if (
                up._file_identity(held_before_write) != expected_identity
                or up._file_identity(path_before_write) != expected_identity
                or path_before_write.st_nlink != 1
            ):
                changed()
            source.seek(0)
            remaining = memoryview(normalized)
            while remaining:
                count = source.write(remaining[:1024 * 1024])
                if count is None or count <= 0:
                    raise ContractError('dependency postimage normalization write failed')
                remaining = remaining[count:]
            source.truncate(len(normalized))
            source.flush()
            os.fsync(source.fileno())
            held_after = os.fstat(source.fileno())
            path_after = os.lstat(target)
            if (
                up._file_identity(held_after) != up._file_identity(path_after)
                or held_after.st_nlink != 1
                or path_after.st_nlink != 1
                or bool(getattr(path_after, 'st_file_attributes', 0) & 0x400)
            ):
                raise ContractError('dependency postimage changed during normalization')
    except OSError as exc:
        raise ContractError(
            f'dependency postimage normalization failed ({type(exc).__name__})'
        ) from None


def apply_dependency_series(checkout: Path, bundle, *, check_only: bool) -> dict:
    from . import upstream as up

    groups = grouped_bodies(bundle)
    pending_groups = []
    authority = {
        (checkout / scope if scope else checkout): directory_ancestry_binding(
            (checkout / scope if scope else checkout).absolute(),
            label='patch dependency checkout',
        )
        for scope in groups
    }
    target_guards = {
        (checkout / scope if scope else checkout): up._patch_target_guard(
            checkout / scope if scope else checkout, bodies,
        )
        for scope, bodies in groups.items()
    }
    applied = checked = 0

    def require_authority() -> None:
        for target, binding in authority.items():
            if (
                directory_ancestry_binding(
                    target.absolute(), label='patch dependency checkout'
                ) != binding
            ):
                raise ContractError('patch dependency checkout authority changed')
            target_guards[target]()

    verify_dependency_roots(checkout, bundle.series)
    require_authority()
    code, revision = up._run_git_capture(checkout, ['rev-parse', 'HEAD'], maximum=128)
    require_authority()
    if code or revision.strip() != bundle.series['chromium_revision'].encode('ascii'):
        raise ContractError('patched checkout does not match the pinned Chromium revision')

    # Preflight every worktree before mutation. A failure during application can
    # leave earlier worktrees applied; the existing classification makes retry
    # explicit and idempotent. There is no cross-worktree transaction.
    for scope, bodies in groups.items():
        target = checkout / scope if scope else checkout
        pending, present = up._classify_patch_population(target, bodies)
        require_authority()
        pending_groups.append((target, pending))
        applied += present
        checked += len(bodies)
    require_authority()
    changed = 0
    if not check_only:
        for target, pending in pending_groups:
            require_authority()
            up._apply_pending_population(target, pending)
            require_authority()
            changed += len(pending)
        # Git can expand an LF patch to CRLF according to a dependency's local
        # checkout settings. Admit normalization only if it produces the exact
        # declared postimage; never normalize away an unrelated source change.
        for scope in dependency_scopes(bundle.series):
            for image in bundle.series['postimages']:
                if not image['path'].startswith(scope+'/'):
                    continue
                require_authority()
                target = checkout / image['path']
                snapshot = up.read_bounded_control_snapshot_result(target,
                    maximum=up.MAX_POSTIMAGE_BYTES, label='dependency postimage', require_single_link=True)
                if snapshot.state != 'complete' or snapshot.body is None:
                    raise ContractError('dependency postimage is not readable after patching')
                before = hashlib.sha256(snapshot.body).hexdigest()
                if before == image['sha256']:
                    continue
                normalized = snapshot.body.replace(b'\r\n', b'\n')
                if hashlib.sha256(normalized).hexdigest() != image['sha256']:
                    raise ContractError('dependency postimage differs after patching')
                if up._stable_file_sha256(target, label='dependency postimage', maximum=up.MAX_POSTIMAGE_BYTES) != before:
                    raise ContractError('dependency postimage changed before normalization')
                require_authority()
                _normalize_dependency_postimage(
                    target, expected_body=snapshot.body,
                    expected_identity=snapshot.identity,
                    normalized=normalized, maximum=up.MAX_POSTIMAGE_BYTES,
                )
                require_authority()
                if up._stable_file_sha256(
                    target, label='dependency postimage', maximum=up.MAX_POSTIMAGE_BYTES
                ) != image['sha256']:
                    raise ContractError('dependency postimage changed after normalization')
    require_authority()
    return {'applied': changed, 'already_applied': applied, 'checked': checked}
