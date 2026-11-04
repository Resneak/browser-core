"""Select a regular Git executable before invoking checkout commands."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path, PureWindowsPath
from typing import Iterator

from .contracts import ContractError
from .owned_paths import directory_ancestry_binding, directory_identity


_PINNED_GIT: ContextVar[Path | None] = ContextVar("browser_core_pinned_git", default=None)


def git_blob_sha1(body: bytes) -> str:
    """Return a SHA-1 Git blob ID from literal bytes without invoking filters."""
    if type(body) is not bytes:
        raise ContractError("Git blob body must be bytes")
    digest = hashlib.sha1()
    digest.update(b"blob " + str(len(body)).encode("ascii") + b"\0")
    digest.update(body)
    return digest.hexdigest()


def decode_portable_git_path(raw: bytes) -> tuple[str, ...]:
    """Admit one Git relative path before mapping it into a Windows worktree."""
    if type(raw) is not bytes or not raw or len(raw) > 4096 or b"\0" in raw:
        raise ContractError("Git path is invalid")
    try:
        rendered = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ContractError("Git path is invalid") from None
    parts = tuple(rendered.split("/"))
    if any(
        part in ("", ".", "..")
        or part.endswith((".", " "))
        or PureWindowsPath(part).is_reserved()
        or any(character in '\\:<>|?*"' or ord(character) < 0x20 or ord(character) == 0x7F for character in part)
        for part in parts
    ):
        raise ContractError("Git path is invalid")
    return parts


@contextmanager
def pinned_git_executable(git_executable: Path | None) -> Iterator[Path]:
    """Pin one checked executable for nested Git calls in this context."""
    selected = select_git_executable(git_executable)
    token = _PINNED_GIT.set(selected)
    try:
        yield selected
    finally:
        _PINNED_GIT.reset(token)


def select_git_executable(
    git_executable: Path | None = None,
    *,
    excluded_checkout: Path | None = None,
) -> Path:
    """Return a checked absolute executable path, never a bare PATH command.

    The explicit argument wins over the process setting. An invalid setting is
    an error instead of permission to fall back to a different Git program.
    """
    if git_executable is None:
        git_executable = _PINNED_GIT.get()
    if git_executable is None:
        configured = os.environ.get("BROWSER_CORE_GIT_EXE")
        if configured is not None:
            try:
                git_executable = Path(configured)
            except (TypeError, ValueError):
                raise ContractError("Git executable selection is invalid") from None
        else:
            found = shutil.which("git.exe" if os.name == "nt" else "git")
            if found is None:
                raise ContractError("Git executable is unavailable")
            git_executable = Path(found)
    if not isinstance(git_executable, Path) or not git_executable.is_absolute():
        raise ContractError("Git executable must be an absolute path")
    rendered = str(git_executable)
    try:
        rendered.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("Git executable path is invalid") from None
    if "\x00" in rendered or (
        os.name == "nt"
        and any(part.endswith((" ", ".")) for part in git_executable.parts[1:])
    ):
        raise ContractError("Git executable path is invalid")
    if git_executable.name.casefold() != ("git.exe" if os.name == "nt" else "git"):
        raise ContractError("Git executable name is invalid")
    parent_binding = directory_ancestry_binding(
        git_executable.parent, label="Git executable parent"
    )
    try:
        metadata = os.lstat(git_executable)
    except OSError:
        raise ContractError("Git executable is unavailable") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)
        or metadata.st_nlink != 1
    ):
        raise ContractError("Git executable must be a regular single-link file")
    if excluded_checkout is not None:
        if not isinstance(excluded_checkout, Path):
            raise ContractError("Git executable checkout path is invalid")
        checkout_identity = directory_identity(
            excluded_checkout.absolute(), label="Git executable checkout"
        )
        if checkout_identity is None:
            raise ContractError("Git executable checkout is unavailable")
        if checkout_identity in parent_binding:
            raise ContractError("Git executable must be outside the checkout")
    if directory_ancestry_binding(
        git_executable.parent, label="Git executable parent"
    ) != parent_binding:
        raise ContractError("Git executable parent changed")
    return git_executable


def git_executable_binding(path: Path) -> tuple[object, ...]:
    """Keep path and file identity for bounded pre/post command rechecks."""
    select_git_executable(path)
    try:
        metadata = os.lstat(path)
    except OSError:
        raise ContractError("Git executable is unavailable") from None
    return (
        directory_ancestry_binding(path.parent, label="Git executable parent"),
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def isolated_git_environment() -> dict[str, str]:
    """Discard inherited Git controls and disable local replacement refs."""
    isolated = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    # A local refs/replace entry can make `rev-parse HEAD` report the pinned
    # commit while tree queries read a different commit's objects.
    isolated["GIT_NO_REPLACE_OBJECTS"] = "1"
    return isolated
