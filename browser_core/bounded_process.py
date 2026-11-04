from __future__ import annotations

import os
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Sequence

from .errors import ContractError
from .numeric import is_finite_number


MAX_PROCESS_ARGUMENT_BYTES = 32 * 1024
MAX_PROCESS_COMMAND_BYTES = 1024 * 1024
MAX_PROCESS_LABEL_BYTES = 256
MAX_PROCESS_ENVIRONMENT_BYTES = 1024 * 1024
MAX_PROCESS_ENVIRONMENT_ENTRIES = 4096


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes


def _kill_and_reap(process: subprocess.Popen[bytes], *, label: str) -> None:
    try:
        process.kill()
    except (OSError, RuntimeError, ValueError):
        # The process may have exited between the failed operation and cleanup;
        # the bounded wait below is the authoritative reap check.
        pass
    try:
        returncode = process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        raise ContractError(f"{label} process cleanup timed out") from None
    except (OSError, RuntimeError, ValueError) as exc:
        raise ContractError(
            f"{label} process cleanup failed ({type(exc).__name__})"
        ) from None
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise ContractError(f"{label} process cleanup status is invalid")


def _reader_start_cleanup(
    process: subprocess.Popen[bytes],
    *,
    label: str,
    reader: threading.Thread | None,
) -> ContractError | None:
    failure: ContractError | None = None
    try:
        _kill_and_reap(process, label=label)
    except ContractError as exc:
        failure = exc
    try:
        if process.stdout is not None:
            process.stdout.close()
    except Exception:
        if failure is None:
            failure = ContractError(f"{label} output cleanup failed")
    if reader is not None and getattr(reader, "ident", None) is not None:
        try:
            reader.join(timeout=5.0)
            if reader.is_alive() and failure is None:
                failure = ContractError(f"{label} output reader cleanup timed out")
        except (OSError, RuntimeError):
            if failure is None:
                failure = ContractError(f"{label} output reader cleanup failed")
    return failure


def run_with_bounded_stdout(
    command: Sequence[str],
    *,
    maximum_stdout: int,
    timeout_seconds: float,
    label: str,
    creationflags: int = 0,
    environment: Mapping[str, str] | None = None,
) -> BoundedProcessResult:
    if (
        not isinstance(label, str)
        or not label
        or len(label.encode("utf-8", errors="surrogatepass")) > MAX_PROCESS_LABEL_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label)
    ):
        raise ContractError("bounded process label is invalid")
    try:
        label.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("bounded process label is invalid") from None
    if not isinstance(command, (list, tuple)) or not command or len(command) > 256:
        raise ContractError(f"{label} command is invalid")
    command_bytes = 0
    for item in command:
        if not isinstance(item, str) or not item or "\0" in item:
            raise ContractError(f"{label} command is invalid")
        try:
            encoded = item.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ContractError(f"{label} command is invalid") from None
        if len(encoded) > MAX_PROCESS_ARGUMENT_BYTES:
            raise ContractError(f"{label} command is invalid")
        command_bytes += len(encoded)
        if command_bytes > MAX_PROCESS_COMMAND_BYTES:
            raise ContractError(f"{label} command is invalid")
    if os.name == "nt":
        # Windows counts the fully quoted UTF-16 command line, including NUL.
        command_line = subprocess.list2cmdline(command)
        if len(command_line.encode("utf-16-le")) // 2 > 32766:
            raise ContractError(f"{label} command is invalid")
    if (
        isinstance(maximum_stdout, bool)
        or not isinstance(maximum_stdout, int)
        or not 0 <= maximum_stdout <= 64 * 1024 * 1024
    ):
        raise ContractError(f"{label} output bound is invalid")
    if not is_finite_number(timeout_seconds) or not 0 < timeout_seconds <= 600:
        raise ContractError(f"{label} timeout is invalid")
    if (
        isinstance(creationflags, bool)
        or not isinstance(creationflags, int)
        or not 0 <= creationflags <= 0xFFFFFFFF
        or (os.name != "nt" and creationflags != 0)
    ):
        raise ContractError(f"{label} creation flags are invalid")
    selected_environment = None
    if environment is not None:
        if not isinstance(environment, Mapping) or len(environment) > MAX_PROCESS_ENVIRONMENT_ENTRIES:
            raise ContractError(f"{label} environment is invalid")
        selected_environment = {}
        total_environment_bytes = 0
        for key, value in environment.items():
            if (
                not isinstance(key, str)
                or not key
                or "=" in key
                or "\x00" in key
                or not isinstance(value, str)
                or "\x00" in value
            ):
                raise ContractError(f"{label} environment is invalid")
            try:
                total_environment_bytes += len(key.encode("utf-8")) + len(value.encode("utf-8")) + 2
            except UnicodeEncodeError:
                raise ContractError(f"{label} environment is invalid") from None
            if total_environment_bytes > MAX_PROCESS_ENVIRONMENT_BYTES:
                raise ContractError(f"{label} environment is invalid")
            selected_environment[key] = value
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            env=selected_environment,
        )
    except (OSError, ValueError, OverflowError) as exc:
        raise ContractError(f"{label} start failed ({type(exc).__name__})") from None
    if process.stdout is None:  # pragma: no cover - guaranteed by PIPE
        _kill_and_reap(process, label=label)
        raise ContractError(f"{label} did not expose bounded output")

    body = bytearray()
    overflow = threading.Event()
    read_failed = threading.Event()

    def _drain() -> None:
        try:
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                if type(chunk) is not bytes:
                    read_failed.set()
                    try:
                        process.kill()
                    except Exception:
                        pass
                    break
                remaining = maximum_stdout - len(body)
                if len(chunk) > remaining:
                    if remaining > 0:
                        body.extend(chunk[:remaining])
                    overflow.set()
                    try:
                        process.kill()
                    except Exception:
                        pass
                    break
                body.extend(chunk)
        except Exception:
            read_failed.set()
            try:
                process.kill()
            except Exception:
                pass
        finally:
            try:
                process.stdout.close()
            except Exception:
                read_failed.set()

    reader: threading.Thread | None = None
    try:
        reader = threading.Thread(target=_drain, name=f"{label}-stdout", daemon=True)
        reader.start()
    except (OSError, RuntimeError) as exc:
        cleanup_failure = _reader_start_cleanup(process, label=label, reader=reader)
        if cleanup_failure is not None:
            raise cleanup_failure
        raise ContractError(
            f"{label} output reader could not start ({type(exc).__name__})"
        ) from None
    deadline = time.monotonic() + float(timeout_seconds)
    try:
        returncode = process.wait(timeout=float(timeout_seconds))
    except subprocess.TimeoutExpired:
        cleanup_failure: ContractError | None = None
        try:
            _kill_and_reap(process, label=label)
        except ContractError as exc:
            cleanup_failure = exc
        try:
            reader.join(timeout=5.0)
            if reader.is_alive() and cleanup_failure is None:
                cleanup_failure = ContractError(
                    f"{label} output reader cleanup timed out"
                )
        except (OSError, RuntimeError):
            if cleanup_failure is None:
                cleanup_failure = ContractError(f"{label} output reader cleanup failed")
        if cleanup_failure is not None:
            raise cleanup_failure
        raise ContractError(f"{label} timed out") from None
    except (OSError, RuntimeError, ValueError) as exc:
        cleanup_failure = None
        try:
            _kill_and_reap(process, label=label)
        except ContractError as cleanup_error:
            cleanup_failure = cleanup_error
        try:
            reader.join(timeout=5.0)
            if reader.is_alive() and cleanup_failure is None:
                cleanup_failure = ContractError(
                    f"{label} output reader cleanup timed out"
                )
        except (OSError, RuntimeError):
            if cleanup_failure is None:
                cleanup_failure = ContractError(f"{label} output reader cleanup failed")
        if cleanup_failure is not None:
            raise cleanup_failure
        raise ContractError(f"{label} wait failed ({type(exc).__name__})") from None
    try:
        reader.join(timeout=min(5.0, max(0.0, deadline - time.monotonic())))
    except (OSError, RuntimeError):
        raise ContractError(f"{label} output read failed") from None
    if reader.is_alive() or read_failed.is_set():
        raise ContractError(f"{label} output read failed")
    if time.monotonic() >= deadline:
        raise ContractError(f"{label} timed out")
    if overflow.is_set():
        raise ContractError(f"{label} output exceeds {maximum_stdout} bytes")
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise ContractError(f"{label} process status is invalid")
    return BoundedProcessResult(returncode=returncode, stdout=bytes(body))
