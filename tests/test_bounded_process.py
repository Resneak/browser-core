from __future__ import annotations

import sys
import os
import threading

import pytest

import browser_core.bounded_process as process_module
from browser_core.bounded_process import run_with_bounded_stdout
from browser_core.contracts import ContractError


def test_bounded_process_returns_only_bounded_stdout() -> None:
    result = run_with_bounded_stdout(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('safe'); sys.stderr.write('private-secret')",
        ],
        maximum_stdout=16,
        timeout_seconds=5,
        label="fixture",
    )
    assert result.returncode == 0
    assert result.stdout == b"safe"
    assert b"private-secret" not in result.stdout


def test_bounded_process_uses_selected_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BROWSER_CORE_ISOLATED_ENV_TEST", "ambient")
    environment = os.environ.copy()
    environment["BROWSER_CORE_ISOLATED_ENV_TEST"] = "selected"
    result = run_with_bounded_stdout(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ['BROWSER_CORE_ISOLATED_ENV_TEST'])",
        ],
        maximum_stdout=32,
        timeout_seconds=5,
        label="fixture",
        environment=environment,
    )
    assert result.stdout.strip() == b"selected"


def test_bounded_process_kills_output_overflow() -> None:
    with pytest.raises(ContractError, match="exceeds 32 bytes"):
        run_with_bounded_stdout(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"],
            maximum_stdout=32,
            timeout_seconds=5,
            label="fixture",
        )


def test_bounded_process_kills_a_timeout() -> None:
    with pytest.raises(ContractError, match="timed out"):
        run_with_bounded_stdout(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            maximum_stdout=32,
            timeout_seconds=0.05,
            label="fixture",
        )


@pytest.mark.parametrize("overrun_phase", ["wait", "reader"])
def test_bounded_process_does_not_accept_a_late_success(
    monkeypatch: pytest.MonkeyPatch, overrun_phase: str
) -> None:
    class Clock:
        now = 0.0

        def monotonic(self) -> float:
            return self.now

    clock = Clock()
    monkeypatch.setattr(process_module, "time", clock, raising=False)

    class Stream:
        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    class Process:
        stdout = Stream()

        def wait(self, timeout: float) -> int:
            assert timeout == 1.0
            if overrun_phase == "wait":
                clock.now = 1.1
            return 0

    class Reader:
        def start(self) -> None:
            return None

        def join(self, timeout: float) -> None:
            if overrun_phase == "reader":
                clock.now = 1.1

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(process_module.subprocess, "Popen", lambda *_a, **_kw: Process())
    monkeypatch.setattr(process_module.threading, "Thread", lambda **_kw: Reader())

    with pytest.raises(ContractError, match="timed out"):
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            maximum_stdout=1,
            timeout_seconds=1,
            label="fixture",
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"maximum_stdout": True, "timeout_seconds": 1},
        {"maximum_stdout": -1, "timeout_seconds": 1},
        {"maximum_stdout": 1, "timeout_seconds": True},
        {"maximum_stdout": 1, "timeout_seconds": float("nan")},
        {"maximum_stdout": 1, "timeout_seconds": 0},
        {"maximum_stdout": 1, "timeout_seconds": 10**400},
    ],
)
def test_bounded_process_budgets_fail_before_process_contact(
    monkeypatch, kwargs
) -> None:
    contacted = False

    def forbidden_popen(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("process contact")

    monkeypatch.setattr(process_module.subprocess, "Popen", forbidden_popen)
    with pytest.raises(ContractError):
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            label="fixture",
            **kwargs,
        )
    assert contacted is False


@pytest.mark.parametrize(
    "override",
    [
        {"command": "python"},
        {"command": []},
        {"command": ["python", True]},
        {"command": ["x" * (32 * 1024 + 1)]},
        {"command": ["\ud800"]},
        {"command": ["x" * (32 * 1024)] * 33},
        {"label": "private\nlabel"},
        {"creationflags": True},
        {"creationflags": -1},
        {"creationflags": 0x1_0000_0000},
    ]
    + ([{"creationflags": 1}] if os.name != "nt" else []),
)
def test_bounded_process_outer_contract_fails_before_process_contact(
    monkeypatch: pytest.MonkeyPatch,
    override: dict,
) -> None:
    contacted = False

    def forbidden_popen(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("process contact")

    monkeypatch.setattr(process_module.subprocess, "Popen", forbidden_popen)
    arguments = {
        "command": [sys.executable, "-c", "pass"],
        "maximum_stdout": 1,
        "timeout_seconds": 1,
        "label": "fixture",
        "creationflags": 0,
    }
    arguments.update(override)
    with pytest.raises(ContractError) as failure:
        run_with_bounded_stdout(**arguments)
    assert "private\nlabel" not in str(failure.value)
    assert contacted is False


@pytest.mark.parametrize("arguments", [
    pytest.param(['"' * 16380], id="quoted-expansion"),
    pytest.param(['\U0001f600' * 7000] * 3, id="utf16-expansion"),
])
def test_windows_command_line_limit_fails_before_process_contact(
    monkeypatch: pytest.MonkeyPatch, arguments: list[str],
) -> None:
    monkeypatch.setattr(process_module.os, "name", "nt")
    contacted = False

    def forbidden_popen(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("process contact")

    monkeypatch.setattr(process_module.subprocess, "Popen", forbidden_popen)
    with pytest.raises(ContractError, match="command is invalid"):
        run_with_bounded_stdout(
            [sys.executable, *arguments], maximum_stdout=1,
            timeout_seconds=1, label="fixture",
        )
    assert contacted is False


def test_bounded_process_normalizes_a_post_validation_spawn_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        process_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("private spawn")),
    )
    with pytest.raises(ContractError, match=r"start failed \(ValueError\)") as failure:
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            maximum_stdout=1,
            timeout_seconds=1,
            label="fixture",
        )
    assert "private spawn" not in str(failure.value)


def test_bounded_process_timeout_cleanup_has_its_own_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptyStream:
        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    class UnreapableProcess:
        stdout = EmptyStream()

        def __init__(self) -> None:
            self.waits = 0
            self.killed = False

        def wait(self, timeout: float) -> int:
            self.waits += 1
            raise process_module.subprocess.TimeoutExpired("fixture", timeout)

        def kill(self) -> None:
            self.killed = True

    process = UnreapableProcess()
    monkeypatch.setattr(
        process_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    with pytest.raises(ContractError, match="cleanup timed out"):
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            maximum_stdout=1,
            timeout_seconds=1,
            label="fixture",
        )
    assert process.killed is True
    assert process.waits == 2


@pytest.mark.parametrize("failure_phase", ["construct", "start"])
def test_bounded_process_reader_start_failure_kills_reaps_and_closes(
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
) -> None:
    class Stream:
        closed = False

        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            self.closed = True

    class Process:
        stdout = Stream()
        killed = False
        waits: list[float] = []

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float) -> int:
            self.waits.append(timeout)
            return 0

    class Reader:
        def start(self) -> None:
            raise OSError("private reader start")

    process = Process()
    monkeypatch.setattr(
        process_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    def thread_factory(**_kwargs):  # noqa: ANN003
        if failure_phase == "construct":
            raise RuntimeError("private reader constructor")
        return Reader()

    monkeypatch.setattr(process_module.threading, "Thread", thread_factory)

    with pytest.raises(ContractError, match="output reader could not start") as raised:
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            maximum_stdout=1,
            timeout_seconds=1,
            label="fixture",
        )

    assert "private" not in str(raised.value)
    assert process.killed is True
    assert process.waits == [5.0]
    assert process.stdout.closed is True


def test_bounded_process_reader_late_start_failure_joins_live_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_thread = threading.Thread

    class Stream:
        def __init__(self) -> None:
            self.closed = threading.Event()

        def read(self, _size: int) -> bytes:
            self.closed.wait(1.0)
            return b""

        def close(self) -> None:
            self.closed.set()

    class Process:
        def __init__(self) -> None:
            self.stdout = Stream()
            self.killed = False
            self.waits: list[float] = []

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float) -> int:
            self.waits.append(timeout)
            return 0

    class LateStartReader:
        def __init__(self, **kwargs) -> None:  # noqa: ANN003
            self.worker = real_thread(**kwargs)
            self.joined = False

        @property
        def ident(self) -> int | None:
            return self.worker.ident

        def start(self) -> None:
            self.worker.start()
            raise OSError("private late start")

        def join(self, timeout: float) -> None:
            self.joined = True
            self.worker.join(timeout)

        def is_alive(self) -> bool:
            return self.worker.is_alive()

    process = Process()
    readers: list[LateStartReader] = []
    monkeypatch.setattr(
        process_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    def reader_factory(**kwargs):  # noqa: ANN003, ANN201
        reader = LateStartReader(**kwargs)
        readers.append(reader)
        return reader

    monkeypatch.setattr(process_module.threading, "Thread", reader_factory)

    with pytest.raises(ContractError, match="output reader could not start"):
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            maximum_stdout=1,
            timeout_seconds=1,
            label="fixture",
        )

    assert process.killed is True
    assert process.waits == [5.0]
    assert process.stdout.closed.is_set()
    assert readers[0].joined is True
    assert readers[0].is_alive() is False


def test_bounded_process_wait_failure_still_kills_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Stream:
        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    class Process:
        stdout = Stream()

        def __init__(self) -> None:
            self.killed = False
            self.waits: list[float] = []

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float) -> int:
            self.waits.append(timeout)
            if len(self.waits) == 1:
                raise OSError("private wait path")
            return 0

    process = Process()
    monkeypatch.setattr(
        process_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    with pytest.raises(
        ContractError,
        match=r"wait failed \(OSError\)",
    ) as raised:
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            maximum_stdout=1,
            timeout_seconds=1,
            label="fixture",
        )

    assert "private wait path" not in str(raised.value)
    assert process.killed is True
    assert process.waits == [1.0, 5.0]


@pytest.mark.parametrize("wait_failure", ["timeout", "error"])
def test_bounded_process_failed_wait_checks_reader_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    wait_failure: str,
) -> None:
    class Stream:
        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    class Process:
        stdout = Stream()

        def __init__(self) -> None:
            self.killed = False
            self.waits = 0

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float) -> int:
            self.waits += 1
            if self.waits == 1:
                if wait_failure == "timeout":
                    raise process_module.subprocess.TimeoutExpired("fixture", timeout)
                raise OSError("private wait")
            return 0

    class StuckReader:
        def start(self) -> None:
            return None

        def join(self, timeout: float) -> None:
            assert timeout == 5.0

        def is_alive(self) -> bool:
            return True

    process = Process()
    monkeypatch.setattr(
        process_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        process_module.threading,
        "Thread",
        lambda **_kwargs: StuckReader(),
    )

    with pytest.raises(ContractError, match="output reader cleanup timed out"):
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            maximum_stdout=1,
            timeout_seconds=1,
            label="fixture",
        )
    assert process.killed is True
    assert process.waits == 2


@pytest.mark.parametrize("mode", ["non-byte", "close-failure"])
def test_bounded_process_reader_failures_are_value_free_and_do_not_escape_thread(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    thread_errors: list[object] = []

    class Stream:
        def read(self, _size: int) -> object:
            return "private non-byte" if mode == "non-byte" else b""

        def close(self) -> None:
            if mode == "close-failure":
                raise OSError("private close path")

    class Process:
        stdout = Stream()
        killed = False

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float) -> int:
            assert timeout == 1.0
            return 0

    process = Process()
    monkeypatch.setattr(
        process_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        process_module.threading,
        "excepthook",
        lambda details: thread_errors.append(details),
    )

    with pytest.raises(ContractError, match="output read failed") as raised:
        run_with_bounded_stdout(
            [sys.executable, "-c", "pass"],
            maximum_stdout=16,
            timeout_seconds=1,
            label="fixture",
        )

    assert "private" not in str(raised.value)
    assert thread_errors == []
    if mode == "non-byte":
        assert process.killed is True


def test_bounded_process_cleanup_requires_integer_reap_status() -> None:
    class Process:
        def kill(self) -> None:
            return None

        def wait(self, *, timeout: float) -> bool:
            assert timeout == 5.0
            return True

    with pytest.raises(ContractError, match="cleanup status is invalid"):
        process_module._kill_and_reap(Process(), label="fixture")  # type: ignore[arg-type]
