"""Call a component under the two-file rule.

The runner writes the input file, sets ``ASCENT_INPUT`` and ``ASCENT_OUTPUT``,
starts the command with an empty stdin, waits, and checks the output file.
This module uses only the standard library and imports only ``result.py`` and
``_child.py`` (by path) from its own folder. A product can copy the three
files into one folder in a sandbox and import that folder as a package,
without an install.
"""

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .result import (
    NO_OUTPUT_MESSAGE,
    AscentError,
    ExitCodeError,
    MetricResult,
    NoOutputError,
    OutputFileError,
    StartError,
    TimeLimitError,
    check_metric_result,
    check_run_output,
    load_json,
)

MAX_OUTPUT_BYTES = 1024 * 1024
LOG_TAIL_BYTES = 64 * 1024
_CHILD = Path(__file__).resolve().with_name("_child.py")


@dataclass(frozen=True)
class FunctionEntry:
    """A Python function entry: ``path/file.py:function``."""

    path: str
    function: str


@dataclass(frozen=True)
class RunCall:
    """The result of a run call."""

    output: object
    stdout: str
    stderr: str
    elapsed_s: float


@dataclass(frozen=True)
class MetricCall:
    """The result of a metric call."""

    result: MetricResult
    stdout: str
    stderr: str
    elapsed_s: float


Entry = FunctionEntry | tuple[str, ...]


def parse_entry(value: object) -> Entry:
    """Normalize an entry: a command or a Python function.

    Args:
        value: A list of strings (a command, for example ``["./metric.sh"]``),
            a string ``"path/file.py:function"``, or an already normalized
            entry.

    Returns:
        A ``FunctionEntry`` or a tuple of command strings.

    Raises:
        ValueError: The value is neither form.
    """
    if isinstance(value, FunctionEntry):
        return value
    if isinstance(value, str):
        path, sep, function = value.rpartition(":")
        if sep and path.endswith(".py") and len(path) > 3 and function.isidentifier():
            return FunctionEntry(path, function)
    elif (
        isinstance(value, list | tuple)
        and value
        and all(isinstance(part, str) for part in value)
        and value[0]
    ):
        return tuple(value)
    raise ValueError(
        f"The entry {value!r} is not valid. Use a command as a list of strings, "
        'for example ["./metric.sh"], or a Python function as "path/file.py:function".'
    )


def call_run(
    entry: object,
    input_value: object,
    *,
    timeout_s: float,
    cwd: str | os.PathLike | None = None,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> RunCall:
    """Call a candidate program or a stage once.

    Args:
        entry: The command or the Python function (see ``parse_entry``).
        input_value: Any JSON value. The input file holds ``{"input": input_value}``.
        timeout_s: The time limit in seconds.
        cwd: The working directory of the command. ``None`` keeps the current one.
        env: The environment of the command. ``None`` inherits the parent
            environment. The two ``ASCENT_*`` variables are always added.
        max_output_bytes: The largest output file that the call accepts.

    Returns:
        The output value, the bounded log text and the elapsed time.

    Raises:
        AscentError: A subclass names the cause of the failure.
    """
    output, stdout, stderr, elapsed = _call(
        entry,
        "run",
        {"input": input_value},
        check_run_output,
        timeout_s,
        cwd,
        env,
        max_output_bytes,
    )
    return RunCall(output=output, stdout=stdout, stderr=stderr, elapsed_s=elapsed)


def call_metric(
    entry: object,
    payload: dict,
    *,
    timeout_s: float,
    cwd: str | os.PathLike | None = None,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> MetricCall:
    """Call a metric once.

    Args:
        entry: The command or the Python function (see ``parse_entry``).
        payload: The metric input object: ``input``, ``output``, and optionally
            ``expected`` and ``elapsed_s``.
        timeout_s: The time limit in seconds.
        cwd: The working directory of the command. ``None`` keeps the current one.
        env: The environment of the command. ``None`` inherits the parent
            environment. The two ``ASCENT_*`` variables are always added.
        max_output_bytes: The largest output file that the call accepts.

    Returns:
        The checked metric result, the bounded log text and the elapsed time.

    Raises:
        ValueError: The payload has no ``input`` or no ``output`` key.
        AscentError: A subclass names the cause of the failure.
    """
    if not isinstance(payload, dict) or "input" not in payload or "output" not in payload:
        raise ValueError(
            "The metric input must be an object with the keys input and output, "
            "and optionally expected and elapsed_s."
        )
    result, stdout, stderr, elapsed = _call(
        entry,
        "metric",
        payload,
        check_metric_result,
        timeout_s,
        cwd,
        env,
        max_output_bytes,
    )
    return MetricCall(result=result, stdout=stdout, stderr=stderr, elapsed_s=elapsed)


def _call(
    entry: object,
    kind: str,
    payload: dict,
    check: Callable[[object], object],
    timeout_s: float,
    cwd: str | os.PathLike | None,
    env: Mapping[str, str] | None,
    max_output_bytes: int,
) -> tuple[object, str, str, float]:
    """Run one call in a new directory and check its output file.

    Args:
        entry: The command or the Python function.
        kind: "run" or "metric".
        payload: The input object.
        check: The form check for the parsed output file.
        timeout_s: The time limit in seconds.
        cwd: The working directory of the command.
        env: The environment of the command, or ``None`` to inherit.
        max_output_bytes: The largest output file that the call accepts.

    Returns:
        The checked value, the stdout tail, the stderr tail and the elapsed time.

    Raises:
        AscentError: A subclass names the cause of the failure.
    """
    argv = _argv(parse_entry(entry), kind, cwd)
    with tempfile.TemporaryDirectory(prefix="ascent-") as tmp:
        call_dir = Path(tmp)
        input_path = call_dir / "input.json"
        output_path = call_dir / "output.json"
        input_path.write_text(json.dumps(payload, allow_nan=False), encoding="utf-8")
        child_env = dict(os.environ if env is None else env)
        child_env["ASCENT_INPUT"] = str(input_path)
        child_env["ASCENT_OUTPUT"] = str(output_path)
        with (
            open(call_dir / "stdout.log", "wb") as out,
            open(call_dir / "stderr.log", "wb") as err,
        ):
            exit_code, elapsed = _run(argv, cwd, child_env, out, err, timeout_s)
        stdout = _tail(call_dir / "stdout.log")
        stderr = _tail(call_dir / "stderr.log")
        try:
            if exit_code is None:
                raise TimeLimitError(
                    f"The command ran longer than the time limit of {timeout_s} s. "
                    "The runner stopped it and its process group. Make the command "
                    "faster, or give it a longer time limit."
                )
            if exit_code != 0:
                raise ExitCodeError(_exit_message(exit_code), exit_code=exit_code)
            value = check(load_json(_read_output(output_path, max_output_bytes)))
        except AscentError as error:
            error.stderr = stderr
            raise
    return value, stdout, stderr, elapsed


def _argv(entry: Entry, kind: str, cwd: str | os.PathLike | None) -> list[str]:
    """Build the command line of a call.

    Args:
        entry: The normalized entry.
        kind: "run" or "metric".
        cwd: The working directory of the command.

    Returns:
        The command line.

    Raises:
        StartError: The function file does not exist.
    """
    if isinstance(entry, tuple):
        return list(entry)
    path = Path(cwd or os.getcwd()) / entry.path
    if not path.is_file():
        raise StartError(
            f"The function file {path} does not exist. Check the path before the colon."
        )
    return [sys.executable, str(_CHILD), kind, str(path), entry.function]


def _run(argv, cwd, env, out, err, timeout_s: float) -> tuple[int | None, float]:
    """Start the command in its own process group and wait for it.

    Args:
        argv: The command line.
        cwd: The working directory.
        env: The full environment.
        out: The open file for stdout.
        err: The open file for stderr.
        timeout_s: The time limit in seconds.

    Returns:
        The exit code (``None`` when the time limit passed) and the elapsed time.

    Raises:
        StartError: The command cannot start.
    """
    start = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            cwd=cwd,
            env=env,
            start_new_session=True,
        )
    except (OSError, ValueError) as error:
        raise StartError(
            f"The command cannot start: {error}. Check that the command exists, "
            "that it is executable, and that the working directory exists."
        ) from None
    try:
        exit_code = process.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        exit_code = None
    finally:
        # Also stop the processes that the command left running after a
        # normal exit, so none of them outlives the call.
        _kill_group(process.pid)
        process.wait()
    return exit_code, time.monotonic() - start


def _kill_group(pgid: int) -> None:
    """Kill every process in a process group.

    Args:
        pgid: The process group id.
    """
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _exit_message(exit_code: int) -> str:
    """Describe a non-zero exit.

    Args:
        exit_code: The exit code. A negative code is a signal number.

    Returns:
        The message.
    """
    if exit_code < 0:
        cause = f"The command was stopped by signal {-exit_code}."
    else:
        cause = f"The command exited with code {exit_code}."
    return f"{cause} Make it exit 0 after it writes the output file. See its stderr."


def _read_output(path: Path, limit: int) -> bytes:
    """Read the output file without following a link, up to the size limit.

    Args:
        path: The output path.
        limit: The largest size in bytes.

    Returns:
        The content of the file.

    Raises:
        NoOutputError: The file does not exist.
        OutputFileError: The path is not a regular file, or the file is too large.
    """
    not_regular = (
        "The output path is not a regular file. Write a plain file, "
        "not a link or a folder, at the path in ASCENT_OUTPUT."
    )
    try:
        # O_NONBLOCK: a FIFO at the path must not block the open.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise NoOutputError(NO_OUTPUT_MESSAGE) from None
    except OSError:
        raise OutputFileError(not_regular) from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OutputFileError(not_regular)
    with open(fd, "rb") as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise OutputFileError(
            f"The output file is larger than {limit} bytes. Write a smaller result."
        )
    return data


def _tail(path: Path) -> str:
    """Read the last ``LOG_TAIL_BYTES`` of a log file.

    Args:
        path: The log file.

    Returns:
        The tail, decoded as UTF-8 with replacement characters.
    """
    with open(path, "rb") as file:
        size = file.seek(0, os.SEEK_END)
        file.seek(max(0, size - LOG_TAIL_BYTES))
        return file.read().decode("utf-8", errors="replace")
