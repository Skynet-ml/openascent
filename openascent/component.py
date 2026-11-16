"""Call a component under the two-file rule.

The runner writes the input file, sets ``ASCENT_INPUT`` and ``ASCENT_OUTPUT``,
starts the command with an empty stdin, waits, and checks the output file.
This module uses only the standard library and imports only ``result.py`` and
``_child.py`` (by path) from its own folder. A product can copy the three
files into one folder in a sandbox and import that folder as a package,
without an install.
"""

import errno
import json
import math
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
from typing import BinaryIO

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
_READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class FunctionEntry:
    """A Python function entry: ``path/file.py:function``.

    ``parse_entry`` checks both fields as it checks the string form. A
    ``pathlib.Path`` in ``path`` is refused: the field is a ``str``.
    """

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
        if _is_function(value.path, value.function):
            return value
    elif isinstance(value, str):
        path, sep, function = value.rpartition(":")
        if sep and _is_function(path, function):
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


def _is_function(path: object, function: object) -> bool:
    """Tell if a path and a name form a valid Python function entry.

    Args:
        path: The path of the ``.py`` file.
        function: The function name.

    Returns:
        True when the path is a ``.py`` file name and the name is an identifier.
    """
    return (
        isinstance(path, str)
        and path.endswith(".py")
        and len(path) > 3
        and isinstance(function, str)
        and function.isidentifier()
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
        ValueError: The time limit is not a finite number greater than 0, the
            output size limit is not an integer greater than 0, the entry is in
            neither form (see ``parse_entry``), or the input value is not strict
            JSON (see ``_input_bytes``).
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
        ValueError: The time limit is not a finite number greater than 0, the
            output size limit is not an integer greater than 0, the entry is in
            neither form (see ``parse_entry``), or the payload has no ``input``
            or no ``output`` key, has an ``elapsed_s`` that is not a number, or
            is not strict JSON (see ``_input_bytes``).
        AscentError: A subclass names the cause of the failure.
    """
    if not isinstance(payload, dict) or "input" not in payload or "output" not in payload:
        raise ValueError(
            "The metric input must be an object with the keys input and output, "
            "and optionally expected and elapsed_s."
        )
    elapsed_s = payload.get("elapsed_s", 0)
    if isinstance(elapsed_s, bool) or not isinstance(elapsed_s, int | float):
        raise ValueError("The metric input key elapsed_s must be a number of seconds.")
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
        ValueError: The time limit, the output size limit, the entry or the
            input object is not valid.
        AscentError: A subclass names the cause of the failure.
    """
    _check_timeout(timeout_s)
    _check_output_limit(max_output_bytes)
    data = _input_bytes(payload)
    argv = _argv(parse_entry(entry), kind, cwd)
    # A command can move or link its call directory away; a failed cleanup
    # must not lose a valid result.
    with tempfile.TemporaryDirectory(prefix="ascent-", ignore_cleanup_errors=True) as tmp:
        call_dir = Path(tmp)
        input_path = call_dir / "input.json"
        output_path = call_dir / "output.json"
        input_path.write_bytes(data)
        child_env = dict(os.environ if env is None else env)
        child_env["ASCENT_INPUT"] = str(input_path)
        child_env["ASCENT_OUTPUT"] = str(output_path)
        # The runner reads the output through this descriptor, not the path:
        # a command can rename the call directory and put a link or another
        # directory at its path, but the descriptor keeps the real one.
        dir_fd = os.open(call_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            # The logs have no path: the command knows the call directory and
            # could put a link or a FIFO at a log path before the runner reads it.
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                exit_code, elapsed = _run(argv, cwd, child_env, out, err, timeout_s)
                stdout = _tail(out)
                stderr = _tail(err)
            try:
                if exit_code is None:
                    raise TimeLimitError(
                        f"The command ran longer than the time limit of {timeout_s} s. "
                        "The runner stopped it and its process group. Make the command "
                        "faster, or give it a longer time limit."
                    )
                if exit_code != 0:
                    raise ExitCodeError(_exit_message(exit_code), exit_code=exit_code)
                value = check(load_json(_read_output(dir_fd, max_output_bytes)))
            except AscentError as error:
                error.stderr = stderr
                raise
        finally:
            os.close(dir_fd)
    return value, stdout, stderr, elapsed


def _check_timeout(timeout_s: object) -> None:
    """Refuse a time limit that is not a finite number greater than 0.

    Args:
        timeout_s: The time limit in seconds.

    Raises:
        ValueError: The time limit is not valid. NaN and infinity would turn
            the limit off.
    """
    valid = isinstance(timeout_s, int | float) and not isinstance(timeout_s, bool)
    if valid:
        try:
            valid = math.isfinite(float(timeout_s)) and timeout_s > 0
        except OverflowError:
            valid = False
    if not valid:
        # No value in the message: repr() of a huge integer can itself fail.
        raise ValueError(
            "The time limit is not valid. Give a finite number of seconds greater than 0."
        )


def _check_output_limit(limit: object) -> None:
    """Refuse an output size limit that is not an integer greater than 0.

    Args:
        limit: The largest output file in bytes.

    Raises:
        ValueError: The limit is not valid. A bad limit would otherwise fail
            only after the command ran.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError(
            "The output size limit is not valid. Give a whole number of bytes greater than 0."
        )


def _input_bytes(payload: dict) -> bytes:
    """Encode the input object as strict UTF-8 JSON.

    Args:
        payload: The input object.

    Returns:
        The content of the input file.

    Raises:
        ValueError: The object holds a value that JSON cannot hold (NaN,
            infinity, a set, any other object), an object key that is not a
            string, or a string with a lone surrogate.
    """
    try:
        text = json.dumps(payload, allow_nan=False, ensure_ascii=False)
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError(
            f"The input value is not strict JSON ({error}). Use only finite numbers, "
            "strings, booleans, None, lists, and dicts with string keys."
        ) from None
    # json.dumps turns a key such as 1 into "1" in silence, and {1: "a", "1": "b"}
    # into a duplicate key. dumps passed, so the value has no cycle to walk into.
    pending = [payload]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ValueError(
                    "The input value holds an object key that is not a string. "
                    "Use only string keys in dicts."
                )
            pending.extend(item.values())
        elif isinstance(item, list | tuple):
            pending.extend(item)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(
            "The input value holds a string with a lone surrogate, which is not "
            "valid Unicode text. Use only valid Unicode strings."
        ) from None


def _argv(entry: Entry, kind: str, cwd: str | os.PathLike | None) -> list[str]:
    """Build the command line of a call.

    Args:
        entry: The normalized entry.
        kind: "run" or "metric".
        cwd: The working directory of the command.

    Returns:
        The command line.

    Raises:
        StartError: The function file does not exist, or the path is relative
            and the current directory is not valid.
    """
    if isinstance(entry, tuple):
        return list(entry)
    path = Path(entry.path)
    if not path.is_absolute():
        # The child runs inside cwd, so a relative path would resolve twice there.
        # getcwd fails when the current directory was deleted.
        try:
            path = (Path(cwd or os.getcwd()) / path).absolute()
        except OSError as error:
            raise StartError(
                f"The current directory is not valid ({error.strerror}), so the runner "
                f"cannot find the function file {entry.path}. Give an absolute path "
                "or a working directory that exists."
            ) from None
    # os.path.isfile returns False on an OSError such as a name that is too long.
    if not os.path.isfile(path):
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
        # Also stop every process still in the command's process group after a
        # normal exit. A process that leaves the group (setsid) survives; to
        # stop it needs an OS sandbox, which is out of scope.
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


def _read_output(dir_fd: int, limit: int) -> bytes:
    """Read the output file without following a link, up to the size limit.

    Args:
        dir_fd: The open descriptor of the real call directory.
        limit: The largest size in bytes.

    Returns:
        The content of the file.

    Raises:
        NoOutputError: The file does not exist.
        OutputFileError: The path is a link, a hard link or not a regular file,
            the runner cannot open it, or the file is too large.
    """
    try:
        # O_NONBLOCK: a FIFO at the path must not block the open.
        fd = os.open("output.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except FileNotFoundError:
        raise NoOutputError(NO_OUTPUT_MESSAGE) from None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise OutputFileError(
                "The output path is a symbolic link. Write a plain file, "
                "not a link, at the path in ASCENT_OUTPUT."
            ) from None
        raise OutputFileError(
            f"The runner cannot open the output file ({error.strerror}). Write a "
            "plain file that the runner can read, at the path in ASCENT_OUTPUT."
        ) from None
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise OutputFileError(
            "The output path is not a regular file. Write a plain file, "
            "not a folder or a FIFO, at the path in ASCENT_OUTPUT."
        )
    # A second name means a hard link: the file can be one that the call did
    # not write.
    if info.st_nlink != 1:
        os.close(fd)
        raise OutputFileError(
            "The output file has more than one name. Write a new file at the "
            "path in ASCENT_OUTPUT, not a hard link."
        )
    # Read in chunks: file.read(limit + 1) would size its buffer from a large limit.
    chunks = []
    total = 0
    with open(fd, "rb") as file:
        while total <= limit:
            chunk = file.read(min(_READ_CHUNK_BYTES, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    data = b"".join(chunks)
    if total > limit:
        raise OutputFileError(
            f"The output file is larger than {limit} bytes. Write a smaller result."
        )
    return data


def _tail(file: BinaryIO) -> str:
    """Read the last ``LOG_TAIL_BYTES`` of an open log file.

    Args:
        file: The anonymous log file that the command wrote.

    Returns:
        The tail, decoded as UTF-8 with replacement characters.
    """
    size = os.fstat(file.fileno()).st_size
    file.seek(max(0, size - LOG_TAIL_BYTES))
    return file.read(LOG_TAIL_BYTES).decode("utf-8", errors="replace")
