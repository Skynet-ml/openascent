"""Check that the current box can run OpenAscent components.

``ascent check --image --role <candidate|metric>`` runs inside a box and
checks the pieces that the role needs. The check uses no network. A runner
reads the JSON report, and a report with a failed check fails the run.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

from . import __version__
from .result import AscentError, check_metric_result, load_json

PROTOCOL_VERSION = 1
ROLES = ("candidate", "metric")
SHELL = "/bin/sh"
# Each subprocess waits at most this long. A role runs at most three
# subprocesses, so a role ends in about 24 seconds.
CHECK_TIMEOUT_S = 8.0
_SAMPLE_METRIC = (
    'def score(output, expected=None):\n    return {"score": 1.0 if output == expected else 0.0}\n'
)
_SAMPLE_INPUT = {"input": "q", "expected": "Paris", "output": "Paris"}


def check_image(
    role: str,
    *,
    python: str | None = None,
    shell: str = SHELL,
    ascent: str | None = None,
    temp_root: str | None = None,
) -> dict:
    """Run the checks of one role and make the report.

    Args:
        role: ``"candidate"`` or ``"metric"``.
        python: The trusted Python runtime. ``None`` uses the interpreter
            that runs this code.
        shell: The shell that the candidate role needs.
        ascent: The ``ascent`` command. ``None`` finds it on ``PATH``.
        temp_root: The folder for the temporary directory. ``None`` uses the
            default temporary folder.

    Returns:
        The report: ``sdk_version``, ``protocol_version``, ``role``, ``ok``,
        ``checks`` (each with ``name``, ``ok`` and ``message``), and for the
        metric role ``python``, the absolute path of the runtime or ``None``
        when the runtime check fails.

    Raises:
        ValueError: The role is not ``candidate`` or ``metric``.
    """
    if role not in ROLES:
        raise ValueError(f"The role must be one of {', '.join(ROLES)}, not {role!r}.")
    python = python if python is not None else sys.executable
    # sys.executable is empty when Python cannot tell its own path.
    python = os.path.abspath(python) if python else ""
    report = {"sdk_version": __version__, "protocol_version": PROTOCOL_VERSION, "role": role}
    if role == "metric":
        runtime = _check_python(python)
        checks = [runtime, _check_score(python), _check_temp(temp_root)]
        report["python"] = python if runtime["ok"] else None
    else:
        if ascent is None:
            ascent = shutil.which("ascent") or ""
        checks = [
            _check_ascent(ascent),
            _check_import(python),
            _check_shell(shell),
            _check_temp(temp_root),
        ]
    report["ok"] = all(check["ok"] for check in checks)
    report["checks"] = checks
    return report


def _result(name: str, ok: bool, message: str) -> dict:
    """Make one check entry of the report.

    Args:
        name: The check name.
        ok: ``True`` when the check passed.
        message: What the check found.

    Returns:
        The entry with ``name``, ``ok`` and ``message``.
    """
    return {"name": name, "ok": ok, "message": message}


def _run(argv: list[str], cwd: str | None = None) -> tuple[bool, str]:
    """Run one command with an empty stdin and the check time limit.

    Args:
        argv: The command and its arguments.
        cwd: The working directory. ``None`` keeps the current one.

    Returns:
        ``(True, stdout)`` when the command exits with 0, otherwise
        ``(False, the reason)``.
    """
    try:
        done = subprocess.run(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=CHECK_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return False, f"{argv[0]} ran longer than {CHECK_TIMEOUT_S:g} seconds"
    except OSError as error:
        return False, f"{argv[0]} cannot start: {error}"
    if done.returncode != 0:
        message = f"{argv[0]} exited with code {done.returncode}"
        tail = done.stderr.strip().splitlines()[-1:] or [""]
        return False, f"{message}: {tail[0]}" if tail[0] else message
    return True, done.stdout


def _check_python(python: str) -> dict:
    """Check that the trusted Python runtime exists and runs.

    Args:
        python: The absolute path of the runtime, or ``""`` when it is unknown.

    Returns:
        The ``python_runtime`` entry.
    """
    name = "python_runtime"
    if not python:
        return _result(name, False, "The path of the Python runtime is unknown.")
    if not (os.path.isfile(python) and os.access(python, os.X_OK)):
        return _result(name, False, f"{python} is not an executable file.")
    ok, out = _run([python, "-c", "import sys; print(sys.version.split()[0])"])
    if not ok:
        return _result(name, False, out)
    return _result(name, True, f"{python} runs Python {out.strip()}.")


def _check_score(python: str) -> dict:
    """Run ``ascent score`` with a sample metric and a sample input.

    The command runs with the trusted runtime, so the check also proves that
    the runtime imports the package.

    Args:
        python: The absolute path of the runtime, or ``""`` when it is unknown.

    Returns:
        The ``ascent_score`` entry.
    """
    name = "ascent_score"
    if not python:
        return _result(name, False, "The path of the Python runtime is unknown.")
    try:
        with tempfile.TemporaryDirectory(prefix="ascent-check-") as folder:
            with open(os.path.join(folder, "metric.py"), "w", encoding="utf-8") as file:
                file.write(_SAMPLE_METRIC)
            with open(os.path.join(folder, "case.json"), "w", encoding="utf-8") as file:
                json.dump(_SAMPLE_INPUT, file)
            argv = [python, "-m", "openascent.cli", "score", "--entry", "metric.py:score"]
            ok, out = _run([*argv, "--input", "case.json", "--timeout", "5"], cwd=folder)
    except OSError as error:
        return _result(name, False, f"Cannot write the sample metric: {error}")
    if not ok:
        return _result(name, False, out)
    try:
        result = check_metric_result(load_json(out.strip().encode("utf-8")))
    except AscentError as error:
        return _result(name, False, f"ascent score printed no valid result: {error}")
    if result.score != 1.0:
        return _result(name, False, f"The sample metric gave {result.score}, not 1.0.")
    return _result(name, True, "The sample metric returned a valid result with score 1.0.")


def _check_ascent(ascent: str) -> dict:
    """Check that the ``ascent`` command exists and runs.

    Args:
        ascent: The path of the command, or ``""`` when it is not on ``PATH``.

    Returns:
        The ``ascent_command`` entry.
    """
    name = "ascent_command"
    if not ascent:
        return _result(name, False, "The ascent command is not on PATH.")
    ok, out = _run([ascent, "--help"])
    if not ok:
        return _result(name, False, out)
    return _result(name, True, f"{ascent} runs.")


def _check_import(python: str) -> dict:
    """Check that the Python runtime imports the package at this version.

    Args:
        python: The absolute path of the runtime, or ``""`` when it is unknown.

    Returns:
        The ``package_import`` entry.
    """
    name = "package_import"
    if not python:
        return _result(name, False, "The path of the Python runtime is unknown.")
    ok, out = _run([python, "-c", "import openascent; print(openascent.__version__)"])
    if not ok:
        return _result(name, False, out)
    version = out.strip()
    if version != __version__:
        return _result(name, False, f"{python} imports openascent {version}, not {__version__}.")
    return _result(name, True, f"{python} imports openascent {version}.")


def _check_shell(shell: str) -> dict:
    """Check that the shell exists and runs a command.

    Args:
        shell: The path of the shell.

    Returns:
        The ``shell`` entry.
    """
    name = "shell"
    ok, out = _run([shell, "-c", "echo ok"])
    if not ok:
        return _result(name, False, out)
    if out.strip() != "ok":
        return _result(name, False, f"{shell} printed {out.strip()!r}, not 'ok'.")
    return _result(name, True, f"{shell} runs.")


def _check_temp(temp_root: str | None) -> dict:
    """Check that a temporary directory is writable.

    Args:
        temp_root: The folder for the temporary directory. ``None`` uses the
            default temporary folder.

    Returns:
        The ``temp_dir`` entry.
    """
    name = "temp_dir"
    try:
        with tempfile.TemporaryDirectory(prefix="ascent-check-", dir=temp_root) as folder:
            path = os.path.join(folder, "probe")
            with open(path, "w", encoding="utf-8") as file:
                file.write("ok")
            with open(path, encoding="utf-8") as file:
                if file.read() != "ok":
                    return _result(name, False, f"{folder} gave back other bytes.")
            parent = os.path.dirname(folder)
    except OSError as error:
        return _result(name, False, f"Cannot write a temporary directory: {error}")
    return _result(name, True, f"{parent} is writable.")
