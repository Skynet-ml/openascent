"""Tests of ``ascent check --image``, with fakes for the missing pieces of a box."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import openascent
from openascent import image_check
from openascent.cli import main
from openascent.image_check import PROTOCOL_VERSION, check_image

PY = os.path.abspath(sys.executable)
BIN = Path(PY).parent


def fake(tmp_path, name, body):
    """Write an executable shell script that stands in for a tool.

    Args:
        tmp_path: The test folder.
        name: The file name.
        body: The script lines after the shebang.

    Returns:
        The path of the script as a string.
    """
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


def ascent_on_path():
    """Find the ``ascent`` command of the test environment.

    Returns:
        The path of the command.
    """
    path = BIN / "ascent"
    if not path.exists():
        pytest.skip("the ascent command of this interpreter is not installed")
    return str(path)


def checks(report):
    """Map each check name to its ``ok`` value.

    Args:
        report: The report of ``check_image``.

    Returns:
        The map.
    """
    return {check["name"]: check["ok"] for check in report["checks"]}


def test_metric_box_passes():
    """A full box passes every metric check and gives the absolute runtime path."""
    report = check_image("metric", python=PY)
    assert report["ok"], report
    assert report["sdk_version"] == openascent.__version__
    assert report["protocol_version"] == PROTOCOL_VERSION
    assert report["role"] == "metric"
    assert report["python"] == PY
    assert os.path.isabs(report["python"])
    assert checks(report) == {"python_runtime": True, "ascent_score": True, "temp_dir": True}
    for check in report["checks"]:
        assert set(check) == {"name", "ok", "message"}
        assert check["message"]


def test_candidate_box_passes():
    """A full box passes every candidate check."""
    report = check_image("candidate", python=PY, ascent=ascent_on_path())
    assert report["ok"], report
    assert report["role"] == "candidate"
    assert "python" not in report
    assert checks(report) == {
        "ascent_command": True,
        "package_import": True,
        "shell": True,
        "temp_dir": True,
    }


def test_missing_runtime_fails_the_metric_checks(tmp_path):
    """A runtime that does not exist fails the runtime and the score check."""
    report = check_image("metric", python=str(tmp_path / "python3"))
    assert not report["ok"]
    assert report["python"] is None
    assert checks(report) == {"python_runtime": False, "ascent_score": False, "temp_dir": True}


def test_broken_runtime_fails(tmp_path):
    """A runtime that exits with an error fails the runtime check."""
    broken = fake(tmp_path, "python3", "echo broken >&2\nexit 3\n")
    report = check_image("metric", python=broken)
    assert not report["ok"]
    runtime = report["checks"][0]
    assert runtime["name"] == "python_runtime"
    assert not runtime["ok"]
    assert "code 3" in runtime["message"]
    assert "broken" in runtime["message"]


def test_failure_message_keeps_the_stderr_tail(tmp_path):
    """The message keeps a trailing colon of stderr, and has no colon when stderr is empty."""
    colon = fake(tmp_path, "colon.sh", "printf 'bad value: ' >&2\nexit 3\n")
    report = check_image("candidate", python=PY, ascent=ascent_on_path(), shell=colon)
    assert report["checks"][2]["message"] == f"{colon} exited with code 3: bad value:"
    quiet = fake(tmp_path, "quiet.sh", "exit 4\n")
    report = check_image("candidate", python=PY, ascent=ascent_on_path(), shell=quiet)
    assert report["checks"][2]["message"] == f"{quiet} exited with code 4"


def test_unknown_runtime_path_fails(monkeypatch):
    """An interpreter that cannot tell its own path fails the metric checks."""
    monkeypatch.setattr(sys, "executable", "")
    report = check_image("metric")
    assert checks(report) == {"python_runtime": False, "ascent_score": False, "temp_dir": True}
    assert report["python"] is None


@pytest.mark.parametrize(
    ("answer", "text"),
    [
        ("echo '{\"score\": 2'", "no valid result"),
        ("echo '{\"score\": 0.0}'", "not 1.0"),
        ("echo 'no such module' >&2; exit 1", "no such module"),
    ],
)
def test_score_path_failures(tmp_path, answer, text):
    """A runtime that runs but gives a bad ``ascent score`` answer fails the score check."""
    runtime = fake(
        tmp_path,
        "python3",
        f'if [ "$1" = "-m" ]; then {answer}; exit 0; fi\nexec "{PY}" "$@"\n',
    )
    report = check_image("metric", python=runtime)
    assert checks(report) == {"python_runtime": True, "ascent_score": False, "temp_dir": True}
    assert text in report["checks"][1]["message"]
    assert not report["ok"]


def test_score_runs_in_the_sample_folder(tmp_path):
    """The score check runs the real ``ascent score`` with the sample files."""
    log = tmp_path / "argv"
    runtime = fake(tmp_path, "python3", f'echo "$@" >> "{log}"\nexec "{PY}" "$@"\n')
    assert check_image("metric", python=runtime)["ok"]
    assert "-m openascent.cli score --entry metric.py:score --input case.json" in log.read_text()


def test_no_writable_temp_dir_fails(tmp_path):
    """A temporary folder that is not a directory fails the temp check of each role."""
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("")
    metric = check_image("metric", python=PY, temp_root=str(not_a_dir))
    assert checks(metric)["temp_dir"] is False
    assert not metric["ok"]
    candidate = check_image(
        "candidate", python=PY, ascent=ascent_on_path(), temp_root=str(not_a_dir)
    )
    assert checks(candidate)["temp_dir"] is False
    assert not candidate["ok"]


def test_missing_ascent_command_fails(tmp_path):
    """No ``ascent`` command on PATH fails the command check."""
    report = check_image("candidate", python=PY, ascent="")
    assert checks(report)["ascent_command"] is False
    assert "not on PATH" in report["checks"][0]["message"]
    assert not report["ok"]


def test_broken_ascent_command_fails(tmp_path):
    """An ``ascent`` command that cannot run fails the command check."""
    report = check_image("candidate", python=PY, ascent=fake(tmp_path, "ascent", "exit 1\n"))
    assert checks(report)["ascent_command"] is False


def test_ascent_command_is_found_on_path(monkeypatch):
    """With no ``ascent`` argument, the check finds the command on ``PATH``."""
    ascent_on_path()
    monkeypatch.setenv("PATH", f"{BIN}{os.pathsep}{os.environ.get('PATH', '')}")
    assert checks(check_image("candidate", python=PY))["ascent_command"] is True


def test_missing_package_fails(tmp_path):
    """A runtime that cannot import the package fails the import check."""
    runtime = fake(tmp_path, "python3", "echo 'No module named openascent' >&2\nexit 1\n")
    report = check_image("candidate", python=runtime, ascent=ascent_on_path())
    assert checks(report)["package_import"] is False
    assert "No module named openascent" in report["checks"][1]["message"]


def test_import_check_ignores_a_local_package(tmp_path, monkeypatch):
    """A local openascent folder in the current directory does not hide the installed package."""
    local = tmp_path / "openascent"
    local.mkdir()
    (local / "__init__.py").write_text('__version__ = "9"\n')
    monkeypatch.chdir(tmp_path)
    report = check_image("candidate", python=PY, ascent=ascent_on_path())
    entry = report["checks"][1]
    assert entry["name"] == "package_import"
    assert entry["ok"], entry
    assert entry["message"] == f"{PY} imports openascent {openascent.__version__}."


def test_other_package_version_fails(tmp_path):
    """A runtime that imports another version of the package fails the import check."""
    runtime = fake(tmp_path, "python3", "echo 9.9.9\n")
    report = check_image("candidate", python=runtime, ascent=ascent_on_path())
    assert checks(report)["package_import"] is False
    assert "9.9.9" in report["checks"][1]["message"]


def test_missing_shell_fails(tmp_path):
    """No shell at the shell path fails the shell check."""
    report = check_image(
        "candidate", python=PY, ascent=ascent_on_path(), shell=str(tmp_path / "sh")
    )
    assert checks(report)["shell"] is False
    assert "cannot start" in report["checks"][2]["message"]
    assert not report["ok"]


def test_wrong_shell_answer_fails(tmp_path):
    """A shell that does not run the command fails the shell check."""
    shell = fake(tmp_path, "sh", "echo nope\n")
    report = check_image("candidate", python=PY, ascent=ascent_on_path(), shell=shell)
    assert checks(report)["shell"] is False


def test_slow_piece_stops_at_the_time_limit(tmp_path, monkeypatch):
    """A piece that hangs fails at the time limit of the check."""
    monkeypatch.setattr(image_check, "CHECK_TIMEOUT_S", 0.5)
    shell = fake(tmp_path, "sh", "exec sleep 30\n")
    start = time.monotonic()
    report = check_image("candidate", python=PY, ascent=ascent_on_path(), shell=shell)
    assert time.monotonic() - start < 10
    assert checks(report)["shell"] is False
    assert "longer than" in report["checks"][2]["message"]


def test_unknown_role_is_refused():
    """The function refuses a role that is not candidate or metric."""
    with pytest.raises(ValueError):
        check_image("judge")


def test_cli_prints_one_json_object(capsys):
    """``ascent check --image`` prints the report and exits 0 when every check passes."""
    assert main(["check", "--image", "--role", "metric"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"]
    assert report["role"] == "metric"


def test_cli_exits_1_on_a_failed_check(capsys, monkeypatch):
    """A failed check makes the command exit 1."""
    monkeypatch.setattr(sys, "executable", "")
    assert main(["check", "--image", "--role", "metric"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


@pytest.mark.parametrize(
    "argv",
    [
        ["check", "--image"],
        ["check", "--image", "--role", "judge"],
        ["check", "--role", "metric"],
        ["check"],
    ],
)
def test_cli_usage_error(argv, capsys):
    """No role, a wrong role, or no ``--image`` is a usage error with exit code 2."""
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2
    assert capsys.readouterr().out == ""


def test_command_runs_in_a_subprocess_in_time():
    """The installed command checks both roles in less than 30 seconds."""
    ascent = ascent_on_path()
    env = {**os.environ, "PATH": f"{BIN}{os.pathsep}{os.environ.get('PATH', '')}"}
    for role in ("metric", "candidate"):
        start = time.monotonic()
        done = subprocess.run(
            [ascent, "check", "--image", "--role", role], capture_output=True, text=True, env=env
        )
        assert time.monotonic() - start < 30
        assert done.returncode == 0, done.stdout + done.stderr
        assert json.loads(done.stdout)["role"] == role
