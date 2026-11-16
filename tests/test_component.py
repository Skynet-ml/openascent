"""Tests of the component call with real subprocesses, and of the ``ascent`` command."""

import json
import os
import subprocess
import sys
import textwrap
import time

import pytest

from openascent import (
    ExitCodeError,
    FunctionEntry,
    InvalidFormError,
    InvalidJsonError,
    MetricResult,
    NoOutputError,
    OutputFileError,
    StartError,
    TimeLimitError,
    call_metric,
    call_run,
    parse_entry,
)
from openascent.cli import main
from openascent.component import LOG_TAIL_BYTES

PY = sys.executable
CASE = {"input": "q", "expected": "Paris", "output": "Paris"}


def script(tmp_path, body, name="component.py"):
    """Write a Python script into ``tmp_path``.

    Args:
        tmp_path: The test folder.
        body: The script source.
        name: The file name.

    Returns:
        The path of the script as a string.
    """
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return str(path)


def writes(tmp_path, text):
    """Write a script that writes ``text`` to the output file.

    Args:
        tmp_path: The test folder.
        text: The output file content.

    Returns:
        The command as a list of strings.
    """
    body = f"""
        import os
        with open(os.environ["ASCENT_OUTPUT"], "w") as f:
            f.write({text!r})
    """
    return [PY, script(tmp_path, body)]


def test_parse_entry_forms():
    """Both entry forms parse, and every other value fails with one clear error."""
    assert parse_entry("dir/metric.py:score") == FunctionEntry("dir/metric.py", "score")
    assert parse_entry(["node", "metric.mjs"]) == ("node", "metric.mjs")
    for bad in ["./metric.sh", "metric.py", "metric.py:", ".py:f", [], [""], [1], 3, None]:
        with pytest.raises(ValueError, match="path/file.py:function"):
            parse_entry(bad)


def test_run_command_success_and_two_files(tmp_path):
    """A run command reads the input file, writes the output file, and its prints are log text."""
    body = """
        import json, os, sys
        assert sys.stdin.read() == ""
        payload = json.load(open(os.environ["ASCENT_INPUT"]))
        print("debug print", payload)
        print("warning", file=sys.stderr)
        with open(os.environ["ASCENT_OUTPUT"], "w") as f:
            json.dump({"output": {"echo": payload, "out": os.environ["ASCENT_OUTPUT"]}}, f)
    """
    call = call_run([PY, script(tmp_path, body)], [1, "a"], timeout_s=10)
    assert call.output["echo"] == {"input": [1, "a"]}
    assert "debug print" in call.stdout
    assert call.stderr == "warning\n"
    assert call.elapsed_s > 0
    assert not os.path.exists(call.output["out"])


def test_each_call_gets_a_new_output_path(tmp_path):
    """Two calls see two different output paths."""
    body = """
        import json, os
        json.dump({"output": os.environ["ASCENT_OUTPUT"]}, open(os.environ["ASCENT_OUTPUT"], "w"))
    """
    entry = [PY, script(tmp_path, body)]
    first = call_run(entry, None, timeout_s=10).output
    second = call_run(entry, None, timeout_s=10).output
    assert first != second


def test_run_output_null(tmp_path):
    """A run output can be null."""
    assert call_run(writes(tmp_path, '{"output": null}'), 1, timeout_s=10).output is None


def test_metric_command_success(tmp_path):
    """A metric command gets the metric input object and gives the checked answer."""
    body = """
        import json, os
        case = json.load(open(os.environ["ASCENT_INPUT"]))
        print("noise")
        answer = {"score": 1 if case["output"] == case["expected"] else 0}
        json.dump(answer, open(os.environ["ASCENT_OUTPUT"], "w"))
    """
    call = call_metric([PY, script(tmp_path, body)], CASE, timeout_s=10)
    assert call.result == MetricResult(1.0)


def test_shell_command_and_env_mapping(tmp_path):
    """A given env replaces the environment; the two variables are still set."""
    body = 'printf \'{"output": "%s"}\' "$EXTRA-${HOME:-none}" > "$ASCENT_OUTPUT"\n'
    path = tmp_path / "run.sh"
    path.write_text(body)
    call = call_run(["sh", str(path)], 1, timeout_s=10, env={"EXTRA": "x", "PATH": os.defpath})
    assert call.output == "x-none"


def test_cwd(tmp_path):
    """The command runs in the given working directory."""
    body = """
        import json, os
        json.dump({"output": os.getcwd()}, open(os.environ["ASCENT_OUTPUT"], "w"))
    """
    entry = [PY, script(tmp_path, body)]
    assert os.path.samefile(call_run(entry, 1, timeout_s=10, cwd=tmp_path).output, tmp_path)


def test_function_run(tmp_path):
    """The function form calls the function with the input value."""
    script(
        tmp_path,
        "import helper\ndef go(value):\n    print('log')\n    return helper.twice(value)\n",
    )
    script(tmp_path, "def twice(v):\n    return v * 2\n", name="helper.py")
    call = call_run("component.py:go", 21, timeout_s=10, cwd=tmp_path)
    assert call.output == 42
    assert call.stdout == "log\n"


def test_function_metric_keyword_fields(tmp_path):
    """The metric function gets the fields it names, and **kwargs gets every field."""
    script(
        tmp_path,
        """
        def named(output, expected=None):
            return {"score": float(output == expected)}

        def every(**fields):
            return {"score": 1, "feedback": ",".join(sorted(fields))}
        """,
    )
    entry = str(tmp_path / "component.py")
    assert call_metric(f"{entry}:named", CASE, timeout_s=10).result.score == 1.0
    payload = {"input": 1, "output": 2, "elapsed_s": 0.5, "future_key": True}
    result = call_metric(f"{entry}:every", payload, timeout_s=10).result
    assert result.feedback == "elapsed_s,future_key,input,output"


def test_function_missing_required_parameter(tmp_path):
    """A required parameter that the input object does not hold is a clear error."""
    script(tmp_path, "def score(output, expected):\n    return {'score': 1}\n")
    payload = {"input": 1, "output": 2}
    with pytest.raises(ExitCodeError) as caught:
        call_metric("component.py:score", payload, timeout_s=10, cwd=tmp_path)
    assert "required parameter 'expected'" in caught.value.stderr


def test_function_raises(tmp_path):
    """An exception in the function is a non-zero exit with the traceback in stderr."""
    script(tmp_path, "def go(value):\n    raise RuntimeError('boom')\n")
    with pytest.raises(ExitCodeError) as caught:
        call_run("component.py:go", 1, timeout_s=10, cwd=tmp_path)
    assert caught.value.exit_code == 1
    assert "RuntimeError: boom" in caught.value.stderr


def test_function_result_is_checked_by_parent(tmp_path):
    """The child writes the return value as is; the parent checks it."""
    script(tmp_path, "def score(output):\n    return {'score': float('nan')}\n")
    with pytest.raises(InvalidJsonError):
        call_metric("component.py:score", CASE, timeout_s=10, cwd=tmp_path)


def test_function_missing_file_or_name(tmp_path):
    """A missing function file cannot start; a missing function name fails with a message."""
    with pytest.raises(StartError):
        call_run("absent.py:go", 1, timeout_s=10, cwd=tmp_path)
    script(tmp_path, "x = 1\n")
    with pytest.raises(ExitCodeError) as caught:
        call_run("component.py:go", 1, timeout_s=10, cwd=tmp_path)
    assert "no function named 'go'" in caught.value.stderr


def test_cannot_start(tmp_path):
    """A command that does not exist or is not executable cannot start."""
    with pytest.raises(StartError) as caught:
        call_run([str(tmp_path / "absent")], 1, timeout_s=10)
    assert caught.value.code == "start_failed"
    plain = tmp_path / "plain.sh"
    plain.write_text("exit 0\n")
    with pytest.raises(StartError):
        call_run([str(plain)], 1, timeout_s=10)


def test_time_limit_kills_the_process_group(tmp_path):
    """After the time limit, the command and its children are gone."""
    pid_file = tmp_path / "pid"
    body = f"""
        import subprocess, time
        child = subprocess.Popen(["sleep", "30"])
        open({str(pid_file)!r}, "w").write(str(child.pid))
        time.sleep(30)
    """
    start = time.monotonic()
    with pytest.raises(TimeLimitError) as caught:
        call_run([PY, script(tmp_path, body)], 1, timeout_s=1)
    assert time.monotonic() - start < 10
    assert caught.value.code == "time_limit"
    child_pid = int(pid_file.read_text())
    for _ in range(100):
        if not _alive(child_pid):
            break
        time.sleep(0.05)
    assert not _alive(child_pid)


def _alive(pid):
    """Tell if a process still exists and is not a zombie.

    Args:
        pid: The process id.

    Returns:
        True when the process runs.
    """
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return state.returncode == 0 and not state.stdout.strip().startswith("Z")


def test_nonzero_exit_keeps_code_and_stderr(tmp_path):
    """A non-zero exit keeps the exit code and the stderr tail."""
    body = (
        'import sys\nprint("x" * 100000, file=sys.stderr)\nprint("last words", file=sys.stderr)\n'
    )
    body += "sys.exit(3)\n"
    with pytest.raises(ExitCodeError) as caught:
        call_run([PY, script(tmp_path, body)], 1, timeout_s=10)
    assert caught.value.code == "nonzero_exit"
    assert caught.value.exit_code == 3
    assert caught.value.stderr.endswith("last words\n")
    assert len(caught.value.stderr) <= 64 * 1024


def test_no_output_file(tmp_path):
    """Exit 0 with no output file gives the exact message."""
    with pytest.raises(NoOutputError) as caught:
        call_run([PY, script(tmp_path, "print('hi')\n")], 1, timeout_s=10)
    assert str(caught.value) == (
        "The command wrote no output file. Write the result as JSON to the path in ASCENT_OUTPUT."
    )


def test_symlink_output_is_refused(tmp_path):
    """An output path that is a link is not a regular file."""
    target = tmp_path / "target.json"
    target.write_text('{"output": 1}')
    body = f'import os\nos.symlink({str(target)!r}, os.environ["ASCENT_OUTPUT"])\n'
    with pytest.raises(OutputFileError, match="not a regular file"):
        call_run([PY, script(tmp_path, body)], 1, timeout_s=10)


def test_folder_output_is_refused(tmp_path):
    """An output path that is a folder is not a regular file."""
    body = 'import os\nos.mkdir(os.environ["ASCENT_OUTPUT"])\n'
    with pytest.raises(OutputFileError, match="not a regular file"):
        call_run([PY, script(tmp_path, body)], 1, timeout_s=10)


def test_too_large_output(tmp_path):
    """An output file larger than the limit is refused."""
    entry = writes(tmp_path, json.dumps({"output": "x" * 200}))
    with pytest.raises(OutputFileError, match="larger than 100 bytes"):
        call_run(entry, 1, timeout_s=10, max_output_bytes=100)
    assert call_run(entry, 1, timeout_s=10, max_output_bytes=1000).output == "x" * 200


def test_invalid_json_output(tmp_path):
    """An output file that is not JSON is invalid JSON."""
    with pytest.raises(InvalidJsonError) as caught:
        call_run(writes(tmp_path, "not json"), 1, timeout_s=10)
    assert caught.value.code == "invalid_json"


def test_invalid_form_output(tmp_path):
    """Valid JSON in the wrong form is an invalid form, for both kinds."""
    with pytest.raises(InvalidFormError):
        call_run(writes(tmp_path, '{"result": 1}'), 1, timeout_s=10)
    with pytest.raises(InvalidFormError) as caught:
        call_metric(writes(tmp_path, "0.5"), CASE, timeout_s=10)
    assert caught.value.code == "invalid_form"


def test_metric_payload_needs_input_and_output():
    """A metric input object without input or output is refused before any call."""
    with pytest.raises(ValueError):
        call_metric(["true"], {"input": 1}, timeout_s=10)


def test_cli_success(tmp_path, capsys, monkeypatch):
    """``ascent score`` prints the checked answer and exits 0."""
    script(
        tmp_path,
        "import sys\ndef score(output):\n    print('note', file=sys.stderr)\n"
        "    return {'score': 1, 'feedback': 'ok'}\n",
    )
    case = tmp_path / "case.json"
    case.write_text(json.dumps(CASE))
    monkeypatch.chdir(tmp_path)
    assert main(["score", "--entry", "component.py:score", "--input", str(case)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"score": 1.0, "feedback": "ok"}
    assert "note" in captured.err


def test_cli_command_entry_and_failure(tmp_path):
    """A command entry is split like a shell line; a failure prints the code and exits 1."""
    case = tmp_path / "case.json"
    case.write_text(json.dumps(CASE))
    good = script(
        tmp_path,
        "import os\nopen(os.environ['ASCENT_OUTPUT'], 'w').write('{\"score\": 0.5}')\n",
        name="good.py",
    )
    command = [PY, "-m", "openascent.cli", "score", "--input", str(case), "--entry"]
    ok = subprocess.run([*command, f"{PY} {good}"], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout) == {"score": 0.5}
    bad = script(tmp_path, "print('hi')\n", name="bad.py")
    failed = subprocess.run([*command, f"{PY} {bad}"], capture_output=True, text=True)
    assert failed.returncode == 1
    assert failed.stdout == ""
    assert "ascent: no_output: The command wrote no output file." in failed.stderr


def test_cli_usage_error(tmp_path):
    """A usage error exits with 2."""
    with pytest.raises(SystemExit) as caught:
        main(["score", "--entry", "x.py:f"])
    assert caught.value.code == 2
    with pytest.raises(SystemExit) as caught:
        main(["score", "--entry", "x.py:f", "--input", str(tmp_path / "absent.json")])
    assert caught.value.code == 2


def test_call_directory_holds_no_log_files(tmp_path):
    """The folder of ASCENT_OUTPUT holds only the input file while the command runs."""
    body = """
        import json, os
        folder = os.path.dirname(os.environ["ASCENT_OUTPUT"])
        names = sorted(os.listdir(folder))
        json.dump({"output": names}, open(os.environ["ASCENT_OUTPUT"], "w"))
    """
    assert call_run([PY, script(tmp_path, body)], 1, timeout_s=10).output == ["input.json"]


def test_links_at_old_log_paths_do_not_leak(tmp_path):
    """Links that the command puts at the old log paths do not reach the log text."""
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET-CONTENT")
    body = f"""
        import os, sys
        folder = os.path.dirname(os.environ["ASCENT_OUTPUT"])
        for name in ("stdout.log", "stderr.log"):
            path = os.path.join(folder, name)
            if os.path.lexists(path):
                os.remove(path)
            os.symlink({str(secret)!r}, path)
        print("out text")
        print("err text", file=sys.stderr)
        open(os.environ["ASCENT_OUTPUT"], "w").write('{{"output": 1}}')
    """
    call = call_run([PY, script(tmp_path, body)], 1, timeout_s=10)
    assert call.stdout == "out text\n"
    assert call.stderr == "err text\n"
    assert "SECRET" not in call.stdout + call.stderr


def test_log_text_is_the_bounded_end(tmp_path):
    """More output than LOG_TAIL_BYTES gives at most LOG_TAIL_BYTES bytes: the end."""
    body = f"""
        import os, sys
        sys.stdout.write("a" * {LOG_TAIL_BYTES * 3} + "THE-END")
        sys.stderr.write("b" * {LOG_TAIL_BYTES * 3} + "ERR-END")
        open(os.environ["ASCENT_OUTPUT"], "w").write('{{"output": 1}}')
    """
    call = call_run([PY, script(tmp_path, body)], 1, timeout_s=10)
    for text, end in ((call.stdout, "THE-END"), (call.stderr, "ERR-END")):
        assert len(text.encode()) == LOG_TAIL_BYTES
        assert text.endswith(end)
