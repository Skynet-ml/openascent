"""Tests of the component call with real subprocesses, and of the ``ascent`` command."""

import json
import math
import os
import shutil
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
    entry = [PY, script(tmp_path, body)]
    # A loaded machine can start the script slowly; retry with a longer limit
    # until the script wrote the pid of its child before the kill.
    for limit in (1, 5, 20):
        start = time.monotonic()
        with pytest.raises(TimeLimitError) as caught:
            call_run(entry, 1, timeout_s=limit)
        assert time.monotonic() - start < limit + 10
        assert caught.value.code == "time_limit"
        if pid_file.exists() and pid_file.read_text():
            break
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
    """An output path that is a link is refused with a link message."""
    target = tmp_path / "target.json"
    target.write_text('{"output": 1}')
    body = f'import os\nos.symlink({str(target)!r}, os.environ["ASCENT_OUTPUT"])\n'
    with pytest.raises(OutputFileError, match="is a symbolic link"):
        call_run([PY, script(tmp_path, body)], 1, timeout_s=10)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a mode-000 file")
def test_unreadable_output_is_refused(tmp_path):
    """An output file that the runner cannot open gives a cannot-open message."""
    body = """
        import os
        with open(os.environ["ASCENT_OUTPUT"], "w") as f:
            f.write('{"output": 1}')
        os.chmod(os.environ["ASCENT_OUTPUT"], 0)
    """
    with pytest.raises(OutputFileError, match="cannot open the output file") as caught:
        call_run([PY, script(tmp_path, body)], 1, timeout_s=10)
    assert caught.value.code == "bad_output_file"


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


MOVE_CALL_DIR = """
    import os, sys
    out = os.environ["ASCENT_OUTPUT"]
    with open(out, "w") as f:
        f.write('{"output": "kept"}')
    folder = os.path.dirname(out)
    os.rename(folder, folder + ".moved")
    os.symlink(folder + ".moved", folder)
    open(%r, "w").write(folder)
    sys.exit(%d)
"""


def _remove_moved(folder_file):
    """Remove the moved call folder and the link that a test command left.

    Args:
        folder_file: The file that holds the path of the original call folder.
    """
    folder = folder_file.read_text()
    os.unlink(folder)
    shutil.rmtree(folder + ".moved")


@pytest.mark.parametrize("exit_code", [0, 3])
def test_moved_call_directory_keeps_the_result(tmp_path, exit_code):
    """A command that moves its call folder and links it back cannot break the call."""
    folder_file = tmp_path / "folder"
    entry = [PY, script(tmp_path, MOVE_CALL_DIR % (str(folder_file), exit_code))]
    try:
        if exit_code == 0:
            assert call_run(entry, 1, timeout_s=10).output == "kept"
        else:
            with pytest.raises(ExitCodeError):
                call_run(entry, 1, timeout_s=10)
    finally:
        _remove_moved(folder_file)


SWAP_CALL_DIR = """
    import json, os, sys
    out = os.environ["ASCENT_OUTPUT"]
    folder = os.path.dirname(out)
    if %(real)r:
        with open(out, "w") as f:
            f.write('{"output": "real"}')
    os.rename(folder, folder + ".moved")
    fake = folder + ".fake"
    os.mkdir(fake)
    with open(os.path.join(fake, "output.json"), "w") as f:
        f.write('{"output": "fake"}')
    if %(link)r:
        os.symlink(fake, folder)
    else:
        os.rename(fake, folder)
    open(%(folder_file)r, "w").write(folder)
"""


def _remove_swapped(folder_file):
    """Remove every folder and link that a swap test command left.

    Args:
        folder_file: The file that holds the path of the original call folder.
    """
    folder = folder_file.read_text()
    if os.path.islink(folder):
        os.unlink(folder)
    for path in (folder, folder + ".moved", folder + ".fake"):
        shutil.rmtree(path, ignore_errors=True)


@pytest.mark.parametrize("link", [False, True])
@pytest.mark.parametrize("real", [True, False])
def test_swapped_call_directory_does_not_redirect_the_read(tmp_path, link, real):
    """A new folder or a link at the old call folder path cannot give a fake result."""
    folder_file = tmp_path / "folder"
    body = SWAP_CALL_DIR % {"real": real, "link": link, "folder_file": str(folder_file)}
    entry = [PY, script(tmp_path, body)]
    try:
        if real:
            assert call_run(entry, 1, timeout_s=10).output == "real"
        else:
            with pytest.raises(NoOutputError):
                call_run(entry, 1, timeout_s=10)
    finally:
        _remove_swapped(folder_file)


def test_hard_link_output_is_refused(tmp_path):
    """An output path that is a hard link to another file is refused."""
    target = tmp_path / "target.json"
    target.write_text('{"output": "outside"}')
    body = f'import os\nos.link({str(target)!r}, os.environ["ASCENT_OUTPUT"])\n'
    with pytest.raises(OutputFileError, match="more than one name") as caught:
        call_run([PY, script(tmp_path, body)], 1, timeout_s=10)
    assert caught.value.code == "bad_output_file"


@pytest.mark.parametrize(
    "bad",
    [math.nan, math.inf, -math.inf, 0, -1, True, "5", None, pytest.param(10**400, id="10**400")],
)
def test_invalid_time_limit_is_refused(tmp_path, bad):
    """A time limit that is not a finite number above 0 is refused before any start."""
    marker = tmp_path / "started"
    entry = ["sh", "-c", f"touch {marker}"]
    with pytest.raises(ValueError, match="time limit"):
        call_run(entry, 1, timeout_s=bad)
    with pytest.raises(ValueError, match="time limit"):
        call_metric(entry, CASE, timeout_s=bad)
    assert not marker.exists()


@pytest.mark.parametrize("bad", ["nan", "inf", "0", "-1", "soon"])
def test_cli_invalid_time_limit(tmp_path, capsys, bad):
    """``--timeout`` that is not a finite number above 0 is a usage error."""
    marker = tmp_path / "started"
    case = tmp_path / "case.json"
    case.write_text(json.dumps(CASE))
    with pytest.raises(SystemExit) as caught:
        main(["score", "--entry", f"touch {marker}", "--input", str(case), "--timeout", bad])
    assert caught.value.code == 2
    assert "--timeout" in capsys.readouterr().err
    assert not marker.exists()


def test_input_must_be_strict_json(tmp_path):
    """An input value with NaN or a lone surrogate is refused before any start."""
    marker = tmp_path / "started"
    entry = ["sh", "-c", f"touch {marker}"]
    with pytest.raises(ValueError, match="finite numbers"):
        call_run(entry, math.nan, timeout_s=10)
    with pytest.raises(ValueError, match="lone surrogate"):
        call_run(entry, "\ud800", timeout_s=10)
    with pytest.raises(ValueError, match="lone surrogate"):
        call_metric(entry, {**CASE, "output": {"\udc00": 1}}, timeout_s=10)
    assert not marker.exists()


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({1, 2}, "not strict JSON"),
        (object(), "not strict JSON"),
        ({1: "a"}, "key that is not a string"),
        ({"a": [{"b": {2: "c"}}]}, "key that is not a string"),
    ],
)
def test_input_must_hold_only_json_values(tmp_path, value, message):
    """A value that JSON cannot hold, or a key that is not a string, is refused before any start."""
    marker = tmp_path / "started"
    entry = ["sh", "-c", f"touch {marker}"]
    with pytest.raises(ValueError, match=message):
        call_run(entry, value, timeout_s=10)
    with pytest.raises(ValueError, match=message):
        call_metric(entry, {**CASE, "output": value}, timeout_s=10)
    assert not marker.exists()


@pytest.mark.parametrize(
    ("kind", "returned", "key"),
    [
        ("run", "{1: 'a'}", "1"),
        ("metric", "{'score': 1.0, 'scores': [{'name': 'a', 'score': 1.0}, {1: 'b'}]}", "1"),
        ("run", "{'a': {True: 1}}", "True"),
        ("metric", "{'score': 1.0, None: 2}", "None"),
        ("run", "{1: 'a', '1': 'b'}", "1"),
        ("run", "{(1, 2): 'a'}", "(1, 2)"),
        ("metric", "(d := {1: 'a'}, d.__setitem__('self', d))[0]", "1"),
    ],
)
def test_function_result_needs_string_keys(tmp_path, kind, returned, key):
    """A returned dict key that is not a string is refused, not turned into a string."""
    script(tmp_path, f"def go(*args, **kwargs):\n    return {returned}\n")
    call = call_run if kind == "run" else call_metric
    value = 1 if kind == "run" else CASE
    with pytest.raises(ExitCodeError) as caught:
        call("component.py:go", value, timeout_s=10, cwd=tmp_path)
    assert caught.value.exit_code == 2
    assert f"the key {key}, which is not a string" in caught.value.stderr


def test_function_result_with_a_cycle_fails_without_a_hang(tmp_path):
    """A cyclic return value with string keys only still fails in json.dumps."""
    script(tmp_path, "def go(value):\n    d = {'a': 1}\n    d['self'] = d\n    return d\n")
    with pytest.raises(ExitCodeError) as caught:
        call_run("component.py:go", 1, timeout_s=10, cwd=tmp_path)
    assert caught.value.code == "nonzero_exit"
    assert caught.value.exit_code == 1
    assert "Circular reference" in caught.value.stderr


def test_cli_deeply_nested_input_is_a_usage_error(tmp_path, capsys):
    """An input file nested too deep for the JSON parser is a usage error, not a traceback."""
    marker = tmp_path / "started"
    case = tmp_path / "case.json"
    case.write_text("[" * 200000 + "]" * 200000)
    with pytest.raises(SystemExit) as caught:
        main(["score", "--entry", f"touch {marker}", "--input", str(case)])
    assert caught.value.code == 2
    err = capsys.readouterr().err
    assert "cannot read the input file" in err
    assert "Traceback" not in err
    assert not marker.exists()


@pytest.mark.parametrize("signature", ["output, /", "output, /, **kw"])
def test_positional_only_parameter_is_refused(tmp_path, signature):
    """A positional-only parameter with no default cannot get its value by name."""
    script(tmp_path, f"def score({signature}):\n    return {{'score': 1}}\n")
    with pytest.raises(ExitCodeError) as caught:
        call_metric("component.py:score", CASE, timeout_s=10, cwd=tmp_path)
    assert caught.value.exit_code == 2
    assert "positional-only parameter 'output'" in caught.value.stderr
    assert "remove the /" in caught.value.stderr


def test_positional_only_parameter_with_default_is_allowed(tmp_path):
    """A positional-only parameter with a default keeps its default."""
    script(tmp_path, "def score(scale=0.5, /, *, output):\n    return {'score': scale}\n")
    assert call_metric("component.py:score", CASE, timeout_s=10, cwd=tmp_path).result.score == 0.5


def test_input_keeps_valid_unicode(tmp_path):
    """Valid non-ASCII text, also a surrogate pair, reaches the command unchanged."""
    body = """
        import json, os
        value = json.load(open(os.environ["ASCENT_INPUT"], encoding="utf-8"))["input"]
        json.dump({"output": value}, open(os.environ["ASCENT_OUTPUT"], "w"))
    """
    assert call_run([PY, script(tmp_path, body)], "Paris \U0001f600 café", timeout_s=10).output == (
        "Paris \U0001f600 café"
    )
