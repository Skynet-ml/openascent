"""Tests of the helper calls against a real local HTTP server."""

import base64
import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from openascent import HelperError, StageError, call, llm, log
from openascent.helpers import MAX_ANSWER_BYTES

PNG = b"\x89PNG\r\n\x1a\n" + b"png-data"
JPEG = b"\xff\xd8\xff\xe0" + b"jpeg-data"
GIF = b"GIF89a" + b"gif-data"
WEBP = b"RIFF\x10\x00\x00\x00WEBP" + b"webp-data"


class Handler(BaseHTTPRequestHandler):
    """Record each POST and send the reply that the test set on the server."""

    def do_POST(self):
        """Record the request and send the reply of the server."""
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.requests.append({"path": self.path, "headers": self.headers, "body": body})
        status, data = self.server.reply
        self.send_response(status)
        if 300 <= status < 400:
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        """Keep the test output free of access log lines.

        Args:
            format: The format string.
            *args: The values of the format string.
        """


def start_server():
    """Start a recording server on a free local port, in a thread.

    Returns:
        The server and its thread.
    """
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.requests = []
    httpd.reply = (200, b"{}")
    httpd.url = f"http://127.0.0.1:{httpd.server_port}"
    # A short poll interval: shutdown() waits for one poll, 0.5 s by default.
    thread = threading.Thread(target=httpd.serve_forever, args=(0.01,), daemon=True)
    thread.start()
    return httpd, thread


def stop_server(httpd, thread):
    """Stop a server from ``start_server`` and wait for its thread.

    Args:
        httpd: The server.
        thread: The thread of the server.
    """
    httpd.shutdown()
    httpd.server_close()
    thread.join()


@pytest.fixture
def server():
    """Give a recording server and shut it down after the test.

    Yields:
        The server. Set ``server.reply`` to ``(status, body bytes)``.
    """
    httpd, thread = start_server()
    yield httpd
    stop_server(httpd, thread)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Remove each helper and proxy variable, so that each test sets its own.

    Args:
        monkeypatch: The pytest fixture.
    """
    for name in list(os.environ):
        upper = name.upper()
        if upper.startswith("ASCENT_") or upper.endswith("_PROXY"):
            monkeypatch.delenv(name)


def reply(server, status, value):
    """Set the reply of the server to a JSON value.

    Args:
        server: The recording server.
        status: The status code.
        value: The JSON value of the body.
    """
    server.reply = (status, json.dumps(value).encode("utf-8"))


def data_url(media_type, data):
    """Build the base64 data URL of image bytes.

    Args:
        media_type: The media type, for example ``image/png``.
        data: The image bytes.

    Returns:
        The data URL.
    """
    return f"data:{media_type};base64,{base64.b64encode(data).decode()}"


def closed_port_url():
    """Return a local URL on which no server listens.

    Returns:
        The URL.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}"


def test_call_success(server, monkeypatch):
    """A stage call posts the input as JSON and returns the output of the answer."""
    monkeypatch.setenv("ASCENT_STAGE_PLANNER_URL", server.url + "/stage/planner")
    reply(server, 200, {"output": {"plan": ["a", "é"]}})
    assert call("planner", {"task": "é", "n": 1}) == {"plan": ["a", "é"]}
    (request,) = server.requests
    assert request["path"] == "/stage/planner"
    assert request["headers"]["Content-Type"] == "application/json"
    assert request["headers"].get("Authorization") is None
    assert json.loads(request["body"].decode("utf-8")) == {"input": {"task": "é", "n": 1}}


def test_call_default_input_is_null(server, monkeypatch):
    """A stage call with no input sends a null input, and a null output is valid."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url)
    reply(server, 200, {"output": None})
    assert call("a") is None
    assert json.loads(server.requests[0]["body"]) == {"input": None}


@pytest.mark.parametrize(
    ("stage", "variable"),
    [
        ("planner", "ASCENT_STAGE_PLANNER_URL"),
        ("planner-v2", "ASCENT_STAGE_PLANNER_V2_URL"),
        ("Judge.Final", "ASCENT_STAGE_JUDGE_FINAL_URL"),
        ("a b/c", "ASCENT_STAGE_A_B_C_URL"),
        ("straße", "ASCENT_STAGE_STRA_E_URL"),
        ("ıd", "ASCENT_STAGE__D_URL"),
        ("x_1", "ASCENT_STAGE_X_1_URL"),
    ],
)
def test_call_name_rule(server, monkeypatch, stage, variable):
    """The stage name maps to its variable: upper case, other characters as ``_``."""
    monkeypatch.setenv(variable, server.url)
    reply(server, 200, {"output": stage})
    assert call(stage) == stage


@pytest.mark.parametrize("value", [None, ""])
def test_call_absent_stage(monkeypatch, value):
    """An absent or empty stage variable names the stage, the variable and the fix."""
    if value is not None:
        monkeypatch.setenv("ASCENT_STAGE_PLANNER_V2_URL", value)
    with pytest.raises(StageError) as caught:
        call("planner-v2", 1)
    message = str(caught.value)
    assert "'planner-v2'" in message
    assert "ASCENT_STAGE_PLANNER_V2_URL" in message
    assert "no stage of this name" in message
    assert "[target.planner-v2]" in message


def test_call_error_answer(server, monkeypatch):
    """An error answer gives a stage error with the error text and the status code."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url)
    reply(server, 504, {"error": "The stage passed its time limit."})
    with pytest.raises(StageError, match=r"status 504: The stage passed its time limit\."):
        call("a", 1)


def test_call_error_answer_not_json(server, monkeypatch):
    """An error answer with a body that is not JSON still gives the status code."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url)
    server.reply = (500, b"<html>oops</html>")
    with pytest.raises(
        StageError, match=r'status 500: the body is not a JSON object with an "error"'
    ):
        call("a", 1)


@pytest.mark.parametrize(
    "body", [b"not json", b'{"output": NaN}', b'{"output": 1, "output": 2}', b"\xff"]
)
def test_call_answer_not_json(server, monkeypatch, body):
    """A 2xx answer that is not strict JSON is a stage error."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url)
    server.reply = (200, body)
    with pytest.raises(StageError, match="not strict JSON"):
        call("a", 1)


@pytest.mark.parametrize("value", [[1], {"result": 1}, "output", None])
def test_call_answer_no_output(server, monkeypatch, value):
    """A 2xx answer that is not an object with the key output is a stage error."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url)
    reply(server, 200, value)
    with pytest.raises(StageError, match='not an object with the key "output"'):
        call("a", 1)


def test_call_connection_refused(monkeypatch):
    """A closed port is a stage error that names the URL."""
    url = closed_port_url()
    monkeypatch.setenv("ASCENT_STAGE_A_URL", url)
    with pytest.raises(StageError, match="cannot be reached at " + url):
        call("a", 1)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://127.0.0.1/x", "127.0.0.1:80"])
def test_call_refuses_other_schemes(monkeypatch, url):
    """A URL whose scheme is not http or https is a stage error."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", url)
    with pytest.raises(StageError, match="not an http or https URL"):
        call("a", 1)


def test_call_answer_too_large(server, monkeypatch):
    """A 2xx answer over the size bound is a stage error."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url)
    server.reply = (200, b" " * (MAX_ANSWER_BYTES + 1))
    with pytest.raises(StageError, match=f"larger than {MAX_ANSWER_BYTES} bytes"):
        call("a", 1)


def test_call_does_not_follow_redirect(server, monkeypatch):
    """A redirect is an error answer: the call never leaves its local URL."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url)
    reply(server, 302, {"output": 1})
    with pytest.raises(StageError, match="status 302"):
        call("a", 1)
    assert len(server.requests) == 1


def test_call_ignores_proxy_variables(server, monkeypatch):
    """A proxy in the environment does not get the local helper call."""
    proxy, thread = start_server()
    try:
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "all_proxy"):
            monkeypatch.setenv(name, proxy.url)
        monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url + "/a")
        reply(server, 200, {"output": "direct"})
        reply(proxy, 200, {"output": "proxy"})
        assert call("a", 1) == "direct"
        assert proxy.requests == []
        assert server.requests[0]["path"] == "/a"
    finally:
        stop_server(proxy, thread)


def test_call_ignores_proxy_variables_at_import(server):
    """A proxy in the environment at import time does not get the call either."""
    proxy, thread = start_server()
    try:
        env = {name: proxy.url for name in ("http_proxy", "HTTP_PROXY", "all_proxy")}
        env["ASCENT_STAGE_A_URL"] = server.url
        reply(server, 200, {"output": "direct"})
        reply(proxy, 200, {"output": "proxy"})
        code = "from openascent import call; print(call('a', 1))"
        done = subprocess.run(
            [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
        )
        assert done.stdout.strip() == "direct"
        assert proxy.requests == []
    finally:
        stop_server(proxy, thread)


@pytest.mark.parametrize(
    ("stage", "value"),
    [("", 1), (None, 1), (3, 1), ("a", float("nan")), ("a", {1: "x"}), ("a", {1}), ("a", "\ud800")],
)
def test_call_bad_arguments(server, monkeypatch, stage, value):
    """A bad stage name or an input that is not strict JSON fails before any request."""
    monkeypatch.setenv("ASCENT_STAGE_A_URL", server.url)
    with pytest.raises(ValueError):
        call(stage, value)
    assert server.requests == []


def test_stage_error_is_helper_error():
    """A stage error is a helper error, so one except clause can catch both."""
    assert issubclass(StageError, HelperError)


def model_env(monkeypatch, server, key=None):
    """Set the model variables to the recording server.

    Args:
        monkeypatch: The pytest fixture.
        server: The recording server.
        key: The value of ``ASCENT_MODEL_KEY``, or ``None`` to leave it absent.
    """
    monkeypatch.setenv("ASCENT_MODEL_URL", server.url + "/v1/")
    monkeypatch.setenv("ASCENT_MODEL", "judge-1")
    if key is not None:
        monkeypatch.setenv("ASCENT_MODEL_KEY", key)
    reply(server, 200, {"choices": [{"message": {"role": "assistant", "content": "0.8"}}]})


def test_llm_prompt_only(server, monkeypatch):
    """With no input, the prompt is the user message of an OpenAI chat request."""
    model_env(monkeypatch, server)
    assert llm("Rate this.") == "0.8"
    (request,) = server.requests
    assert request["path"] == "/v1/chat/completions"
    assert request["headers"]["Content-Type"] == "application/json"
    assert json.loads(request["body"]) == {
        "model": "judge-1",
        "messages": [{"role": "user", "content": "Rate this."}],
    }


def test_llm_prompt_and_input(server, monkeypatch):
    """With an input, the prompt is the system message, and a non-string input is JSON text."""
    model_env(monkeypatch, server)
    llm("You judge.", "the text")
    llm("You judge.", {"a": [1, "é"]})
    first, second = (json.loads(r["body"])["messages"] for r in server.requests)
    assert first == [
        {"role": "system", "content": "You judge."},
        {"role": "user", "content": "the text"},
    ]
    assert second[1] == {"role": "user", "content": '{"a": [1, "é"]}'}


@pytest.mark.parametrize(
    ("key", "header"), [("sk-test", "Bearer sk-test"), ("", None), (None, None)]
)
def test_llm_authorization(server, monkeypatch, key, header):
    """The Authorization header goes only with a key that is not empty."""
    model_env(monkeypatch, server, key)
    llm("x")
    assert server.requests[0]["headers"].get("Authorization") == header


@pytest.mark.parametrize(
    # os.environ refuses a null byte, so other control characters stand for it.
    "key",
    ["sk-test\n", "sk-test\r\n", "sk test", "sk-test\t", "sk-tést", "sk-\x01test", "sk-test\x7f"],
)
def test_llm_bad_key(server, monkeypatch, key):
    """A key with a character outside visible ASCII fails before any request, and hides the key."""
    model_env(monkeypatch, server, key)
    with pytest.raises(HelperError, match="ASCENT_MODEL_KEY") as caught:
        llm("x")
    assert "sk-" not in str(caught.value)
    assert server.requests == []


def test_llm_images(server, monkeypatch, tmp_path):
    """URL strings go as is; files and bytes go as base64 data URLs with their media type."""
    model_env(monkeypatch, server)
    path = tmp_path / "shot.png"
    path.write_bytes(PNG)
    images = ["https://example.com/a.png", "data:image/png;base64,AAAA", path, JPEG, GIF, WEBP]
    llm("Look.", images=images)
    (message,) = json.loads(server.requests[0]["body"])["messages"]
    assert message["role"] == "user"
    text, *parts = message["content"]
    assert text == {"type": "text", "text": "Look."}
    assert all(part["type"] == "image_url" for part in parts)
    urls = [part["image_url"]["url"] for part in parts]
    assert urls == [
        "https://example.com/a.png",
        "data:image/png;base64,AAAA",
        data_url("image/png", PNG),
        data_url("image/jpeg", JPEG),
        data_url("image/gif", GIF),
        data_url("image/webp", WEBP),
    ]


def test_llm_bad_images(server, monkeypatch, tmp_path):
    """Each image item in no valid form fails before any request."""
    model_env(monkeypatch, server)
    text_file = tmp_path / "notes.txt"
    text_file.write_text("hi")
    bad = ["shot.png", "ftp://x/a.png", text_file, tmp_path / "missing.png", b"hello", 3, None]
    for item in bad:
        with pytest.raises(ValueError):
            llm("Look.", images=[item])
    with pytest.raises(ValueError, match="list"):
        llm("Look.", images=PNG)
    assert server.requests == []


def test_llm_file_type_from_bytes(server, monkeypatch, tmp_path):
    """The type of a file image comes from its bytes, not from its name."""
    model_env(monkeypatch, server)
    webp = tmp_path / "shot.webp"
    webp.write_bytes(WEBP)
    png = tmp_path / "picture.bin"
    png.write_bytes(PNG)
    llm("Look.", images=[webp, png])
    (message,) = json.loads(server.requests[0]["body"])["messages"]
    urls = [part["image_url"]["url"] for part in message["content"][1:]]
    assert urls == [data_url("image/webp", WEBP), data_url("image/png", PNG)]


@pytest.mark.parametrize("name", ["x.svg", "x.png"])
def test_llm_file_not_image(server, monkeypatch, tmp_path, name):
    """A file whose bytes are not a PNG, JPEG, GIF or WebP image fails before any request."""
    model_env(monkeypatch, server)
    path = tmp_path / name
    path.write_bytes(b"not an image at all")
    with pytest.raises(ValueError) as caught:
        llm("Look.", images=[path])
    assert str(path) in str(caught.value)
    assert "PNG, JPEG, GIF or WebP" in str(caught.value)
    assert server.requests == []


@pytest.mark.parametrize(("prompt", "value"), [("", None), (None, None), (1, None), ("x", {1})])
def test_llm_bad_arguments(server, monkeypatch, prompt, value):
    """A prompt that is not a non-empty string, or a bad input, fails before any request."""
    model_env(monkeypatch, server)
    with pytest.raises(ValueError):
        llm(prompt, value)
    assert server.requests == []


@pytest.mark.parametrize("absent", ["ASCENT_MODEL_URL", "ASCENT_MODEL"])
@pytest.mark.parametrize("empty", [True, False])
def test_llm_no_model(server, monkeypatch, absent, empty):
    """An absent or empty model variable says that the contract gives no judge model."""
    model_env(monkeypatch, server)
    if empty:
        monkeypatch.setenv(absent, "")
    else:
        monkeypatch.delenv(absent)
    with pytest.raises(HelperError, match="no judge model"):
        llm("x")
    assert server.requests == []


def test_llm_error_answer(server, monkeypatch):
    """An error answer gives a helper error with the error text and the status code."""
    model_env(monkeypatch, server)
    reply(server, 429, {"error": "Too many requests."})
    with pytest.raises(HelperError, match=r"status 429: Too many requests\."):
        llm("x")


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"choices": []},
        {"choices": [{}]},
        {"choices": [{"message": {"content": None}}]},
        {"choices": [{"message": {"content": [{"type": "text", "text": "x"}]}}]},
        [1],
    ],
)
def test_llm_answer_no_text(server, monkeypatch, value):
    """A 2xx answer with no text at choices[0].message.content is a helper error."""
    model_env(monkeypatch, server)
    reply(server, 200, value)
    with pytest.raises(HelperError, match=r"no text at choices\[0\]\.message\.content"):
        llm("x")


def test_llm_connection_refused(monkeypatch):
    """A closed port is a helper error."""
    monkeypatch.setenv("ASCENT_MODEL_URL", closed_port_url())
    monkeypatch.setenv("ASCENT_MODEL", "judge-1")
    with pytest.raises(HelperError, match="cannot be reached"):
        llm("x")


def test_log_success(server, monkeypatch):
    """A log call posts one event with its fields, and any 2xx body is fine."""
    monkeypatch.setenv("ASCENT_LOG_URL", server.url + "/log")
    server.reply = (204, b"")
    assert log("judge_done", score=0.5, notes=["é"], ok=True) is None
    (request,) = server.requests
    assert request["path"] == "/log"
    assert request["headers"]["Content-Type"] == "application/json"
    assert json.loads(request["body"]) == {
        "event": "judge_done",
        "fields": {"score": 0.5, "notes": ["é"], "ok": True},
    }


def test_log_no_fields(server, monkeypatch):
    """A log call with no fields sends an empty fields object."""
    monkeypatch.setenv("ASCENT_LOG_URL", server.url)
    server.reply = (200, b"not json")
    log("start")
    assert json.loads(server.requests[0]["body"]) == {"event": "start", "fields": {}}


def test_log_field_named_event(server, monkeypatch):
    """A field can have the name event: the event name is positional only."""
    monkeypatch.setenv("ASCENT_LOG_URL", server.url)
    server.reply = (204, b"")
    log("case_done", event="x", fields=1)
    assert json.loads(server.requests[0]["body"]) == {
        "event": "case_done",
        "fields": {"event": "x", "fields": 1},
    }


@pytest.mark.parametrize("value", [None, ""])
def test_log_absent(monkeypatch, value):
    """An absent or empty log variable is a helper error."""
    if value is not None:
        monkeypatch.setenv("ASCENT_LOG_URL", value)
    with pytest.raises(HelperError, match="ASCENT_LOG_URL is absent or empty"):
        log("x")


def test_log_error_answer(server, monkeypatch):
    """An error answer gives a helper error with the error text and the status code."""
    monkeypatch.setenv("ASCENT_LOG_URL", server.url)
    reply(server, 400, {"error": "The event is too large."})
    with pytest.raises(HelperError, match=r"status 400: The event is too large\."):
        log("x")


def test_log_connection_refused(monkeypatch):
    """A closed port is a helper error."""
    monkeypatch.setenv("ASCENT_LOG_URL", closed_port_url())
    with pytest.raises(HelperError, match="cannot be reached"):
        log("x")


@pytest.mark.parametrize(
    ("event", "fields"),
    [("", {}), (None, {}), ("x", {"v": float("inf")}), ("x", {"v": object()})],
)
def test_log_bad_arguments(server, monkeypatch, event, fields):
    """A bad event name or fields that are not strict JSON fail before any request."""
    monkeypatch.setenv("ASCENT_LOG_URL", server.url)
    with pytest.raises(ValueError):
        log(event, **fields)
    assert server.requests == []
