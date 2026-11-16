"""Call the helpers of a metric: stages, the judge model and the log.

The runner gives each helper to the metric as a local URL in an environment
variable. Each call is one HTTP POST with a JSON body and a JSON answer, so a
metric in any language can call a helper with no library. This module is the
thin Python form of those calls. It uses only the standard library.
"""

import base64
import os
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPException
from pathlib import Path

from .component import _input_bytes
from .result import InvalidJsonError, load_json

MAX_ANSWER_BYTES = 16 * 1024 * 1024
_IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


class HelperError(Exception):
    """A helper call failed."""


class StageError(HelperError):
    """A stage call failed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse each redirect, so that a helper call never leaves its local URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return no new request, so that the redirect answer is an error answer.

        Args:
            req: The request.
            fp: The answer body.
            code: The status code.
            msg: The status text.
            headers: The answer headers.
            newurl: The URL of the redirect.

        Returns:
            ``None``.
        """
        return None


# The helpers are local URLs: a proxy from the environment must not get them.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def call(stage: str, input: object = None) -> object:
    """Run one stage of the run on an input and return its output.

    The call has no time limit of its own. The time limit of the metric call
    bounds the wait.

    Args:
        stage: The name of a ``[target.<name>]`` stage in the contract.
        input: Any strict JSON value. The stage gets it as its input.

    Returns:
        The output of the stage.

    Raises:
        ValueError: The stage name is not a non-empty string, or the input is
            not strict JSON. No request is sent.
        StageError: The contract has no such stage, the runner gave an error
            answer, the answer is not valid, or the connection failed.
    """
    if not isinstance(stage, str) or not stage:
        raise ValueError("The stage name must be a non-empty string.")
    body = _input_bytes({"input": input})
    # Map each character on its own: str.upper() can turn one non-ASCII
    # character into ASCII letters ("ß" into "SS", "ı" into "I").
    name = "".join(char.upper() if char.isascii() and char.isalnum() else "_" for char in stage)
    variable = f"ASCENT_STAGE_{name}_URL"
    url = os.environ.get(variable)
    if not url:
        raise StageError(
            f"The variable {variable} for the stage {stage!r} is absent or empty. "
            f"The contract gives the metric no stage of this name. Add a [target.{stage}] stage."
        )
    what = f"The stage {stage!r}"
    answer = _load(_post(url, body, {}, StageError, what), StageError, what)
    if not isinstance(answer, dict) or "output" not in answer:
        raise StageError(f'{what} gave an answer that is not an object with the key "output".')
    return answer["output"]


def llm(prompt: str, input: object = None, images: list | None = None) -> str:
    """Ask the judge model once and return the text of its answer.

    The call has no time limit of its own. The time limit of the metric call
    bounds the wait.

    Args:
        prompt: The system message when ``input`` is given, else the user message.
        input: The user message. A value that is not a string goes as its JSON text.
        images: Images for the user message. Each item is a URL string that
            starts with ``http://``, ``https://`` or ``data:``, a ``Path`` of a
            PNG, JPEG, GIF or WebP file, or the ``bytes`` of such an image. The
            helper reads the type of a file from its bytes, not from its name.

    Returns:
        The text at ``choices[0].message.content`` of the answer.

    Raises:
        ValueError: The prompt is not a non-empty string, the input is not
            strict JSON, or an image is not valid. No request is sent.
        HelperError: The contract has no judge model, ``ASCENT_MODEL`` is
            not UTF-8 text or ``ASCENT_MODEL_KEY`` holds a character outside
            visible ASCII (no request is sent), the endpoint gave an error
            answer, the answer is not valid or has no text, or the connection
            failed.
    """
    if not isinstance(prompt, str) or not prompt:
        raise ValueError("The prompt must be a non-empty string.")
    if input is None:
        messages, text = [], prompt
    else:
        messages = [{"role": "system", "content": prompt}]
        text = input if isinstance(input, str) else _input_bytes(input).decode("utf-8")
    content = text
    if images is not None:
        if not isinstance(images, list):
            raise ValueError("The images must be a list.")
        content = [{"type": "text", "text": text}]
        content += [{"type": "image_url", "image_url": {"url": _image_url(i)}} for i in images]
    messages.append({"role": "user", "content": content})
    # The body check below runs after the variable checks. A bad string argument
    # must be a ValueError with or without a judge model, as in call and log.
    _input_bytes(messages)
    base = os.environ.get("ASCENT_MODEL_URL")
    model = os.environ.get("ASCENT_MODEL")
    if not base or not model:
        raise HelperError(
            "The variable ASCENT_MODEL_URL or ASCENT_MODEL is absent or empty. "
            "The contract gives the metric no judge model."
        )
    try:
        model.encode("utf-8")
    except UnicodeEncodeError:
        raise HelperError(
            "The variable ASCENT_MODEL holds a byte that is not UTF-8. "
            "Give the model name as UTF-8 text."
        ) from None
    key = os.environ.get("ASCENT_MODEL_KEY")
    # http.client puts a bad header value in its error text, so a check after
    # the request would show the key.
    if key and not all("!" <= char <= "~" for char in key):
        raise HelperError(
            "The variable ASCENT_MODEL_KEY holds a character outside visible ASCII, "
            "for example a line end or a space. Remove the character from the key."
        )
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    body = _input_bytes({"model": model, "messages": messages})
    what = "The model endpoint"
    url = base.rstrip("/") + "/chat/completions"
    answer = _load(_post(url, body, headers, HelperError, what), HelperError, what)
    try:
        result = answer["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        result = None
    if not isinstance(result, str):
        raise HelperError(f"{what} gave an answer with no text at choices[0].message.content.")
    return result


def log(event: str, /, **fields: object) -> None:
    """Send one log event to the runner.

    The call has no time limit of its own. The time limit of the metric call
    bounds the wait.

    Args:
        event: The name of the event.
        **fields: The fields of the event. Each value is strict JSON. A field
            can have any name, also ``event``.

    Raises:
        ValueError: The event name is not a non-empty string, or the fields
            are not strict JSON. No request is sent.
        HelperError: The contract gives the metric no log, the runner gave an
            error answer or an answer that is too large, or the connection
            failed.
    """
    if not isinstance(event, str) or not event:
        raise ValueError("The event name must be a non-empty string.")
    body = _input_bytes({"event": event, "fields": fields})
    url = os.environ.get("ASCENT_LOG_URL")
    if not url:
        raise HelperError(
            "The variable ASCENT_LOG_URL is absent or empty. The contract gives the metric no log."
        )
    _post(url, body, {}, HelperError, "The log endpoint")


def _image_url(image: object) -> str:
    """Turn one image item into the URL of an ``image_url`` part.

    Args:
        image: A URL string, a ``Path`` of a PNG, JPEG, GIF or WebP file, or
            the bytes of such an image. The type comes from the bytes.

    Returns:
        The URL as is, or a base64 data URL.

    Raises:
        ValueError: The item is not one of the three forms, the file cannot be
            read, or the bytes are not a PNG, JPEG, GIF or WebP image.
    """
    if isinstance(image, str):
        if image.startswith(("http://", "https://", "data:")):
            return image
        raise ValueError(
            "An image string must be a URL that starts with http://, https:// or data:. "
            "Give a file as a pathlib.Path."
        )
    if isinstance(image, Path):
        try:
            data = image.read_bytes()
        except OSError as error:
            raise ValueError(f"The image file {image} cannot be read ({error.strerror}).") from None
        media_type = _image_type(data)
        if not media_type:
            raise ValueError(f"The file {image} is not a PNG, JPEG, GIF or WebP image.")
    elif isinstance(image, bytes):
        data = image
        media_type = _image_type(data)
        if not media_type:
            raise ValueError("The image bytes are not a PNG, JPEG, GIF or WebP image.")
    else:
        raise ValueError(
            "An image must be a URL string, a pathlib.Path of an image file, or image bytes."
        )
    return f"data:{media_type};base64,{base64.b64encode(data).decode('ascii')}"


def _image_type(data: bytes) -> str:
    """Find the media type of image bytes from their signature.

    Args:
        data: The image bytes.

    Returns:
        The media type of a PNG, JPEG, GIF or WebP image, else an empty string.
    """
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return next((t for sig, t in _IMAGE_SIGNATURES if data.startswith(sig)), "")


def _post(
    url: str, body: bytes, headers: dict[str, str], error: type[HelperError], what: str
) -> bytes:
    """Send one JSON POST to a helper URL and return the body of a 2xx answer.

    Args:
        url: The helper URL.
        body: The UTF-8 JSON body.
        headers: The headers to add to ``Content-Type``.
        error: The error type of the helper.
        what: The subject of the error messages, for example "The log endpoint".

    Returns:
        The body of the answer, at most ``MAX_ANSWER_BYTES``.

    Raises:
        HelperError: The URL is not valid or not http or https, the answer
            is an error answer or too large, or the connection failed. The type
            is ``error``.
    """
    try:
        scheme = urllib.parse.urlsplit(url).scheme
    except ValueError:
        raise error(f"{what} has the URL {url!r}, which is not a valid URL.") from None
    if scheme not in ("http", "https"):
        raise error(f"{what} has the URL {url!r}, which is not an http or https URL.")
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json", **headers}
    )
    try:
        with _OPENER.open(request) as answer:
            data = answer.read(MAX_ANSWER_BYTES + 1)
    except urllib.error.HTTPError as answer:
        text = _error_text(answer)
        raise error(f"{what} gave an error answer with status {answer.code}: {text}") from None
    except (urllib.error.URLError, HTTPException, OSError, ValueError) as failure:
        raise error(f"{what} cannot be reached at {url}: {failure}") from None
    if len(data) > MAX_ANSWER_BYTES:
        raise error(f"{what} gave an answer larger than {MAX_ANSWER_BYTES} bytes.")
    return data


def _error_text(answer: urllib.error.HTTPError) -> str:
    """Read the text of an error answer.

    Args:
        answer: The error answer.

    Returns:
        The ``error`` text of the JSON body, or a fixed text when the body is
        not the error form.
    """
    try:
        data = answer.read(MAX_ANSWER_BYTES + 1)
        value = load_json(data) if len(data) <= MAX_ANSWER_BYTES else None
    except (InvalidJsonError, HTTPException, OSError, ValueError):
        value = None
    finally:
        answer.close()
    if isinstance(value, dict) and isinstance(value.get("error"), str):
        return value["error"]
    return 'the body is not a JSON object with an "error" text.'


def _load(data: bytes, error: type[HelperError], what: str) -> object:
    """Parse the body of a 2xx answer as strict JSON.

    Args:
        data: The body of the answer.
        error: The error type of the helper.
        what: The subject of the error message.

    Returns:
        The parsed JSON value.

    Raises:
        HelperError: The body is not strict JSON. The type is ``error``.
    """
    try:
        return load_json(data)
    except InvalidJsonError:
        raise error(f"{what} gave an answer that is not strict JSON.") from None
