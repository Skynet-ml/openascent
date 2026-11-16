"""Check the result of a component call, and define the error types.

This module uses only the standard library and imports nothing from the rest
of the package. A product can copy it into a sandbox without an install.
"""

import json
import math
from dataclasses import dataclass, field

RUN_FORM = '{"output": <any JSON value>}'
METRIC_FORM = (
    '{"score": <finite number>, "feedback": <string, optional>, '
    '"scores": <optional object of {"score": <finite number>, '
    '"feedback": <string, optional>}>}'
)
NO_OUTPUT_MESSAGE = (
    "The command wrote no output file. Write the result as JSON to the path in ASCENT_OUTPUT."
)

_METRIC_KEYS = ("score", "feedback", "scores")
_NAMED_SCORE_KEYS = ("score", "feedback")


class AscentError(Exception):
    """Base class of every failure of a component call.

    Attributes:
        code: A stable short name of the cause.
        stderr: The bounded tail of the command's stderr, or "" when no
            command ran.
    """

    code = "ascent_error"

    def __init__(self, message: str, *, stderr: str = "") -> None:
        """Create the error.

        Args:
            message: The cause and the fix, in plain words.
            stderr: The bounded tail of the command's stderr.
        """
        super().__init__(message)
        self.stderr = stderr


class StartError(AscentError):
    """The command cannot start: it is not found or not executable, the function file
    does not exist, or the working directory or the environment is not valid.
    """

    code = "start_failed"


class TimeLimitError(AscentError):
    """The command ran longer than the time limit."""

    code = "time_limit"


class ExitCodeError(AscentError):
    """The command exited with a code that is not 0.

    Attributes:
        exit_code: The exit code. A negative code is the signal that stopped
            the command.
    """

    code = "nonzero_exit"

    def __init__(self, message: str, *, exit_code: int, stderr: str = "") -> None:
        """Create the error.

        Args:
            message: The cause and the fix, in plain words.
            exit_code: The exit code of the command.
            stderr: The bounded tail of the command's stderr.
        """
        super().__init__(message, stderr=stderr)
        self.exit_code = exit_code


class NoOutputError(AscentError):
    """The command exited 0 but wrote no output file."""

    code = "no_output"


class OutputFileError(AscentError):
    """The output path is a link or a hard link, not a regular file, unreadable, or too large."""

    code = "bad_output_file"


class InvalidJsonError(AscentError):
    """The output file is not strict UTF-8 JSON."""

    code = "invalid_json"


class InvalidFormError(AscentError):
    """The output file is valid JSON but not in the valid form.

    Attributes:
        problems: Every mistake found, each one starting with its key path.
    """

    code = "invalid_form"

    def __init__(self, what: str, problems: list[str], form: str) -> None:
        """Create the error from a list of problems.

        Args:
            what: The name of the checked object, for example "metric result".
            problems: Every mistake found.
            form: The valid form, as text.
        """
        lines = "\n".join(f"- {problem}" for problem in problems)
        super().__init__(
            f"The {what} is not in the valid form:\n{lines}\nThe valid form is: {form}"
        )
        self.problems = tuple(problems)


@dataclass(frozen=True)
class NamedScore:
    """One named part of a metric result."""

    score: float
    feedback: str | None = None


@dataclass(frozen=True)
class MetricResult:
    """A checked metric result. Only ``score`` ranks versions."""

    score: float
    feedback: str | None = None
    scores: dict[str, NamedScore] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return the result in its JSON form, without the absent keys.

        Returns:
            The metric answer object.
        """
        answer: dict = {"score": self.score}
        if self.feedback is not None:
            answer["feedback"] = self.feedback
        if self.scores:
            answer["scores"] = {name: _part_dict(part) for name, part in self.scores.items()}
        return answer


def _part_dict(part: NamedScore) -> dict:
    """Return a named score in its JSON form.

    Args:
        part: The named score.

    Returns:
        The named score object, without an absent feedback.
    """
    if part.feedback is None:
        return {"score": part.score}
    return {"score": part.score, "feedback": part.feedback}


def load_json(data: bytes) -> object:
    """Parse the bytes of an output file as strict JSON.

    Args:
        data: The content of the output file.

    Returns:
        The parsed JSON value.

    Raises:
        InvalidJsonError: The bytes are not UTF-8 or not JSON. Also: a NaN or
            Infinity token, a float literal that overflows (``1e400``), an
            integer longer than the digit limit of the interpreter (4300
            digits by default), a duplicate key, or a string or key with a
            lone surrogate escape (``"\\ud800"``).
            A large integer within the digit limit parses; the form check
            decides if it fits.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InvalidJsonError(
            f"The output file is not UTF-8 text (bad byte at offset {error.start}). "
            "Write the result as UTF-8 JSON."
        ) from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (ValueError, RecursionError) as error:
        raise InvalidJsonError(
            f"The output file is not valid JSON: {error}. Write one strict JSON "
            "value: UTF-8, no NaN or Infinity, no duplicate keys."
        ) from None
    if _has_lone_surrogate(value):
        raise InvalidJsonError(
            "The output file holds a string with a lone surrogate escape, for "
            'example "\\ud800". Write only valid Unicode text.'
        )
    return value


def _has_lone_surrogate(value: object) -> bool:
    """Tell if a parsed JSON value holds a string or key with a lone surrogate.

    A walk with a list, not recursion, so a deep value cannot overflow the stack.

    Args:
        value: The parsed JSON value.

    Returns:
        True when a string cannot be encoded as UTF-8.
    """
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if not item.isascii():
                try:
                    item.encode("utf-8")
                except UnicodeEncodeError:
                    return True
        elif isinstance(item, dict):
            pending.extend(item)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    """Build a JSON object and refuse a duplicate key.

    Args:
        pairs: The key and value pairs of the object, in file order.

    Returns:
        The object.

    Raises:
        ValueError: A key occurs more than once.
    """
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"the key {key!r} occurs more than once in one object")
        obj[key] = value
    return obj


def _reject_constant(token: str) -> float:
    """Refuse the NaN, Infinity and -Infinity tokens.

    Args:
        token: The token.

    Raises:
        ValueError: Always.
    """
    raise ValueError(f"{token} is not a JSON number")


def _finite_float(text: str) -> float:
    """Parse a JSON number with a fraction or exponent, and refuse an overflow.

    Args:
        text: The number as written in the file.

    Returns:
        The number.

    Raises:
        ValueError: The number is too large for a float.
    """
    number = float(text)
    if math.isinf(number):
        raise ValueError(f"the number {text[:40]} is too large for a float")
    return number


def check_run_output(obj: object) -> object:
    """Check the run output form ``{"output": <any JSON value>}``.

    Args:
        obj: The parsed output file.

    Returns:
        The value of the ``output`` key. It can be ``None``.

    Raises:
        InvalidFormError: The object is not in the run output form.
    """
    if not isinstance(obj, dict):
        raise InvalidFormError(
            "run output", [f"top level: must be an object, got {_kind(obj)}"], RUN_FORM
        )
    problems = [f"{key}: unknown key" for key in obj if key != "output"]
    if "output" not in obj:
        problems.insert(0, "output: missing")
    if problems:
        raise InvalidFormError("run output", problems, RUN_FORM)
    return obj["output"]


def check_metric_result(obj: object) -> MetricResult:
    """Check the metric answer form, and report every mistake at once.

    Args:
        obj: The parsed output file.

    Returns:
        The checked metric result.

    Raises:
        InvalidFormError: The object is not in the metric answer form.
    """
    if not isinstance(obj, dict):
        raise InvalidFormError(
            "metric result",
            [f"top level: must be an object, got {_kind(obj)}"],
            METRIC_FORM,
        )
    problems: list[str] = []
    score = _score(obj, "", problems)
    feedback = _feedback(obj, "", problems)
    scores: dict[str, NamedScore] = {}
    if "scores" in obj:
        named = obj["scores"]
        if isinstance(named, dict):
            for name, part in named.items():
                checked = _named_score(part, f"scores.{name}", problems)
                if checked is not None:
                    scores[name] = checked
        else:
            problems.append(f"scores: must be an object, got {_kind(named)}")
    problems.extend(f"{key}: unknown key" for key in obj if key not in _METRIC_KEYS)
    if problems:
        raise InvalidFormError("metric result", problems, METRIC_FORM)
    return MetricResult(score=score, feedback=feedback, scores=scores)


def _named_score(part: object, path: str, problems: list[str]) -> NamedScore | None:
    """Check one named score.

    Args:
        part: The value of the named score.
        path: The key path of the named score, for example "scores.recall".
        problems: The list that collects every mistake.

    Returns:
        The named score, or ``None`` when it has a mistake.
    """
    if not isinstance(part, dict):
        problems.append(f'{path}: must be an object like {{"score": 0.5}}, got {_kind(part)}')
        return None
    before = len(problems)
    score = _score(part, path + ".", problems)
    feedback = _feedback(part, path + ".", problems)
    problems.extend(f"{path}.{key}: unknown key" for key in part if key not in _NAMED_SCORE_KEYS)
    if len(problems) > before:
        return None
    return NamedScore(score=score, feedback=feedback)


def _score(obj: dict, prefix: str, problems: list[str]) -> float:
    """Check the required ``score`` key of an object.

    Args:
        obj: The object that must hold the score.
        prefix: The key path of the object, with a trailing dot, or "".
        problems: The list that collects every mistake.

    Returns:
        The score as a float, or NaN when it has a mistake.
    """
    path = prefix + "score"
    if "score" not in obj:
        problems.append(f"{path}: missing; a result needs a finite number here")
        return math.nan
    value = obj["score"]
    if isinstance(value, bool) or not isinstance(value, int | float):
        problems.append(f"{path}: must be a finite number, got {_kind(value)}")
        return math.nan
    try:
        number = float(value)
    except OverflowError:
        problems.append(f"{path}: the number is too large for a float")
        return math.nan
    if not math.isfinite(number):
        problems.append(f"{path}: must be a finite number, got {number}")
    return number


def _feedback(obj: dict, prefix: str, problems: list[str]) -> str | None:
    """Check the optional ``feedback`` key of an object.

    Args:
        obj: The object that can hold the feedback.
        prefix: The key path of the object, with a trailing dot, or "".
        problems: The list that collects every mistake.

    Returns:
        The feedback, or ``None`` when it is absent or has a mistake.
    """
    if "feedback" not in obj:
        return None
    value = obj["feedback"]
    if not isinstance(value, str):
        problems.append(f"{prefix}feedback: must be a string, got {_kind(value)}")
        return None
    return value


def _kind(value: object) -> str:
    """Name the JSON type of a value, for an error message.

    Args:
        value: A parsed JSON value.

    Returns:
        The JSON type name, for example "a number" or "null".
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int | float):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return "an object"
