"""Tests of the result forms and the strict JSON loader."""

import pytest

from openascent.result import (
    InvalidFormError,
    InvalidJsonError,
    MetricResult,
    NamedScore,
    check_metric_result,
    check_run_output,
    load_json,
)

VALID_METRIC = [
    ('{"score": 0.78}', MetricResult(0.78)),
    ('{"score": 1}', MetricResult(1.0)),
    ('{"score": -2.5, "feedback": "Too slow."}', MetricResult(-2.5, "Too slow.")),
    (
        '{"score": 0.78, "feedback": "Misses short names.", "scores": {'
        '"precision": {"score": 0.90}, '
        '"recall": {"score": 0.69, "feedback": "Misses names under 4 letters."}}}',
        MetricResult(
            0.78,
            "Misses short names.",
            {
                "precision": NamedScore(0.9),
                "recall": NamedScore(0.69, "Misses names under 4 letters."),
            },
        ),
    ),
    ('{"score": 0, "scores": {}}', MetricResult(0.0)),
]

# Each case: the output file text, the error type, and the problems the error must list.
INVALID_METRIC = [
    ("0.78", InvalidFormError, ["top level: must be an object, got a number"]),
    ("[0.78, 0.5]", InvalidFormError, ["top level: must be an object, got an array"]),
    ("null", InvalidFormError, ["top level: must be an object, got null"]),
    ("{}", InvalidFormError, ["score: missing; a result needs a finite number here"]),
    ('{"score": true}', InvalidFormError, ["score: must be a finite number, got a boolean"]),
    ('{"score": "0.5"}', InvalidFormError, ["score: must be a finite number, got a string"]),
    ('{"score": null}', InvalidFormError, ["score: must be a finite number, got null"]),
    ('{"score": 1, "extra": 2}', InvalidFormError, ["extra: unknown key"]),
    ('{"score": 1, "feedback": 3}', InvalidFormError, ["feedback: must be a string, got a number"]),
    ('{"score": 1, "feedback": null}', InvalidFormError, ["feedback: must be a string, got null"]),
    ('{"score": 1, "scores": [1]}', InvalidFormError, ["scores: must be an object, got an array"]),
    ('{"score": 1, "scores": null}', InvalidFormError, ["scores: must be an object, got null"]),
    (
        '{"score": 1, "scores": {"recall": 0.5}}',
        InvalidFormError,
        ['scores.recall: must be an object like {"score": 0.5}, got a number'],
    ),
    (
        '{"score": 1, "scores": {"recall": {"score": 0.5, "weight": 2}}}',
        InvalidFormError,
        ["scores.recall.weight: unknown key"],
    ),
    (
        '{"score": 1, "scores": {"recall": {"feedback": "x"}}}',
        InvalidFormError,
        ["scores.recall.score: missing; a result needs a finite number here"],
    ),
    (
        '{"score": 1, "scores": {"recall": {"score": 1, "scores": {}}}}',
        InvalidFormError,
        ["scores.recall.scores: unknown key"],
    ),
    ('{"score": 1' + "0" * 400 + "}", InvalidFormError, ["score: the number is too large"]),
    ('{"score": NaN}', InvalidJsonError, []),
    ('{"score": Infinity}', InvalidJsonError, []),
    ('{"score": -Infinity}', InvalidJsonError, []),
    ('{"score": 1e400}', InvalidJsonError, []),
    ('{"score": 1, "score": 2}', InvalidJsonError, []),
    ('{"score": 1, "scores": {"a": {"score": 1}, "a": {"score": 2}}}', InvalidJsonError, []),
    ('{"score": 1, "feedback": "\\udc00"}', InvalidJsonError, []),
    ('{"score": 1, "scores": {"\\ud800": {"score": 1}}}', InvalidJsonError, []),
    ('{"score": 1', InvalidJsonError, []),
    ("", InvalidJsonError, []),
    (
        '{"score": "high", "feedback": false, "scores": {"a": 1, "b": {"score": NaN}}}',
        InvalidJsonError,
        [],
    ),
    (
        '{"score": "high", "feedback": false, "extra": 1, '
        '"scores": {"a": 1, "b": {"score": true, "note": "x"}}}',
        InvalidFormError,
        [
            "score: must be a finite number, got a string",
            "feedback: must be a string, got a boolean",
            'scores.a: must be an object like {"score": 0.5}, got a number',
            "scores.b.score: must be a finite number, got a boolean",
            "scores.b.note: unknown key",
            "extra: unknown key",
        ],
    ),
]

VALID_RUN = [
    ('{"output": "Paris"}', "Paris"),
    ('{"output": null}', None),
    ('{"output": {"a": [1, 2.5, true]}}', {"a": [1, 2.5, True]}),
    ('{"output": "\\ud83d\\ude00"}', "\U0001f600"),
]

INVALID_RUN = [
    ('"Paris"', InvalidFormError, ["top level: must be an object, got a string"]),
    ("{}", InvalidFormError, ["output: missing"]),
    ('{"result": 1}', InvalidFormError, ["output: missing", "result: unknown key"]),
    ('{"output": 1, "log": "x"}', InvalidFormError, ["log: unknown key"]),
    ('{"output": 1, "output": 2}', InvalidJsonError, []),
    ('{"output": NaN}', InvalidJsonError, []),
    ('{"output": "\\ud800"}', InvalidJsonError, []),
    ('{"output": ["ok", {"\\udc00": 1}]}', InvalidJsonError, []),
]


@pytest.mark.parametrize(("text", "expected"), VALID_METRIC)
def test_valid_metric_result(text, expected):
    """A valid metric answer object gives the checked result."""
    assert check_metric_result(load_json(text.encode())) == expected


@pytest.mark.parametrize(("text", "error", "problems"), INVALID_METRIC)
def test_invalid_metric_result(text, error, problems):
    """Each invalid form gives its error type and lists every problem."""
    with pytest.raises(error) as caught:
        check_metric_result(load_json(text.encode()))
    if error is InvalidFormError:
        assert len(caught.value.problems) == len(problems)
        for found, wanted in zip(caught.value.problems, problems, strict=True):
            assert found.startswith(wanted)
        assert "The valid form is:" in str(caught.value)


@pytest.mark.parametrize(("text", "expected"), VALID_RUN)
def test_valid_run_output(text, expected):
    """A valid run output gives the output value, also null."""
    assert check_run_output(load_json(text.encode())) == expected


@pytest.mark.parametrize(("text", "error", "problems"), INVALID_RUN)
def test_invalid_run_output(text, error, problems):
    """Each invalid run output gives its error type and lists every problem."""
    with pytest.raises(error) as caught:
        check_run_output(load_json(text.encode()))
    if error is InvalidFormError:
        assert list(caught.value.problems) == problems
        assert '{"output": <any JSON value>}' in str(caught.value)


def test_not_utf8_is_invalid_json():
    """Bytes that are not UTF-8 are invalid JSON."""
    with pytest.raises(InvalidJsonError, match="not UTF-8"):
        load_json(b'{"output": "\xff"}')


def test_python_object_with_nan_is_refused():
    """A Python float NaN or infinity is not a finite score."""
    with pytest.raises(InvalidFormError):
        check_metric_result({"score": float("nan")})
    with pytest.raises(InvalidFormError):
        check_metric_result({"score": 1, "scores": {"a": {"score": float("inf")}}})


def test_to_dict_omits_absent_keys():
    """The JSON form of a result has only the keys that hold a value."""
    result = MetricResult(0.5, None, {"a": NamedScore(1.0), "b": NamedScore(0.0, "No.")})
    assert result.to_dict() == {
        "score": 0.5,
        "scores": {"a": {"score": 1.0}, "b": {"score": 0.0, "feedback": "No."}},
    }


# The codes for a large number, pinned: the loader refuses a float
# literal that overflows and an integer past Python's digit limit; the metric
# form refuses a large integer score; a run output keeps a large integer.
LARGE_NUMBERS = [
    (b'{"score": 1e400}', check_metric_result, InvalidJsonError),
    (b'{"score": 1' + b"0" * 5000 + b"}", check_metric_result, InvalidJsonError),
    (b'{"score": 1' + b"0" * 400 + b"}", check_metric_result, InvalidFormError),
    (b'{"output": 1' + b"0" * 400 + b"}", check_run_output, None),
]


@pytest.mark.parametrize(("data", "check", "error"), LARGE_NUMBERS)
def test_large_numbers(data, check, error):
    """Each kind of large number gives its pinned result."""
    if error is None:
        assert check(load_json(data)) == 10**400
    else:
        with pytest.raises(error):
            check(load_json(data))
