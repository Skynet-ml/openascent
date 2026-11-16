"""An exact-match metric in Python, in the function form.

The score is 1.0 when the output is a string equal to the expected answer,
and 0.0 with feedback when it is not. The runner calls ``score`` with the
fields of the input object that the function names, and writes the returned
object as the result. Try it from this folder:

    ascent score --entry metric.py:score --input ../case.json
"""

FEEDBACK = "The output does not match the expected answer."


def score(output, expected=None):
    """Score one case by exact match.

    Args:
        output: The candidate's output value.
        expected: The expected answer. ``None`` when the case has none.

    Returns:
        The metric answer object.
    """
    if isinstance(output, str) and output == expected:
        return {"score": 1.0}
    return {"score": 0.0, "feedback": FEEDBACK}
