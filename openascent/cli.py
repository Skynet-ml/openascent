"""The ``ascent`` command.

``ascent score --entry <entry> --input <file> [--timeout <seconds>]`` runs one
metric call in the current directory and prints the checked answer as JSON.

``ascent check <file>`` checks an ``ascent.toml`` contract and prints one line
for each problem: ``file:line``, the section and key, the level (``error`` or
``warning``) and the message. A last line counts them, such as ``2 errors, 1
warning``. It exits 1 when there is an error, and 0 with only warnings. It
checks the file alone; the runner checks the files that it names.

``ascent check --image --role <candidate|metric>`` checks that the current box
can run components of that role and prints the report as JSON.

``ascent schema`` prints the JSON Schema of ``ascent.toml``.
"""

import argparse
import json
import math
import re
import shlex
import sys
from pathlib import Path

from .component import FunctionEntry, call_metric, parse_entry
from .contract import (
    CONSTRAINTS_FILE,
    ERROR,
    WARNING,
    ConstraintsError,
    Diagnostic,
    parse_constraints,
)
from .image_check import ROLES, check_image
from .result import AscentError
from .schema import schema_text

DEFAULT_TIMEOUT_S = 60.0

# C0 and C1 controls, DEL, the bidi marks, embeddings, overrides and isolates,
# and the line and paragraph separators.
_UNSAFE_CHARS = re.compile(
    "[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
)


def main(argv: list[str] | None = None) -> int:
    """Run the ``ascent`` command.

    Args:
        argv: The arguments without the program name. ``None`` reads ``sys.argv``.

    Returns:
        The exit code: 0 on success, 1 when the call or a check fails. A
        usage error exits with 2.
    """
    parser = argparse.ArgumentParser(prog="ascent", description="Run OpenAscent components.")
    commands = parser.add_subparsers(dest="command", required=True)
    score = commands.add_parser(
        "score", help="Run one metric call and print the checked answer as JSON."
    )
    score.add_argument(
        "--entry",
        required=True,
        help='"path/file.py:function", or a command such as "./metric.sh" or "node metric.mjs".',
    )
    score.add_argument("--input", required=True, help="A JSON file with the metric input object.")
    score.add_argument(
        "--timeout",
        type=_timeout,
        default=DEFAULT_TIMEOUT_S,
        help=f"The time limit in seconds (default {DEFAULT_TIMEOUT_S:g}).",
    )
    check = commands.add_parser(
        "check", help="Check an ascent.toml file, or with --image the current box."
    )
    check.add_argument("file", nargs="?", help="The ascent.toml file to check.")
    check.add_argument("--image", action="store_true", help="Check the current box, not a file.")
    check.add_argument("--role", choices=ROLES, help="The role of the box (with --image).")
    commands.add_parser("schema", help="Print the JSON Schema of ascent.toml.")
    args = parser.parse_args(argv)
    if args.command == "schema":
        sys.stdout.write(schema_text())
        return 0
    if args.command == "check":
        if args.image:
            if args.file is not None:
                check.error("--image checks the current box and takes no file")
            if args.role is None:
                check.error("--image needs --role candidate or --role metric")
            report = check_image(args.role)
            print(json.dumps(report))
            return 0 if report["ok"] else 1
        if args.file is None:
            check.error("give an ascent.toml file, or --image --role <role>")
        if args.role is not None:
            check.error("--role needs --image")
        diagnostics = _check_file(check, args.file)
        for diagnostic in diagnostics:
            print(_diagnostic_line(args.file, diagnostic))
        errors = sum(diagnostic.level == ERROR for diagnostic in diagnostics)
        warnings = len(diagnostics) - errors
        print(f"{_count(errors, ERROR)}, {_count(warnings, WARNING)}")
        return 1 if errors else 0
    try:
        entry = _entry(args.entry)
    except ValueError as error:
        score.error(str(error))
    try:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    # A very deep nesting makes json.loads raise RecursionError, not ValueError.
    except (OSError, ValueError, RecursionError) as error:
        score.error(f"cannot read the input file {args.input}: {error}")
    try:
        call = call_metric(entry, payload, timeout_s=args.timeout)
    except ValueError as error:
        score.error(str(error))
    except AscentError as error:
        sys.stderr.write(error.stderr)
        print(f"ascent: {error.code}: {error}", file=sys.stderr)
        return 1
    sys.stderr.write(call.stderr)
    print(json.dumps(call.result.to_dict()))
    return 0


def _check_file(check: argparse.ArgumentParser, path: str) -> list[Diagnostic]:
    """Check one ``ascent.toml`` file with the full parser.

    Args:
        check: The ``check`` parser, which reports an unreadable file.
        path: The path of the file.

    Returns:
        Every error and warning of the file, in the parser's order.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        check.error(f"cannot read {path}: {error}")
    try:
        return list(parse_constraints(raw).warnings)
    except ConstraintsError as error:
        return list(error.errors)


def _diagnostic_line(path: str, diagnostic: Diagnostic) -> str:
    """Write one problem as ``file:line: [section] key: level: message``.

    Args:
        path: The checked file, as the command got it.
        diagnostic: The problem.

    Returns:
        The line, with each control character escaped. The line number,
        section and key are left out when the problem has none.
    """
    place = path if diagnostic.line is None else f"{path}:{diagnostic.line}"
    setting = " ".join(
        part for part in (diagnostic.section and f"[{diagnostic.section}]", diagnostic.key) if part
    )
    # The place is already at the start of the line, so the message does not repeat the file.
    message = diagnostic.message.removeprefix(f"{CONSTRAINTS_FILE}: ")
    line = ": ".join(part for part in (place, setting, diagnostic.level, message) if part)
    # Keys and quoted values come from the file, so a control character could
    # move the cursor or reorder the text in a terminal or a CI log.
    return _UNSAFE_CHARS.sub(_escape, line)


def _escape(match: re.Match[str]) -> str:
    """Write one unsafe character as a visible escape, such as ``\\x1b`` or ``\\u202e``.

    Args:
        match: The match of one character.

    Returns:
        The escape.
    """
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def _count(number: int, level: str) -> str:
    """Write a count of one level, such as ``1 error`` or ``2 warnings``.

    Args:
        number: How many problems have the level.
        level: ``error`` or ``warning``.

    Returns:
        The count with the level in the singular or the plural.
    """
    return f"{number} {level}" + ("" if number == 1 else "s")


def _timeout(text: str) -> float:
    """Read the ``--timeout`` value: a finite number of seconds greater than 0.

    Args:
        text: The value of ``--timeout``.

    Returns:
        The time limit in seconds.

    Raises:
        argparse.ArgumentTypeError: The value is not a finite number greater than 0.
    """
    try:
        seconds = float(text)
    except ValueError:
        seconds = math.nan
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not valid; give a finite number of seconds greater than 0"
        )
    return seconds


def _entry(text: str) -> FunctionEntry | tuple[str, ...]:
    """Read the ``--entry`` string as a function entry or as a command.

    The string is split like a shell line in both forms, so a path with a
    space needs inner quotes.

    Args:
        text: The value of ``--entry``.

    Returns:
        The normalized entry.

    Raises:
        ValueError: The value is empty or cannot be split.
    """
    words = shlex.split(text)
    if len(words) == 1:
        try:
            return parse_entry(words[0])
        except ValueError:
            pass
    return parse_entry(words)


if __name__ == "__main__":
    sys.exit(main())
