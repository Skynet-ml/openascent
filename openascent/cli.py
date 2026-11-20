"""The ``ascent`` command.

``ascent score --entry <entry> --input <file> [--timeout <seconds>]`` runs one
metric call in the current directory and prints the checked answer as JSON.

``ascent check <file>`` checks an ``ascent.toml`` contract and prints the
report as JSON: ``ok``, and for an invalid file the error with its section and
key. It checks the file alone; the runner checks the files that it names.

``ascent check --image --role <candidate|metric>`` checks that the current box
can run components of that role and prints the report as JSON.

``ascent schema`` prints the JSON Schema of ``ascent.toml``.
"""

import argparse
import json
import math
import shlex
import sys
from pathlib import Path

from .component import FunctionEntry, call_metric, parse_entry
from .contract import ConstraintsError, parse_constraints
from .image_check import ROLES, check_image
from .result import AscentError
from .schema import schema_text

DEFAULT_TIMEOUT_S = 60.0


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
        elif args.file is None:
            check.error("give an ascent.toml file, or --image --role <role>")
        elif args.role is not None:
            check.error("--role needs --image")
        else:
            report = _check_file(check, args.file)
        print(json.dumps(report))
        return 0 if report["ok"] else 1
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


def _check_file(check: argparse.ArgumentParser, path: str) -> dict[str, object]:
    """Check one ``ascent.toml`` file with the full parser.

    Args:
        check: The ``check`` parser, which reports an unreadable file.
        path: The path of the file.

    Returns:
        The report: ``ok``, the file and, when the file is invalid, the error
        with its section and key (``null`` when the error has none).
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        check.error(f"cannot read {path}: {error}")
    try:
        parse_constraints(raw)
    except ConstraintsError as error:
        return {
            "ok": False,
            "file": path,
            "error": str(error),
            "section": error.section,
            "key": error.key,
        }
    return {"ok": True, "file": path}


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
