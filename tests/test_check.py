"""Tests of ``ascent check <file>``, ``ascent schema`` and the committed ``ascent.schema.json``."""

import json
import re
import tomllib
import types
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from openascent import cli
from openascent.cli import main
from openascent.contract import (
    _SECTIONS,
    _TARGET_KEYS,
    ERROR,
    WARNING,
    ConstraintsError,
    Diagnostic,
    parse_constraints,
)
from openascent.schema import contract_schema, schema_text

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_FILE = ROOT / "ascent.schema.json"

# Every section and key that parse_constraints accepts on its own, with no repository files.
FULL = b"""
version = 1
instructions = "docs/intent.md"

[paths]
editable = ["src"]
protected = ["src/eval"]

[setup]
command = "pip install -r requirements.txt"

[proposer]
entry = ["node", "agent/run.js"]
setup = ["npm", "ci"]
network = ["api.example.com"]
illegal = "docs/rules.md"
mcp = "agent/.mcp.json"

[run]
entry = "run.py:main"
timeout = 30
vcpus = 2
network = []
services = ["maps"]

[target.planner]
entry = ["node", "planner.js"]
vcpus = 1
timeout = 10.5

[services.maps]
url = "https://maps.example.com"
headers = { Authorization = "Bearer ${MAPS_KEY}" }
query = { key = "${MAPS_KEY}" }

[metric]
files = ["eval"]
entry = "eval/metric.py:score"
direction = "minimize"
setup = "pip install -r eval/requirements.txt"
vcpus = 4
reference = "eval/reference"
exploits = "eval/exploits"

[metric.scores]
"rouge.l" = "maximize"
latency = "minimize"

[data]
cases = "eval/cases.jsonl"

[sandbox]
compose = "compose.yaml"

[outcome]
target = 0.9

[outcome.require]
latency = 2.5

[tool.mine]
anything = 1
"""


def _validator() -> Draft202012Validator:
    """Load the committed schema.

    Returns:
        A validator for ``ascent.toml`` read as TOML.
    """
    return Draft202012Validator(json.loads(SCHEMA_FILE.read_text(encoding="utf-8")))


def _write(tmp_path: Path, raw: bytes) -> str:
    """Write a contract file.

    Args:
        tmp_path: Scratch folder.
        raw: The bytes of the file.

    Returns:
        The path of the file.
    """
    path = tmp_path / "ascent.toml"
    path.write_bytes(raw)
    return str(path)


def test_the_committed_schema_is_the_output_of_ascent_schema(capsys):
    """``ascent schema`` prints exactly ``ascent.schema.json``.

    When this test fails, run ``ascent schema > ascent.schema.json`` and commit the file.
    """
    assert main(["schema"]) == 0
    assert capsys.readouterr().out == SCHEMA_FILE.read_text(encoding="utf-8") == schema_text()


def test_the_schema_is_a_valid_draft_2020_12_schema():
    """The schema itself passes the meta-schema."""
    Draft202012Validator.check_schema(contract_schema())


def test_the_schema_names_every_section_and_key_of_the_parser():
    """The schema and the parser accept the same sections and keys, so they cannot drift."""
    properties = contract_schema()["properties"]
    assert set(properties) == {*_SECTIONS, "target", "services", "version", "instructions", "tool"}
    for name, keys in _SECTIONS.items():
        assert set(properties[name]["properties"]) == keys
    named = {name: properties[name]["additionalProperties"] for name in ("target", "services")}
    assert set(named["target"]["properties"]) == _TARGET_KEYS
    assert set(named["services"]["properties"]) == {"url", "headers", "query"}


def test_a_contract_with_every_key_passes_the_parser_and_the_schema():
    """The full sample is valid for both checks."""
    parse_constraints(FULL)
    assert list(_validator().iter_errors(tomllib.loads(FULL.decode()))) == []


def test_a_unicode_function_name_passes_the_parser_and_the_schema():
    """The schema accepts every function name that ``str.isidentifier()`` accepts."""
    raw = 'version = 1\n[run]\nentry = "run.py:scoré"\n'.encode()

    assert parse_constraints(raw).run_entry == "run.py:scoré"
    assert list(_validator().iter_errors(tomllib.loads(raw.decode()))) == []


@pytest.mark.parametrize(
    "raw",
    [
        b'[run]\nentry = "run.py:main"\n',
        b'version = 1\n[run]\nentry = "run.py:main"\n[paths]\nhidden = ["x"]\n',
        b'version = 1\n[run]\nentry = "run.py:main"\n[extra]\nkey = 1\n',
        b'version = 1\n[run]\nentry = "run.py:main"\nvcpus = 3\n',
        b'version = 1\n[run]\nentry = "run.py:main"\n[metric]\ndirection = "up"\n',
        b"version = 1\n[target.planner]\nvcpus = 2\n",
        b'version = 1\n[run]\nentry = "run.py:main"\n[services.maps]\nheaders = {}\n',
    ],
)
def test_the_schema_refuses_what_its_shape_rules_refuse(raw):
    """A missing version, an unknown key or section, a wrong value or a missing key fails both.

    Args:
        raw: An invalid contract.
    """
    with pytest.raises(ValueError):
        parse_constraints(raw)
    assert list(_validator().iter_errors(tomllib.loads(raw.decode())))


def test_a_rule_across_sections_passes_the_schema_but_not_ascent_check(tmp_path, capsys):
    """The schema cannot hold "a [metric] needs a [run] or a stage"; ``ascent check`` can.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    raw = b'version = 1\n[metric]\nentry = "metric.py:score"\n'
    assert list(_validator().iter_errors(tomllib.loads(raw.decode()))) == []

    path = _write(tmp_path, raw)
    assert main(["check", path]) == 1
    first, count = capsys.readouterr().out.splitlines()
    assert first.startswith(f"{path}:2: [metric]: error: [metric] has nothing to judge.")
    assert count == "1 error, 0 warnings"


def test_check_accepts_a_valid_file(tmp_path, capsys):
    """A valid file prints only the count line and exits 0.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    assert main(["check", _write(tmp_path, FULL)]) == 0
    assert capsys.readouterr().out == "0 errors, 0 warnings\n"


def test_check_reports_the_error_with_its_line_section_and_key(tmp_path, capsys):
    """An invalid file prints the place, level and message of the error, and exits 1.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    path = _write(tmp_path, b'version = 1\n[run]\nentry = "run.py:main"\nvcpus = 3\n')

    assert main(["check", path]) == 1
    assert capsys.readouterr().out == (
        f"{path}:4: [run] vcpus: error: [run] vcpus must be 1 or an even number from 2 to 32.\n"
        "1 error, 0 warnings\n"
    )


def test_check_reports_every_mistake_and_counts_them(tmp_path, capsys):
    """A file with three mistakes in three sections prints three errors, then the count.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    raw = (
        b'version = 1\n[run]\nentry = "run.py:main"\nvcpus = 3\n'
        b'[paths]\neditable = ["src/"]\n[metrc]\n'
    )
    path = _write(tmp_path, raw)

    assert main(["check", path]) == 1
    assert capsys.readouterr().out.splitlines() == [
        f"{path}:7: [metrc]: error: [metrc] is not a supported section. Did you mean 'metric'?",
        f"{path}:6: [paths] editable: error: 'src/' in [paths] editable must be written 'src':"
        " '/' between folders, and no space or '/' at the start or the end.",
        f"{path}:4: [run] vcpus: error: [run] vcpus must be 1 or an even number from 2 to 32.",
        "3 errors, 0 warnings",
    ]


@pytest.mark.parametrize(
    ("levels", "count", "code"),
    [
        ([WARNING], "0 errors, 1 warning", 0),
        ([WARNING, WARNING], "0 errors, 2 warnings", 0),
        ([ERROR, WARNING], "1 error, 1 warning", 1),
        ([ERROR, ERROR, WARNING, WARNING], "2 errors, 2 warnings", 1),
    ],
)
def test_check_counts_each_level_and_fails_only_on_an_error(
    tmp_path, capsys, monkeypatch, levels, count, code
):
    """The count line uses the singular for one, and only an error makes the exit code 1.

    No check gives a warning yet, so the parser is replaced with one that gives these levels.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
        monkeypatch: Replaces the parser.
        levels: The level of each diagnostic.
        count: The expected count line.
        code: The expected exit code.
    """
    found = [
        Diagnostic(level=level, message=f"ascent.toml: problem {n}.")
        for n, level in enumerate(levels)
    ]
    errors = [d for d in found if d.level == ERROR]

    def parse(raw):
        """Return the warnings, or raise the errors with the warnings, as the parser does."""
        if errors:
            raise ConstraintsError(errors[0].message, errors=found)
        return types.SimpleNamespace(warnings=tuple(found))

    monkeypatch.setattr(cli, "parse_constraints", parse)
    path = _write(tmp_path, FULL)

    assert main(["check", path]) == code
    lines = capsys.readouterr().out.splitlines()
    assert lines[:-1] == [f"{path}: {d.level}: problem {n}." for n, d in enumerate(found)]
    assert lines[-1] == count


def test_check_escapes_control_and_bidi_characters_from_the_file(tmp_path, capsys):
    """A key with ESC, line separators, bidi marks or a bidi override prints them as escapes.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    key = "a\\u001bb\\u0085c\\u202ed\\u061ce\\u200ef\\u200fg\\u2028h\\u2029i"
    raw = f'version = 1\n[run]\nentry = "run.py:main"\n"{key}" = 1\n'.encode()
    path = _write(tmp_path, raw)

    assert main(["check", path]) == 1
    out = capsys.readouterr().out
    unsafe = "[\x00-\x09\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
    assert re.search(unsafe, out) is None
    assert "a\\x1bb\\x85c\\u202ed\\u061ce\\u200ef\\u200fg\\u2028h\\u2029i" in out


def test_check_reports_a_timeout_too_large_for_a_float(tmp_path, capsys):
    """A timeout integer with hundreds of digits prints the report, not a traceback.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    raw = b'version = 1\n[run]\nentry = "run.py:main"\ntimeout = 1' + b"0" * 400 + b"\n"
    path = _write(tmp_path, raw)

    assert main(["check", path]) == 1
    assert capsys.readouterr().out == (
        f"{path}:4: [run] timeout: error: [run] timeout must be a positive number of seconds"
        " for each case.\n1 error, 0 warnings\n"
    )


def test_check_reports_an_error_with_no_section_without_a_place(tmp_path, capsys):
    """A file that is not TOML has no line, section or key, so the line names only the file.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    path = _write(tmp_path, b"version = \n")
    assert main(["check", path]) == 1
    first, count = capsys.readouterr().out.splitlines()
    assert first.startswith(f"{path}: error: ascent.toml is not valid TOML:")
    assert count == "1 error, 0 warnings"


def test_check_reports_a_file_nested_too_deeply(tmp_path, capsys):
    """Deeply nested arrays print the report and exit 1, not a RecursionError traceback.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    raw = b"version = 1\nx = " + b"[" * 20000 + b"]" * 20000 + b"\n"
    path = _write(tmp_path, raw)

    assert main(["check", path]) == 1
    first, count = capsys.readouterr().out.splitlines()
    assert first.startswith(f"{path}: error: ascent.toml is not valid TOML:")
    assert count == "1 error, 0 warnings"


@pytest.mark.parametrize(
    "argv",
    [
        ["check", "missing/ascent.toml"],
        ["check", "ascent.toml", "--image", "--role", "metric"],
        ["check", "ascent.toml", "--role", "metric"],
    ],
)
def test_check_file_usage_error(argv, capsys, tmp_path, monkeypatch):
    """An unreadable file, a file with ``--image``, or ``--role`` with no ``--image`` exits 2.

    Args:
        argv: The arguments.
        capsys: Captures the output.
        tmp_path: The current directory, which holds a valid ``ascent.toml``.
        monkeypatch: Changes the current directory.
    """
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, FULL)

    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2
    assert capsys.readouterr().out == ""


def test_every_example_contract_passes_ascent_check(capsys):
    """Each ``examples/*/ascent.toml`` is valid; today no example has one.

    Args:
        capsys: Captures the reports.
    """
    for path in sorted((ROOT / "examples").glob("*/ascent.toml")):
        assert main(["check", str(path)]) == 0, capsys.readouterr().out


def test_check_counts_every_error_of_a_capped_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A check of 600 errors shows 500 and a count line, and the last line counts all 600.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    unknown = "".join(f"k{n} = 1\n" for n in range(600))
    path = _write(tmp_path, f'version = 1\n[run]\nentry = "run.py:main"\n{unknown}'.encode())

    assert main(["check", path]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 502
    assert lines[-2] == (
        f"{path}: error: 100 more errors are not shown. Fix the errors above and check again."
    )
    assert lines[-1] == "600 errors, 0 warnings"
