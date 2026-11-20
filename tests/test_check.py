"""Tests of ``ascent check <file>``, ``ascent schema`` and the committed ``ascent.schema.json``."""

import json
import tomllib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from openascent.cli import main
from openascent.contract import _SECTIONS, _TARGET_KEYS, parse_constraints
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

    assert main(["check", _write(tmp_path, raw)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["error"].startswith("ascent.toml: [metric] has nothing to judge.")
    assert (report["section"], report["key"]) == ("metric", None)


def test_check_accepts_a_valid_file(tmp_path, capsys):
    """A valid file prints ``ok`` and exits 0.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    path = _write(tmp_path, FULL)

    assert main(["check", path]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "file": path}


def test_check_reports_the_error_with_its_section_and_key(tmp_path, capsys):
    """An invalid file prints the parser's error, section and key, and exits 1.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    path = _write(tmp_path, b'version = 1\n[run]\nentry = "run.py:main"\nvcpus = 3\n')

    assert main(["check", path]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "file": path,
        "error": "ascent.toml: [run] vcpus must be 1 or an even number from 2 to 32.",
        "section": "run",
        "key": "vcpus",
    }


def test_check_reports_a_timeout_too_large_for_a_float(tmp_path, capsys):
    """A timeout integer with hundreds of digits prints the JSON report, not a traceback.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    raw = b'version = 1\n[run]\nentry = "run.py:main"\ntimeout = 1' + b"0" * 400 + b"\n"
    path = _write(tmp_path, raw)

    assert main(["check", path]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "file": path,
        "error": "ascent.toml: [run] timeout must be a positive number of seconds for each case.",
        "section": "run",
        "key": "timeout",
    }


def test_check_reports_an_error_with_no_section_as_null(tmp_path, capsys):
    """A file that is not TOML has no section and no key.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    assert main(["check", _write(tmp_path, b"version = \n")]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["error"].startswith("ascent.toml is not valid TOML:")
    assert (report["section"], report["key"]) == (None, None)


def test_check_reports_a_file_nested_too_deeply(tmp_path, capsys):
    """Deeply nested arrays print the JSON report and exit 1, not a RecursionError traceback.

    Args:
        tmp_path: Scratch folder.
        capsys: Captures the report.
    """
    raw = b"version = 1\nx = " + b"[" * 20000 + b"]" * 20000 + b"\n"
    path = _write(tmp_path, raw)

    assert main(["check", path]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["error"].startswith("ascent.toml is not valid TOML:")
    assert (report["file"], report["section"], report["key"]) == (path, None, None)


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
