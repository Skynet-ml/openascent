"""Tests of the run record schema and the hash rules in the README."""

import copy
import hashlib
import json
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

SCHEMA = json.loads((files("openascent") / "record.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)
FIXTURES = Path(__file__).parent / "fixtures"

HEX_A = "a" * 64
HEX_B = "b" * 64

FULL_RECORD = {
    "record_version": 1,
    "contract_sha256": HEX_A,
    "metric_sha256": HEX_B,
    "metric_source": "request",
    "cases_sha256": "c" * 64,
    "cases_source": "file",
    "base_commit": "d" * 40,
    "change_sha256": "e" * 64,
    "baseline_score": 0.25,
    "final_score": 0.75,
    "seed": 3,
    "split": {
        "rule": "pairs",
        "seed": 3,
        "search": [0, 1],
        "validation": [2],
        "held_out": [3, 4],
    },
    "image": "registry.example/sandbox@sha256:" + "f" * 64,
    "contract_met": False,
    "target_reached": True,
    "requirements_passed": False,
    "failed_requirements": [
        {
            "name": "latency_s",
            "direction": "minimize",
            "limit": 1.5,
            "value": 2.0,
            "reason": "The median latency is above the limit.",
        }
    ],
}

REQUIRED = sorted(SCHEMA["required"])
# Not read from the schema: an empty required list in the schema must not empty these tests.
SPLIT_REQUIRED = sorted(FULL_RECORD["split"])
FAILED_REQUIRED = sorted(FULL_RECORD["failed_requirements"][0])


def _record(**changes):
    """Return a copy of the full record with some keys changed.

    Args:
        **changes: Keys to set in the copy.

    Returns:
        The changed copy.
    """
    record = copy.deepcopy(FULL_RECORD)
    record.update(changes)
    return record


def _split(**changes):
    """Return a copy of the full record's split with some keys changed.

    Args:
        **changes: Keys to set in the split copy.

    Returns:
        The changed split copy.
    """
    split = copy.deepcopy(FULL_RECORD["split"])
    split.update(changes)
    return split


def _failed(**changes):
    """Return a copy of the full record's failed requirement with some keys changed.

    Args:
        **changes: Keys to set in the entry copy.

    Returns:
        The changed entry copy.
    """
    entry = copy.deepcopy(FULL_RECORD["failed_requirements"][0])
    entry.update(changes)
    return entry


def test_schema_is_valid_draft_2020_12():
    """The schema is valid against the draft 2020-12 meta-schema."""
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_every_object_is_closed():
    """The record, the split and each failed requirement reject unknown keys."""
    objects = [SCHEMA, SCHEMA["$defs"]["split"], SCHEMA["$defs"]["failed_requirement"]]
    assert all(obj["additionalProperties"] is False for obj in objects)


def test_required_keys_are_the_version_1_keys():
    """Every key is required except the three verdict keys."""
    assert set(SCHEMA["required"]) == set(SCHEMA["properties"]) - {
        "target_reached",
        "requirements_passed",
        "failed_requirements",
    }


def test_full_record_is_valid():
    """A record with every key, a split and a failed requirement is valid."""
    VALIDATOR.validate(FULL_RECORD)


def test_skynet_record_is_valid():
    """A record from a Skynet test is valid."""
    record = json.loads((FIXTURES / "skynet_record.json").read_text(encoding="utf-8"))
    VALIDATOR.validate(record)


def test_unknown_key_fails():
    """An unknown top-level key is an error."""
    assert not VALIDATOR.is_valid(_record(reruns=3))


@pytest.mark.parametrize("key", REQUIRED)
def test_missing_required_key_fails(key):
    """Each required key is required."""
    record = _record()
    del record[key]
    assert not VALIDATOR.is_valid(record)


@pytest.mark.parametrize("key", SPLIT_REQUIRED)
def test_missing_split_key_fails(key):
    """Each key of the split is required."""
    split = _split()
    del split[key]
    assert not VALIDATOR.is_valid(_record(split=split))


@pytest.mark.parametrize("key", FAILED_REQUIRED)
def test_missing_failed_requirement_key_fails(key):
    """Each key of a failed requirement is required."""
    entry = _failed()
    del entry[key]
    assert not VALIDATOR.is_valid(_record(failed_requirements=[entry]))


def test_record_that_is_not_an_object_fails():
    """A record must be a JSON object."""
    assert not VALIDATOR.is_valid([])


INVALID = [
    ("version 2", {"record_version": 2}),
    ("version as string", {"record_version": "1"}),
    ("version as true", {"record_version": True}),
    ("hash in upper case", {"contract_sha256": "A" * 64}),
    ("hash too short", {"metric_sha256": "a" * 63}),
    ("hash too long", {"metric_sha256": "a" * 65}),
    ("hash of 64 hex and a newline", {"contract_sha256": "a" * 64 + "\n"}),
    ("hash of 63 hex and a newline", {"metric_sha256": "a" * 63 + "\n"}),
    ("hash not hex", {"change_sha256": "g" * 64}),
    ("hash as number", {"contract_sha256": 1}),
    ("cases hash not hex", {"cases_sha256": "g" * 64}),
    ("base commit too short", {"base_commit": "d" * 39}),
    ("base commit of 40 hex and a newline", {"base_commit": "d" * 40 + "\n"}),
    ("base commit of 39 hex and a newline", {"base_commit": "d" * 39 + "\n"}),
    ("base commit of 63 hex and a newline", {"base_commit": "d" * 63 + "\n"}),
    ("base commit of 50 characters", {"base_commit": "d" * 50}),
    ("base commit not hex", {"base_commit": "g" * 40}),
    ("base commit as number", {"base_commit": 1}),
    ("bad metric source", {"metric_source": "file"}),
    ("cases hash with null source", {"cases_source": None}),
    ("cases source with null hash", {"cases_sha256": None}),
    ("bad cases source", {"cases_source": "repository"}),
    ("true as baseline score", {"baseline_score": True}),
    ("false as final score", {"final_score": False}),
    ("true as seed", {"seed": True}),
    ("score as string", {"final_score": "0.9"}),
    ("contract_met null", {"contract_met": None}),
    ("image as number", {"image": 1}),
    ("target_reached as string", {"target_reached": "yes"}),
    ("requirements_passed as string", {"requirements_passed": "yes"}),
    ("split as list", {"split": ["pairs"]}),
    ("unknown key in split", {"split": _split(extra=1)}),
    ("empty split rule", {"split": _split(rule="")}),
    ("split rule as number", {"split": _split(rule=1)}),
    ("true as split seed", {"split": _split(seed=True)}),
    ("split seed as string", {"split": _split(seed="1")}),
    ("positions as number", {"split": _split(search=0)}),
    ("negative position", {"split": _split(held_out=[-1])}),
    ("negative validation position", {"split": _split(validation=[-1])}),
    ("true as position", {"split": _split(search=[True])}),
    ("failed requirements as object", {"failed_requirements": {}}),
    ("failed requirement as string", {"failed_requirements": ["latency_s"]}),
    ("unknown key in failed requirement", {"failed_requirements": [_failed(weight=1)]}),
    ("failed requirement name as number", {"failed_requirements": [_failed(name=1)]}),
    ("bad direction", {"failed_requirements": [_failed(direction="up")]}),
    ("true as limit", {"failed_requirements": [_failed(limit=True)]}),
    ("true as value", {"failed_requirements": [_failed(value=True)]}),
    ("failed requirement reason as number", {"failed_requirements": [_failed(reason=1)]}),
    ("requirements passed with a failed requirement", {"requirements_passed": True}),
    ("requirements failed with no failed requirement", {"failed_requirements": []}),
]


@pytest.mark.parametrize(("name", "changes"), INVALID, ids=[name for name, _ in INVALID])
def test_invalid_form_fails(name, changes):
    """Each invalid form is an error."""
    assert not VALIDATOR.is_valid(_record(**changes))


@pytest.mark.parametrize("key", ["requirements_passed", "failed_requirements"])
def test_one_requirement_verdict_key_alone_fails(key):
    """A record has both requirement verdict keys or neither."""
    record = _record()
    del record[key]
    assert not VALIDATOR.is_valid(record)


def _minimal():
    """Return a record with every nullable key null and no verdict keys.

    Returns:
        The record.
    """
    record = _record(
        cases_sha256=None,
        cases_source=None,
        change_sha256=None,
        baseline_score=None,
        final_score=None,
        seed=None,
        split=None,
        image=None,
    )
    for key in ("target_reached", "requirements_passed", "failed_requirements"):
        del record[key]
    return record


VALID = [
    ("all nullable keys null, no verdict keys", _minimal()),
    (
        "requirements passed with no failed requirement",
        _record(failed_requirements=[], requirements_passed=True),
    ),
    ("requirements failed with one failed requirement", _record()),
    (
        "no requirement verdict keys",
        {
            key: value
            for key, value in FULL_RECORD.items()
            if key not in ("requirements_passed", "failed_requirements")
        },
    ),
    ("sha-256 base commit", _record(base_commit="d" * 64)),
    ("request cases", _record(cases_source="request")),
    ("integer scores", _record(baseline_score=0, final_score=1)),
    ("split with null seed and empty lists", _record(split=_split(seed=None, validation=[]))),
    ("custom split rule", _record(split=_split(rule="k-fold"))),
    ("failed requirement with null value", _record(failed_requirements=[_failed(value=None)])),
]


@pytest.mark.parametrize(("name", "record"), VALID, ids=[name for name, _ in VALID])
def test_valid_edge_form_passes(name, record):
    """Each valid edge form passes."""
    VALIDATOR.validate(record)


def _sha256(data):
    """Return the SHA-256 hex of bytes.

    Args:
        data: The bytes.

    Returns:
        64 lowercase hex characters.
    """
    return hashlib.sha256(data).hexdigest()


def test_contract_hash_rule():
    """The contract hash is the SHA-256 of the file bytes."""
    contract = b'[metric]\nentry = "metric.py:score"\n'
    assert _sha256(contract) == "a7bee4c6b7495cdbb4cd70b2524931ae6c17305eecf855a812c4949ec1431a98"


def test_metric_hash_rule():
    """The metric hash follows the framed-parts rule in the README."""
    metric_files = {
        "metric.py": (
            b"def score(output, expected=None):\n"
            b'    return {"score": 1.0 if output == expected else 0.0}\n'
        ),
        "lib/util.py": b"X = 1\n",
    }
    # The 64-character hex end makes each part self-delimiting, so the parts join with no separator.
    parts = b"".join(
        path.encode("utf-8")
        + b"\0"
        + str(len(metric_files[path])).encode()
        + b"\0"
        + _sha256(metric_files[path]).encode()
        for path in sorted(metric_files, key=lambda path: path.encode("utf-8"))
    )
    assert parts.startswith(b"lib/util.py\x006\x00")
    assert _sha256(parts) == "4cb4243c16a70758b85e0c463763a1ef6048098b3e14496fb85f45067334e0eb"


def test_request_cases_hash_rule():
    """The request cases hash is the SHA-256 of the compact sorted-key JSON."""
    cases = [{"input": "café", "expected": "CAFÉ"}, {"input": "b", "expected": 2}]
    text = json.dumps(cases, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert text == '[{"expected":"CAFÉ","input":"café"},{"expected":2,"input":"b"}]'
    assert (
        _sha256(text.encode("utf-8"))
        == "8bd9a64966e3a93ec1736d506f4535affb9098fbab0860b550e707343b481f6e"
    )


def test_change_hash_rule():
    """The change hash is the SHA-256 of the patch text as UTF-8."""
    patch = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-X = 1\n+X = 2\n"
    assert (
        _sha256(patch.encode("utf-8"))
        == "18b48432344deb00d1f9ee5a1d55457a1479f62539deecbb79989aa70edf2dc7"
    )
