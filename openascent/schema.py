"""The JSON Schema of ``ascent.toml``, for editors and other tools.

The schema holds the sections, the keys and the type of each value. It cannot
hold the rules across sections, such as "a [metric] needs a [run] or a stage",
or the rules on the files that the contract names. :func:`openascent.contract.parse_constraints`
and ``ascent check`` are the full check.
"""

from __future__ import annotations

import json
from typing import Any

from .contract import (
    _CONTROL_CHARS,
    _MAX_COMMAND_CHARS,
    _MAX_COMMAND_PARTS,
    _MAX_HOSTS,
    _MAX_NAMES,
    _MAX_PATHS,
    _MAX_TABLES,
    _MAX_VCPUS,
    DIRECTIONS,
)

_ID = "https://raw.githubusercontent.com/Skynet-ml/openascent/main/ascent.schema.json"
_TABLE_NAME = "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
_PATH = {"type": "string", "description": "A path inside the repository."}
_PATHS = {"type": "array", "items": _PATH, "maxItems": _MAX_PATHS}
# The parser refuses a control character in any command part, so the schema can too.
_NO_CONTROL_CHARS = f"^[^{_CONTROL_CHARS.pattern[1:-1]}]*$"
_COMMAND = {
    "type": "array",
    "items": {
        "type": "string",
        "minLength": 1,
        "maxLength": _MAX_COMMAND_CHARS,
        "pattern": _NO_CONTROL_CHARS,
    },
    "minItems": 1,
    "maxItems": _MAX_COMMAND_PARTS,
}
_ENTRY = {
    "description": '"path/to/file.py:function", or a command list such as ["node", "run.js"].',
    "anyOf": [{"type": "string", "pattern": r"\.py:[^:]+$"}, _COMMAND],
}
_TIMEOUT = {"type": "number", "exclusiveMinimum": 0, "description": "Seconds."}
_VCPUS = {
    "type": "integer",
    "minimum": 1,
    "maximum": _MAX_VCPUS,
    "anyOf": [{"const": 1}, {"multipleOf": 2}],
    "description": f"1, or an even number from 2 to {_MAX_VCPUS} with the default runner limits.",
}
_ROLE = {
    "mcp": {**_PATH, "description": "The path of the role's .mcp.json file."},
    "network": {
        "type": "array",
        "items": {"type": "string", "maxLength": 253},
        "maxItems": _MAX_HOSTS,
        "description": "The public host names the role can reach; [] for no network.",
    },
    "services": {
        "type": "array",
        "items": {"type": "string"},
        "maxItems": _MAX_NAMES,
        "description": "Names of [services.<name>] tables.",
    },
    "illegal": {**_PATH, "description": "The path of a markdown file of rules."},
}
_SCORES = {
    "type": "object",
    "propertyNames": {"minLength": 1},
    "maxProperties": _MAX_NAMES,
}
_KEYS: dict[str, dict[str, Any]] = {
    "paths": {"editable": {**_PATHS, "minItems": 1}, "protected": _PATHS},
    "setup": {"command": {"type": "string"}},
    "proposer": {**_ROLE, "entry": _COMMAND, "setup": _COMMAND},
    "metric": {
        **_ROLE,
        "files": _PATHS,
        "exploits": _PATH,
        "reference": _PATH,
        "entry": _ENTRY,
        "direction": {"enum": list(DIRECTIONS)},
        "setup": {"type": "string"},
        "vcpus": _VCPUS,
        "scores": {**_SCORES, "additionalProperties": {"enum": list(DIRECTIONS)}},
    },
    "run": {**_ROLE, "entry": _ENTRY, "timeout": _TIMEOUT, "vcpus": _VCPUS},
    "data": {"cases": {**_PATH, "description": "The path of a JSONL file of cases."}},
    "sandbox": {"compose": {**_PATH, "description": "The path of a Compose file."}},
    "outcome": {
        "target": {"type": "number"},
        "require": {**_SCORES, "additionalProperties": {"type": "number"}},
    },
}
_REQUIRED = {"run": ["entry"], "data": ["cases"]}
_HEADERS = {"type": "object", "additionalProperties": {"type": "string"}}


def _table(keys: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    """Build the schema of one table that accepts only the given keys.

    Args:
        keys: The schema of each key.
        required: The keys the table must have.

    Returns:
        The table's schema.
    """
    table: dict[str, Any] = {"type": "object", "additionalProperties": False, "properties": keys}
    if required:
        table["required"] = required
    return table


def _named(table: dict[str, Any]) -> dict[str, Any]:
    """Build the schema of a section that holds one table for each name.

    Args:
        table: The schema of each named table.

    Returns:
        The section's schema.
    """
    return {
        "type": "object",
        "propertyNames": {"pattern": _TABLE_NAME},
        "maxProperties": _MAX_TABLES,
        "additionalProperties": table,
    }


def contract_schema() -> dict[str, Any]:
    """Build the JSON Schema of ``ascent.toml``, read as TOML into JSON.

    Returns:
        The schema, draft 2020-12.
    """
    sections = {name: _table(keys, _REQUIRED.get(name)) for name, keys in _KEYS.items()}
    target = {**_ROLE, "entry": _ENTRY, "vcpus": _VCPUS, "timeout": _TIMEOUT}
    service = {"url": {"type": "string"}, "headers": _HEADERS, "query": _HEADERS}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": _ID,
        "title": "OpenAscent contract (ascent.toml), version 1",
        "description": (
            "The sections, keys and value types of ascent.toml. The schema cannot hold the"
            " rules across sections, such as 'a [metric] needs a [run] or a stage', or the"
            " rules on the files the contract names. ascent check is the full check."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": ["version"],
        "properties": {
            "version": {"type": "integer", "const": 1},
            "instructions": {**_PATH, "description": "The path of the instructions file."},
            "tool": {
                "type": "object",
                "additionalProperties": {"type": "object"},
                "description": "[tool.<name>] tables hold data that the parser does not read.",
            },
            **sections,
            "target": _named(_table(target, ["entry"])),
            "services": _named(_table(service, ["url"])),
        },
    }


def schema_text() -> str:
    """Return the schema as the text of ``ascent.schema.json``.

    Returns:
        Indented JSON with a final newline.
    """
    return json.dumps(contract_schema(), indent=2) + "\n"
