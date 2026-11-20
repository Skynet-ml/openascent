"""Read an ``ascent.toml`` contract and work out the environment its run gets.

The parser came from Skynet (SKY-759). It accepts and refuses the same files,
with the same error texts. It uses only the Python standard library.

The file travels with the repository, so anyone who can push to it wrote it.
It may only narrow what the customer approved: it can shrink the editable
paths, protect more files, propose a setup command when none was chosen, and
add instructions for the agent. It can never widen an editable path or hold a
secret value; asking for either fails with the reason.

:func:`parse_constraints` checks the bytes of the file: every section, key
and value, and the rules across sections. :func:`read_constraints` reads the
file from a repository archive and also checks the files it names: the
instructions and rule files, the ``.mcp.json`` files and the ``[data] cases``
file. Every file it names is protected like ``ascent.toml`` itself, so no
version can rewrite its own rules.

Two things belong to the runner, not to this package:

- Its limits, such as the most vCPUs of a box. The caller gives them as
  :class:`RunnerLimits`; the defaults are Skynet's limits.
- The Compose file that ``[sandbox] compose`` names. The parser checks only the
  path. :func:`read_constraints` reads the file only when the caller gives a
  ``compose_parser``, and keeps what it returns in ``compose_services``.

``version = 1`` is required. Each ``[tool.<name>]`` table is accepted and
skipped: the parser reads nothing in it.
"""

from __future__ import annotations

import difflib
import hashlib
import ipaddress
import json
import math
import posixpath
import re
import shlex
import socket
import tarfile
import tomllib
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict
from urllib.parse import urlsplit

CONSTRAINTS_FILE = "ascent.toml"
_MAX_FILE_BYTES = 64 * 1024
_MAX_PATHS = 200
_MAX_INTENT_CHARS = 4_000
_MAX_RULE_FILE_BYTES = 32 * 1024
_MAX_CASES_FILE_BYTES = 20 * 1024 * 1024
# The same limit as the cases list of a run request.
_MAX_CASES = 200_000
# A cases file can be 20 MiB, so a file of bad lines reports only the first ones.
_MAX_CASE_LINE_ERRORS = 100
# One check reports at most this many errors, however many files have errors.
_MAX_ERRORS = 500
# tomllib before Python 3.14 has no lineno on its error, only this text in the message.
_TOML_ERROR_LINE = re.compile(r"\(at line (\d+), column \d+\)")
_CASE_KEYS = frozenset({"input", "expected"})
_MAX_COMMAND_CHARS = 300
_MAX_RULES = 50
_MAX_RULE_CHARS = 500
_MAX_NAMES = 50
_MAX_NAME_CHARS = 100
_MAX_HOSTS = 100
_MAX_TABLES = 20
_MAX_COMMAND_PARTS = 50
# harness_bridge's gateway key tokens. A launch command with one gets the
# proposer's relay key in its text, so the file's own commands cannot name them.
_KEY_TOKENS = ("__APP_API_KEY__", "__SKYNET_API_KEY__")
# Popen raises ValueError on a NUL byte, outside the setup check's clear error, and
# other control characters only hide what the command does. That covers the C1
# controls and the bidi embeddings, overrides, isolates and marks, which reorder the
# shown text. Other format characters stay legal: a ZWJ or ZWNJ is part of real names.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_DEFAULT_VCPUS = 2
# Skynet's runner limits; RunnerLimits() keeps them,
# so a caller that gives none gets Skynet's checks.
_MAX_VCPUS = 32
_DEFAULT_TIMEOUT_SECONDS = 60.0
_DEFAULT_EXPLOITS = ".optimize/exploits"
# Every contract written before [metric] entry existed runs as this entry (SKY-738).
DEFAULT_METRIC_ENTRY = "metric.py:score"
# ``[metric] direction``: a higher score is better by
# default; a minimize run wants the lowest (SKY-750).
MAXIMIZE = "maximize"
MINIMIZE = "minimize"
DIRECTIONS = (MAXIMIZE, MINIMIZE)
_ROLE_KEYS = frozenset({"mcp", "network", "services", "illegal"})
_TARGET_KEYS = _ROLE_KEYS | {"entry", "vcpus", "timeout"}
_SECTIONS: dict[str, frozenset[str]] = {
    "paths": frozenset({"editable", "protected"}),
    "setup": frozenset({"command"}),
    # entry and setup name the user's own proposer command (SKY-753).
    "proposer": _ROLE_KEYS | {"entry", "setup"},
    # direction says which way the score improves (SKY-750); setup builds the metric once (SKY-740);
    # scores gives each named score its own direction (SKY-775).
    "metric": frozenset(
        {
            "files",
            "exploits",
            "reference",
            "entry",
            "direction",
            "setup",
            "mcp",
            "network",
            "services",
            "illegal",
            "vcpus",
            "scores",
        }
    ),
    "run": frozenset({"entry", "timeout", "mcp", "network", "services", "illegal", "vcpus"}),
    "data": frozenset({"cases"}),
    # Compose services run beside the scorer; [services.<name>] stays the API relay.
    "sandbox": frozenset({"compose"}),
    "outcome": frozenset({"target", "require"}),
}
# Every role names its MCP servers in a .mcp.json file, not catalog tool names (E46).
_ROLE_SECTIONS = frozenset({"proposer", "run", "metric"})
_BULLET = re.compile(r"[-*+](?:[ \t]+(.*))?")
# Only an ATX heading counts; "#1 Do not ..." or
# "#tag" is text and must not be dropped as a heading.
_HEADING = re.compile(r"#{1,6}(?:[ \t]|$)")
# Each of these holds one table per name, so its keys are checked per table.
_NAMED_SECTIONS = frozenset({"target", "services"})
# The keys before any section header; tool is the one other top-level table.
_TOP_KEYS = frozenset({"version", "instructions"})
_TOP_TABLES = frozenset({*_SECTIONS, *_NAMED_SECTIONS, "tool"})
_TABLE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_SECRET_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,127}")
_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
_QUERY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")
_MAX_URL_CHARS = 2_048
_MAX_HEADER_CHARS = 1_000
# Wildcard DNS names such as 169.254.169.254.nip.io resolve to the address they hold.
_DOTTED_IPV4 = re.compile(r"(^|\.)[0-9]{1,3}(\.[0-9]{1,3}){3}(\.|$)")
_HOST = re.compile(r"(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*(:[0-9]{1,5})?")
_SERVICE_KEYS = frozenset({"url", "headers", "query"})
_MCP_HTTP_TYPES = frozenset({"http", "streamable-http", "sse"})
_MCP_HTTP_KEYS = frozenset({"type", "url", "headers"})
# Only http servers are supported now (E64): a stdio
# server would run code and hold secrets in the box.
_MCP_STDIO_KEYS = frozenset({"command", "args", "env"})
# Known key formats: OpenAI/Stripe, GitHub, Slack, Google, AWS, GitLab, Hugging Face, and JWTs.
_SECRET_PREFIX = re.compile(
    r"(sk|pk|rk)[-_]|gh[pousr]_|github_pat_|xox[abposr]-|AIza|AKIA|ASIA|glpat-|hf_|eyJ"
)
_SECRET_TOKEN = re.compile(r"[A-Za-z0-9_\-+/.~]{24,}")
# Some providers issue UUID keys, which the dashed-slug rule below would let through.
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


@dataclass(frozen=True)
class RunnerLimits:
    """The limits of one runner, which the caller gives to the parser.

    The defaults are Skynet's limits, so a caller that gives none gets the same checks.
    """

    # A box has 1 vCPU, or an even number of vCPUs from 2 to max_vcpus.
    max_vcpus: int = _MAX_VCPUS
    # The longest timeout in seconds of [run] or a [target.<name>] stage; None sets no maximum.
    # An unset timeout is min(60, max_timeout), and an unset stage vcpus is min(2, max_vcpus).
    max_timeout: float | None = None


ERROR = "error"
WARNING = "warning"


@dataclass(frozen=True, kw_only=True)
class Diagnostic:
    """One problem that a check found in a contract file, with its place in the file.

    ``level`` is :data:`ERROR`, which stops the run before it starts, or
    :data:`WARNING`, which does not. ``line`` is the line of the key, or of
    the section header when the key is absent; it is ``None`` when the
    section is absent too, or when the problem belongs to the whole file.
    """

    level: str
    file: str = CONSTRAINTS_FILE
    line: int | None = None
    section: str | None = None
    key: str | None = None
    message: str


class ConstraintsError(ValueError):
    """The repository's constraints file is invalid or asks for more than the run allows.

    ``errors`` holds every problem of one check, in a fixed order. The text,
    ``section`` and ``key`` of the error are those of the first problem.
    ``hidden`` counts the errors past the cap that ``errors`` leaves out; the
    last item of ``errors`` then says how many they are.
    """

    def __init__(
        self,
        message: str,
        *,
        section: str | None = None,
        key: str | None = None,
        errors: Sequence[Diagnostic] = (),
        hidden: int = 0,
    ) -> None:
        """Keep the message and where in the file the problem is, so an editor can show it there.

        Args:
            message: The reason, which names the setting.
            section: The table, such as ``paths`` or ``target.planner``;
                ``None`` for a top-level key or the whole file.
            key: The setting in that table, such as ``editable``;
                ``None`` when the whole table is wrong.
            errors: Every problem of the check; empty for this one problem only.
            hidden: The errors past the cap that ``errors`` does not hold.
        """
        super().__init__(message)
        self.section = section
        self.key = key
        self.hidden = hidden
        self.errors = tuple(errors) or (
            Diagnostic(level=ERROR, section=section, key=key, message=message),
        )


class _Problems:
    """Collect the errors of one check, so that one mistake does not hide the next."""

    def __init__(self) -> None:
        """Start with no errors."""
        self.errors: list[Diagnostic] = []

    def add(self, message: str, *, section: str | None = None, key: str | None = None) -> None:
        """Record one error.

        Args:
            message: The reason, which names the setting.
            section: The table the error points to.
            key: The key the error points to.
        """
        self.errors.append(Diagnostic(level=ERROR, section=section, key=key, message=message))

    def check(self, read: Callable[..., Any], *args: Any, default: Any = None) -> Any:
        """Run one read, and record its errors instead of stopping.

        Args:
            read: A function that returns a value or raises :class:`ConstraintsError`.
            *args: The arguments of ``read``.
            default: The safe value to return when ``read`` fails.

        Returns:
            The value of ``read``, or ``default`` when it raised.
        """
        try:
            return read(*args)
        except ConstraintsError as error:
            self.errors += error.errors
            return default

    def raise_any(self, text: str | None = None) -> None:
        """Raise one error that holds every recorded error, when there is one.

        Args:
            text: The text of the contract file, to find the line of each error.
                Only the full check passes it, so only that error list is capped
                at ``_MAX_ERRORS``.

        Raises:
            ConstraintsError: When an error was recorded.
        """
        if not self.errors:
            return
        errors = self.errors
        hidden = 0
        if text is not None:
            hidden = max(len(errors) - _MAX_ERRORS, 0)
            errors = _with_lines(errors[:_MAX_ERRORS], text)
            if hidden > 0:
                errors.append(
                    Diagnostic(
                        level=ERROR,
                        message=f"{CONSTRAINTS_FILE}: {hidden} more"
                        f" {'error is' if hidden == 1 else 'errors are'} not shown. Fix"
                        " the errors above and check again.",
                    )
                )
        first = errors[0]
        raise ConstraintsError(
            first.message, section=first.section, key=first.key, errors=errors, hidden=hidden
        )


# Contract names are at most four parts deep, such as services.maps.headers.X;
# a cap keeps a hostile dotted name of 30000 parts linear in the line scan.
_MAX_NAME_PARTS = 8
# One part of a dotted key, and the "." or "=" after it.
# No two quantifiers can match the same text, so a hostile line takes linear time.
_KEY_PART = re.compile(r"""\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([A-Za-z0-9_-]+))\s*([.=])""")
# One part of a table header name, and the "." or "]" after it. A quoted part
# can hold "]", such as [target."a]b"].
_HEADER_PART = re.compile(r"""\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([A-Za-z0-9_-]+))\s*([.\]])""")
# The start of a table header such as [target.planner], or of a [[name]] array.
_HEADER_OPEN = re.compile(r"\s*\[\[?")
_HEADER_END = re.compile(r"\s*(?:#.*)?")


def _part(match: re.Match[str]) -> str:
    """Return the decoded name of one matched key part or header part.

    Args:
        match: A match of ``_KEY_PART`` or ``_HEADER_PART``.

    Returns:
        The part's name, with the escapes of a double-quoted part decoded.
    """
    if match.group(1) is not None:
        return _basic_key(match.group(1))
    return match.group(2) if match.group(2) is not None else match.group(3)


def _header_parts(line: str) -> list[str] | None:
    """Read a table header line, such as ``[target."a]b"]`` or ``[[name]]``.

    Args:
        line: One line of the file.

    Returns:
        The decoded parts of the header's name, or ``None`` when the line is
        not a header.
    """
    opening = _HEADER_OPEN.match(line)
    if opening is None:
        return None
    parts: list[str] = []
    index = opening.end()
    while (part := _HEADER_PART.match(line, index)) is not None:
        parts.append(_part(part))
        index = part.end()
        if part.group(4) == "]":
            if opening.group().endswith("[["):
                if not line.startswith("]", index):
                    return None
                index += 1
            return parts if _HEADER_END.fullmatch(line, index) else None
    return None


def _key_parts(line: str) -> tuple[list[str], int] | None:
    """Read the dotted key at the start of a line, such as ``require."f1" =``.

    Args:
        line: One line of the file.

    Returns:
        The decoded parts and the index after the ``=``, or ``None`` when the
        line does not start with a key.
    """
    parts: list[str] = []
    index = 0
    while (part := _KEY_PART.match(line, index)) is not None:
        parts.append(_part(part))
        index = part.end()
        if part.group(4) == "=":
            return parts, index
    return None


def _with_lines(errors: Sequence[Diagnostic], text: str) -> list[Diagnostic]:
    """Add the line of each error's key, or of its section header, from the file's text.

    tomllib gives no line numbers, so a small scan finds each header and key.

    Args:
        errors: The errors, without lines.
        text: The text of the contract file.

    Returns:
        The errors in the same order, each with the line found, or ``None``.
    """
    headers: dict[str, int] = {}
    # The first header under each section name, for a section that exists only
    # as the parent of subtables, such as [targt] in [targt.plan].
    subtables: dict[str, int] = {}
    keys: dict[tuple[str | None, str], int] = {}
    section: str | None = None
    # A value that goes on past its line: open brackets, and an open multi-line string.
    depth, open_string = 0, None
    for number, line in enumerate(text.split("\n"), start=1):
        if depth or open_string:
            depth, open_string = _value_state(line, 0, depth, open_string)
            continue
        header = _header_parts(line)
        if header is not None:
            section = ".".join(header)
            headers.setdefault(section, number)
            names = section.split(".", _MAX_NAME_PARTS)
            for count in range(1, min(len(names), _MAX_NAME_PARTS)):
                subtables.setdefault(".".join(names[:count]), number)
            continue
        key = _key_parts(line)
        if key is not None:
            parts, end = key
            # require.f1 = 1 sets f1 in [<section>.require], and names require in <section>.
            table = section
            for part in parts[:_MAX_NAME_PARTS]:
                keys.setdefault((table, part), number)
                table = f"{table}.{part}" if table else part
            depth, open_string = _value_state(line, end, 0, None)

    def line_of(section: str | None, key: str | None) -> int | None:
        """Return the line of the key, else of the nearest header or dotted key that holds it."""
        if key is not None:
            found = keys.get((section, key)) or headers.get(f"{section}.{key}" if section else key)
            if found is not None:
                return found
        while section:
            parent, _, last = section.rpartition(".")
            found = (
                headers.get(section) or keys.get((parent or None, last)) or subtables.get(section)
            )
            if found is not None:
                return found
            section = parent
        return None

    return [replace(error, line=line_of(error.section, error.key)) for error in errors]


def _basic_key(raw: str) -> str:
    """Decode the escapes of a quoted key, such as ``"a\\u202eb"``, as TOML does.

    Args:
        raw: The text between the double quotes.

    Returns:
        The key, or ``raw`` when it is not a valid quoted key.
    """
    if "\\" not in raw:
        return raw
    try:
        return next(iter(tomllib.loads(f'"{raw}" = 0')))
    except tomllib.TOMLDecodeError:
        return raw


def _value_state(
    line: str, start: int, depth: int, open_string: str | None
) -> tuple[int, str | None]:
    """Follow a value from ``start`` to the end of the line, one character at a time.

    Args:
        line: One line of the file.
        start: Where the value starts, or 0 for a line inside a value.
        depth: The brackets and braces still open before the line.
        open_string: The three quotes that opened a multi-line string still
            open before the line, or ``None``.

    Returns:
        The open brackets and the open multi-line string at the end of the line.
    """
    index = start
    while index < len(line):
        char = line[index]
        if open_string is not None:
            if char == "\\" and open_string == '"""':
                index += 2
                continue
            if line.startswith(open_string, index):
                index += 3
                open_string = None
                continue
            index += 1
            continue
        if char == "#":
            break
        if line.startswith(('"""', "'''"), index):
            open_string = line[index : index + 3]
            index += 3
            continue
        if char in "\"'":
            index += 1
            while index < len(line) and line[index] != char:
                index += 2 if char == '"' and line[index] == "\\" else 1
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth = max(depth - 1, 0)
        index += 1
    return depth, open_string


def _did_you_mean(name: str, valid: Iterable[str]) -> str:
    """Return the hint that names the nearest valid name, or an empty text when none is close.

    Args:
        name: The unknown name.
        valid: The names that are valid in that place.

    Returns:
        `` Did you mean '<name>'?``, or ``""``.
    """
    close = difflib.get_close_matches(name, sorted(valid), n=1)
    return f" Did you mean '{close[0]}'?" if close else ""


def _missing(section: Mapping[str, Any], key: str, valid: Collection[str]) -> bool:
    """Tell whether a required key is absent and no unknown key of the section is its misspelling.

    The unknown key already gets an error that names ``key``, so a second
    "missing" error for the same mistake would be a follow-on error.

    Args:
        section: The parsed table.
        key: The required key.
        valid: The keys the table may hold.

    Returns:
        ``True`` when the "missing" error is the only report of the mistake.
    """
    if key in section:
        return False
    unknown = sorted(set(section) - set(valid))
    return not any(difflib.get_close_matches(name, sorted(valid), n=1) == [key] for name in unknown)


class _Place(TypedDict):
    """The ``section`` and ``key`` keyword arguments of :class:`ConstraintsError`."""

    section: str | None
    key: str | None


def _at(setting: str) -> _Place:
    """Split a setting as errors name it, such as ``[target.planner] entry``, into section and key.

    Args:
        setting: ``[section] key ...``, ``[section]``, or a top-level key such as ``instructions``.

    Returns:
        The ``section`` and ``key`` keyword arguments of :class:`ConstraintsError`.
    """
    if not setting.startswith("["):
        return {"section": None, "key": setting}
    section, _, rest = setting[1:].partition("]")
    words = rest.split()
    return {"section": section, "key": words[0] if words else None}


@dataclass(frozen=True)
class McpServer:
    """One http server in a role's ``.mcp.json`` file (E49, E64).

    Header values hold secrets only as ``${NAME}`` placeholders, which the
    trusted parent resolves; the file never holds a value.
    """

    name: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str:
        """Return the lowercase host the server's calls go to."""
        return _host_of(self.url)

    @property
    def secrets(self) -> tuple[str, ...]:
        """Return the secret names the server's headers use, in file order."""
        return _placeholders(*self.headers.values())

    def record(self) -> dict[str, Any]:
        """Describe the server for the run's disclosure, without secret values.

        Returns:
            The name, the type, the host and the secret names.
        """
        return {"name": self.name, "type": "http", "host": self.host, "secrets": list(self.secrets)}


@dataclass(frozen=True)
class RoleEnvironment:
    """The environment one role's box gets: the proposer or one target stage.

    ``network`` is ``None`` when the file sets no list, which keeps the role's
    default: the relay and the package registries for the proposer (E57), and
    the relay only for a target. An empty tuple means the relay only. For the
    proposer, a list adds its hosts to the registries.
    """

    network: tuple[str, ...] | None = None
    services: tuple[str, ...] = ()
    illegal: tuple[str, ...] = ()
    # The repository path of the role's .mcp.json file (E46).
    mcp: str | None = None
    # The repository path the file names in illegal; read_constraints fills illegal from it (E48).
    illegal_file: str | None = None
    # The servers of the mcp file; read_constraints fills them from the same snapshot (E49).
    mcp_servers: tuple[McpServer, ...] = ()


@dataclass(frozen=True, kw_only=True)
class TargetStage(RoleEnvironment):
    """One ``[target.<name>]`` stage: its environment and how the runner starts it.

    ``entry`` is ``"path/to/file.py:function"`` for a Python function, or a
    command such as ``("node", "planner.js")``. ``timeout`` is in seconds for
    each ``openascent.call``.
    """

    entry: str | tuple[str, ...]
    vcpus: int = _DEFAULT_VCPUS
    timeout: float = _DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True)
class ServiceSpec:
    """One ``[services.<name>]`` declaration: the names of the secrets it needs, never values."""

    # The ${NAME} placeholders of headers, then of query, in file order (E53, SKY-630).
    secrets: tuple[str, ...] = ()
    # The parser always sets it (E53); only specs built in code leave it None.
    url: str | None = None
    # As written in the file, with ${SECRET} placeholders; None when the file sets none.
    headers: Mapping[str, str] | None = None
    # URL query parameters whose values are each one ${SECRET} placeholder, for an API
    # that reads its key from the query, such as Google Geocoding's ?key= (SKY-630).
    query: Mapping[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str | None:
        """Return the lowercase host the service's calls go to, or ``None`` when it has no url."""
        return _host_of(self.url) if self.url is not None else None

    @property
    def request_headers(self) -> dict[str, str]:
        """Return the headers to send, with ``${SECRET}`` placeholders still unresolved.

        Returns:
            The file's headers, or ``Authorization: Bearer ${SECRET}`` when it
            sets no headers and no query and the service has exactly one
            secret (E45). A query secret never goes out as a header too.
        """
        if self.headers is not None:
            return dict(self.headers)
        if not self.query and len(self.secrets) == 1:
            return {"Authorization": f"Bearer ${{{self.secrets[0]}}}"}
        return {}


@dataclass(frozen=True)
class MetricSpec:
    """The ``[metric]`` section: what the agent must never see."""

    files: tuple[str, ...] = ()
    exploits: str = _DEFAULT_EXPLOITS
    reference: str | None = None
    # "path.py:function" for request code, or a command
    # list that runs a [metric] files file (SKY-738).
    entry: str | tuple[str, ...] = DEFAULT_METRIC_ENTRY
    direction: str = MAXIMIZE
    # One shell command that builds the metric once in the metric setup box (SKY-740).
    setup: str | None = None
    # [metric.scores]: the direction of each named score
    # the table names; any other name maximizes (SKY-775).
    scores: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RepoConstraints:
    """What a repository's constraints file proposes, already validated.

    ``rules`` and ``proposer.illegal`` hold the same list: the top-level
    bullets of the ``[proposer] illegal`` file. :func:`parse_constraints`
    reads only the toml, so it leaves ``intent`` and every role's ``illegal``
    empty; :func:`read_constraints` fills them from the files in the snapshot.
    """

    sha256: str
    editable_paths: tuple[str, ...] | None = None
    protected_paths: tuple[str, ...] = ()
    setup_command: str | None = None
    # None means the file has no [run] section; a
    # [target.<name>] stage then runs the version (E39, SKY-761).
    run_entry: str | tuple[str, ...] | None = None
    run_timeout: float = _DEFAULT_TIMEOUT_SECONDS
    # The candidate box runs [run] and the metric box runs [metric] (SKY-398),
    # so each role sets its own network and vcpus. Each role gets only the
    # services it lists and only its own MCP file (E55).
    run_role: RoleEnvironment = RoleEnvironment()
    metric_role: RoleEnvironment = RoleEnvironment()
    # None keeps the runtime's default size for the box.
    run_vcpus: int | None = None
    metric_vcpus: int | None = None
    instructions_file: str | None = None
    intent: str | None = None
    rules: tuple[str, ...] = ()
    proposer: RoleEnvironment = RoleEnvironment()
    # None keeps the runner's own agent; a run that names its own proposer replaces both (SKY-753).
    proposer_entry: tuple[str, ...] | None = None
    proposer_setup: tuple[str, ...] | None = None
    # The repository files and folders that entry and setup name; read_constraints fills them,
    # and the file proposer protects them.
    proposer_command_files: tuple[str, ...] = ()
    targets: Mapping[str, TargetStage] = field(default_factory=dict)
    services: Mapping[str, ServiceSpec] = field(default_factory=dict)
    metric: MetricSpec = MetricSpec()
    # [data] cases: the only source of a repository run's cases (E58). parse_constraints
    # keeps the path; read_constraints fills cases from the file in the snapshot.
    cases_file: str | None = None
    cases: tuple[dict[str, Any], ...] = ()
    # parse_constraints keeps the path; read_constraints fills the services from the snapshot.
    compose_file: str | None = None
    # read_constraints fills them only with a compose_parser; the runner owns the Compose format.
    compose_services: tuple[Any, ...] = ()
    # [outcome]: the search stops at the target (SKY-691);
    # the run end judges the target and each limit (SKY-692).
    outcome_target: float | None = None
    outcome_limits: Mapping[str, float] = field(default_factory=dict)
    # The warnings of the check; a warning does not stop the run. No check gives one yet (SKY-762).
    warnings: tuple[Diagnostic, ...] = ()

    @property
    def rule_files(self) -> tuple[str, ...]:
        """Return the distinct repository paths of the instructions and rule files in the toml."""
        return tuple(dict.fromkeys(path for _, path in rule_file_settings(self)))

    @property
    def mcp_files(self) -> tuple[str, ...]:
        """Return the distinct repository paths of the ``.mcp.json`` files that the roles name."""
        return tuple(
            dict.fromkeys(role.mcp for role in self.mcp_roles.values() if role.mcp is not None)
        )

    @property
    def mcp_roles(self) -> dict[str, RoleEnvironment]:
        """Return every role, which may name an MCP file, by the label the file uses for it."""
        targets = {f"[target.{name}]": stage for name, stage in self.targets.items()}
        return {
            "[proposer]": self.proposer,
            "[run]": self.run_role,
            "[metric]": self.metric_role,
            **targets,
        }

    @property
    def secret_hosts(self) -> dict[str, str]:
        """Return the one host each secret may go to, by secret name (E52).

        Returns:
            Each secret that a ``[services]`` header or an MCP server's
            header uses, mapped to the host of that url.
        """
        hosts = {
            name: spec.host for spec in self.services.values() for name in spec.secrets if spec.host
        }
        for role in self.mcp_roles.values():
            hosts |= {name: server.host for server in role.mcp_servers for name in server.secrets}
        return hosts

    @property
    def secret_names(self) -> tuple[str, ...]:
        """Return every secret name the file and its MCP files use, in file order."""
        names = [name for spec in self.services.values() for name in spec.secrets]
        names += [
            name
            for role in self.mcp_roles.values()
            for server in role.mcp_servers
            for name in server.secrets
        ]
        return tuple(dict.fromkeys(names))


@dataclass(frozen=True)
class RepoEnvironment:
    """The effective rules a repository run is held to."""

    editable_paths: tuple[str, ...]
    protected_paths: tuple[str, ...]
    setup_command: str | None
    constraints: RepoConstraints | None = None
    notes: tuple[str, ...] = ()
    # The file's proposer command when the run names no proposer of its own; else None (SKY-753).
    proposer_entry: tuple[str, ...] | None = None
    proposer_setup: tuple[str, ...] | None = None

    @property
    def rules(self) -> tuple[str, ...]:
        """Return the plain-language rules the judges enforce, in file order."""
        return self.constraints.rules if self.constraints is not None else ()

    def record(
        self,
        *,
        repository: str,
        commit: str,
        readonly_paths: Sequence[str],
        secret_names: Iterable[str],
    ) -> dict[str, Any]:
        """Describe the environment as the JSON saved with the run and shown before it starts.

        Args:
            repository: ``owner/name``.
            commit: The pinned starting commit.
            readonly_paths: Submodules and Git LFS files.
            secret_names: Names of the variables the scorer receives; never values.

        Returns:
            A JSON-ready summary of what the run can and cannot do.
        """
        file = self.constraints
        services = file.services if file else {}
        roles = file.mcp_roles if file else {}
        return {
            "repository": repository,
            "commit": commit,
            "constraints_file": {"path": CONSTRAINTS_FILE, "sha256": file.sha256} if file else None,
            "editable_paths": list(self.editable_paths),
            "protected_paths": list(self.protected_paths),
            "readonly_paths": list(readonly_paths),
            "secret_names": sorted(secret_names),
            "services": [
                {"name": name, "host": spec.host, "secrets": list(spec.secrets)}
                for name, spec in services.items()
            ],
            "mcp_servers": {
                label: [server.record() for server in role.mcp_servers]
                for label, role in roles.items()
                if role.mcp_servers
            },
            "secret_hosts": file.secret_hosts if file else {},
            "instructions": {"path": file.instructions_file, "intent": file.intent}
            if file and file.intent
            else None,
            "rules": list(self.rules),
            "notes": list(self.notes),
            "outcome": {
                "target": file.outcome_target if file else None,
                "require": dict(file.outcome_limits) if file else {},
                "direction": file.metric.direction if file else MAXIMIZE,
                # Only a contract with [metric.scores] has the
                # key, so older records stay equal on resume.
                **({"scores": dict(file.metric.scores)} if file and file.metric.scores else {}),
            },
            # Only a run that uses the file's proposer has
            # the key, so older records stay equal on resume.
            **(
                {"proposer_entry": list(self.proposer_entry)}
                if self.proposer_entry is not None
                else {}
            ),
            **(
                {"proposer_setup": list(self.proposer_setup)}
                if self.proposer_setup is not None
                else {}
            ),
        }


# Set only for the duration of one parse_constraints or read_constraints call
# with legacy_forms=True, so the deep helpers need no extra argument.
_LEGACY_FORMS: ContextVar[bool] = ContextVar("openascent_legacy_forms", default=False)


def _clean_path(raw: Any, setting: str) -> str:
    """Check one repository-relative path from the file, which must be in its one valid form.

    Args:
        raw: The value as parsed.
        setting: The setting it came from, such as ``[paths] editable``, named in errors.

    Returns:
        The path as written; ``.`` for the whole tree. Under ``legacy_forms``,
        the cleaned path: stripped, ``\\`` changed to ``/``, and no ``/`` at
        the start or the end, as the older reader gave it.

    Raises:
        ConstraintsError: When the value is not a path inside the repository, is
            a pattern, or, unless under ``legacy_forms``, is not written in its
            one form: ``/`` between folders, and no space or ``/`` at the start
            or the end.
    """
    if not isinstance(raw, str):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: every entry of {setting} must be a text path.", **_at(setting)
        )
    path = raw.strip().replace("\\", "/")
    clean = "." if path in (".", "./") else path.strip("/")
    if (
        path.startswith("/")
        or not clean
        or (clean != "." and any(part in ("", ".", "..") for part in clean.split("/")))
    ):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: '{raw}' in {setting} must be relative and stay inside the"
            " repository.",
            **_at(setting),
        )
    if clean == ".git" or clean.startswith(".git/"):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} cannot name the .git folder.", **_at(setting)
        )
    # Paths are compared literally, so a pattern would match no file and
    # protect nothing while still being listed as protected.
    if any(char in clean for char in "*?["):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: '{raw}' in {setting} looks like a pattern. Patterns are not"
            " supported; name the files or folders.",
            **_at(setting),
        )
    # The parser does not convert a path, so the file says exactly what the run protects.
    # A run that started under the older reader keeps the cleaned path that reader used.
    if clean != raw and not _LEGACY_FORMS.get():
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: '{raw}' in {setting} must be written '{clean}': '/' between"
            " folders, and no space or '/' at the start or the end.",
            **_at(setting),
        )
    return clean


def _distinct(values: Sequence[str], setting: str, problems: _Problems) -> tuple[str, ...]:
    """Record each value that a list holds twice: a list has one form, with each value once.

    Under ``legacy_forms`` a repeat is no error, because the older reader
    dropped each repeat and kept the first value.

    Args:
        values: The checked values, in file order.
        setting: The setting of the list, named in errors.
        problems: Records each error.

    Returns:
        Each value once, in file order, so a duplicate hides no other mistake.
    """
    unique = tuple(dict.fromkeys(values))
    if len(unique) < len(values) and not _LEGACY_FORMS.get():
        for value in dict.fromkeys(value for value in values if values.count(value) > 1):
            problems.add(
                f"{CONSTRAINTS_FILE}: {setting} holds '{value}' more than once. List each value"
                " once.",
                **_at(setting),
            )
    return unique


def _paths(
    section: Mapping[str, Any], key: str, problems: _Problems, section_name: str = "paths"
) -> tuple[str, ...] | None:
    """Read one list of paths from a section.

    Args:
        section: The parsed table.
        key: The setting, such as ``editable`` or ``files``.
        problems: Records each error.
        section_name: The table's name, used in errors.

    Returns:
        The valid paths, each once, so one bad path hides no check of the others;
        ``None`` when the key is absent or the value is not a bounded list.
    """
    paths = _path_items(section, key, problems, section_name)
    return None if paths is None else _distinct(paths, f"[{section_name}] {key}", problems)


def _path_items(
    section: Mapping[str, Any], key: str, problems: _Problems, section_name: str
) -> list[str] | None:
    """Read the valid paths of one list, in file order, with any repeats kept.

    Args:
        section: The parsed table.
        key: The setting, such as ``editable`` or ``files``.
        problems: Records each error of the list's shape and of each path.
        section_name: The table's name, used in errors.

    Returns:
        The cleaned valid paths, or ``None`` when the key is absent or the
        value is not a bounded list.
    """
    if key not in section:
        return None
    setting = f"[{section_name}] {key}"
    values = section[key]
    if not isinstance(values, list) or len(values) > _MAX_PATHS:
        problems.add(
            f"{CONSTRAINTS_FILE}: {setting} must be a list of at most {_MAX_PATHS} paths.",
            **_at(setting),
        )
        return None
    paths = [problems.check(_clean_path, value, setting) for value in values]
    return [path for path in paths if path is not None]


def _text(value: Any, setting: str, limit: int) -> str:
    """Read one bounded text setting.

    Args:
        value: The value as parsed.
        setting: The setting's name, used in errors.
        limit: Most characters allowed.

    Returns:
        The text as written.

    Raises:
        ConstraintsError: When the value is not text, is blank, is too long, or
            starts or ends with a space.
    """
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} must be text of 1 to {limit} characters.",
            **_at(setting),
        )
    if value != value.strip():
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} must not start or end with a space or a line break."
            f" Write '{_shown(value.strip())}'.",
            **_at(setting),
        )
    return value


def _shown(value: str) -> str:
    """Write each control character of a value as a visible escape, for an error message.

    Args:
        value: The value from the file.

    Returns:
        The value, with each control character escaped.
    """
    return _CONTROL_CHARS.sub(lambda match: match.group().encode("unicode_escape").decode(), value)


def _shell_command(value: Any, setting: str) -> str:
    """Read one shell command, such as ``[setup] command``.

    Under ``legacy_forms`` the command is stripped and may hold line breaks,
    tabs and other control characters, as the older reader allowed, so a
    multi-line command keeps its lines. The length limit applies to the
    value before the strip, as in the older reader.

    Args:
        value: The value as parsed.
        setting: The setting's name, used in errors.

    Returns:
        The command; stripped under ``legacy_forms``.

    Raises:
        ConstraintsError: When the value is not text of 1 to the command limit
            of characters, or, unless under ``legacy_forms``, has a space at the
            start or the end or holds a control character.
    """
    legacy = _LEGACY_FORMS.get()
    # The older reader checked the length before the strip, so a too-long value still fails.
    if legacy and isinstance(value, str) and len(value) <= _MAX_COMMAND_CHARS:
        value = value.strip()
    command = _text(value, setting, _MAX_COMMAND_CHARS)
    if not legacy and _CONTROL_CHARS.search(command):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} must be one command without control characters, such"
            ' as "pip install -r requirements.txt".',
            **_at(setting),
        )
    return command


def _one_file(raw: Any, setting: str) -> str:
    """Read the repository path of one file, such as an ``.mcp.json`` or a rule file.

    Args:
        raw: The value as parsed.
        setting: The setting it came from, such as ``[run] mcp``, named in errors.

    Returns:
        The cleaned repository-relative path.

    Raises:
        ConstraintsError: When the value is not a path to one file inside the repository.
    """
    path = _clean_path(raw, setting)
    if path == ".":
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} must name one file, not the whole repository.",
            **_at(setting),
        )
    return path


def _illegal_file(section: Mapping[str, Any], label: str) -> str | None:
    """Read the optional ``illegal`` path: the markdown file that holds a role's rules (E48).

    Args:
        section: The parsed table.
        label: The table as the file names it, such as ``[proposer]``, used in errors.

    Returns:
        The repository path of the rule file, or ``None`` when the key is absent.

    Raises:
        ConstraintsError: When the value is an inline list of
            rules, or not a path to one file in the repository.
    """
    if "illegal" not in section:
        return None
    if not isinstance(section["illegal"], str):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} illegal must be the path of a markdown rule file, not the"
            " rules themselves. Move the rules into a file in the repository, one top-level '- '"
            f' bullet for each rule, and set illegal = "<path>" in {label}.',
            **_at(f"{label} illegal"),
        )
    return _one_file(section["illegal"], f"{label} illegal")


def _names(
    section: Mapping[str, Any], key: str, label: str, problems: _Problems
) -> tuple[str, ...]:
    """Read an optional list of short names, such as tools or services.

    Args:
        section: The parsed table.
        key: The setting.
        label: The table as the file names it, used in errors.
        problems: Records each error.

    Returns:
        The valid names, each once, in file order; empty when the key is absent
        or the value is not a bounded list. Under ``legacy_forms`` each name is
        stripped first, as the older reader did. The length limit applies to
        the name before the strip, as in the older reader.
    """
    values = section.get(key, [])
    setting = f"{label} {key}"
    if not isinstance(values, list) or len(values) > _MAX_NAMES:
        problems.add(
            f"{CONSTRAINTS_FILE}: {setting} must be a list of at most {_MAX_NAMES} names.",
            **_at(setting),
        )
        return ()
    if _LEGACY_FORMS.get():
        values = [
            value.strip() if isinstance(value, str) and len(value) <= _MAX_NAME_CHARS else value
            for value in values
        ]
    names = [problems.check(_text, value, setting, _MAX_NAME_CHARS) for value in values]
    return _distinct([name for name in names if name is not None], setting, problems)


def _network_host(host: Any, label: str) -> str:
    """Check one entry of a ``network`` list.

    Under ``legacy_forms`` the host is put in lower case after the host-name
    check, as the older reader did. The public-host check stays under
    ``legacy_forms``, unlike the older reader: the list comes from the
    repository, so localhost or a private IP address would let a run reach
    internal hosts.

    Args:
        host: The entry as parsed.
        label: The table as the file names it, used in errors.

    Returns:
        The host as written; in lower case under ``legacy_forms``.

    Raises:
        ConstraintsError: When the entry is not a host name, is not a public
            host, or, unless under ``legacy_forms``, is not in lower case.
    """
    setting = f"{label} network"
    if not isinstance(host, str) or len(host) > 253 or not _HOST.fullmatch(host):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} network entry {str(host)[:100]!r} must be a host name"
            " such as api.example.com, not a URL. Use network = [] for no network.",
            **_at(setting),
        )
    # The host check runs first, so a non-ASCII letter that lowers to ASCII, such as
    # the Kelvin sign, still fails, as in the older reader.
    if _LEGACY_FORMS.get():
        host = host.lower()
    # The same rules as a service url, so an allowlist cannot open a path to internal hosts.
    # This holds under legacy_forms too, though the older reader had no such check (SSRF).
    if not _public_host(host.lower().removeprefix("*.").partition(":")[0]):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} network entry {host!r} must name a public host such"
            " as api.example.com, not an IP address or localhost.",
            **_at(setting),
        )
    if host != host.lower():
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} network entry '{host}' must be in lower case. Write"
            f" '{host.lower()}'.",
            **_at(setting),
        )
    return host


def _network(section: Mapping[str, Any], label: str, problems: _Problems) -> tuple[str, ...] | None:
    """Read an optional list of allowed hosts.

    Args:
        section: The parsed table.
        label: The table as the file names it, used in errors.
        problems: Records each error, such as a host that fails the public-host
            check of :func:`_public_host`.

    Returns:
        The valid hosts, each once; ``()`` for offline; ``None`` when the key is
        absent or the value is not a bounded list.
    """
    if "network" not in section:
        return None
    hosts = section["network"]
    if not isinstance(hosts, list) or len(hosts) > _MAX_HOSTS:
        problems.add(
            f"{CONSTRAINTS_FILE}: {label} network must be a list of at most {_MAX_HOSTS} host"
            " names.",
            **_at(f"{label} network"),
        )
        return None
    checked = [problems.check(_network_host, host, label) for host in hosts]
    return _distinct([host for host in checked if host is not None], f"{label} network", problems)


def _role(
    section: Mapping[str, Any], label: str, declared: Collection[str] | None, problems: _Problems
) -> dict[str, Any]:
    """Read the settings every role shares: mcp, network, services and illegal.

    Each setting is checked on its own; a setting with an error gets its unset value.

    Args:
        section: The parsed ``[proposer]`` or ``[target.<name>]`` table.
        label: The table as the file names it, used in errors.
        declared: The name of each ``[services.<name>]`` table of the file, valid or not;
            ``None`` when the file's services value is not a table, so no name is checked.
        problems: Records each error.

    Returns:
        Keyword arguments for :class:`RoleEnvironment`.
    """
    named = _names(section, "services", label, problems)
    for name in named:
        if declared is not None and name not in declared:
            problems.add(
                f"{CONSTRAINTS_FILE}: {label} services names '{name}', but the file has no"
                f" [services.{name}] table.",
                **_at(f"{label} services"),
            )
    return {
        "mcp": problems.check(_mcp, section, label),
        "network": _network(section, label, problems),
        "services": tuple(name for name in named if declared is not None and name in declared),
        "illegal_file": problems.check(_illegal_file, section, label),
    }


def _vcpus(value: Any, label: str, section: str, limits: RunnerLimits) -> int:
    """Check a box size: 1, or an even number from 2 to the runner's maximum.

    Args:
        value: The ``vcpus`` value from the file.
        label: The table as the file names it, used in errors.
        section: The section name the error points to.
        limits: The runner's limits.

    Returns:
        The number of vCPUs.

    Raises:
        ConstraintsError: When the value is not a valid box size.
    """
    # bool is an int in Python, so ``vcpus = true`` would otherwise read as 1.
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not (value == 1 or (value % 2 == 0 and 2 <= value <= limits.max_vcpus))
    ):
        allowed = (
            "1" if limits.max_vcpus < 2 else f"1 or an even number from 2 to {limits.max_vcpus}"
        )
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} vcpus must be {allowed}.",
            section=section,
            key="vcpus",
        )
    return value


def _tools_moved(label: str) -> ConstraintsError:
    """Build the error for a ``tools`` key that names catalog tools, not an MCP file (E46).

    Args:
        label: The role's table as the file names it.

    Returns:
        The error, with the fix that points to ``mcp``.
    """
    return ConstraintsError(
        f"{CONSTRAINTS_FILE}: {label} tools is not supported. List the MCP servers in a .mcp.json"
        f' file in the repository and set mcp = "<path>" in {label} instead.',
        **_at(f"{label} tools"),
    )


def _mcp(section: Mapping[str, Any], label: str) -> str | None:
    """Read the optional ``mcp`` path of a role.

    Args:
        section: The parsed table.
        label: The table as the file names it, used in errors.

    Returns:
        The repository-relative path of the ``.mcp.json`` file, or ``None`` when the key is absent.

    Raises:
        ConstraintsError: When the value is not a path to one file inside the repository.
    """
    if "mcp" not in section:
        return None
    return _one_file(section["mcp"], f"{label} mcp")


def _entry(value: Any, label: str) -> str | tuple[str, ...]:
    """Read how the runner starts a target stage or the ``[run]`` candidate.

    Args:
        value: The ``entry`` value as parsed.
        label: The entry's table, used in errors.

    Returns:
        ``"path.py:function"`` with a cleaned path, or the command as a tuple.

    Raises:
        ConstraintsError: When the value is neither form. A command part may
            hold a control character only under ``legacy_forms``, as the older
            reader allowed.
    """
    problem = ConstraintsError(
        f'{CONSTRAINTS_FILE}: {label} entry must be "path/to/file.py:function" for a Python'
        ' function, or a command list such as ["node", "planner.js"].',
        **_at(f"{label} entry"),
    )
    if isinstance(value, str):
        path, _, function = value.rpartition(":")
        if not path.endswith(".py") or not function.isidentifier():
            raise problem
        try:
            return f"{_clean_path(path, f'{label} entry')}:{function}"
        except ConstraintsError as error:
            fixed = posixpath.normpath(path.strip().replace("\\", "/"))
            if path.strip().startswith(("/", "\\")) or fixed.startswith(".."):
                raise problem from error
            try:
                _clean_path(fixed, f"{label} entry")
            except ConstraintsError:
                raise problem from error
            raise ConstraintsError(
                f"{problem} Write '{fixed}:{function}'.", **_at(f"{label} entry")
            ) from error
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= _MAX_COMMAND_PARTS
        or not all(
            isinstance(part, str)
            and part.strip()
            and len(part) <= _MAX_COMMAND_CHARS
            and (_LEGACY_FORMS.get() or not _CONTROL_CHARS.search(part))
            for part in value
        )
    ):
        raise problem
    return tuple(value)


def _command(section: Mapping[str, Any], key: str, label: str) -> tuple[str, ...] | None:
    """Read an optional command list, such as ``[proposer] entry``.

    Args:
        section: The parsed table.
        key: The setting, such as ``entry`` or ``setup``.
        label: The table as the file names it, used in errors.

    Returns:
        The command as a tuple, or ``None`` when the key is absent.

    Raises:
        ConstraintsError: When the value is not a non-empty list of non-empty
            strings without control characters, or names a gateway key token.
    """
    if key not in section:
        return None
    value = section[key]
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= _MAX_COMMAND_PARTS
        or not all(
            isinstance(part, str)
            and part.strip()
            and len(part) <= _MAX_COMMAND_CHARS
            and not _CONTROL_CHARS.search(part)
            for part in value
        )
    ):
        raise ConstraintsError(
            f'{CONSTRAINTS_FILE}: {label} {key} must be a command list such as ["node",'
            ' "my-agent.js"].',
            **_at(f"{label} {key}"),
        )
    token = next((token for token in _KEY_TOKENS if any(token in part for part in value)), None)
    if token is not None:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} {key} cannot contain {token}. The command reads the model"
            " key from the APP_API_KEY environment variable.",
            **_at(f"{label} {key}"),
        )
    return tuple(value)


def _target(
    section: Any,
    name: str,
    declared: Collection[str] | None,
    limits: RunnerLimits,
    problems: _Problems,
) -> RoleEnvironment | None:
    """Read one ``[target.<name>]`` stage.

    Args:
        section: The value under the stage's name.
        name: The stage's name.
        declared: The name of each ``[services.<name>]`` table of the file, or
            ``None`` when the file's services value is not a table.
        limits: The runner's limits.
        problems: Records every error of the stage: it is not a named table,
            or a setting is missing, unknown or malformed.

    Returns:
        The validated :class:`TargetStage`. When the stage has an error, a
        :class:`RoleEnvironment` with only its valid role settings, so the
        rules across sections still check them. ``None`` when it is not a table.
    """
    if not isinstance(section, dict):
        problems.add(
            f"{CONSTRAINTS_FILE}: [target] {name} needs a stage name: use [target.<name>] for each"
            ' stage, for example [target.planner] with entry = "agents/planner.py:plan".',
            section="target",
            key=name,
        )
        return None
    errors = len(problems.errors)
    if not _TABLE_NAME.fullmatch(name):
        problems.add(
            f"{CONSTRAINTS_FILE}: the [target] stage name {name[:100]!r} must start with a letter"
            " or digit and use only letters, digits, '-' and '_' (at most 64).",
            section=f"target.{name}",
        )
    label = f"[target.{name}]"
    if "tools" in section:
        problems.errors += _tools_moved(label).errors
    for key in sorted(set(section) - _TARGET_KEYS - {"tools"}):
        problems.add(
            f"{CONSTRAINTS_FILE}: {label} {key} is not a supported setting."
            + _did_you_mean(key, _TARGET_KEYS),
            section=f"target.{name}",
            key=key,
        )
    if _missing(section, "entry", _TARGET_KEYS):
        problems.add(
            f"{CONSTRAINTS_FILE}: {label} entry is missing. Name the function"
            ' ("path/to/file.py:function") or the command (["node", "planner.js"]) that runs the'
            " stage.",
            section=f"target.{name}",
            key="entry",
        )
    # The default box is 2 vCPUs; a 1-vCPU runner gets 1, which is still a valid size.
    default_vcpus = min(_DEFAULT_VCPUS, limits.max_vcpus)
    vcpus = (
        problems.check(
            _vcpus, section["vcpus"], label, f"target.{name}", limits, default=default_vcpus
        )
        if "vcpus" in section
        else default_vcpus
    )
    role = _role(section, label, declared, problems)
    entry = problems.check(_entry, section["entry"], label) if "entry" in section else None
    timeout = problems.check(_timeout, section, label, "openascent.call", limits)
    # An absent or invalid entry records an error, so a stage with no entry is never returned.
    if len(problems.errors) > errors or entry is None:
        return RoleEnvironment(**role)
    return TargetStage(**role, entry=entry, vcpus=vcpus, timeout=timeout)


def _default_timeout(limits: RunnerLimits) -> float:
    """Return the 60-second default timeout, cut to the runner's maximum."""
    if limits.max_timeout is None:
        return _DEFAULT_TIMEOUT_SECONDS
    return min(_DEFAULT_TIMEOUT_SECONDS, float(limits.max_timeout))


def _timeout(section: Mapping[str, Any], label: str, unit: str, limits: RunnerLimits) -> float:
    """Read an optional ``timeout`` in seconds.

    Args:
        section: The parsed table.
        label: The table as the file names it, used in errors.
        unit: What one timeout covers, such as ``openascent.call``, named in errors.
        limits: The runner's limits.

    Returns:
        The timeout, or the default when the key is absent.

    Raises:
        ConstraintsError: When the value is not a positive finite number, or is
            more than the runner's maximum.
    """
    if "timeout" not in section:
        return _default_timeout(limits)
    timeout = section["timeout"]
    # bool is an int in Python, so ``timeout = true`` would otherwise read as 1.
    number = (
        timeout if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) else math.nan
    )
    try:
        number = float(number)
    except OverflowError:
        # A TOML integer can have hundreds of digits, more than a float holds.
        number = math.nan
    if not math.isfinite(number) or number <= 0:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} timeout must be a positive number of seconds for each"
            f" {unit}.",
            **_at(f"{label} timeout"),
        )
    if limits.max_timeout is not None and number > limits.max_timeout:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} timeout must be at most {limits.max_timeout:g} seconds"
            f" for each {unit}.",
            **_at(f"{label} timeout"),
        )
    return number


def _run(
    section: Mapping[str, Any] | None, limits: RunnerLimits, problems: _Problems
) -> tuple[str | tuple[str, ...] | None, float]:
    """Read the ``[run]`` section: how the runner starts the candidate for each case (E39).

    Args:
        section: The parsed ``[run]`` table, or ``None`` when the file has none.
        limits: The runner's limits.
        problems: Records each error: no entry, or a malformed entry or timeout.

    Returns:
        The entry, or ``None`` when the file has none or it is malformed, and the
        timeout in seconds for each case. A bad timeout keeps a valid entry, so
        the entry's own checks still run.
    """
    if section is None:
        return None, _default_timeout(limits)
    if _missing(section, "entry", _SECTIONS["run"]):
        problems.add(
            f"{CONSTRAINTS_FILE}: [run] entry is missing. Name the function"
            ' ("path/to/file.py:function") or the command (["pytest", "-q"]) that runs the'
            " candidate for each case.",
            section="run",
            key="entry",
        )
    entry = problems.check(_entry, section["entry"], "[run]") if "entry" in section else None
    timeout = problems.check(_timeout, section, "[run]", "case", limits, default=None)
    return entry, _default_timeout(limits) if timeout is None else timeout


def _score_value(value: Any, setting: str, section: str, key: str) -> float:
    """Check a score that the file sets, such as ``[outcome] target``.

    Scores have no fixed range: the metric returns any finite number.

    Args:
        value: The value from the file.
        setting: The setting as the file names it, used in errors.
        section: The section name the error points to.
        key: The key the error points to.

    Returns:
        The score as a float.

    Raises:
        ConstraintsError: When the value is not a finite number.
    """
    # bool is an int in Python, so ``target = true`` would otherwise read as 1.
    number = value if isinstance(value, (int, float)) and not isinstance(value, bool) else math.nan
    try:
        number = float(number)
    except OverflowError:
        # A TOML integer can have hundreds of digits, more than a float holds.
        number = math.nan
    if not math.isfinite(number):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} must be a finite number, such as 0.9.",
            section=section,
            key=key,
        )
    return number


def _outcome(section: Mapping[str, Any]) -> tuple[float | None, dict[str, float]]:
    """Read the ``[outcome]`` section: the run's target score and the limit of each named score.

    Args:
        section: The parsed ``[outcome]`` table; empty when the file has none.

    Returns:
        The target, or ``None`` when the file sets none, and each limit by score name.

    Raises:
        ConstraintsError: With every error of the section: the target or a limit
            is not a finite number, or ``require`` is not a bounded table of named scores.
    """
    problems = _Problems()
    target = (
        problems.check(_score_value, section["target"], "[outcome] target", "outcome", "target")
        if "target" in section
        else None
    )
    require = section.get("require", {})
    if not isinstance(require, dict) or len(require) > _MAX_NAMES:
        problems.add(
            f"{CONSTRAINTS_FILE}: [outcome.require] must be a table of at most {_MAX_NAMES} score"
            " names, each set to its limit score.",
            section="outcome",
            key="require",
        )
        require = {}
    limits: dict[str, float] = {}
    for name, value in require.items():
        if not name:
            problems.add(
                f"{CONSTRAINTS_FILE}: [outcome.require] has an empty score name. Use the name the"
                " metric gives the score.",
                section="outcome.require",
            )
        # TOML reads an unquoted ``rouge.l = 0.5`` as the table ``rouge = {l = 0.5}``.
        elif isinstance(value, dict):
            problems.add(
                f"{CONSTRAINTS_FILE}: [outcome.require] {name} is a table. Quote a score name that"
                f' has a dot, such as "{name}.{next(iter(value), "l")}" = 0.9.',
                section="outcome.require",
                key=name,
            )
        else:
            limits[name] = problems.check(
                _score_value, value, f"[outcome.require] {name}", "outcome.require", name
            )
    problems.raise_any()
    return target, limits


def _service(section: Any, name: str, problems: _Problems) -> ServiceSpec | None:
    """Read one ``[services.<name>]`` declaration.

    The file is public with the repository, so it may name secrets but must
    never hold one. A header names each secret as ``${NAME}`` (E53), and so
    does each ``query`` value (SKY-630). Error messages never repeat a
    refused value.

    Args:
        section: The value under the service's name.
        name: The service's name.
        problems: Records every error of the declaration: it is not a table,
            has no url, has an unknown key or the removed ``secrets`` key, a
            header holds a raw secret value, or a query value is not one
            ``${NAME}``.

    Returns:
        The declaration. When it has an error, it holds only its valid parts,
        so the rules across sections still check them, and ``url`` is
        ``None`` when the url has an error. ``None`` when it is not a table.
    """
    if not isinstance(section, dict):
        problems.add(
            f"{CONSTRAINTS_FILE}: [services] {name[:100]} must be a [services.<name>] table with a"
            " url and headers. A repository file cannot grant services with a value.",
            section="services",
            key=name,
        )
        return None
    if not _TABLE_NAME.fullmatch(name):
        problems.add(
            f"{CONSTRAINTS_FILE}: the service name {name[:100]!r} must start with a letter or digit"
            " and use only letters, digits, '-' and '_' (at most 64).",
            section=f"services.{name}",
        )
    label = f"[services.{name}]"
    # The older form listed names in secrets = [...]
    # (E53); name the move instead of "not supported".
    if "secrets" in section:
        problems.add(
            f"{CONSTRAINTS_FILE}: {label} secrets is no longer supported. Remove it and write each"
            ' secret as ${NAME} in headers, such as Authorization = "Bearer ${API_KEY}".',
            section=f"services.{name}",
            key="secrets",
        )
    for key in sorted(set(section) - _SERVICE_KEYS - {"secrets"}):
        problems.add(
            f"{CONSTRAINTS_FILE}: {label} {key[:100]} is not a supported setting. A service"
            " has only a url, headers and query; write each secret as ${NAME} in headers or"
            " query, never as a value." + _did_you_mean(key, _SERVICE_KEYS),
            section=f"services.{name}",
            key=key,
        )
    # The secrets error already asks for a rewrite of the table, so it gives no url error too.
    if "secrets" not in section and _missing(section, "url", _SERVICE_KEYS):
        problems.add(
            f'{CONSTRAINTS_FILE}: {label} needs a url, such as url = "https://api.example.com".',
            section=f"services.{name}",
            key="url",
        )
    headers = None
    if "headers" in section:
        headers = problems.check(_service_headers, section["headers"], label)
        if headers is None:
            headers = _valid_items(_service_headers, section["headers"], label) or None
    query = {}
    if "query" in section:
        query = problems.check(_service_query, section["query"], label)
        if query is None:
            query = _valid_items(_service_query, section["query"], label)
    url = problems.check(_service_url, section["url"], label) if "url" in section else None
    return ServiceSpec(
        secrets=_placeholders(*(headers or {}).values(), *query.values()),
        url=url,
        headers=headers,
        query=query,
    )


def _valid_items(
    read: Callable[[Any, str], dict[str, str]], value: Any, label: str
) -> dict[str, str]:
    """Return the items of a table that pass ``read`` one by one, without new errors.

    The caller already recorded the errors of the whole table.

    Args:
        read: The reader of the whole table, such as :func:`_service_headers`.
        value: The table as parsed.
        label: The table as the file names it.

    Returns:
        The valid items, in file order.
    """
    if not isinstance(value, dict) or len(value) > _MAX_NAMES:
        return {}
    kept: dict[str, str] = {}
    for item in value.items():
        try:
            kept |= read(dict([item]), label)
        except ConstraintsError:
            continue
    return kept


def _public_host(host: str) -> bool:
    """Return whether a host name passes the parse-time public-host check.

    The check reads only the text. A public name can still resolve to a private
    address, so the caller that connects must check the address too.

    Args:
        host: The lowercase host, without a port, a ``*.`` prefix or a final dot.

    Returns:
        ``False`` for an IP address, ``localhost``, a name that ends in
        ``.localhost``, ``.internal`` or ``.local``, a name that holds a dotted
        IPv4 address, a name with no dot, or a name whose last label has no letter.
    """
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    # inet_aton reads the IPv4 forms that ip_address refuses, such as 0x7f.0x1 or
    # 169.254.169.0xfe, the way an HTTP client resolves them.
    try:
        socket.inet_aton(host)
        return False
    except (OSError, ValueError):  # ValueError: a NUL in the host, which TOML's \u0000 allows
        pass
    # A last label with no letter also catches IP forms that ip_address refuses, such as 0x7f.1.
    last = host.rsplit(".", 1)[-1]
    return not (
        host == "localhost"
        or host.endswith((".localhost", ".internal", ".local"))
        or _DOTTED_IPV4.search(host)
        or "." not in host
        or not _HOST.fullmatch(host)
        or not any(char.isalpha() for char in last)
    )


def _service_url(value: Any, label: str, prefix: str = CONSTRAINTS_FILE) -> str:
    """Read the ``url`` of a service or an http MCP server: https on a public host (E45, E49).

    This is a parse-time check of the written text only. It refuses the
    obvious internal names early, but a public name can still resolve to a
    private address. The relay that calls the url (SKY-374) must resolve the
    host and refuse private, loopback and link-local addresses at connect
    time; this check does not stop SSRF on its own.

    Args:
        value: The ``url`` value as parsed.
        label: The service's table or the MCP server, used in errors.
        prefix: The file the error names first.

    Returns:
        The url as written.

    Raises:
        ConstraintsError: When the value is not https, holds credentials, a
            placeholder or what looks like a raw secret, or names an IP address, ``localhost``, an
            ``.internal`` or ``.local`` name, a name that holds a dotted IPv4
            address, or a host without a domain.
    """
    if (
        not isinstance(value, str)
        or len(value) > _MAX_URL_CHARS
        or not value.startswith("https://")
    ):
        raise ConstraintsError(
            f"{prefix}: {label} url must be an https:// address.", **_at(f"{label} url")
        )
    # A secret in the url would reach logs and the box; only headers carry secrets.
    if "${" in value:
        raise ConstraintsError(
            f"{prefix}: {label} url must not hold a ${{NAME}} secret; put it in headers.",
            **_at(f"{label} url"),
        )
    try:
        parts = urlsplit(value)
        parts.port  # noqa: B018 - reading it raises ValueError for a bad port
    except ValueError as error:
        raise ConstraintsError(
            f"{prefix}: {label} url is not a valid address.", **_at(f"{label} url")
        ) from error
    if _looks_secret(" ".join(re.split(r"[/?&#=]+", f"{parts.path}?{parts.query}"))):
        raise ConstraintsError(
            f"{prefix}: {label} url holds what looks like a secret value. Put the secret in headers"
            " as ${NAME}.",
            **_at(f"{label} url"),
        )
    if parts.username is not None or parts.password is not None:
        raise ConstraintsError(
            f"{prefix}: {label} url must not hold credentials; write the secret as ${{NAME}} in"
            " headers.",
            **_at(f"{label} url"),
        )
    if not _public_host((parts.hostname or "").rstrip(".")):
        raise ConstraintsError(
            f"{prefix}: {label} url must name a public host such as api.example.com, not an IP"
            " address or localhost.",
            **_at(f"{label} url"),
        )
    return value


def _service_headers(value: Any, label: str, prefix: str = CONSTRAINTS_FILE) -> dict[str, str]:
    """Read a ``headers`` table whose values name secrets only as ``${NAME}`` (E45, E53).

    Args:
        value: The ``headers`` value as parsed.
        label: The service's table or the MCP server, used in errors.
        prefix: The file the error names first.

    Returns:
        The headers as written.

    Raises:
        ConstraintsError: With an error for each bad header: the value is not
            a table of header names to one line of text, a placeholder is
            malformed, or a value holds what looks like a raw secret.
    """
    if not isinstance(value, dict) or len(value) > _MAX_NAMES:
        raise ConstraintsError(
            f"{prefix}: {label} headers must be a table of at most {_MAX_NAMES} header names to"
            " text.",
            **_at(f"{label} headers"),
        )
    problems = _Problems()
    for header, text in value.items():
        if not _HEADER_NAME.fullmatch(header):
            problems.add(
                f"{prefix}: {label} header name {header[:100]!r} must use only letters, digits and"
                " '-'.",
                **_at(f"{label} headers"),
            )
        if (
            not isinstance(text, str)
            or len(text) > _MAX_HEADER_CHARS
            or "\r" in text
            or "\n" in text
        ):
            problems.add(
                f"{prefix}: {label} headers {header} must be one line of at most"
                f" {_MAX_HEADER_CHARS} characters.",
                **_at(f"{label} headers"),
            )
        else:
            problems.check(_check_value, text, f"{label} headers {header}", prefix)
    problems.raise_any()
    return dict(value)


def _service_query(value: Any, label: str) -> dict[str, str]:
    """Read a service's ``query`` table: each value is one ``${NAME}`` placeholder (SKY-630).

    The relay adds each parameter, filled, to the url it calls. A query value
    is never mixed text, so it can only name a secret, never hold one.

    Args:
        value: The ``query`` value as parsed.
        label: The service's table, used in errors.

    Returns:
        The query parameters as written.

    Raises:
        ConstraintsError: With an error for each bad parameter: the value is
            not a table of parameter names to one ``${NAME}`` each. The
            message never repeats a value.
    """
    if not isinstance(value, dict) or len(value) > _MAX_NAMES:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {label} query must be a table of at most {_MAX_NAMES} parameter"
            ' names to ${NAME}, such as query = { key = "${MAPS_API_KEY}" }.',
            **_at(f"{label} query"),
        )
    problems = _Problems()
    for name, text in value.items():
        if not _QUERY_NAME.fullmatch(name):
            problems.add(
                f"{CONSTRAINTS_FILE}: {label} query name {name[:100]!r} must use only letters,"
                " digits, '_', '.' and '-'.",
                **_at(f"{label} query"),
            )
        placeholder = _PLACEHOLDER.fullmatch(text) if isinstance(text, str) else None
        if placeholder is None or not _SECRET_NAME.fullmatch(placeholder.group(1)):
            problems.add(
                f"{CONSTRAINTS_FILE}: {label} query {name} must be one ${{NAME}} placeholder with"
                ' A-Z, 0-9 and _ only, such as "${MAPS_API_KEY}". The file is public with the'
                " repository; save the value as a Skynet secret.",
                **_at(f"{label} query"),
            )
    problems.raise_any()
    return dict(value)


def _check_value(text: str, where: str, prefix: str) -> None:
    """Check that a header value names secrets only as ``${NAME}`` placeholders (E49).

    Args:
        text: The value as written.
        where: The setting that holds the value, used in errors.
        prefix: The file the error names first.

    Raises:
        ConstraintsError: When a placeholder is not a secret name, a ``${`` is
            not closed, or the text outside the placeholders looks like a raw
            secret. The message never repeats the value.
    """
    for name in _PLACEHOLDER.findall(text):
        if not _SECRET_NAME.fullmatch(name):
            raise ConstraintsError(
                f"{prefix}: {where} uses a placeholder that is not a secret name. Write ${{NAME}}"
                " with A-Z, 0-9 and _ only, such as ${MAPS_API_KEY}.",
                **_at(where),
            )
    rest = _PLACEHOLDER.sub(" ", text)
    if "${" in rest:
        raise ConstraintsError(
            f"{prefix}: {where} has a ${{ that is not closed. Write each secret as ${{NAME}}.",
            **_at(where),
        )
    if _looks_secret(rest):
        raise ConstraintsError(
            f"{prefix}: {where} holds what looks like a secret value. The file is public with the"
            " repository. Save the value as a Skynet secret and write ${NAME} here instead, such"
            ' as "Bearer ${API_KEY}".',
            **_at(where),
        )


def _looks_secret(text: str) -> bool:
    """Report whether text outside the placeholders looks like a raw key or token.

    A known key prefix counts, and so does a long run of letters and digits
    that is not a path or a dashed slug. It is a guard against a pasted key,
    not proof that a value is safe.

    Args:
        text: The value with its placeholders removed.

    Returns:
        Whether a part of the text looks like a secret.
    """
    for token in re.split(r"[\s,;=\"']+", text):
        if (len(token) >= 12 and _SECRET_PREFIX.match(token)) or _UUID.fullmatch(token):
            return True
        if (
            _SECRET_TOKEN.fullmatch(token)
            and not token.startswith(("/", "./", "../", "~/"))
            and token.count("-") < 3
            and sum(char.isdigit() for char in token) >= 4
            and sum(char.isalpha() for char in token) >= 4
        ):
            return True
    return False


def _placeholders(*texts: str) -> tuple[str, ...]:
    """Return the secret names the texts use as ``${NAME}``, in order and without repeats.

    Args:
        *texts: Header values.

    Returns:
        The names.
    """
    return tuple(dict.fromkeys(name for text in texts for name in _PLACEHOLDER.findall(text)))


def _host_of(url: str) -> str:
    """Return the lowercase host of an accepted url, without a trailing dot.

    Args:
        url: A url :func:`_service_url` accepted.

    Returns:
        The host name.
    """
    return (urlsplit(url).hostname or "").rstrip(".").lower()


def _named_tables(document: Mapping[str, Any], section_name: str) -> Mapping[str, Any]:
    """Return the tables of a section that holds one table per name.

    Args:
        document: The parsed file.
        section_name: ``target`` or ``services``.

    Returns:
        The tables by name; empty when the section is absent.

    Raises:
        ConstraintsError: When the section holds too many tables.
    """
    tables = document.get(section_name, {})
    if len(tables) > _MAX_TABLES:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: [{section_name}] may hold at most {_MAX_TABLES} tables.",
            section=section_name,
        )
    return tables


def _metric_path(section: Mapping[str, Any], key: str) -> str | None:
    """Read one optional path from ``[metric]``.

    Args:
        section: The parsed ``[metric]`` table.
        key: ``exploits`` or ``reference``.

    Returns:
        The cleaned path, or ``None`` when the key is absent.

    Raises:
        ConstraintsError: When the value is not a path inside the repository.
    """
    if key not in section:
        return None
    if not isinstance(section[key], str):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: [metric] {key} must be a text path.", section="metric", key=key
        )
    return _clean_path(section[key], f"[metric] {key}")


def _metric(section: Mapping[str, Any], problems: _Problems) -> MetricSpec:
    """Read the ``[metric]`` section.

    Each setting is checked on its own; a setting with an error gets its unset
    value. The errors are a path that is malformed or names the whole
    repository, an ``entry`` that is neither form or is a command that runs no
    file from ``[metric] files``, a ``setup`` that is not bounded text, and a
    ``[metric.scores]`` that is not a bounded table of directions.

    Args:
        section: The parsed ``[metric]`` table; empty when the file has none.
        problems: Records each error.

    Returns:
        The section, with the default exploit folder when none is set.
    """
    errors = len(problems.errors)
    items = _path_items(section, "files", problems, "metric")
    # A repeated path is still a valid path, so only a bad path or list makes files invalid.
    files_valid = len(problems.errors) == errors
    files = () if items is None else _distinct(items, "[metric] files", problems)
    exploits = problems.check(_metric_path, section, "exploits") or _DEFAULT_EXPLOITS
    reference = problems.check(_metric_path, section, "reference")
    # The runtime hides these paths from the agent, so "." would hide the whole repository.
    if "." in (*files, exploits, reference):
        problems.add(
            f"{CONSTRAINTS_FILE}: [metric] cannot name the whole repository.", section="metric"
        )
    entry = (
        problems.check(_entry, section["entry"], "[metric]", default=DEFAULT_METRIC_ENTRY)
        if "entry" in section
        else DEFAULT_METRIC_ENTRY
    )
    # Only the [metric] files reach the metric box, hidden from the agent; a
    # command that runs no such file would run nothing the contract pins.
    if (
        files_valid
        and isinstance(entry, tuple)
        and not any(_inside(posixpath.normpath(part.strip()), files) for part in entry)
    ):
        problems.add(
            f"{CONSTRAINTS_FILE}: [metric] entry {list(entry)!r} runs no file from [metric] files."
            " Add the"
            ' command\'s file to [metric] files, for example files = ["metric.sh"] and entry ='
            ' ["./metric.sh"].',
            section="metric",
            key="entry",
        )
    direction = section.get("direction", MAXIMIZE)
    if direction not in DIRECTIONS:
        problems.add(
            f'{CONSTRAINTS_FILE}: [metric] direction must be "{MAXIMIZE}" or "{MINIMIZE}".',
            section="metric",
            key="direction",
        )
        direction = MAXIMIZE
    setup = (
        problems.check(_shell_command, section["setup"], "[metric] setup")
        if "setup" in section
        else None
    )
    return MetricSpec(
        files=files,
        exploits=exploits,
        reference=reference,
        entry=entry,
        direction=direction,
        setup=setup,
        scores=problems.check(_score_directions, section.get("scores", {}), default={}),
    )


def _score_directions(table: Any) -> dict[str, str]:
    """Read ``[metric.scores]``: the direction of each named score that the table names.

    Args:
        table: The parsed ``[metric.scores]`` table; empty when the file has none.

    Returns:
        Each direction by score name. A name that the table omits is a maximize score.

    Raises:
        ConstraintsError: With an error for each bad entry: the table is not a
            bounded table, a name is empty or unquoted with a dot, or a value
            is not one of the two directions.
    """
    if not isinstance(table, dict) or len(table) > _MAX_NAMES:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: [metric.scores] must be a table of at most {_MAX_NAMES} score"
            f' names, each set to "{MAXIMIZE}" or "{MINIMIZE}".',
            section="metric",
            key="scores",
        )
    problems = _Problems()
    directions: dict[str, str] = {}
    for name, value in table.items():
        if not name:
            problems.add(
                f"{CONSTRAINTS_FILE}: [metric.scores] has an empty score name. Use the name the"
                " metric gives the score.",
                section="metric.scores",
            )
        # TOML reads an unquoted ``rouge.l = "minimize"`` as the table ``rouge = {l = "minimize"}``.
        elif isinstance(value, dict):
            problems.add(
                f"{CONSTRAINTS_FILE}: [metric.scores] {name} is a table. Quote a score name that"
                f' has a dot, such as "{name}.{next(iter(value), "l")}" = "{MINIMIZE}".',
                section="metric.scores",
                key=name,
            )
        elif value not in DIRECTIONS:
            problems.add(
                f'{CONSTRAINTS_FILE}: [metric.scores] {name} must be "{MAXIMIZE}" or "{MINIMIZE}".',
                section="metric.scores",
                key=name,
            )
        else:
            directions[name] = value
    problems.raise_any()
    return directions


def _cases_file(section: Mapping[str, Any] | None) -> str | None:
    """Read the ``[data]`` section: the path of the run's JSONL cases file (E58).

    Args:
        section: The parsed ``[data]`` table, or ``None`` when the file has none.

    Returns:
        The repository path of the cases file, or ``None`` when there is no ``[data]``.

    Raises:
        ConstraintsError: When ``[data]`` has no ``cases``
            path, or the value is not a path to one file.
    """
    if section is None:
        return None
    if "cases" not in section:
        if not _missing(section, "cases", _SECTIONS["data"]):
            return None
        raise ConstraintsError(
            f'{CONSTRAINTS_FILE}: [data] must set cases = "<path>" to a JSONL file of cases, or be'
            " removed.",
            section="data",
            key="cases",
        )
    if not isinstance(section["cases"], str):
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: [data] cases must be the path of one JSONL file.",
            section="data",
            key="cases",
        )
    return _one_file(section["cases"], "[data] cases")


def _refuse_visible_cases(cases_file: str | None, rule_files: list[tuple[str, str | None]]) -> None:
    """Refuse a cases file that is also the instructions or a rule file (E61).

    The brief quotes those files to the agent, so a shared path would show it
    every ``expected`` answer.

    Args:
        cases_file: The ``[data] cases`` path, or ``None``.
        rule_files: Each text file setting and its path, or ``None`` when unset.

    Raises:
        ConstraintsError: With an error for each of those paths that equals the cases path.
    """
    if cases_file is None:
        return
    problems = _Problems()
    for setting, path in rule_files:
        if path is not None and cases_file == path:
            problems.add(
                f"{CONSTRAINTS_FILE}: [data] cases and {setting} name the same file '{path}'. The"
                " agent reads the instructions and rule files, so the cases must be in a file of"
                " their own.",
                section="data",
                key="cases",
            )
    problems.raise_any()


def _scoring_paths(metric: MetricSpec, cases_file: str | None) -> tuple[str, ...]:
    """Return the hidden paths that can hold other files: the scorer's side of the tree (E62).

    Args:
        metric: The validated ``[metric]`` section.
        cases_file: The ``[data] cases`` path, or ``None``.

    Returns:
        The ``[metric]`` files, exploit folder and reference, and the cases file.
    """
    return tuple(
        path
        for path in (*metric.files, metric.exploits, metric.reference, cases_file)
        if path is not None
    )


def _refuse_hidden_visible_files(
    scoring: Sequence[str],
    visible: list[tuple[str, str | None]],
    run_entry: str | tuple[str, ...] | None,
    metric_only: Sequence[str],
) -> None:
    """Refuse a visible file or the ``[run]`` entry inside the scorer's side (D43, E62).

    The agent's tree leaves out every path inside a hidden one, so such a
    rule file would be stripped and the brief would name a hidden path.

    Args:
        scoring: ``ascent.toml`` and the paths from ``_scoring_paths``.
        visible: Each visible file setting and its path, or ``None`` when unset.
        run_entry: The ``[run]`` entry, or ``None``.
        metric_only: The ``[metric] illegal`` and ``mcp`` files that no visible setting names.

    Raises:
        ConstraintsError: With an error for each of those paths that equals or
            lies inside a scoring path.
    """
    problems = _Problems()
    for setting, path in visible:
        if path is not None and _inside(path, scoring):
            problems.add(
                f"{CONSTRAINTS_FILE}: {setting} '{path}' is inside the hidden scoring files"
                f" ({CONSTRAINTS_FILE}, [metric] or [data] cases), but the agent must read it. Move"
                " it out of the hidden paths.",
                **_at(setting),
            )
    parts = () if run_entry is None else run_entry
    if isinstance(parts, str):
        parts = (parts.rpartition(":")[0],)
    for part in parts:
        if _inside(posixpath.normpath(part.strip()), (*scoring, *metric_only)):
            problems.add(
                f"{CONSTRAINTS_FILE}: [run] entry names '{part}', which is inside the hidden"
                f" scoring files ({CONSTRAINTS_FILE} or [metric] or [data] cases). The candidate's"
                " box does not hold them; name a visible file.",
                section="run",
                key="entry",
            )
    problems.raise_any()


def _toml_error(error: tomllib.TOMLDecodeError) -> ConstraintsError:
    """Build the error of a TOML syntax error, with the line of the error.

    Python 3.14 gives the line as ``error.lineno``; older versions give it
    only in the message, as "(at line N, column M)".

    Args:
        error: The error that ``tomllib`` raised.

    Returns:
        The error, with one diagnostic that has the line when it is known.
    """
    line = getattr(error, "lineno", None)
    if line is None:
        match = _TOML_ERROR_LINE.search(str(error))
        line = int(match.group(1)) if match else None
    message = f"{CONSTRAINTS_FILE} is not valid TOML: {error}"
    return ConstraintsError(message, errors=(Diagnostic(level=ERROR, line=line, message=message),))


def parse_constraints(
    raw: bytes,
    *,
    require_version: bool = True,
    limits: RunnerLimits = RunnerLimits(),
    legacy_forms: bool = False,
) -> RepoConstraints:
    """Validate the bytes of a constraints file.

    See :func:`_parse_constraints` for the checks.

    Args:
        raw: The file's contents.
        require_version: Whether a file with no ``version`` fails. ``False``
            reads it as version 1, for a run that started before the key
            was required (SKY-690); a wrong ``version`` fails either way.
        limits: The runner's limits, such as the most vCPUs of a box.
        legacy_forms: Only for re-reading the contract of a run that started
            under an older, lenient reader (SKY-760). ``True`` accepts each
            form that reader accepted, and gives the values that reader gave:
            a ``[setup] command`` or ``[metric] setup`` is stripped and may
            hold line breaks and tabs; a path with spaces around it, a ``\\``
            between folders or a ``/`` at the end is cleaned; each name of a
            ``services`` list is stripped; a ``network`` host is put in lower
            case; a part of a command ``entry`` may hold a control character;
            and a value that a list holds twice is dropped with no error, and
            the first stays. One difference from that reader is on purpose: a
            ``network`` entry must still be a public host, because the list
            comes from the repository and localhost or a private IP address
            would let a run reach internal hosts. All other rules stay the
            same. New checks keep the default, ``False``.

    Returns:
        The validated proposal.

    Raises:
        ConstraintsError: When the file is too large, not TOML, or holds an
            unknown, malformed, or unsupported setting. ``errors`` holds
            every error, each with its line.
    """
    token = _LEGACY_FORMS.set(legacy_forms)
    try:
        return _parse_constraints(raw, require_version=require_version, limits=limits)
    finally:
        _LEGACY_FORMS.reset(token)


def _parse_constraints(
    raw: bytes, *, require_version: bool, limits: RunnerLimits
) -> RepoConstraints:
    """Validate the bytes of a constraints file.

    Unknown sections and keys fail rather than being ignored, so a rule the
    runtime cannot enforce is never silently dropped. One check finds every
    error: only a file that is too large or not TOML stops it early. A
    setting with an error gets its unset value, and a rule that reads it is
    not checked, so one mistake gives one error.

    Args:
        raw: The file's contents.
        require_version: Whether a file with no ``version`` fails. ``False``
            reads it as version 1, for a run that started before the key
            was required (SKY-690); a wrong ``version`` fails either way.
        limits: The runner's limits, such as the most vCPUs of a box.

    Returns:
        The validated proposal.

    Raises:
        ConstraintsError: When the file is too large, not TOML, or holds an
            unknown, malformed, or unsupported setting. ``errors`` holds
            every error, each with its line.
    """
    if len(raw) > _MAX_FILE_BYTES:
        raise ConstraintsError(f"{CONSTRAINTS_FILE} is larger than {_MAX_FILE_BYTES // 1024} KiB.")
    try:
        text = raw.decode("utf-8")
        document = tomllib.loads(text)
    except UnicodeDecodeError as error:
        raise ConstraintsError(f"{CONSTRAINTS_FILE} is not valid TOML: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise _toml_error(error) from error
    except RecursionError as error:
        # tomllib recurses once for each nested array, so deep nesting under the size limit
        # overflows the stack; Skynet's own parser crashes on this input.
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE} is not valid TOML: arrays or tables are nested too deeply."
        ) from error
    problems = _Problems()
    top_keys = {name: value for name, value in document.items() if not isinstance(value, dict)}
    # A [version] table is a type error of its own, not a missing version.
    if require_version and "version" not in document and _missing(top_keys, "version", _TOP_KEYS):
        problems.add(
            f"{CONSTRAINTS_FILE}: version is missing. Put version = 1 at the top of the file,"
            " before any section.",
            key="version",
        )
    version = document.pop("version", 1)
    # ``true == 1`` and ``1.0 == 1`` in Python, so the type is checked too.
    if type(version) is not int or version != 1:
        problems.add(
            f"{CONSTRAINTS_FILE}: version {version!r} is not supported; use version = 1.",
            key="version",
        )
    # [tool.<name>] is the one place for data that
    # Skynet does not read, so only its shape is checked.
    tools = document.pop("tool", {})
    if not isinstance(tools, dict):
        problems.add(f"{CONSTRAINTS_FILE}: tool must be a [tool.<name>] table.", key="tool")
        tools = {}
    for name, table in tools.items():
        if not isinstance(table, dict):
            problems.add(
                f"{CONSTRAINTS_FILE}: tool.{name} must be a [tool.{name}] table.",
                section="tool",
                key=name,
            )
    instructions = document.pop("instructions", None)
    # The older forms held the text in the toml (E48); name the move instead of "not supported".
    if isinstance(instructions, dict):
        problems.add(
            f"{CONSTRAINTS_FILE}: [instructions] is no longer supported. Move the intent and"
            ' invariants text into a file in the repository and set instructions = "<path>" at the'
            " top of the file, before any section.",
            section="instructions",
        )
        instructions = None
    if "rules" in document:
        document.pop("rules")
        problems.add(
            f"{CONSTRAINTS_FILE}: [rules] is no longer supported. Move the rules into a markdown"
            " file in the repository, one top-level '- ' bullet for each rule, and set"
            ' illegal = "<path>" in [proposer].',
            section="rules",
        )
    # The rules across sections ask which sections the file has, so a section
    # with an error still counts as present and gives no second error.
    present = {name: bool(value) or not isinstance(value, dict) for name, value in document.items()}
    # Service names of a misspelled [services] table, such as [servics.maps].
    misspelled_services: list[str] = []
    # A services value that is not a table names no services, so no role
    # gets an error for a service that the file does not declare.
    services_unknown = False
    for name, section in list(document.items()):
        if name not in _SECTIONS and name not in _NAMED_SECTIONS:
            del document[name]
            # Callers match this text and place, so a top-level value such as
            # foo = 1 or [[foo]] keeps the error of an unknown section.
            problems.add(
                f"{CONSTRAINTS_FILE}: [{name}] is not a supported section."
                + _did_you_mean(name, (*_TOP_TABLES, *_TOP_KEYS)),
                section=name,
            )
            # The misspelling already has its error, so the rules that need the
            # section it names count that section as present, as _missing does
            # for keys. This holds also for a value that is not a table, such as rn = 1.
            close = difflib.get_close_matches(name, sorted(_TOP_TABLES), n=1)
            if close:
                present[close[0]] = True
                if close[0] == "services" and isinstance(section, dict):
                    misspelled_services += section
                elif close[0] == "services":
                    services_unknown = True
            continue
        if not isinstance(section, dict):
            problems.add(f"{CONSTRAINTS_FILE}: {name} must be a [{name}] table.", key=name)
            services_unknown |= name == "services"
            del document[name]
            continue
        if name in _NAMED_SECTIONS:
            continue
        unknown = set(section) - _SECTIONS[name]
        if name in _ROLE_SECTIONS and "tools" in section:
            problems.errors += _tools_moved(f"[{name}]").errors
            unknown.discard("tools")
        for key in sorted(unknown):
            # The split comes from the run seed (E59), so a split key would be ignored, not obeyed.
            if name == "data" and key == "split":
                problems.add(
                    f"{CONSTRAINTS_FILE}: [data] split is not supported. The run shuffles the"
                    " cases with its seed and splits them 70/15/15. Remove the setting.",
                    section="data",
                    key="split",
                )
            else:
                problems.add(
                    f"{CONSTRAINTS_FILE}: [{name}] {key} is not a supported setting."
                    + _did_you_mean(key, _SECTIONS[name]),
                    section=name,
                    key=key,
                )
    paths = document.get("paths", {})
    setup = document.get("setup", {})
    protected = _paths(paths, "protected", problems) or ()
    if "." in protected:
        problems.add(
            f"{CONSTRAINTS_FILE}: [paths] protected cannot protect the whole repository.",
            section="paths",
            key="protected",
        )
    editable = _paths(paths, "editable", problems)
    # A list whose every path is bad already has an error for each path.
    if editable == () and paths.get("editable") == []:
        problems.add(
            f"{CONSTRAINTS_FILE}: [paths] editable is empty, so no version could change anything."
            " List at least one path, or remove the setting to keep the approved ones.",
            section="paths",
            key="editable",
        )
    # Every declared name counts, so a role that names a service with an error gets no second one.
    declared = None if services_unknown else (*document.get("services", {}), *misspelled_services)
    # A stage or service with an error keeps its valid parts, so the rules
    # across sections still check them and a second mistake is not hidden.
    services = {
        name: spec
        for name, table in problems.check(_named_tables, document, "services", default={}).items()
        if (spec := _service(table, name, problems)) is not None
    }
    stages = {
        name: stage
        for name, table in problems.check(_named_tables, document, "target", default={}).items()
        if (stage := _target(table, name, declared, limits, problems)) is not None
    }
    targets = {name: stage for name, stage in stages.items() if isinstance(stage, TargetStage)}
    proposer_section = document.get("proposer", {})
    proposer = _role(proposer_section, "[proposer]", declared, problems)
    proposer_entry = problems.check(_command, proposer_section, "entry", "[proposer]")
    proposer_setup = problems.check(_command, proposer_section, "setup", "[proposer]")
    if "setup" in proposer_section and _missing(proposer_section, "entry", _SECTIONS["proposer"]):
        problems.add(
            f"{CONSTRAINTS_FILE}: [proposer] setup needs [proposer] entry. setup prepares your own"
            " proposer command; add entry, or remove setup to use the runner's own agent.",
            section="proposer",
            key="setup",
        )
    run_entry, run_timeout = _run(document.get("run"), limits, problems)
    run_section = document.get("run", {})
    run_role = _role(run_section, "[run]", declared, problems)
    metric_section = document.get("metric", {})
    metric_role = _role(metric_section, "[metric]", declared, problems)
    # A url with an error is None, and an unknown host is no second host for a secret.
    problems.check(
        _check_secret_receivers,
        {name: spec for name, spec in services.items() if spec.url is not None},
        {},
    )
    instructions_file = (
        None if instructions is None else problems.check(_one_file, instructions, "instructions")
    )
    cases_file = problems.check(_cases_file, document.get("data"))
    sandbox = document.get("sandbox", {})
    compose_file = (
        problems.check(_one_file, sandbox["compose"], "[sandbox] compose")
        if "compose" in sandbox
        else None
    )
    outcome_target, outcome_limits = problems.check(
        _outcome, document.get("outcome", {}), default=(None, {})
    )
    rule_files = [("instructions", instructions_file)]
    rule_files += [
        (label, role["illegal_file"])
        for label, role in (
            ("[proposer] illegal", proposer),
            ("[run] illegal", run_role),
            ("[metric] illegal", metric_role),
        )
    ]
    rule_files += [
        (f"[target.{name}] illegal", stage.illegal_file) for name, stage in stages.items()
    ]
    problems.check(_refuse_visible_cases, cases_file, rule_files)
    metric = _metric(metric_section, problems)
    # A rule file that is the cases file already has its error, so the hidden-file rule skips it.
    visible = [
        (setting, path)
        for setting, path in rule_files
        if setting != "[metric] illegal" and (cases_file is None or path != cases_file)
    ]
    visible += [("[proposer] mcp", proposer["mcp"]), ("[run] mcp", run_role["mcp"])]
    visible += [(f"[target.{name}] mcp", stage.mcp) for name, stage in stages.items()]
    visible_paths = {path for _, path in visible}
    metric_only = [
        path
        for path in (metric_role["illegal_file"], metric_role["mcp"])
        if path not in visible_paths
    ]
    scoring = _scoring_paths(metric, cases_file)
    # An invalid exploits falls back to the default folder, which the file did
    # not name, so checking other paths against it would report a false error.
    if any(error.section == "metric" and error.key == "exploits" for error in problems.errors):
        scoring = tuple(path for path in scoring if path != metric.exploits)
    # "." already has its own error, and every path is inside it.
    scoring = tuple(path for path in scoring if path != ".")
    problems.check(
        _refuse_hidden_visible_files,
        (CONSTRAINTS_FILE, *scoring),
        visible,
        run_entry,
        [path for path in metric_only if path is not None],
    )
    run_vcpus = (
        problems.check(_vcpus, run_section["vcpus"], "[run]", "run", limits)
        if "vcpus" in run_section
        else None
    )
    metric_vcpus = (
        problems.check(_vcpus, metric_section["vcpus"], "[metric]", "metric", limits)
        if "vcpus" in metric_section
        else None
    )
    # The metric box holds no repository tree (SKY-398), so a metric with no [run]
    # and no target stage sees nothing of the version and gives each one the same score.
    # The metric code can come with the run request,
    # so the rule holds with no [metric] too (SKY-761).
    if "run" not in present and not present.get("target"):
        if "metric" in present:
            problems.add(
                f"{CONSTRAINTS_FILE}: [metric] has nothing to judge. The metric box holds no"
                " repository files, so add a [run] section or a [target.<name>] stage whose"
                " outputs the metric scores.",
                section="metric",
            )
        else:
            problems.add(
                f"{CONSTRAINTS_FILE}: the metric cannot score a version with no output. Add a [run]"
                " section or a [target.<name>] stage whose outputs the metric scores."
            )
    # A command metric reads only its input file; it has no call() helper to run a stage itself.
    elif isinstance(metric.entry, tuple) and "run" not in present:
        problems.add(
            f"{CONSTRAINTS_FILE}: a command [metric] entry scores the [run] output, and this file"
            " has no [run] section. Add [run], or use a Python entry such as entry ="
            ' "metric.py:score".',
            section="metric",
            key="entry",
        )
    setup_command = (
        problems.check(_shell_command, setup["command"], "[setup] command")
        if "command" in setup
        else None
    )
    problems.raise_any(text)
    return RepoConstraints(
        sha256=hashlib.sha256(raw).hexdigest(),
        editable_paths=editable,
        protected_paths=protected,
        setup_command=setup_command,
        run_entry=run_entry,
        run_timeout=run_timeout,
        run_role=RoleEnvironment(**run_role),
        metric_role=RoleEnvironment(**metric_role),
        run_vcpus=run_vcpus,
        metric_vcpus=metric_vcpus,
        instructions_file=instructions_file,
        proposer=RoleEnvironment(**proposer),
        proposer_entry=proposer_entry,
        proposer_setup=proposer_setup,
        targets=targets,
        services=services,
        metric=metric,
        cases_file=cases_file,
        compose_file=compose_file,
        outcome_target=outcome_target,
        outcome_limits=outcome_limits,
    )


def read_constraints(
    archive: Path,
    *,
    require_version: bool = True,
    limits: RunnerLimits = RunnerLimits(),
    compose_parser: Callable[[str], tuple[Any, ...]] | None = None,
    legacy_forms: bool = False,
) -> RepoConstraints | None:
    """Read the constraints file at the root of a packed snapshot.

    See :func:`_read_constraints` for the checks.

    Args:
        archive: The repository tree as a gzip tar archive.
        require_version: Passed to :func:`parse_constraints`.
        limits: Passed to :func:`parse_constraints`.
        compose_parser: The runner's reader of the ``[sandbox] compose`` file's
            text, as for :func:`_read_constraints`.
        legacy_forms: Only for re-reading the contract of a run that started
            under an older, lenient reader (SKY-760). Passed to
            :func:`parse_constraints`, and also lets an MCP server ``type`` of
            a named ``.mcp.json`` file match in any case. New checks keep the
            default, ``False``.

    Returns:
        The validated proposal, or ``None`` when the repository has no such file.

    Raises:
        ConstraintsError: As for :func:`_read_constraints`.
    """
    token = _LEGACY_FORMS.set(legacy_forms)
    try:
        return _read_constraints(
            archive, require_version=require_version, limits=limits, compose_parser=compose_parser
        )
    finally:
        _LEGACY_FORMS.reset(token)


def _read_constraints(
    archive: Path,
    *,
    require_version: bool,
    limits: RunnerLimits,
    compose_parser: Callable[[str], tuple[Any, ...]] | None,
) -> RepoConstraints | None:
    """Read the constraints file at the root of a packed snapshot.

    The named files are checked only when ``ascent.toml`` itself has no error.
    When it has one, the raised error lists only the mistakes of ``ascent.toml``,
    because a path with an error names no file to check.

    The package does not know the Compose format, which belongs to the runner.
    With no ``compose_parser``, the ``[sandbox] compose`` file is not read and
    ``compose_services`` stays empty.

    Args:
        archive: The repository tree as a gzip tar archive.
        require_version: Passed to :func:`parse_constraints`.
        limits: Passed to :func:`parse_constraints`.
        compose_parser: The runner's reader of the ``[sandbox] compose`` file's
            text. It returns the services and raises ``ValueError`` with the
            reason when the box cannot run the file.

    Returns:
        The validated proposal, or ``None`` when the repository has no such file.

    Raises:
        ConstraintsError: When the file is not a regular file or is invalid, when
            a named MCP file is missing or not a valid ``mcpServers`` file, when
            one secret goes to two hosts, when a named instructions or rule
            file is missing, not a regular text file, too large, empty, or not
            a list of top-level bullets, or when the ``[data] cases`` file is
            missing, too large, empty, or has a line that is not one case,
            or, with a ``compose_parser``, when the ``[sandbox] compose`` file
            is missing or the parser refuses it, or when a ``[proposer] entry`` or
            ``setup`` argument names a symbolic link, a path inside one, or a
            folder that holds one.
    """
    raw = read_constraints_file(archive)
    if raw is None:
        return None
    constraints = _parse_constraints(raw, require_version=require_version, limits=limits)
    # Each loader fills its own fields, so one that fails leaves the others valid input.
    problems = _Problems()
    constraints = _load_mcp_files(constraints, archive, problems)
    problems.check(_check_secret_receivers, constraints.services, constraints.mcp_roles)
    constraints = problems.check(_load_rule_files, constraints, archive, default=constraints)
    constraints = problems.check(_load_cases, constraints, archive, default=constraints)
    if compose_parser is not None:
        constraints = problems.check(
            _load_compose, constraints, archive, compose_parser, default=constraints
        )
    constraints = problems.check(_load_command_files, constraints, archive, default=constraints)
    problems.raise_any(raw.decode("utf-8"))
    return constraints


def _load_command_files(constraints: RepoConstraints, archive: Path) -> RepoConstraints:
    """Find the repository files and folders that ``[proposer] entry`` and ``setup`` name.

    An argument names a path when, normalized, it is relative and equals a
    file or a symbolic link of the snapshot, such as ``agent/run.js``, or a
    folder that holds one, such as ``agent`` in ``npm ci --prefix agent``.
    The checkout root (``.``) is never one, and a protected folder covers all
    its files.

    Args:
        constraints: The parsed proposal.
        archive: The repository tree as a gzip tar archive, the same snapshot the toml came from.

    Returns:
        The proposal with ``proposer_command_files`` filled, unchanged without an entry.

    Raises:
        ConstraintsError: With one error for each argument that names a
            symbolic link of the snapshot, a path inside a linked folder, or a
            folder that holds a symbolic link at any depth.
    """
    if constraints.proposer_entry is None:
        return constraints
    with tarfile.open(archive, "r:gz") as packed:
        members = [member for member in packed.getmembers() if member.isfile() or member.issym()]
    files = {PurePosixPath(member.name) for member in members}
    links = {str(PurePosixPath(member.name)) for member in members if member.issym()}
    paths = {str(path) for file in files for path in (file, *file.parents)} - {"."}
    problems = _Problems()
    named: list[str] = []
    for key, command in (
        ("entry", constraints.proposer_entry),
        ("setup", constraints.proposer_setup or ()),
    ):
        for part in command:
            if part.startswith("/"):
                continue
            path = posixpath.normpath(part)
            # Protection matches paths, so a link would leave the code it
            # points at open to a version; refuse it, as for hidden paths.
            link = next(
                (
                    str(p)
                    for p in (PurePosixPath(path), *PurePosixPath(path).parents)
                    if str(p) in links
                ),
                None,
            )
            if link is not None:
                problems.add(
                    f"{CONSTRAINTS_FILE}: [proposer] {key} names '{part}', which goes through the"
                    f" symbolic link '{link}'. Name the real path, so that no version can change"
                    " the proposer.",
                    section="proposer",
                    key=key,
                )
                continue
            # A named folder protects its paths, not the files that its links
            # point at, so a link anywhere inside it is refused too.
            inner = next((name for name in sorted(links) if name.startswith(f"{path}/")), None)
            if inner is not None:
                problems.add(
                    f"{CONSTRAINTS_FILE}: [proposer] {key} names the folder '{part}', which holds"
                    f" the symbolic link '{inner}'. Remove the link from the folder, so that no"
                    " version can change the proposer.",
                    section="proposer",
                    key=key,
                )
                continue
            if path in paths:
                named.append(path)
    problems.raise_any()
    return replace(constraints, proposer_command_files=tuple(dict.fromkeys(named)))


def _load_compose(
    constraints: RepoConstraints, archive: Path, compose_parser: Callable[[str], tuple[Any, ...]]
) -> RepoConstraints:
    """Fill the compose services from the ``[sandbox] compose`` file.

    Args:
        constraints: The parsed proposal.
        archive: The repository tree as a gzip tar archive, the same snapshot the toml came from.
        compose_parser: The runner's reader of the file's
            text; it raises ``ValueError`` to refuse it.

    Returns:
        The proposal with ``compose_services`` filled, unchanged when there is no compose file.

    Raises:
        ConstraintsError: When the file is missing, not a regular text file,
            too large, or refused by ``compose_parser``.
    """
    path = constraints.compose_file
    if path is None:
        return constraints
    with tarfile.open(archive, "r:gz") as packed:
        members = {str(PurePosixPath(m.name)): m for m in packed.getmembers()}
        text = _read_text_file(packed, members.get(path), "[sandbox] compose", path)
    try:
        services = compose_parser(text)
    except ValueError as error:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: [sandbox] compose names '{path}': {error}",
            section="sandbox",
            key="compose",
        ) from None
    return replace(constraints, compose_services=services)


def _load_cases(constraints: RepoConstraints, archive: Path) -> RepoConstraints:
    """Fill the run's cases from the ``[data] cases`` JSONL file (E58).

    Args:
        constraints: The parsed proposal.
        archive: The repository tree as a gzip tar archive, the same snapshot the toml came from.

    Returns:
        The proposal with ``cases`` filled, unchanged when there is no ``[data]``.

    Raises:
        ConstraintsError: When the file is missing, is a link or folder, is too
            large, is not UTF-8, or holds no case or too many. Also with one
            error for each line, up to the first ``_MAX_CASE_LINE_ERRORS``, that
            is not a JSON object with ``input`` and an optional ``expected``.
    """
    path = constraints.cases_file
    if path is None:
        return constraints
    setting = "[data] cases"
    with tarfile.open(archive, "r:gz") as packed:
        member = next((m for m in packed.getmembers() if str(PurePosixPath(m.name)) == path), None)
        if member is None:
            raise ConstraintsError(
                f"{CONSTRAINTS_FILE}: {setting} names '{path}', but the repository has no such"
                " file.",
                **_at(setting),
            )
        if not member.isfile():
            raise ConstraintsError(
                f"{CONSTRAINTS_FILE}: {setting} names '{path}', which must be a regular file, not a"
                " link or folder.",
                **_at(setting),
            )
        if member.size > _MAX_CASES_FILE_BYTES:
            raise ConstraintsError(
                f"{CONSTRAINTS_FILE}: {setting} names '{path}', which is larger than"
                f" {_MAX_CASES_FILE_BYTES // (1024 * 1024)} MiB.",
                **_at(setting),
            )
        handle = packed.extractfile(member)
        data = handle.read() if handle is not None else b""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} names '{path}', which is not UTF-8 text.",
            **_at(setting),
        ) from exc
    cases: list[dict[str, Any]] = []
    problems = _Problems()
    bad_lines = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except (ValueError, RecursionError):
            case = None
        if not isinstance(case, dict) or "input" not in case or set(case) - _CASE_KEYS:
            bad_lines += 1
            if bad_lines > _MAX_CASE_LINE_ERRORS:
                problems.add(
                    f"{CONSTRAINTS_FILE}: '{path}' ({setting}) has more than"
                    f" {_MAX_CASE_LINE_ERRORS} lines that are not cases; only the first"
                    f" {_MAX_CASE_LINE_ERRORS} are shown.",
                    **_at(setting),
                )
                break
            problems.add(
                f"{CONSTRAINTS_FILE}: line {number} of '{path}' ({setting}) is not a case. Write"
                ' each case on one line as a JSON object {"input": ..., "expected": ...};'
                ' "expected" is optional.',
                **_at(setting),
            )
            continue
        cases.append(case)
        if len(cases) > _MAX_CASES:
            problems.add(
                f"{CONSTRAINTS_FILE}: '{path}' ({setting}) holds more than {_MAX_CASES} cases.",
                **_at(setting),
            )
            break
    if not cases and not bad_lines:
        problems.add(
            f"{CONSTRAINTS_FILE}: {setting} names '{path}', which holds no cases.", **_at(setting)
        )
    problems.raise_any()
    return replace(constraints, cases=tuple(cases))


def rule_file_settings(constraints: RepoConstraints) -> list[tuple[str, str]]:
    """List each setting that names an instructions or rule file, with the path it names.

    Args:
        constraints: The parsed proposal.

    Returns:
        ``(setting, path)`` pairs in file order, such as ``("[proposer] illegal",
        "docs/rules.md")``.
    """
    roles = [
        ("[proposer] illegal", constraints.proposer),
        ("[run] illegal", constraints.run_role),
        ("[metric] illegal", constraints.metric_role),
        *((f"[target.{name}] illegal", stage) for name, stage in constraints.targets.items()),
    ]
    settings = [("instructions", constraints.instructions_file)]
    settings += [(setting, role.illegal_file) for setting, role in roles]
    return [(setting, path) for setting, path in settings if path is not None]


def _load_rule_files(constraints: RepoConstraints, archive: Path) -> RepoConstraints:
    """Fill the intent and every role's rules from the files the toml names (E48).

    Args:
        constraints: The parsed proposal, with paths but no rule text.
        archive: The repository tree as a gzip tar archive, the same snapshot the toml came from.

    Returns:
        The proposal with ``intent``, ``rules`` and each role's ``illegal`` filled.

    Raises:
        ConstraintsError: When a named file is missing, not a regular text file,
            too large, empty, or not a list of top-level bullets.
    """
    settings = rule_file_settings(constraints)
    if not settings:
        return constraints
    texts: dict[str, str] = {}
    # A path that failed to read is reported once, at the first setting that names it.
    failed: set[str] = set()
    problems = _Problems()
    with tarfile.open(archive, "r:gz") as packed:
        members = {str(PurePosixPath(m.name)): m for m in packed.getmembers()}
        for setting, path in settings:
            if path not in texts and path not in failed:
                text = problems.check(_read_text_file, packed, members.get(path), setting, path)
                if text is None:
                    failed.add(path)
                else:
                    texts[path] = text
    split: dict[str, tuple[str, ...]] = {}

    def rules_of(role: RoleEnvironment, setting: str) -> RoleEnvironment:
        """Return the role with its ``illegal`` rules read from its rule file."""
        path = role.illegal_file
        if path is None or path not in texts:
            return role
        if path not in split:
            split[path] = problems.check(_split_rules, texts[path], setting, path, default=())
        return replace(role, illegal=split[path])

    intent = None
    path = constraints.instructions_file
    if path is not None and path in texts:
        intent = texts[path].strip()
        if not intent:
            problems.add(
                f"{CONSTRAINTS_FILE}: instructions names '{path}', but that file is empty.",
                key="instructions",
            )
        elif len(intent) > _MAX_INTENT_CHARS:
            problems.add(
                f"{CONSTRAINTS_FILE}: the instructions file '{path}' is longer than"
                f" {_MAX_INTENT_CHARS} characters.",
                key="instructions",
            )
    proposer = rules_of(constraints.proposer, "[proposer] illegal")
    run_role = rules_of(constraints.run_role, "[run] illegal")
    metric_role = rules_of(constraints.metric_role, "[metric] illegal")
    targets = {
        name: rules_of(stage, f"[target.{name}] illegal")
        for name, stage in constraints.targets.items()
    }
    problems.raise_any()
    return replace(
        constraints,
        intent=intent,
        rules=proposer.illegal,
        proposer=proposer,
        run_role=run_role,
        metric_role=metric_role,
        targets=targets,
    )


def _read_text_file(
    packed: tarfile.TarFile, member: tarfile.TarInfo | None, setting: str, path: str
) -> str:
    """Read one instructions, rule or MCP file from the snapshot as text.

    Args:
        packed: The open snapshot.
        member: The file's entry, or ``None`` when the snapshot has no such path.
        setting: The setting that names the file, such as ``[proposer] illegal``, named in errors.
        path: The repository path the setting names.

    Returns:
        The file's text.

    Raises:
        ConstraintsError: When the file is missing, is a link
            or folder, is too large, or is not UTF-8 text.
    """
    if member is None:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} names '{path}', but the repository has no such file.",
            **_at(setting),
        )
    if not member.isfile():
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} names '{path}', which must be a regular file, not a"
            " link or folder.",
            **_at(setting),
        )
    if member.size > _MAX_RULE_FILE_BYTES:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} names '{path}', which is larger than"
            f" {_MAX_RULE_FILE_BYTES // 1024} KiB.",
            **_at(setting),
        )
    handle = packed.extractfile(member)
    try:
        # utf-8-sig drops a leading byte-order mark, which editors on Windows add.
        return (handle.read() if handle is not None else b"").decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE}: {setting} names '{path}', which is not UTF-8 text.",
            **_at(setting),
        ) from exc


def _split_rules(text: str, setting: str, path: str) -> tuple[str, ...]:
    """Split a markdown rule file into its rules: one rule for each top-level bullet.

    Indented lines, and lines that directly follow a bullet with no blank line
    between, continue that bullet. Headings and blank lines between bullets
    are allowed; any other text outside a bullet is refused, so a rule cannot
    be lost by being written as a paragraph.

    Args:
        text: The file's text.
        setting: The setting that names the file, named in errors.
        path: The file's repository path, named in errors.

    Returns:
        The rules in file order, each joined onto one line.

    Raises:
        ConstraintsError: With one error for each line of text outside a
            bullet, and for each bullet that is empty or too long, or when the
            file holds no bullet or more than the maximum bullets. Only the
            first ``_MAX_CASE_LINE_ERRORS`` errors of the file are reported.
    """
    problems = _Problems()
    rules: list[list[str]] = []
    open_rule = False
    after_blank = False
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            after_blank = True
            continue
        bullet = _BULLET.fullmatch(line.rstrip())
        if bullet is not None:
            rules.append([(bullet.group(1) or "").strip()])
            open_rule = True
        elif _HEADING.match(line):
            open_rule = False
        elif open_rule and (line[0] in " \t" or not after_blank):
            rules[-1].append(line.strip())
        else:
            problems.add(
                f"{CONSTRAINTS_FILE}: line {number} of '{path}' ({setting}) is not part of a"
                " top-level bullet. Write each rule as a line that starts with '- '.",
                **_at(setting),
            )
        after_blank = False
    # A file whose lines are all bad already has an error for each line.
    if not rules and not problems.errors:
        problems.add(
            f"{CONSTRAINTS_FILE}: {setting} names '{path}', which holds no rules. Write each rule"
            " as a line that starts with '- '.",
            **_at(setting),
        )
    if len(rules) > _MAX_RULES:
        problems.add(
            f"{CONSTRAINTS_FILE}: '{path}' ({setting}) holds {len(rules)} rules; the most is"
            f" {_MAX_RULES}.",
            **_at(setting),
        )
    joined = [" ".join(part for part in parts if part) for parts in rules]
    for number, rule in enumerate(joined, start=1):
        if not rule or len(rule) > _MAX_RULE_CHARS:
            problems.add(
                f"{CONSTRAINTS_FILE}: rule {number} in '{path}' ({setting}) must be text of 1 to"
                f" {_MAX_RULE_CHARS} characters.",
                **_at(setting),
            )
    # A 32 KiB file can have thousands of bad lines, so it reports only the first ones.
    if len(problems.errors) > _MAX_CASE_LINE_ERRORS:
        del problems.errors[_MAX_CASE_LINE_ERRORS:]
        problems.add(
            f"{CONSTRAINTS_FILE}: '{path}' ({setting}) has more than {_MAX_CASE_LINE_ERRORS}"
            f" errors; only the first {_MAX_CASE_LINE_ERRORS} are shown.",
            **_at(setting),
        )
    problems.raise_any()
    return tuple(joined)


def _load_mcp_files(
    constraints: RepoConstraints, archive: Path, problems: _Problems
) -> RepoConstraints:
    """Fill each role with the valid servers of the MCP file it names (E49).

    The files come from the same snapshot as the toml, so the servers a run
    gets are the ones the setup check showed. A file that is missing, not a
    regular text file, too large, or not a valid ``mcpServers`` file, and each
    invalid server, records an error; the valid servers stay, so that the
    secret receiver check still sees them.

    Args:
        constraints: The parsed proposal.
        archive: The repository tree as a gzip tar archive.
        problems: Records each error.

    Returns:
        The proposal with each role's ``mcp_servers`` filled.
    """
    wanted = {label: role for label, role in constraints.mcp_roles.items() if role.mcp is not None}
    if not wanted:
        return constraints
    servers: dict[str, tuple[McpServer, ...]] = {}
    # A file that two roles name is read once, so its errors appear once, at
    # the first setting that names it, as for rule files.
    by_path: dict[str, tuple[McpServer, ...]] = {}
    with tarfile.open(archive, "r:gz") as packed:
        members = {str(PurePosixPath(m.name)): m for m in packed.getmembers()}
        for label, role in wanted.items():
            path = role.mcp or ""
            if path not in by_path:
                setting = f"{label} mcp"
                text = problems.check(_read_text_file, packed, members.get(path), setting, path)
                by_path[path] = (
                    problems.check(_mcp_servers, text, setting, path, problems, default=())
                    if text is not None
                    else ()
                )
            servers[label] = by_path[path]
    return replace(
        constraints,
        proposer=replace(constraints.proposer, mcp_servers=servers.get("[proposer]", ())),
        run_role=replace(constraints.run_role, mcp_servers=servers.get("[run]", ())),
        metric_role=replace(constraints.metric_role, mcp_servers=servers.get("[metric]", ())),
        targets={
            name: replace(stage, mcp_servers=servers.get(f"[target.{name}]", ()))
            for name, stage in constraints.targets.items()
        },
    )


def _mcp_servers(text: str, setting: str, path: str, problems: _Problems) -> tuple[McpServer, ...]:
    """Read a standard ``.mcp.json`` file: ``{"mcpServers": {<name>: <server>}}`` (E49).

    Each server is an http server (``type`` http, streamable-http or sse, or a
    ``url`` with no type) with a url and headers; the relay calls it. A stdio
    server (``command``, ``args``, ``env``) fails: only http servers are
    supported now (E64). Secrets appear only as ``${NAME}`` in header values.

    Args:
        text: The file's text.
        setting: The setting that names the file, such as ``[metric] mcp``.
        path: The file's repository path.
        problems: Records the error of each server that has an unknown type or
            key, or a value that breaks the url or secret rules.

    Returns:
        The valid servers in file order.

    Raises:
        ConstraintsError: When the file is not that shape.
    """
    prefix = f"{CONSTRAINTS_FILE}: {setting} file '{path}'"
    try:
        document = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise ConstraintsError(f"{prefix} is not valid JSON.", **_at(setting)) from error
    if not isinstance(document, dict) or set(document) != {"mcpServers"}:
        raise ConstraintsError(
            f'{prefix} must be one object with only "mcpServers": {{"<name>": {{...}}}}.',
            **_at(setting),
        )
    entries = document["mcpServers"]
    if not isinstance(entries, dict) or len(entries) > _MAX_TABLES:
        raise ConstraintsError(
            f"{prefix}: mcpServers must be an object of at most {_MAX_TABLES} servers.",
            **_at(setting),
        )
    found = _Problems()
    servers = [found.check(_mcp_server, name, entry, prefix) for name, entry in entries.items()]
    # A server's errors name it inside the .mcp.json file;
    # the toml place to fix is the role's mcp setting.
    problems.errors += [replace(error, **_at(setting)) for error in found.errors]
    return tuple(server for server in servers if server is not None)


def _mcp_server(name: str, entry: Any, prefix: str) -> McpServer:
    """Read one server of an ``.mcp.json`` file.

    Args:
        name: The server's name.
        entry: The server's object.
        prefix: The file, named first in errors.

    Returns:
        The validated server.

    Raises:
        ConstraintsError: When the name, type, a key or a value is invalid.
    """
    problems = _Problems()
    if not _TABLE_NAME.fullmatch(name):
        problems.add(
            f"{prefix}: the server name {name[:100]!r} must start with a letter or digit and use"
            " only letters, digits, '-' and '_' (at most 64)."
        )
    label = f"server '{name}'"
    if not isinstance(entry, dict):
        problems.add(f"{prefix}: {label} must be an object.")
        problems.raise_any()
    # The type is matched exactly, so "HTTP" gets the type error; under legacy_forms
    # it matches in any case, as in the older reader. A type such as
    # "STDIO" still fails, but with the stdio advice, which says what to change.
    kind = entry.get("type", "http")
    if _LEGACY_FORMS.get() and isinstance(kind, str):
        kind = kind.lower()
    if (isinstance(kind, str) and kind.lower() == "stdio") or _MCP_STDIO_KEYS & set(entry):
        problems.add(
            f"{prefix}: {label} is a stdio server (command, args, env). Only http servers are"
            ' supported now; give it a "url" and put each secret in "headers" as ${NAME}.'
        )
        problems.raise_any()
    if not isinstance(kind, str) or kind not in _MCP_HTTP_TYPES:
        problems.add(f"{prefix}: {label} type must be http, streamable-http or sse.")
    for key in sorted(set(entry) - _MCP_HTTP_KEYS):
        problems.add(
            f"{prefix}: {label} {key[:100]} is not a supported setting for an http server."
            + _did_you_mean(key, _MCP_HTTP_KEYS)
        )
    if _missing(entry, "url", _MCP_HTTP_KEYS):
        problems.add(f"{prefix}: {label} needs a url.")
    headers = (
        problems.check(_service_headers, entry["headers"], label, prefix, default={})
        if "headers" in entry
        else {}
    )
    url = problems.check(_service_url, entry["url"], label, prefix) if "url" in entry else None
    problems.raise_any()
    # An absent or invalid url recorded an error, so raise_any raised.
    assert url is not None
    return McpServer(name=name, url=url, headers=headers)


def _check_secret_receivers(
    services: Mapping[str, ServiceSpec], roles: Mapping[str, RoleEnvironment]
) -> None:
    """Check that each secret goes to one host only (E52, E53 rule 3).

    The relay sends a secret only to the host it is bound to, so a file that
    sends ``${GOOGLE_MAPS_KEY}`` to a second host could leak the key there.

    Args:
        services: The file's ``[services]`` declarations.
        roles: Every role with its MCP servers, by label: ``[proposer]``,
            ``[run]``, ``[metric]`` and each ``[target.<name>]``.

    Raises:
        ConstraintsError: With an error for each use that sends a secret to a
            second host.
    """
    places: dict[str, str] = {}
    uses = [
        (name, spec.host or "", f"[services.{service}]")
        for service, spec in services.items()
        for name in spec.secrets
    ]
    for label, role in roles.items():
        for server in role.mcp_servers:
            uses += [
                (name, server.host, f"{label} mcp server '{server.name}'")
                for name in server.secrets
            ]
    problems = _Problems()
    for name, where, setting in uses:
        first = places.setdefault(name, where)
        if first != where:
            problems.add(
                f"{CONSTRAINTS_FILE}: ${{{name}}} goes to {first} and, in {setting}, to {where}. A"
                " secret may go to one host only; use a separate secret for each host.",
                **_at(setting),
            )
    problems.raise_any()


def read_constraints_file(archive: Path) -> bytes | None:
    """Read the raw bytes of the constraints file at the root of a packed snapshot.

    Args:
        archive: The repository tree as a gzip tar archive.

    Returns:
        The file's contents, not yet validated, or ``None`` when the repository has no such file.

    Raises:
        ConstraintsError: When the file is not a regular file or is too large.
    """
    with tarfile.open(archive, "r:gz") as packed:
        member = next(
            (m for m in packed.getmembers() if str(PurePosixPath(m.name)) == CONSTRAINTS_FILE), None
        )
        if member is None:
            return None
        if not member.isfile():
            raise ConstraintsError(
                f"{CONSTRAINTS_FILE} must be a regular file, not a link or folder."
            )
        if member.size > _MAX_FILE_BYTES:
            raise ConstraintsError(
                f"{CONSTRAINTS_FILE} is larger than {_MAX_FILE_BYTES // 1024} KiB."
            )
        handle = packed.extractfile(member)
        return handle.read() if handle is not None else b""


def _inside(path: str, roots: Iterable[str]) -> bool:
    """Report whether ``path`` is one of ``roots`` or lies below one.

    Args:
        path: Repository-relative path; ``.`` is the whole tree.
        roots: Repository-relative files or folders; ``.`` is the whole tree.

    Returns:
        Whether a root covers the path.
    """
    return any(
        root == "." or path == root or path.startswith(root.rstrip("/") + "/") for root in roots
    )


def scorer_only_paths(constraints: RepoConstraints) -> tuple[str, ...]:
    """Return every repository path that only the parent's scorer may read (E61, E62).

    A path that a visible role also names, such as one ``.mcp.json`` for
    ``[run]`` and ``[metric]``, stays visible, because hiding it would break
    that role. ``ascent.toml`` is always hidden: it names every hidden path.

    Args:
        constraints: The repository's validated constraints.

    Returns:
        ``ascent.toml``, the ``[metric]`` files, exploit folder, reference,
        rule file and ``mcp`` file, and the ``[data] cases`` file, without
        the keys the file does not set.
    """
    metric = constraints.metric
    hidden = (
        *metric.files,
        metric.exploits,
        metric.reference,
        constraints.cases_file,
        constraints.metric_role.illegal_file,
        constraints.metric_role.mcp,
    )
    visible = {
        constraints.instructions_file,
        constraints.proposer.illegal_file,
        constraints.proposer.mcp,
        constraints.run_role.illegal_file,
        constraints.run_role.mcp,
        *(stage.illegal_file for stage in constraints.targets.values()),
        *(stage.mcp for stage in constraints.targets.values()),
    }
    shown = (path for path in hidden if path is not None and path not in visible)
    return tuple(dict.fromkeys((CONSTRAINTS_FILE, *shown)))


def effective_environment(
    constraints: RepoConstraints | None,
    *,
    approved_editable: Sequence[str],
    approved_setup: str | None,
    approved_proposer: bool = False,
) -> RepoEnvironment:
    """Combine the customer's approved settings with what the repository proposes.

    The constraints file and every instructions, rule, MCP or Compose file it
    names are always protected, so no version can change the rules it is scored
    under or the services beside the scorer.

    Args:
        constraints: The repository's proposal, or ``None`` when it has none.
        approved_editable: Editable paths from the submitted run.
        approved_setup: Setup command from the submitted run, if any.
        approved_proposer: Whether the submitted run names its own proposer,
            which then replaces ``[proposer] entry`` and ``setup``.

    Returns:
        The rules the run is held to.

    Raises:
        ConstraintsError: When the file proposes an editable path outside the approved ones,
            an editable path lies inside a path from ``scorer_only_paths``, or the protected paths
            (always including the file itself) cover every editable path.
    """
    if constraints is None:
        editable = tuple(approved_editable)
        if all(_inside(path, (CONSTRAINTS_FILE,)) for path in editable):
            raise ConstraintsError(
                f"{CONSTRAINTS_FILE} is always protected, so the approved editable paths"
                f" ({', '.join(editable)}) leave nothing a version can change. Approve a path other"
                " than the constraints file."
            )
        return RepoEnvironment(
            editable_paths=editable,
            protected_paths=(CONSTRAINTS_FILE,),
            setup_command=approved_setup,
        )
    editable = tuple(approved_editable)
    if constraints.editable_paths is not None:
        wider = [
            path for path in constraints.editable_paths if not _inside(path, approved_editable)
        ]
        if wider:
            approved = ", ".join(approved_editable)
            raise ConstraintsError(
                f"{CONSTRAINTS_FILE} makes '{wider[0]}' editable, which is outside the approved"
                f" editable paths ({approved}). A repository file can only narrow them; widen them"
                " in the run's settings.",
                section="paths",
                key="editable",
            )
        editable = constraints.editable_paths
    use_file_proposer = constraints.proposer_entry is not None and not approved_proposer
    # A version must not rewrite the proposer command, or
    # the setup it runs, that writes the next versions.
    # Only exact argv paths are known here; the docs tell
    # users to protect the files the command imports.
    command_files = constraints.proposer_command_files if use_file_proposer else ()
    protected = tuple(
        dict.fromkeys(
            (
                CONSTRAINTS_FILE,
                *constraints.rule_files,
                *constraints.mcp_files,
                *((constraints.compose_file,) if constraints.compose_file else ()),
                *constraints.protected_paths,
                *command_files,
            )
        )
    )
    # Protected paths win over editable ones when a patch is checked, so this
    # run could only spend its budget on versions that are all refused.
    if all(_inside(path, protected) for path in editable):
        without_commands = tuple(path for path in protected if path not in command_files)
        if command_files and not all(_inside(path, without_commands) for path in editable):
            raise ConstraintsError(
                f"{CONSTRAINTS_FILE} protects every editable path ({', '.join(editable)}), because"
                " the run protects the files that [proposer] entry and setup name"
                f" ({', '.join(command_files)}), so no version could change anything. Make a path"
                " outside those files editable.",
                section="proposer",
                key="entry",
            )
        raise ConstraintsError(
            f"{CONSTRAINTS_FILE} protects every editable path ({', '.join(editable)}), so no"
            " version could change anything. Protect less, or make a path outside [paths]"
            " protected editable.",
            section="paths",
            key="protected",
        )
    # The brief names every editable path, so one inside
    # a scorer-only path would name a hidden path.
    hidden = scorer_only_paths(constraints)
    hidden_editable = [path for path in editable if _inside(path, hidden)]
    if hidden_editable:
        raise ConstraintsError(
            f"'{hidden_editable[0]}' is editable, but only the scorer reads it: it is"
            f" {CONSTRAINTS_FILE} or inside the hidden scoring files ([metric] or [data] cases)."
            " Make only paths outside them editable.",
            section="paths",
            key="editable",
        )
    notes: list[str] = []
    setup = approved_setup
    if approved_setup is not None and approved_setup.strip():
        if constraints.setup_command and constraints.setup_command != approved_setup.strip():
            notes.append(f"The run's own setup command replaces the one in {CONSTRAINTS_FILE}.")
    else:
        setup = constraints.setup_command
    if constraints.proposer_entry is not None and approved_proposer:
        notes.append("The run's own proposer replaces the one in the contract file.")
    elif use_file_proposer:
        notes.append(
            "The run uses the proposer command in the contract file:"
            f" {shlex.join(constraints.proposer_entry or ())}"
        )
    return RepoEnvironment(
        editable_paths=editable,
        protected_paths=protected,
        setup_command=setup,
        constraints=constraints,
        notes=tuple(notes),
        proposer_entry=constraints.proposer_entry if use_file_proposer else None,
        proposer_setup=constraints.proposer_setup if use_file_proposer else None,
    )


def instructions_brief(environment: RepoEnvironment, hidden_paths: Collection[str]) -> str:
    """Write the repository's rules as text the optimization agent reads.

    The agent never sees ``ascent.toml`` or the scorer's files, so this
    brief is its only copy of the rules, and it names no hidden path (E61).

    Args:
        environment: The effective rules.
        hidden_paths: The paths only the parent's scorer reads.

    Returns:
        Markdown naming the editable and the visible protected paths, the
        ``[run]`` entry and timeout, every numbered plain-language rule, the
        ``[run]`` rules and the file's instructions, marked as guidance where
        the runtime does not enforce them.
    """
    hidden = {posixpath.normpath(path) for path in hidden_paths}
    protected = [
        path
        for path in environment.protected_paths
        if not _inside(posixpath.normpath(path), hidden)
    ]
    lines = [
        "## Repository rules",
        "",
        "Editable, change only these paths: "
        + ", ".join(f"`{path}`" for path in environment.editable_paths)
        + ".",
    ]
    if protected:
        lines.append(
            "Protected, every change to them is rejected before scoring: "
            + ", ".join(f"`{path}`" for path in protected)
            + "."
        )
    lines.append(
        "Some repository files are hidden from you. Only the scorer reads them, and you cannot"
        " change them."
    )
    file = environment.constraints
    if file is not None and file.run_entry is not None:
        entry = file.run_entry if isinstance(file.run_entry, str) else " ".join(file.run_entry)
        lines.append(
            f"Each version runs through `{entry}`, with a limit of {file.run_timeout:g} seconds"
            " each time it runs."
        )
    if environment.rules:
        lines += [
            "",
            "Illegal approaches. A judge model checks your work against these rules during the"
            " run, and checks every version before it is scored. A version that breaks a rule is"
            " not scored. It is rejected, and the run history keeps the judge's reason.",
            "",
        ]
        lines += [f"- {label}: {rule}" for label, rule in numbered_rules(environment.rules)]
    if file is not None and file.run_role.illegal:
        lines += ["", "Rules for the code that each version runs:", ""]
        lines += [f"- {rule}" for rule in file.run_role.illegal]
    if file is not None and file.intent:
        lines += [
            "",
            f"Guidance from `{file.instructions_file}` (not enforced; the scorer decides):",
            "",
            file.intent,
        ]
    return "\n".join(lines)


def numbered_rules(rules: Sequence[str]) -> list[tuple[str, str]]:
    """Name each plain-language rule the way the agent, judges and events refer to it.

    Args:
        rules: The rules in file order.

    Returns:
        ``("Rule 1", text)`` pairs, numbered from 1.
    """
    return [(f"Rule {index}", rule) for index, rule in enumerate(rules, start=1)]
