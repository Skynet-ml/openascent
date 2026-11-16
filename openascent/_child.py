"""Call a Python function under the two-file rule, in a child process.

The package starts this file by its path with ``sys.executable``:
``python _child.py run|metric <file.py> <function>``. The file imports nothing
from the package, so it works when the package is not installed in the
child's environment. It does no result checking; the parent checks.
"""

import importlib.util
import inspect
import json
import os
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    """Load the function, call it with the input file, and write the output file.

    Args:
        argv: The kind of call ("run" or "metric"), the file path and the
            function name.

    Returns:
        The exit code: 0 on success, 2 when the function cannot be called or
        returns a dict key that is not a string.
    """
    kind, file, name = argv
    path = Path(file).resolve()
    # Import the user's sibling modules as a script would, and never this
    # package's own modules (result.py, cli.py) by accident.
    sys.path[0] = str(path.parent)
    spec = importlib.util.spec_from_file_location("__ascent_entry__", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    function = getattr(module, name, None)
    if not callable(function):
        print(f"The file {path} has no function named {name!r}.", file=sys.stderr)
        return 2
    with open(os.environ["ASCENT_INPUT"], encoding="utf-8") as file_in:
        payload = json.load(file_in)
    if kind == "run":
        result = {"output": function(payload["input"])}
    else:
        arguments = _arguments(function, payload)
        if arguments is None:
            return 2
        result = function(**arguments)
    # The walk runs before dumps: dumps turns some keys (1, None) into strings
    # in silence and fails on others (a tuple) with a TypeError. The message
    # holds no key: a key's repr can raise or be very large.
    if _has_non_string_key(result):
        print(
            "The function returned a dict with a key that is not a string. "
            "Use only string keys in dicts.",
            file=sys.stderr,
        )
        return 2
    _write(os.environ["ASCENT_OUTPUT"], json.dumps(result))
    return 0


def _has_non_string_key(value) -> bool:
    """Tell if a dict at any depth has a key that is not a string.

    Args:
        value: The return value. It can hold a cycle; the walk visits each
            container once.

    Returns:
        True when some dict key is not a string.
    """
    pending = [value]
    seen = set()
    while pending:
        item = pending.pop()
        if isinstance(item, dict | list | tuple):
            if id(item) in seen:
                continue
            seen.add(id(item))
        if isinstance(item, dict):
            for key in item:
                if not isinstance(key, str):
                    return True
            pending.extend(item.values())
        elif isinstance(item, list | tuple):
            pending.extend(item)
    return False


def _arguments(function, payload: dict) -> dict | None:
    """Pick the fields of the metric input that the function names.

    Args:
        function: The metric function.
        payload: The metric input object.

    Returns:
        The keyword arguments, or ``None`` after it prints why a required
        parameter has no value.
    """
    parameters = inspect.signature(function).parameters.values()
    for p in parameters:
        if p.kind is p.POSITIONAL_ONLY and p.default is p.empty:
            print(
                f"The metric function has the positional-only parameter {p.name!r}. "
                "The metric function gets its values by name, so remove the / "
                "from the signature.",
                file=sys.stderr,
            )
            return None
    if any(p.kind is p.VAR_KEYWORD for p in parameters):
        return dict(payload)
    arguments = {}
    for p in parameters:
        if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY) and p.name in payload:
            arguments[p.name] = payload[p.name]
        elif p.default is p.empty and p.kind is not p.VAR_POSITIONAL:
            print(
                f"The metric function cannot get its required parameter {p.name!r} "
                "from the input object. Name each parameter after a key of the "
                "input object (input, expected, output, elapsed_s), or give it "
                "a default value.",
                file=sys.stderr,
            )
            return None
    return arguments


def _write(path: str, text: str) -> None:
    """Write the output file in one step, so the parent never reads half of it.

    Args:
        path: The output path.
        text: The JSON text.
    """
    partial = path + ".part"
    # A link that the function left at this path must not take the write.
    Path(partial).unlink(missing_ok=True)
    with open(partial, "w", encoding="utf-8") as file_out:
        file_out.write(text)
    os.replace(partial, path)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
