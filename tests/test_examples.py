"""Each example metric gives the same answer for the same cases.

A test for a language whose toolchain is absent reports skipped. With
``ASCENT_REQUIRE_TOOLCHAINS=1`` (set on CI) a missing tool fails the test.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from openascent import MetricResult, call_metric

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
FEEDBACK = "The output does not match the expected answer."
CASES = [
    (json.loads((EXAMPLES / "case.json").read_text()), MetricResult(1.0)),
    ({"input": "q", "expected": "Paris", "output": "Lyon"}, MetricResult(0.0, FEEDBACK)),
    ({"input": "q", "output": "Paris"}, MetricResult(0.0, FEEDBACK)),
    ({"input": "q", "expected": 1, "output": 1, "elapsed_s": 0.1}, MetricResult(0.0, FEEDBACK)),
]


def need(tool):
    """Skip the test when a tool is absent, or fail it when CI requires the tool.

    Args:
        tool: The command name.
    """
    if shutil.which(tool) is None:
        message = f"{tool} is not installed"
        if os.environ.get("ASCENT_REQUIRE_TOOLCHAINS") == "1":
            pytest.fail(message + " and ASCENT_REQUIRE_TOOLCHAINS=1")
        pytest.skip(message)


@pytest.fixture(scope="session")
def go_binary(tmp_path_factory):
    """Build the Go example once.

    Returns:
        The path of the binary.
    """
    need("go")
    binary = tmp_path_factory.mktemp("go") / "metric"
    subprocess.run(["go", "build", "-o", str(binary), "."], cwd=EXAMPLES / "go", check=True)
    return str(binary)


@pytest.fixture(scope="session")
def rust_binary(tmp_path_factory):
    """Build the Rust example once, into a temporary target folder.

    Returns:
        The path of the binary.
    """
    need("cargo")
    target = tmp_path_factory.mktemp("rust")
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "--target-dir", str(target)],
        cwd=EXAMPLES / "rust",
        check=True,
    )
    return str(target / "release" / "openascent-metric")


@pytest.mark.parametrize(("payload", "expected"), CASES)
def test_python(payload, expected):
    """The Python example in the function form."""
    call = call_metric("metric.py:score", payload, timeout_s=10, cwd=EXAMPLES / "python")
    assert call.result == expected


@pytest.mark.parametrize(("payload", "expected"), CASES)
def test_node(payload, expected):
    """The Node.js example."""
    need("node")
    call = call_metric(["node", "metric.mjs"], payload, timeout_s=10, cwd=EXAMPLES / "node")
    assert call.result == expected


@pytest.mark.parametrize(("payload", "expected"), CASES)
def test_go(go_binary, payload, expected):
    """The Go example."""
    assert call_metric([go_binary], payload, timeout_s=10).result == expected


@pytest.mark.parametrize(("payload", "expected"), CASES)
def test_rust(rust_binary, payload, expected):
    """The Rust example."""
    assert call_metric([rust_binary], payload, timeout_s=10).result == expected


@pytest.mark.parametrize(("payload", "expected"), CASES)
def test_shell(payload, expected):
    """The POSIX sh example with jq."""
    need("jq")
    call = call_metric(["./metric.sh"], payload, timeout_s=10, cwd=EXAMPLES / "shell")
    assert call.result == expected
