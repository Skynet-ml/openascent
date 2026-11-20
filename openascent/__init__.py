"""OpenAscent: the reference Python package of the OpenAscent standard.

A component reads the JSON file that ``ASCENT_INPUT`` names, writes the JSON
file that ``ASCENT_OUTPUT`` names, and exits 0. This package implements the
runner side of that rule, and reads the ``ascent.toml`` contract.
"""

from .component import (
    MAX_OUTPUT_BYTES,
    FunctionEntry,
    MetricCall,
    RunCall,
    call_metric,
    call_run,
    parse_entry,
)
from .contract import (
    CONSTRAINTS_FILE,
    ConstraintsError,
    RepoConstraints,
    RunnerLimits,
    parse_constraints,
    read_constraints,
)
from .helpers import HelperError, StageError, call, llm, log
from .result import (
    AscentError,
    ExitCodeError,
    InvalidFormError,
    InvalidJsonError,
    MetricResult,
    NamedScore,
    NoOutputError,
    OutputFileError,
    StartError,
    TimeLimitError,
    check_metric_result,
    check_run_output,
    load_json,
)
from .schema import contract_schema

__version__ = "0.3.0"

__all__ = [
    "CONSTRAINTS_FILE",
    "MAX_OUTPUT_BYTES",
    "AscentError",
    "ConstraintsError",
    "ExitCodeError",
    "FunctionEntry",
    "HelperError",
    "InvalidFormError",
    "InvalidJsonError",
    "MetricCall",
    "MetricResult",
    "NamedScore",
    "NoOutputError",
    "OutputFileError",
    "RepoConstraints",
    "RunCall",
    "RunnerLimits",
    "StageError",
    "StartError",
    "TimeLimitError",
    "__version__",
    "call",
    "call_metric",
    "call_run",
    "check_metric_result",
    "check_run_output",
    "contract_schema",
    "llm",
    "load_json",
    "log",
    "parse_constraints",
    "parse_entry",
    "read_constraints",
]
