"""OpenAscent: the reference Python package of the OpenAscent standard.

A component reads the JSON file that ``ASCENT_INPUT`` names, writes the JSON
file that ``ASCENT_OUTPUT`` names, and exits 0. This package implements the
runner side of that rule.
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

__version__ = "0.1.0"

__all__ = [
    "MAX_OUTPUT_BYTES",
    "AscentError",
    "ExitCodeError",
    "FunctionEntry",
    "InvalidFormError",
    "InvalidJsonError",
    "MetricCall",
    "MetricResult",
    "NamedScore",
    "NoOutputError",
    "OutputFileError",
    "RunCall",
    "StartError",
    "TimeLimitError",
    "__version__",
    "call_metric",
    "call_run",
    "check_metric_result",
    "check_run_output",
    "load_json",
    "parse_entry",
]
