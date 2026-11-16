# OpenAscent

Define a metric. The machine climbs it.

OpenAscent is an open standard for optimization runs.
You write a metric that gives a score to the output of a program.
A runner changes the program, measures each version with your metric, and keeps the versions that score better.

This repository holds the reference Python package of the standard.
It implements the runner side of the rule below and the `ascent` command.

## The two-file rule

A component is a metric or a candidate program. You can write it in any language. It needs no library.
It obeys one rule:

1. Read the JSON file that the `ASCENT_INPUT` environment variable names.
2. Write the JSON file that the `ASCENT_OUTPUT` environment variable names.
3. Exit with code 0.

The runner starts the command with an empty stdin.
Each call gets a new directory and a new output path. The runner tries to remove the directory after the call.
A command that moves or links its directory away can leave files behind.
What the command prints on stdout and stderr is log text. It is never part of the result, so a debug print cannot change the result.

## The two kinds of call

### Run call (a candidate program or a stage)

| File | Field | Type | Required |
| --- | --- | --- | --- |
| input | `input` | any JSON value | yes |
| output | `output` | any JSON value, also `null` | yes |

The input file holds exactly `{"input": ...}`.
The output file must hold exactly one object with exactly one key: `{"output": ...}`.

### Metric call

| File | Field | Type | Required |
| --- | --- | --- | --- |
| input | `input` | any JSON value: the case input | yes |
| input | `expected` | any JSON value: the expected answer | no; absent when the case has none |
| input | `output` | any JSON value: the candidate's output | yes |
| input | `elapsed_s` | number: seconds the candidate took | no; present when the runner measured it |
| output | `score` | finite number | yes |
| output | `feedback` | string | no |
| output | `scores` | object of named scores | no |
| output | `scores.<name>.score` | finite number | yes, in each named score |
| output | `scores.<name>.feedback` | string | no |

A metric must ignore input keys that it does not know. The standard can add a key later.

### The metric answer object

```json
{
  "score": 0.78,
  "feedback": "Misses short names.",
  "scores": {
    "precision": {"score": 0.90},
    "recall": {"score": 0.69, "feedback": "Misses names under 4 letters."}
  }
}
```

- Only `score` ranks versions. The named scores and the feedback help a person or an optimizer understand the score.
- A named score has no parts of its own.
- Every other form is an error: a bare number, an array, a named score that is a plain number, an unknown key, or `null` for any key.
- `true` and `false` are not numbers. `NaN`, `Infinity`, `-Infinity` and a number too large for a float are errors.
- The file must be UTF-8 JSON. A duplicate key in one object is an error.

The check finds every mistake in one pass and reports all of them in one error.
Each problem names its key path, for example `scores.recall.score`.

## Failures

The runner never invents a score. A failure is a typed error, never a score of 0.
Each error type has a stable `code`:

| Code | Cause |
| --- | --- |
| `start_failed` | The command cannot start, for example it is not found or not executable, or the working directory or the environment is not valid. |
| `time_limit` | The command ran longer than the time limit. The runner kills its whole process group. A process that leaves the group (for example with `setsid`) is not stopped; that needs an OS sandbox. |
| `nonzero_exit` | The command exited with a code that is not 0. The error keeps the code and the tail of stderr. |
| `no_output` | The command wrote no output file. |
| `bad_output_file` | The output path is a symbolic link or a hard link, or not a regular file, the runner cannot open the file, or the file is larger than the size limit (1 MiB by default). The runner reads the output through the call directory that it made, so a command that swaps that directory cannot redirect the read. |
| `invalid_json` | The output file is not strict JSON: not UTF-8, a `NaN` or `Infinity` token, a float literal that overflows (`1e400`), an integer longer than 4300 digits, a duplicate key, or a lone surrogate escape such as `"\ud800"`. |
| `invalid_form` | The output file is valid JSON but not the valid form, for example a metric result with no `score`, or a `score` that is an integer too large for a float. A large integer in a run output is valid. |

## The two entry forms

- A command: a list of strings, for example `["./metric.sh"]` or `["node", "metric.mjs"]`.
- A Python function: the string `"path/file.py:function"`.

The function form obeys the same two-file rule. The package starts a child Python process with the same interpreter.
The child loads the file, calls the function, and writes the output file. The time limit and all checks apply the same way to both forms.

- In a run call, the child calls `function(input_value)` and writes `{"output": <return value>}`.
- In a metric call, the child calls the function with the input fields that it names as parameters: `input`, `expected`, `output`, `elapsed_s`. A function with `**kwargs` gets every field. The child gives each value by name, so a positional-only parameter (before a `/`) with no default is an error with exit code 2. The return value is the metric answer object.
- A dict in the return value must have string keys only. A key that is not a string is a `nonzero_exit` failure with exit code 2.
- An exception in the function is a `nonzero_exit` failure. The traceback is in stderr.

## The `ascent score` command

`ascent score --entry <entry> --input <file> [--timeout <seconds>]` runs one metric call in the current directory.
It prints the checked answer as JSON on stdout and exits with code 0.
On a failure it prints the error code and message on stderr and exits with code 1.
The default time limit is 60 seconds. The command needs no account and no network.

`--entry` is `path/file.py:function`, or a command line that the command splits like a shell does.

Try the shell example. It needs [jq](https://jqlang.org):

```sh
cd examples/shell
ascent score --entry ./metric.sh --input ../case.json
```

It prints:

```json
{"score": 1.0}
```

The `examples` folder holds the same exact-match metric in Python, Node.js, Go, Rust and POSIX sh.

## A short metric

In bash, with jq:

```bash
#!/bin/bash
jq -c '{score: (if .output == .expected then 1 else 0 end)}' "$ASCENT_INPUT" > "$ASCENT_OUTPUT"
```

In Python, in the function form (`metric.py:score`):

```python
def score(output, expected=None):
    return {"score": 1.0 if output == expected else 0.0}
```

## The metric direction

The contract key `[metric] direction` tells the runner which way is better: `"maximize"` or `"minimize"`.
The default is `"maximize"`. The result of a metric is one finite number with no direction in it.
The contract file is `ascent.toml`. This package does not parse `ascent.toml` yet.

## Install

Install from the repository, at a release tag:

```sh
pip install git+https://github.com/Skynet-ml/openascent@<tag>
```

The package needs Python 3.12 or later and has no runtime dependency.

## Supported platforms

Linux and macOS (POSIX). Windows is not supported.

## License

Apache-2.0. See `LICENSE`.
