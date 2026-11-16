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
A command that moves or links its directory away, or makes a directory that the runner cannot remove, can leave files behind.
The result of the call does not change then.
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
| `start_failed` | The command cannot start: it is not found or not executable, the function file does not exist, or the working directory or the environment is not valid. A relative function path with a current directory that no longer exists also gives this code. |
| `time_limit` | The command ran longer than the time limit. The runner kills its whole process group. A process that leaves the group (for example with `setsid`) is not stopped; that needs an OS sandbox. |
| `nonzero_exit` | The command exited with a code that is not 0. The error keeps the code and the tail of stderr. |
| `no_output` | The command wrote no output file. |
| `bad_output_file` | The output path is a symbolic link or a hard link, or not a regular file, the runner cannot open the file, or the file is larger than the size limit (1 MiB by default). The runner reads the output through the call directory that it made, so a command that swaps that directory cannot redirect the read. |
| `invalid_json` | The output file is not strict JSON: not UTF-8, a `NaN` or `Infinity` token, a float literal that overflows (`1e400`), an integer longer than the digit limit of the Python interpreter (4300 digits by default), a duplicate key, or a lone surrogate escape such as `"\ud800"`. |
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
On a usage error it prints the usage and a message on stderr and exits with code 2.
A usage error is a bad argument, or an input file that the command cannot read, that is not JSON, or that is not a valid metric input.
The default time limit is 60 seconds. The command needs no account and no network.

`--entry` is `path/file.py:function`, or a command line that the command splits like a shell does.
The command splits the value like a shell line in both forms. Put a path that has a space in inner quotes, for example `--entry "'my dir/m.py:score'"`.

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

## Helper calls

A metric can call helpers: the stages of the run, a judge model, and a log.
The runner gives each helper to the metric as a local URL in an environment variable.
Each call is one HTTP POST with a UTF-8 JSON body and the header `Content-Type: application/json`.
The answer is JSON. A metric in any language needs no library to call a helper.

| Variable | Helper |
| --- | --- |
| `ASCENT_STAGE_<NAME>_URL` | The URL of the stage `<name>`. One variable for each stage. |
| `ASCENT_MODEL_URL` | The base URL of the judge model endpoint. |
| `ASCENT_MODEL` | The name of the judge model. |
| `ASCENT_MODEL_KEY` | The key of the judge model. Empty or absent when the runner adds the key itself. The key holds only visible ASCII characters, with no space or line end. |
| `ASCENT_LOG_URL` | The URL of the log. |

A helper variable is absent when the contract gives the metric no such helper.
A helper call has no time limit of its own. The time limit of the metric call bounds the wait.

### The name rule

`<NAME>` comes from the stage name. Each ASCII letter becomes upper case. Each ASCII digit stays.
Each other character becomes `_`.
Two stage names that give the same `<NAME>` are not valid in one contract.

| Stage | Variable |
| --- | --- |
| `planner` | `ASCENT_STAGE_PLANNER_URL` |
| `planner-v2` | `ASCENT_STAGE_PLANNER_V2_URL` |
| `Judge.Final` | `ASCENT_STAGE_JUDGE_FINAL_URL` |

### Stage call

POST to `ASCENT_STAGE_<NAME>_URL` with the body `{"input": <the stage input>}`.
A success answer has a 2xx status and the body `{"output": <the stage output>}`.

### Model call

POST to `<ASCENT_MODEL_URL>/chat/completions` in the OpenAI chat form, with `model` (the value of `ASCENT_MODEL`) and `messages`.
Send the header `Authorization: Bearer <key>` only when `ASCENT_MODEL_KEY` is not empty.
The text of the answer is at `choices[0].message.content`.

### Log event

POST to `ASCENT_LOG_URL` with one event as the body `{"event": "<name>", "fields": {"<name>": <JSON value>, ...}}`.
A success answer has any 2xx status. The body of the answer is not used.

### The error answer

Each helper gives the same error answer: a status code that is not 2xx and the body `{"error": "<text>"}`.
The runner gives an error answer to a stage call in these four failures:

- The stage is not in the run (an unknown stage).
- The stage failed.
- The stage gave no valid output.
- The stage passed its time limit.

The standard fixes no status code for each failure. The `error` text says which failure occurred.

### The Python helpers

```python
from openascent import StageError, call, llm, log


def score(input, output):
    try:
        facts = call("fact-finder", input)
    except StageError as error:
        return {"score": 0.0, "feedback": f"No facts: {error}"}
    verdict = llm(
        "Answer yes or no: does the text hold the facts?", {"facts": facts, "text": output}
    )
    log("judge", verdict=verdict)
    return {"score": 1.0 if verdict.strip().lower().startswith("yes") else 0.0}
```

- `call(stage, input=None)` returns the output of the stage. It raises `StageError` on a failure.
- `llm(prompt, input=None, images=None)` returns the text of the answer. With `input`, `prompt` is the system message and `input` is the user message. An `input` that is not a string goes as its JSON text. Each image is a URL string (`http://`, `https://` or `data:`), a `pathlib.Path` of a PNG, JPEG, GIF or WebP file, or the bytes of such an image. The helper reads the type of a file from its bytes, not from its name.
- `log(event, /, **fields)` sends one event. A field can have any name, also `event`.
- `llm` and `log` raise `HelperError` on a failure. `StageError` is a kind of `HelperError`. A bad argument raises `ValueError` before any request.
- The helpers do not use the proxy settings of the environment, and do not follow a redirect. An answer larger than 16 MiB is a failure for each helper, also for `log`.

### A stage call with curl

```sh
curl -sS -X POST "$ASCENT_STAGE_FACT_FINDER_URL" \
  -H 'Content-Type: application/json' \
  -d '{"input": "The capital of France"}'
```

It prints the answer, for example `{"output": ["Paris"]}`.

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
