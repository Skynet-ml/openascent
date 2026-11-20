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
| `nonzero_exit` | The command exited with a code that is not 0. The error keeps the code, the tail of stderr and the tail of stdout. |
| `no_output` | The command wrote no output file. |
| `bad_output_file` | The output path is a symbolic link or a hard link, or not a regular file, the runner cannot open the file, or the file is larger than the size limit (1 MiB by default). The runner reads the output through the call directory that it made, so a command that swaps that directory cannot redirect the read. |
| `invalid_json` | The output file is not strict JSON: not UTF-8, a `NaN` or `Infinity` token, a float literal that overflows (`1e400`), an integer longer than the digit limit of the Python interpreter (4300 digits by default), a duplicate key, or a lone surrogate escape such as `"\ud800"`. |
| `invalid_form` | The output file is valid JSON but not the valid form, for example a metric result with no `score`, or a `score` that is an integer too large for a float. A large integer in a run output is valid. |

Every error after the command runs keeps the tails of stdout and stderr in `error.stdout` and `error.stderr`. A `start_failed` error has empty tails.

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

## The `ascent check --image` command

`ascent check --image --role <candidate|metric>` runs inside a box and checks that the box image speaks the protocol.
The user image only gives the tools. The OpenAscent package in the image speaks the protocol.
A runner runs this command in each image before the run. A non-zero exit fails the run.
The command needs no network. A role runs at most three subprocesses, and each one stops after 8 seconds, so a role ends in about 24 seconds.

The `metric` role checks:

| Check | What it proves |
| --- | --- |
| `python_runtime` | The trusted Python runtime exists and runs. The report gives its absolute path in `python`. |
| `ascent_score` | `ascent score` works end to end with that runtime: a built-in sample metric gets a sample input and returns a valid result. |
| `temp_dir` | A temporary directory is writable. |

The `candidate` role checks:

| Check | What it proves |
| --- | --- |
| `ascent_command` | The `ascent` command is on `PATH` and runs. |
| `package_import` | The Python runtime imports the `openascent` package at the version of the command. |
| `shell` | A shell at `/bin/sh` runs a command. |
| `temp_dir` | A temporary directory is writable. |

The trusted Python runtime is the interpreter that runs the `ascent` command.

The command prints one JSON object on stdout:

```json
{
  "sdk_version": "<version>",
  "protocol_version": 1,
  "role": "metric",
  "python": "/usr/local/bin/python3.12",
  "ok": true,
  "checks": [
    {"name": "python_runtime", "ok": true, "message": "/usr/local/bin/python3.12 runs Python 3.12.16."},
    {"name": "ascent_score", "ok": true, "message": "The sample metric returned a valid result with score 1.0."},
    {"name": "temp_dir", "ok": true, "message": "/tmp is writable."}
  ]
}
```

- `sdk_version` is the version of the installed package. `protocol_version` is the version of the protocol that the package speaks.
- `ok` is `true` exactly when each check passed.
- `python` is present only for the `metric` role. It is `null` when the `python_runtime` check failed.
- The exit code is 0 when each check passed, and 1 when a check failed.
- No `--role`, a wrong role, or no `--image` is a usage error: the command prints the usage on stderr and exits with code 2.

To add the package to any image, add one line with a pinned version, for example in a Dockerfile:

```dockerfile
RUN pip install openascent==<version>
```

`ascent check --image` ships in 0.2.0, so pin 0.2.0 or a later release.

The image needs Python 3.12 or later.

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

## The run record

A runner returns one JSON object with the run result: the run record.
When the run opens a pull request, the runner also puts the record in the text of that pull request as a JSON block.
There is no record file in the repository.
A reader uses the record to check a score by hand.

```json
{
  "record_version": 1,
  "contract_sha256": "a7bee4c6b7495cdbb4cd70b2524931ae6c17305eecf855a812c4949ec1431a98",
  "metric_sha256": "4cb4243c16a70758b85e0c463763a1ef6048098b3e14496fb85f45067334e0eb",
  "metric_source": "repository",
  "cases_sha256": null,
  "cases_source": null,
  "base_commit": "0123456789abcdef0123456789abcdef01234567",
  "change_sha256": "18b48432344deb00d1f9ee5a1d55457a1479f62539deecbb79989aa70edf2dc7",
  "baseline_score": 0.3,
  "final_score": 0.9,
  "seed": 7,
  "split": null,
  "image": null,
  "contract_met": true,
  "target_reached": true
}
```

### The keys

The record is a closed object. An unknown key is an error. All keys are required, except the three verdict keys.

| Key | Type | Meaning |
| --- | --- | --- |
| `record_version` | the integer `1` | The version of the record format. |
| `contract_sha256` | SHA-256 hex | The hash of the bytes of the contract file `ascent.toml`. |
| `metric_sha256` | SHA-256 hex | The hash of the metric files (see the rule below). |
| `metric_source` | `"repository"` or `"request"` | Where the metric files come from. |
| `cases_sha256` | SHA-256 hex or `null` | The hash of the cases. `null` when the run has no cases. |
| `cases_source` | `"file"`, `"request"` or `null` | Where the cases come from. `null` exactly when `cases_sha256` is `null`. |
| `base_commit` | full commit SHA | The commit of the repository before the change: 40 lowercase hex characters, or 64 in a SHA-256 repository. |
| `change_sha256` | SHA-256 hex or `null` | The hash of the patch text as UTF-8 bytes. `null` when the patch is empty: the hash of zero bytes is not valid here. |
| `baseline_score` | number or `null` | The score before the change. |
| `final_score` | number or `null` | The score after the change. |
| `seed` | integer or `null` | The seed of the run. |
| `split` | object or `null` | How the run split the cases (see below). |
| `image` | string or `null` | The container image that the run used. |
| `contract_met` | boolean | `true` when the result meets the contract. |
| `target_reached` | boolean | Verdict key. `true` when the final score reaches the target. Present only when the contract has a target. |
| `requirements_passed` | boolean | Verdict key. `true` when every requirement passed. Present only when the contract has requirements. |
| `failed_requirements` | array | Verdict key. The requirements that failed. Present only when the contract has requirements. |

A record has both `requirements_passed` and `failed_requirements`, or neither.
`requirements_passed` is `true` exactly when `failed_requirements` is empty.

A SHA-256 hex value is exactly 64 lowercase hex characters. `true` and `false` are not numbers.

The `split` object is closed. It has exactly these keys:

- `rule`: the name of the split rule, a string that is not empty. Skynet uses `pairs` and `single`. Another runner can use its own name.
- `seed`: the seed of the split, an integer or `null`.
- `search`, `validation`, `held_out`: the positions of the cases in each part, arrays of integers that are 0 or more. Position 0 is the first case.

Each entry in `failed_requirements` is a closed object with exactly these keys:
`name` (string), `direction` (`"maximize"` or `"minimize"`), `limit` (number), `value` (number or `null`), `reason` (string).

### The hashes

Each hash is a SHA-256 value in lowercase hex.

A file hash is the hash of the bytes of the file on disk, where the runner read the file.
For a file of the repository, these are the bytes in a checkout of `base_commit`.
Usually they are the bytes that git stores. A checkout filter can make them different: a line-end rule in `.gitattributes`, or Git LFS.
Then the checker must make its checkout with the same filters as the runner. The documentation of the runner names them.

This command gives the hash of one file, here of `ascent.toml`:

```sh
python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())' < ascent.toml
```

`contract_sha256` is the hash of the file `ascent.toml`.

`metric_sha256` is the hash of the metric files: the files that the runner puts where it runs the metric.
The standard does not fix this set of files. The documentation of the runner names it.
Each file gives one part: `<path>\0<length>\0<hash>`.
`<path>` is the path of the file in UTF-8, relative to the repository root, with `/` between folders, and with no `./` and no `/` at the start.
`<length>` is the byte length of the file in decimal. `<hash>` is the SHA-256 hex of the file bytes.
`\0` is one zero byte.
The parts are in sorted path order: the order of the paths as UTF-8 bytes.
The parts join with no byte between them. Each part ends with exactly 64 hex characters, so the join has only one meaning.
`metric_sha256` is the hash of the joined parts. There is no special first part and no fixed path.
Metric code that comes in the run request counts as one file.
Its path is the path where the runner puts the file to run the metric, relative to the repository root.

Run this in the repository root. Give the path of each metric file in the form above, for example `lib/util.py`, not `./lib/util.py`.

```sh
python3 -c 'import hashlib,os,sys; h=lambda b: hashlib.sha256(b).hexdigest(); print(h(b"".join(p+b"\0"+str(len(d)).encode()+b"\0"+h(d).encode() for p in sorted(os.fsencode(a) for a in sys.argv[1:]) for d in [open(p,"rb").read()])))' metric.py lib/util.py
```

`cases_sha256` depends on `cases_source`:

- `file`: the cases are one file in the repository at `base_commit`. The hash is of the bytes of that file.
  The documentation of the runner says which file it is.
  For the file `cases.jsonl`, use the command for one file with `< cases.jsonl` at its end.

- `request`: the cases came with the run request. The checker gets the cases from the person who ran the run.
  The hash proves that the cases are the same.
  The hash is of the compact JSON text of the cases, with sorted keys, in UTF-8.
  In Python: `json.dumps(cases, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.
  This Python expression defines the text, also the form of each number.
  For the cases in `cases.json`:

  ```sh
  python3 -c 'import hashlib,json,sys; print(hashlib.sha256(json.dumps(json.load(sys.stdin.buffer), sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")).hexdigest())' < cases.json
  ```

- `null`: the run has no cases.

`change_sha256` is the hash of the patch text as UTF-8 bytes.
For the patch in `change.patch`, use the command for one file with `< change.patch` at its end.

### The metric source

- `repository`: the metric files are in the repository at `base_commit`. A checker computes `metric_sha256` from a checkout of that commit.
- `request`: the metric code came with the run request. The checker gets the code from the person who ran the run. The hash proves that the code is the same.

### Check a score

1. Get the commit `base_commit`: `git checkout <base_commit>`.
2. Compute `contract_sha256`, `metric_sha256` and `cases_sha256`. Compare each one with the record.
   When `cases_sha256` is `null`, the run has no cases, and there is no cases hash to compare.
3. Get the patch text from the run result. The documentation of the runner says where the result holds it.
   Compute its hash, and compare it with `change_sha256`. Apply the patch: `git apply change.patch`.
   Then compute the hashes of step 2 again. Each hash must be the same as before the patch.
   A different hash shows that the patch changed the contract, a metric file or the cases file.
   Then the record does not prove the score: stop.
   When `change_sha256` is `null`, the run made no change: skip this step.
4. Run the metric on the cases that give the final score.
   For each case, get the output of the changed program for the case (see "Run call").
   Then make the metric input from the case and that output, and start the metric (see "Metric call").
   The contract `ascent.toml` names the command of the metric and the commands of the program.
   The standard does not fix these cases, or how the case scores combine into one score. The documentation of the runner says both.
   Skynet, for example, uses the mean of the scores of the held-out cases (the positions in `split.held_out`).
5. Compare the score with `final_score`.
   When `final_score` is `null`, the run gave no final score, and there is no score to compare.

### The schema

The JSON Schema (draft 2020-12) of the record is in the package: `openascent/record.schema.json`. Load it like this:

```python
import json
from importlib.resources import files

schema = json.loads((files("openascent") / "record.schema.json").read_text(encoding="utf-8"))
```

The package does not validate records. It has no dependency for that. Use a JSON Schema validator, for example `jsonschema`.

## Install

Install from PyPI, with a pinned version:

```sh
pip install openascent==0.2.1
```

Or install from the repository, at a release tag:

```sh
pip install git+https://github.com/Skynet-ml/openascent@<tag>
```

The package needs Python 3.12 or later and has no runtime dependency.

## Supported platforms

Linux and macOS (POSIX). Windows is not supported.

## License

Apache-2.0. See `LICENSE`.
