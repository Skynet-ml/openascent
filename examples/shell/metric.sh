#!/bin/sh
# An exact-match metric in POSIX sh. It needs jq (https://jqlang.org).
#
# The score is 1 when the output is a string equal to the expected answer,
# and 0 with feedback when it is not. Try it from this folder:
#
#   ascent score --entry ./metric.sh --input ../case.json
set -eu

jq -c '
  if (.output | type) == "string" and .output == .expected
  then {score: 1}
  else {score: 0, feedback: "The output does not match the expected answer."}
  end
' "$ASCENT_INPUT" > "$ASCENT_OUTPUT"
