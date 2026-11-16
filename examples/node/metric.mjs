// An exact-match metric in Node.js, with no npm dependency.
//
// The score is 1 when the output is a string equal to the expected answer,
// and 0 with feedback when it is not. Try it from this folder:
//
//   ascent score --entry "node metric.mjs" --input ../case.json

import { readFileSync, writeFileSync } from "node:fs";

const FEEDBACK = "The output does not match the expected answer.";

const metricInput = JSON.parse(readFileSync(process.env.ASCENT_INPUT, "utf8"));
const match =
  typeof metricInput.output === "string" &&
  metricInput.output === metricInput.expected;
const answer = match ? { score: 1 } : { score: 0, feedback: FEEDBACK };
writeFileSync(process.env.ASCENT_OUTPUT, JSON.stringify(answer));
