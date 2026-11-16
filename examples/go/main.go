// An exact-match metric in Go, with the standard library only.
//
// The score is 1 when the output is a string equal to the expected answer,
// and 0 with feedback when it is not. Try it from this folder:
//
//	go build -o metric . && ascent score --entry ./metric --input ../case.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const feedback = "The output does not match the expected answer."

type metricInput struct {
	Output   any `json:"output"`
	Expected any `json:"expected"`
}

type answer struct {
	Score    float64 `json:"score"`
	Feedback string  `json:"feedback,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	data, err := os.ReadFile(os.Getenv("ASCENT_INPUT"))
	if err != nil {
		return err
	}
	var in metricInput
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	output, isString := in.Output.(string)
	expected, hasExpected := in.Expected.(string)
	result := answer{Score: 0, Feedback: feedback}
	if isString && hasExpected && output == expected {
		result = answer{Score: 1}
	}
	text, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return os.WriteFile(os.Getenv("ASCENT_OUTPUT"), text, 0o644)
}
