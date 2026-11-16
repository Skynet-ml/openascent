// An exact-match metric in Rust, with serde_json.
//
// The score is 1 when the output is a string equal to the expected answer,
// and 0 with feedback when it is not. Try it from this folder:
//
//   cargo build --release --locked
//   ascent score --entry ./target/release/openascent-metric --input ../case.json

use serde_json::{json, Value};
use std::{env, error::Error, fs, process};

const FEEDBACK: &str = "The output does not match the expected answer.";

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let text = fs::read_to_string(env::var("ASCENT_INPUT")?)?;
    let case: Value = serde_json::from_str(&text)?;
    let output = case.get("output").and_then(Value::as_str);
    let expected = case.get("expected").and_then(Value::as_str);
    let answer = match (output, expected) {
        (Some(output), Some(expected)) if output == expected => json!({"score": 1.0}),
        _ => json!({"score": 0.0, "feedback": FEEDBACK}),
    };
    fs::write(env::var("ASCENT_OUTPUT")?, answer.to_string())?;
    Ok(())
}
