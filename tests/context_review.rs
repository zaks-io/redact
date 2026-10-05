#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use redact::{filter, fingerprint};
use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const CANARY: &str = "SYNTHETIC_CONTEXT_REVIEW_CANARY_0123456789";

fn marker(value: &str) -> String {
    format!("[REDACTED sha256={}]", fingerprint(value))
}

fn run(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rstr"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .must();
    let mut stdout = child.stdout.take().must();
    let mut stderr = child.stderr.take().must();
    let stdout_thread = std::thread::spawn(move || {
        let mut data = Vec::new();
        stdout.read_to_end(&mut data).must();
        data
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut data = Vec::new();
        stderr.read_to_end(&mut data).must();
        data
    });
    let mut stdin = child.stdin.take().must();
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let started = Instant::now();
    while child.try_wait().must().is_none() {
        if started.elapsed() > Duration::from_secs(5) {
            child.kill().must();
            child.wait().must();
            panic!("context review subprocess exceeded five seconds");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    writer.join().must().ok();
    Output {
        status: child.wait().must(),
        stdout: stdout_thread.join().must(),
        stderr: stderr_thread.join().must(),
    }
}

#[test]
fn prose_apostrophes_inch_marks_and_wire_escaped_quotes_do_not_hide_fields() {
    let cases = [
        (
            format!("error: can't authenticate {{'password': '{CANARY}'}}"),
            format!(
                "error: can't authenticate {{'password': '{}'}}",
                marker(CANARY)
            ),
        ),
        (
            format!("size 5\" display {{\"password\":\"{CANARY}\"}}"),
            format!("size 5\" display {{\"password\":\"{}\"}}", marker(CANARY)),
        ),
        (
            format!(r#"payload: {{\"password\":\"{CANARY}\"}}"#),
            format!(r#"payload: {{\"password\":\"{}\"}}"#, marker(CANARY)),
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(filter(input.as_bytes()).must(), expected);
        let output = run(input.as_bytes());
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn bracket_leading_opaque_values_keep_their_complete_suffix_protected() {
    for value in [
        format!("{{synthetic}}{CANARY}"),
        format!("[a]{CANARY}"),
        format!("[synthetic-{CANARY}"),
        format!("[\"{CANARY}\"]tail"),
    ] {
        let input = format!("DB_PASSWORD={value}\n");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("DB_PASSWORD={}\n", marker(&value))
        );
    }
    let value = format!("[\"{CANARY}\",{{\"nested\":\"{CANARY}\"}}]");
    let input = format!("{{\"password\":{value},\"status\":401}}");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("{{\"password\":{},\"status\":401}}", marker(&value))
    );
}

#[test]
fn sequence_yaml_blocks_and_plain_scalar_continuations_are_complete() {
    let block = format!("|\n    {CANARY}\n    synthetic-suffix");
    let input = format!("- password: {block}\n  host: public\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("- password: {}\n  host: public\n", marker(&block))
    );
    let block = format!("{CANARY}\n    synthetic-suffix");
    let input = format!("- password:\n    {block}\n  host: public\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("- password:\n    {}\n  host: public\n", marker(&block))
    );
    let value = format!("synthetic-head\n  {CANARY}");
    let input = format!("password: {value}\nstatus: 401\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("password: {}\nstatus: 401\n", marker(&value))
    );
    let value = format!("synthetic-head\r    {CANARY}");
    let input = format!("- password: {value}\r  host: public\r");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("- password: {}\r  host: public\r", marker(&value))
    );
    let empty = "- password:\n  host: public\n";
    assert_eq!(filter(empty.as_bytes()).must(), empty);
}

#[test]
fn spaces_and_tabs_in_quoted_names_are_word_separators() {
    for name in [
        "Admin Password",
        "Client Secret",
        "API Token",
        "Admin\tPassword",
    ] {
        let input = serde_json::json!({name:CANARY,"status":401}).to_string();
        let escaped = serde_json::to_string(name).must();
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("{{{escaped}:\"{}\",\"status\":401}}", marker(CANARY))
        );
    }
}

#[test]
fn yaml_prefix_checks_and_failed_quote_candidates_make_linear_progress() {
    for input in [
        format!("{{{}", "\"password\":#,".repeat(50000)),
        "password:\r".repeat(100000),
        format!("\"{}", "\\\"".repeat(100000)),
    ] {
        let output = run(input.as_bytes());
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8(output.stdout).must().contains(CANARY));
    }
}
