#[path = "support/redaction_report.rs"]
mod report;

#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use redact::{Span, detect, filter};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn marker(value: &str) -> String {
    let hash: String = Sha256::digest(value.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("[REDACTED sha256={hash}]")
}

fn bounded_filter(input: Vec<u8>) -> (Output, Duration) {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rstr"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .must();
    let mut stdin = child.stdin.take().must();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let mut stdout = child.stdout.take().must();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).must();
        bytes
    });
    let mut stderr = child.stderr.take().must();
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).must();
        bytes
    });
    let status = loop {
        if let Some(status) = child.try_wait().must() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(5) {
            child.kill().must();
            child.wait().must();
            panic!("provider near-match regression exceeded five-second process budget");
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    writer.join().must().must();
    (
        Output {
            status,
            stdout: out.join().must(),
            stderr: err.join().must(),
        },
        started.elapsed(),
    )
}

#[test]
fn large_boundary_invalid_hints_finish_and_recover_later_credentials() {
    let token = "ghp_SYNTHETIC_REVIEW_CANARY_0123456789";
    for (hint, repeats) in [("sk-", 5_000_000), ("AKIA", 3_000_000)] {
        let near_match = format!("x{}", hint.repeat(repeats));
        let input = format!("{near_match}\nGET /v1/hooks/{token} HTTP/1.1\n");
        let expected = format!("{near_match}\nGET /v1/hooks/{} HTTP/1.1\n", marker(token));
        let (output, elapsed) = bounded_filter(input.into_bytes());
        assert_eq!(output.status.code(), Some(0), "hint {hint}");
        report::assert_report(&output.stdout, &output.stderr);
        assert!(
            output.stdout == expected.as_bytes(),
            "hint {hint} exact output"
        );
        eprintln!(
            "synthetic {hint} near-match latency: {:.3}s",
            elapsed.as_secs_f64()
        );
    }
}

#[test]
fn rejected_outer_hints_keep_inner_credentials_and_delimiters() {
    let first = "ghp_SYNTHETIC_REVIEW_CANARY_0123456789";
    let second = "AKIAABCDEFGHIJKLMNOP";
    for input in [
        format!("devops_ref={first};status=401"),
        format!("GET /v1/hooks/{first} HTTP/1.1"),
        format!("[{first}],({second})"),
        format!("{first} {second}"),
    ] {
        let expected = input
            .replace(first, &marker(first))
            .replace(second, &marker(second));
        assert_eq!(filter(input.as_bytes()).must(), expected);
    }
    let compound = format!("{first}/{second}");
    assert_eq!(
        detect(&compound).must(),
        [Span {
            start: 0,
            end: compound.len()
        }]
    );
    assert_eq!(filter(compound.as_bytes()).must(), marker(&compound));
}

#[test]
fn distinct_verifier_markers_recover_after_adjacent_provider_tokens() {
    let token = "ghp_SYNTHETIC_REVIEW_CANARY_0123456789";
    for verifier in [
        format!("$2b$12${}", "A".repeat(53)),
        "$argon2id$v=19$m=65536,t=3,p=4$c3ludGhldGlj$c3ludGhldGlj".to_owned(),
    ] {
        let input = format!("{token}{verifier}");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("{}{}", marker(token), marker(&verifier))
        );
    }
}

#[test]
fn bare_specific_markers_do_not_fall_back_to_generic_provider_matches() {
    for prefix in ["sk-proj-", "sk-admin-", "sk-ant-admin", "sk-ant-api03-"] {
        assert_eq!(filter(prefix.as_bytes()).must(), prefix);
        let input = format!("{prefix} ghp_SYNTHETIC_REVIEW_CANARY_0123456789");
        let expected = format!(
            "{prefix} {}",
            marker("ghp_SYNTHETIC_REVIEW_CANARY_0123456789")
        );
        assert_eq!(filter(input.as_bytes()).must(), expected);
    }
}
