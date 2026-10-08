#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use proptest::prelude::*;
use redact::{
    RedactionReport,
    error::{ErrorKind, SafeError},
    filter_with_evidence,
    rstr::filter_to_writer,
};
use std::{
    io::{self, Read},
    process::Command,
};

const CANARY: &str = "SYNTHETIC_R8_ERROR_ORIGIN_CANARY";
const BEGIN: &str = "-----BEGIN A PRIVATE KEY-----";
const END: &str = "-----END A PRIVATE KEY-----";
const MALFORMED: &str = "malformed sensitive container. Correct its delimiters and retry.";
const STRUCTURED_DEPTH: &str = "structured input exceeds nesting limit. Reduce nesting and retry.";
const SENSITIVE_DEPTH: &str =
    "sensitive container exceeds nesting limit. Reduce nesting and retry.";
const JSON_STRING: &str = "invalid quoted JSON value. Correct its string escapes and retry.";

struct Case {
    name: &'static str,
    input: String,
    output: Option<String>,
    report: String,
    diagnostic: Option<&'static str>,
}

fn unchanged(name: &'static str, input: String) -> Case {
    Case {
        name,
        output: Some(input.clone()),
        input,
        report: String::new(),
        diagnostic: None,
    }
}

fn failure(name: &'static str, input: String, diagnostic: &'static str) -> Case {
    Case {
        name,
        input,
        output: None,
        report: String::new(),
        diagnostic: Some(diagnostic),
    }
}

fn context_prefix() -> String {
    format!("{{'{BEGIN}':\n{CANARY}\n{END}' ")
}

fn cases() -> Vec<Case> {
    let j = format!("'\\{END}\"'");
    let nesting = format!("{{\"a\":{j}{}{}\n", "{".repeat(64), "}".repeat(65));
    let mut cases = vec![
        unchanged("JSON candidate nesting", format!("{nesting}x\"\n")),
        unchanged(
            "grep marker candidate nesting",
            format!(
                "M\"\\{END}\"\n{{\"{}{}\nx\"\n",
                "{".repeat(64),
                "}".repeat(65)
            ),
        ),
        unchanged(
            "JSON nesting with later logs",
            format!("{nesting}{}msg=\"done\"\n", "INFO ok\n".repeat(3)),
        ),
        unchanged(
            "depth control below limit",
            format!("{{\"a\":{j}{}{}\nx\"\n", "{".repeat(62), "}".repeat(63)),
        ),
        unchanged(
            "marker without backslash",
            format!(
                "{{\"a\":'{END}\"'{}{}\nx\"\n",
                "{".repeat(64),
                "}".repeat(65)
            ),
        ),
        failure(
            "JSON nesting without later quote",
            nesting,
            STRUCTURED_DEPTH,
        ),
    ];
    for (name, value, rendered, hash) in [
        (
            "context malformed container",
            "\"password\": {\"a\": ]}}\n".to_string(),
            "[REDACTED sha256=e7a528d208961fc2]".to_string(),
            "e7a528d208961fc2",
        ),
        (
            "context raw tab JSON",
            "\"password\": \"a\tb\"}\n".to_string(),
            "\"[REDACTED sha256=894891f8b78a9945]\"}".to_string(),
            "894891f8b78a9945",
        ),
        (
            "context sensitive nesting",
            format!("\"password\": {}{}}}\n", "[".repeat(65), "]".repeat(65)),
            "[REDACTED sha256=c868e85df442c740]".to_string(),
            "c868e85df442c740",
        ),
    ] {
        cases.push(Case {
            name,
            input: format!("{}{value}'\n", context_prefix()),
            output: Some(format!("{{'[REDACTED sha256=a13f7d5530ca8963]' \"password\": {rendered}\n'\n")),
            report: format!("rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=a13f7d5530ca8963; private-key block\nrstr: line 3: sha256={hash}; sensitive field or quoted credential\n"),
            diagnostic: None,
        });
    }
    cases.push(failure(
        "context without later quote",
        format!("{}\"password\": {{\"a\": ]}}}}\n", context_prefix()),
        MALFORMED,
    ));
    cases.push(failure(
        "no quote after BEGIN",
        format!("{{'{BEGIN}:\n{CANARY}\n{END}' \"password\": {{\"a\": ]}}}}\n'\n"),
        MALFORMED,
    ));
    cases
}

struct Reads<'a> {
    input: &'a [u8],
    at: usize,
    cuts: Vec<usize>,
    size: usize,
    interrupt: bool,
}

impl Read for Reads<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.interrupt && self.at == self.input.len() {
            return Err(io::Error::other("synthetic producer failed"));
        }
        let end = self
            .cuts
            .iter()
            .copied()
            .find(|cut| *cut > self.at)
            .unwrap_or(self.input.len());
        let count = (end - self.at).min(out.len()).min(self.size);
        out[..count].copy_from_slice(&self.input[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

#[derive(PartialEq, Eq)]
struct Outcome {
    output: Vec<u8>,
    report: Vec<u8>,
    error: Option<SafeError>,
}

fn stream(input: &[u8], cuts: Vec<usize>, size: usize, interrupt: bool) -> Outcome {
    let mut output = Vec::new();
    let mut report = Vec::new();
    let error = match filter_to_writer(
        Reads {
            input,
            at: 0,
            cuts,
            size,
            interrupt,
        },
        &mut output,
    ) {
        Ok(metadata) => {
            metadata.write(&mut report).must();
            None
        }
        Err(error) => Some(error),
    };
    Outcome {
        output,
        report,
        error,
    }
}

fn batch(case: &Case) -> Outcome {
    match filter_with_evidence(case.input.as_bytes()) {
        Ok(filtered) => {
            let mut metadata = RedactionReport::default();
            let mut report = Vec::new();
            metadata.observe(&filtered.redactions, 1).must();
            metadata.write(&mut report).must();
            assert!(
                Some(&filtered.output) == case.output.as_ref(),
                "pinned batch output changed: {}",
                case.name
            );
            assert!(
                report == case.report.as_bytes(),
                "pinned batch evidence changed: {}",
                case.name
            );
            Outcome {
                output: filtered.output.into_bytes(),
                report,
                error: None,
            }
        }
        Err(error) => {
            let error = error.in_stream(1, false);
            assert!(
                case.output.is_none()
                    && error.to_string() == format!("line 1: {}", case.diagnostic.must()),
                "pinned batch failure changed: {}: {error}",
                case.name
            );
            Outcome {
                output: Vec::new(),
                report: Vec::new(),
                error: Some(error),
            }
        }
    }
}

fn safe(outcome: &Outcome) {
    assert!(!String::from_utf8_lossy(&outcome.output).contains(CANARY));
    assert!(!String::from_utf8_lossy(&outcome.report).contains(CANARY));
    if let Some(error) = &outcome.error {
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }
}

#[test]
fn provisional_error_reproductions_and_controls_keep_exact_batch_results_at_every_split() {
    for case in cases() {
        let expected = batch(&case);
        safe(&expected);
        for split in 0..=case.input.len() {
            assert!(
                stream(case.input.as_bytes(), vec![split], usize::MAX, false) == expected,
                "{} changed at split {split}",
                case.name
            );
        }
        for size in [1, 2, 7, 31] {
            assert!(
                stream(case.input.as_bytes(), Vec::new(), size, false) == expected,
                "{} changed at read size {size}",
                case.name
            );
        }
        let cuts = case
            .input
            .bytes()
            .enumerate()
            .filter_map(|(at, byte)| (byte == b'\n').then_some(at + 1))
            .collect();
        assert!(
            stream(case.input.as_bytes(), cuts, usize::MAX, false) == expected,
            "{} changed at line reads",
            case.name
        );
    }
}

#[test]
fn provisional_error_prefixes_wait_for_completion_and_input_failures_use_global_lines() {
    for case in cases().into_iter().filter(|case| {
        case.name != "no quote after BEGIN" && case.name != "marker without backslash"
    }) {
        let end = if case.name.starts_with("context ") && case.output.is_some() {
            case.input.len() - 2
        } else if case.name == "JSON nesting with later logs" {
            case.input.find("INFO").must()
        } else if case.output.is_some() {
            case.input.len() - 3
        } else {
            case.input.len()
        };
        let input = format!("status=200\n{}", &case.input[..end]);
        let expected = stream(input.as_bytes(), Vec::new(), usize::MAX, true);
        let error = expected.error.as_ref().must();
        assert!(
            error.kind == ErrorKind::Input && error.line == Some(2) && error.earlier_output_emitted,
            "provisional parse error did not wait: {}",
            case.name
        );
        assert!(expected.output == b"status=200\n" && expected.report.is_empty());
        safe(&expected);
        for split in 0..=input.len() {
            assert!(
                stream(input.as_bytes(), vec![split], 7, true) == expected,
                "interrupted hold changed at split {split}: {}",
                case.name
            );
        }
    }
}

fn final_errors() -> Vec<Case> {
    vec![
        failure(
            "closed log nested quote",
            format!("level=error msg=\"bad line: password=\\\"{CANARY}\" code=1\n"),
            "unterminated quoted value. Close the quoted value and retry.",
        ),
        failure(
            "closed JSON nested quote",
            format!("{{\"msg\":\"bad line: password=\\\"{CANARY}\"}}\n"),
            "unterminated quoted value. Close the quoted value and retry.",
        ),
        failure(
            "closed nested escaped quote",
            format!("level=error msg=\"token=\\\\\\\"{CANARY}\" code=1\n"),
            "unterminated escaped quoted value. Close its escaped quote and retry.",
        ),
        failure(
            "definite malformed container",
            format!("{{\"password\":[}}]}} {CANARY}\n"),
            MALFORMED,
        ),
        failure(
            "definite sensitive nesting",
            format!(
                "{{\"password\":{}{}{CANARY}}}\n",
                "[".repeat(65),
                "]".repeat(65)
            ),
            SENSITIVE_DEPTH,
        ),
        failure(
            "definite structured nesting",
            format!("{}{CANARY}{}\n", "{\"x\":".repeat(65), "}".repeat(65)),
            STRUCTURED_DEPTH,
        ),
        failure(
            "definite raw tab JSON",
            format!("{{\"password\":\"{CANARY}\ta\"}}\n"),
            JSON_STRING,
        ),
    ]
}

#[test]
fn final_nested_and_structure_errors_fail_without_reading_eof_or_later_records() {
    for case in final_errors() {
        let mut expected = batch(&case);
        let error = expected.error.as_mut().must();
        *error = error.clone().in_stream(2, true);
        expected.output = b"status=200\n".to_vec();
        let input = format!("status=200\n{}", case.input);
        for size in [1, 7, usize::MAX] {
            let result = stream(input.as_bytes(), Vec::new(), size, true);
            assert!(
                result == expected,
                "final error waited for input: {}",
                case.name
            );
            safe(&result);
        }
        for split in 0..=input.len() {
            assert!(
                stream(input.as_bytes(), vec![split], usize::MAX, true) == expected,
                "final error changed at split {split}: {}",
                case.name
            );
        }
    }
}

#[test]
fn unresolved_provisional_errors_at_eof_preserve_prior_output_and_exact_global_diagnostics() {
    for case in cases().into_iter().filter(|case| case.output.is_none()) {
        let input = format!("status=200\n{}", case.input);
        let error = batch(&case).error.must().in_stream(2, true);
        assert!(
            error.to_string()
                == format!(
                    "line 2: {} Earlier filtered output was emitted; the unfinished record was withheld.",
                    case.diagnostic.must()
                )
        );
        let expected = Outcome {
            output: b"status=200\n".to_vec(),
            report: Vec::new(),
            error: Some(error),
        };
        safe(&expected);
        for split in 0..=input.len() {
            assert!(
                stream(input.as_bytes(), vec![split], 7, false) == expected,
                "global EOF error changed at split {split}: {}",
                case.name
            );
        }
    }
}

#[test]
fn staged_cli_holds_provisional_failures_and_reports_final_errors_before_eof() {
    let mut records = Vec::new();
    for case in cases()
        .into_iter()
        .filter(|case| case.output.is_some() && case.name != "marker without backslash")
    {
        let expected = batch(&case);
        records.push(serde_json::json!({"name":case.name,"input":case.input,"output":String::from_utf8(expected.output).must(),"stderr":String::from_utf8(expected.report).must(),"exit":0,"hold":true}));
    }
    for case in final_errors() {
        let expected = batch(&case).error.must().in_stream(2, true);
        records.push(serde_json::json!({"name":case.name,"input":format!("status=200\n{}",case.input),"output":"status=200\n","stderr":format!("rstr: {expected}\n"),"exit":2,"hold":false}));
    }
    let result = Command::new("python3").env_clear().env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, select, subprocess, sys
for case in json.loads(sys.argv[2]):
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    try:
        if case['hold']:
            for line in case['input'].splitlines(keepends=True):
                p.stdin.write(line.encode()); p.stdin.flush()
                ready = select.select([p.stdout, p.stderr], [], [], .02)[0]
                assert not ready and p.poll() is None, 'provisional candidate escaped its hold: ' + case['name']
            p.stdin.close(); p.stdin = None
        else:
            p.stdin.write(case['input'].encode()); p.stdin.flush()
            p.wait(timeout=5)
            p.stdin = None
        out, err = p.communicate(timeout=5)
        assert p.returncode == case['exit'], 'CLI status mismatch: ' + case['name']
        assert out == case['output'].encode(), 'CLI stdout mismatch: ' + case['name']
        assert err == case['stderr'].encode(), 'CLI stderr mismatch: ' + case['name']
        assert b'SYNTHETIC_R8_ERROR_ORIGIN_CANARY' not in out + err, 'CLI canary disclosure'
    finally:
        if p.poll() is None: p.kill(); p.wait()
"#, env!("CARGO_BIN_EXE_rstr"), &serde_json::to_string(&records).must()]).output().must();
    assert!(
        result.status.success(),
        "staged origin regressions failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 192, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn provisional_error_cases_keep_status_spans_and_evidence_under_generated_reads(index in 0usize..11, size in 1usize..128, cuts in prop::collection::vec(0usize..4096, 0..12)) {
        let case = cases().into_iter().nth(index).must();
        let expected = batch(&case);
        let mut cuts: Vec<_> = cuts.into_iter().map(|cut| cut % (case.input.len() + 1)).collect();
        cuts.sort_unstable(); cuts.dedup();
        prop_assert!(stream(case.input.as_bytes(), cuts, size, false) == expected, "provisional error changed at generated read boundaries");
    }
}
