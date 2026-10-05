use serde::Deserialize;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixtures {
    fixture_version: u32,
    synthetic_only: bool,
    inventory: Vec<Inventory>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    id: String,
    evidence: String,
    source_document: String,
    retrieved: String,
    scope: String,
    rule: String,
    versions: String,
    limitation: String,
    span_boundary: String,
    classification: String,
    default_v1: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    inventory_id: String,
    variant: String,
    input: String,
    spans: Vec<ExpectedSpan>,
    expected_stdout: String,
    expected_exit: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedSpan {
    start: usize,
    end: usize,
    fingerprint: String,
}

fn fixtures() -> Fixtures {
    serde_json::from_str(include_str!("fixtures/secret-formats.json")).unwrap()
}

fn run(command: Command, input: &[u8]) -> Output {
    run_synthetic(command, input, None)
}

fn run_synthetic(mut command: Command, input: &[u8], value: Option<&str>) -> Output {
    command.env_clear();
    if let Some(value) = value {
        command.env("SYNTHETIC_FORMAT_VALUE", value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("synthetic subprocess starts");
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    child.stdin.take().unwrap().write_all(input).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("synthetic subprocess exceeded 10-second budget");
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    Output {
        status,
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}

#[test]
fn inventory_rows_have_executable_coverage_and_literal_span_oracles() {
    let fixtures = fixtures();
    assert_eq!(fixtures.fixture_version, 1);
    assert!(fixtures.synthetic_only);
    let ids: BTreeSet<_> = fixtures
        .inventory
        .iter()
        .map(|row| row.id.as_str())
        .collect();
    assert_eq!(ids.len(), fixtures.inventory.len());
    let mut documented = BTreeSet::new();
    for doc in [
        include_str!("../docs/secret-formats/providers.md"),
        include_str!("../docs/secret-formats/cloud.md"),
        include_str!("../docs/secret-formats/structures.md"),
    ] {
        for line in doc.lines().filter(|line| line.starts_with("| ")) {
            let id = line.split('|').nth(1).unwrap().trim();
            if id.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                documented.insert(id);
            }
        }
    }
    assert_eq!(ids, documented);
    for row in &fixtures.inventory {
        assert!(["documented", "example-backed", "context-only"].contains(&row.evidence.as_str()));
        for field in [
            &row.source_document,
            &row.retrieved,
            &row.scope,
            &row.rule,
            &row.versions,
            &row.limitation,
            &row.span_boundary,
            &row.classification,
        ] {
            assert!(!field.is_empty(), "{} has missing ledger metadata", row.id);
        }
        for variant in ["positive", "negative", "malformed", "delimiter", "encoding"] {
            assert!(
                fixtures
                    .cases
                    .iter()
                    .any(|case| case.inventory_id == row.id && case.variant.starts_with(variant)),
                "{} missing {variant}",
                row.id
            );
        }
    }
    assert!(fixtures.inventory.iter().any(|row| row.default_v1));
    let mut case_ids = BTreeSet::new();
    for case in &fixtures.cases {
        assert!(case_ids.insert(&case.id), "duplicate fixture ID");
        assert!(ids.contains(case.inventory_id.as_str()));
        if case.expected_exit == 0 {
            assert_eq!(
                reference_render(&case.input, &case.spans),
                case.expected_stdout,
                "{} fixture oracle is inconsistent",
                case.id
            );
        }
    }
}

fn reference_render(input: &str, spans: &[ExpectedSpan]) -> String {
    let mut output = String::new();
    let mut offset = 0;
    for span in spans {
        assert!(span.start >= offset && span.end > span.start && span.end <= input.len());
        assert!(input.is_char_boundary(span.start) && input.is_char_boundary(span.end));
        assert_eq!(span.fingerprint.len(), 16);
        assert!(
            span.fingerprint
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        output.push_str(&input[offset..span.start]);
        output.push_str(&format!("[REDACTED sha256={}]", span.fingerprint));
        offset = span.end;
    }
    output.push_str(&input[offset..]);
    output
}

#[test]
fn researched_formats_pass_real_rstr_subprocesses() {
    let mut failures = Vec::new();
    for case in fixtures().cases {
        let output = run(
            Command::new(env!("CARGO_BIN_EXE_rstr")),
            case.input.as_bytes(),
        );
        if output.status.code() != Some(case.expected_exit)
            || output.stdout != case.expected_stdout.as_bytes()
        {
            failures.push(format!(
                "{}: exit {:?}, spans {:?}",
                case.id,
                output.status.code(),
                redact::detect(&case.input)
            ));
        }
        if case.expected_exit == 0 {
            assert!(output.stderr.is_empty(), "{} success diagnostics", case.id);
        } else {
            assert!(
                !output.stderr.is_empty(),
                "{} needs safe recovery diagnostic",
                case.id
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_CREDENTIAL_CANARY"),
                "{} error leaked canary",
                case.id
            );
        }
        for span in &case.spans {
            let removed = &case.input[span.start..span.end];
            if removed.len() >= 16 {
                if String::from_utf8_lossy(&output.stdout).contains(removed) {
                    failures.push(format!("{}: stdout leaked synthetic span", case.id));
                }
                if String::from_utf8_lossy(&output.stderr).contains(removed) {
                    failures.push(format!("{}: stderr leaked synthetic span", case.id));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "format failures:\n{}",
        failures.join("\n")
    );
}

#[path = "../fuzz/oracle.rs"]
mod fuzz_oracle;

#[test]
fn fuzz_leak_oracle_rejects_deliberately_defective_outputs() {
    let secret = "SYNTHETIC_FUZZ_CANARY_0123456789\\\"suffix";
    assert!(fuzz_oracle::leaks_canary(secret, secret));
    assert!(fuzz_oracle::leaks_canary(
        &serde_json::to_string(secret).unwrap(),
        secret
    ));
    assert!(fuzz_oracle::leaks_canary(
        "failed: SYNTHETIC_FUZZ_CANARY_",
        secret
    ));
    assert!(!fuzz_oracle::leaks_canary(
        "[REDACTED sha256=ba7816bf8f01cfea]",
        secret
    ));
}

#[test]
fn all_format_spans_remain_hidden_by_rprintenv_independent_of_family() {
    let mut seen = BTreeSet::new();
    for case in fixtures().cases {
        for span in case.spans {
            let value = &case.input[span.start..span.end];
            if !seen.insert(value.to_owned()) {
                continue;
            }
            let mut command = Command::new(env!("CARGO_BIN_EXE_rprintenv"));
            command.args(["--json", "SYNTHETIC_FORMAT_VALUE"]);
            // run() clears inherited environment; explicitly set synthetic data there.
            let output = run_with_value(command, value);
            assert_eq!(
                output.status.code(),
                Some(0),
                "{} environment exit",
                case.id
            );
            assert!(
                output.stderr.is_empty(),
                "{} environment diagnostics",
                case.id
            );
            let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let expected = serde_json::json!({
                "schema_version": 1,
                "records": [{"source":{"kind":"environment"}, "name":"SYNTHETIC_FORMAT_VALUE", "state":"redacted", "value":null, "fingerprint":span.fingerprint}]
            });
            assert_eq!(actual, expected, "{} default environment hiding", case.id);
        }
    }
}

fn run_with_value(command: Command, value: &str) -> Output {
    run_synthetic(command, &[], Some(value))
}

proptest::proptest! {
    #[test]
    fn format_mutations_stay_hidden_under_sensitive_context(
        index in 0usize..1024,
        suffix in "[A-Za-z0-9_./+~=-]{0,128}",
    ) {
        let fixtures = fixtures();
        let case = &fixtures.cases[index % fixtures.cases.len()];
        let original = case.spans.first().map(|span| &case.input[span.start..span.end]).unwrap_or("unknown_future_format");
        let mutated = format!("SYNTHETIC_CREDENTIAL_CANARY_{original}_{suffix}");
        let encoded = serde_json::to_string(&mutated).unwrap();
        let input = format!("{{\"client_secret\":{encoded},\"status\":\"failed\"}}");
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&encoded.as_bytes()[1..encoded.len()-1]);
        let hash: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        let expected = format!("{{\"client_secret\":\"[REDACTED sha256={hash}]\",\"status\":\"failed\"}}");
        proptest::prop_assert_eq!(redact::filter(input.as_bytes()).unwrap(), expected);
    }
}

#[path = "../fuzz/render_oracle.rs"]
mod render_oracle;

#[test]
fn fuzz_render_oracle_accepts_canary_metadata_and_rejects_extra_hidden_data() {
    let name = "SYNTHETIC_FUZZ_CANARY_METADATA";
    let secret = "SYNTHETIC_FUZZ_CANARY_secret_0123456789";
    let snapshots = [redact::environment::Snapshot {
        source: redact::environment::Source::Environment,
        values: redact::environment::RawVariables::from_pairs([(
            name.to_owned(),
            secret.to_owned(),
        )]),
    }];
    let records = redact::environment::sanitize(&snapshots, &Default::default());
    let text = redact::environment::render_text(&records).unwrap();
    let json = redact::environment::render_json(&records).unwrap();
    use sha2::{Digest, Sha256};
    let hash: String = Sha256::digest(secret.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(render_oracle::matches_record(
        name,
        secret,
        "redacted",
        Some(&hash),
        &text,
        &json
    ));
    let mut defective: serde_json::Value = serde_json::from_str(&json).unwrap();
    defective["records"][0]["debug_value"] = secret.into();
    assert!(!render_oracle::matches_record(
        name,
        secret,
        "redacted",
        Some(&hash),
        &text,
        &defective.to_string()
    ));
    assert!(!render_oracle::matches_record(
        name,
        secret,
        "redacted",
        Some(&hash),
        &format!("{text}{secret}"),
        &json
    ));
}
