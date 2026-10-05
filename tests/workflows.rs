#[path = "workflows/failures.rs"]
mod failures;
mod support;

use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixtures {
    fixture_version: u32,
    synthetic_only: bool,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    binary: String,
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    files: BTreeMap<String, String>,
    stdin_utf8: String,
    expect: Expectation,
    hidden_canaries: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expectation {
    exit_code: i32,
    stdout_utf8: Option<String>,
    stdout_json: Option<Value>,
    stderr_utf8: Option<String>,
    stderr_contains: Option<Vec<String>>,
}

fn cases() -> Vec<Case> {
    let mut ids = BTreeSet::new();
    let mut cases = Vec::new();
    for source in [
        include_str!("fixtures/rprintenv-workflows.json"),
        include_str!("fixtures/rstr-workflows.json"),
    ] {
        let fixtures: Fixtures =
            serde_json::from_str(source).unwrap_or_else(|_| panic!("invalid fixture schema"));
        assert_eq!(fixtures.fixture_version, 1);
        assert!(fixtures.synthetic_only);
        for case in fixtures.cases {
            assert!(ids.insert(case.id.clone()), "duplicate fixture ID");
            assert!(matches!(case.binary.as_str(), "rprintenv" | "rstr"));
            assert_ne!(
                case.expect.stdout_utf8.is_some(),
                case.expect.stdout_json.is_some()
            );
            assert_ne!(
                case.expect.stderr_utf8.is_some(),
                case.expect.stderr_contains.is_some()
            );
            for path in case.files.keys() {
                assert!(!path.is_empty());
                assert!(
                    Path::new(path)
                        .components()
                        .all(|part| matches!(part, Component::Normal(_))),
                    "unsafe fixture path"
                );
            }
            cases.push(case);
        }
    }
    cases
}

fn run(id: &str) {
    let case = cases()
        .into_iter()
        .find(|case| case.id == id)
        .unwrap_or_else(|| panic!("missing named fixture"));
    execute(&case);
}

fn execute(case: &Case) {
    let id = case.id.as_str();
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("fixture directory failed"));
    for (path, contents) in &case.files {
        let destination = temp.path().join(path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|_| panic!("fixture directory failed"));
        }
        std::fs::write(destination, contents).unwrap_or_else(|_| panic!("fixture file failed"));
    }
    let repeats = if id == "stable_text_fingerprint" {
        2
    } else {
        1
    };
    let mut previous = None;
    for _ in 0..repeats {
        let mut command = support::command(&case.binary);
        command
            .args(&case.args)
            .envs(&case.environment)
            .current_dir(temp.path());
        let start = Instant::now();
        let output = support::capture(&mut command, case.stdin_utf8.as_bytes());
        assert_eq!(
            output.status.code(),
            Some(case.expect.exit_code),
            "{id}: exit mismatch"
        );
        for canary in &case.hidden_canaries {
            for bytes in [&output.stdout, &output.stderr] {
                let text = String::from_utf8_lossy(bytes);
                assert!(!text.contains(canary), "{id}: canary disclosed");
                let escaped = serde_json::to_string(canary)
                    .unwrap_or_else(|_| panic!("canary encoding failed"));
                assert!(
                    !text.contains(&escaped[1..escaped.len() - 1]),
                    "{id}: escaped canary disclosed"
                );
            }
        }
        if let Some(expected) = &case.expect.stdout_utf8 {
            assert!(
                output.stdout == expected.as_bytes(),
                "{id}: stdout mismatch"
            );
        }
        if let Some(expected) = &case.expect.stdout_json {
            let actual: Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|_| panic!("{id}: invalid output JSON"));
            assert!(actual == *expected, "{id}: JSON mismatch");
        }
        if let Some(expected) = &case.expect.stderr_utf8 {
            assert!(
                output.stderr == expected.as_bytes(),
                "{id}: stderr mismatch"
            );
        }
        if let Some(fragments) = &case.expect.stderr_contains {
            let stderr = String::from_utf8_lossy(&output.stderr);
            for fragment in fragments {
                assert!(
                    stderr.contains(fragment),
                    "{id}: required diagnostic missing"
                );
            }
        }
        if let Some(previous) = &previous {
            assert!(
                *previous == output.stdout,
                "{id}: output changed across processes"
            );
        }
        eprintln!(
            "{id}: commands=1 elapsed_us={} stdout_bytes={}",
            start.elapsed().as_micros(),
            output.stdout.len()
        );
        previous = Some(output.stdout);
    }
}

#[test]
fn recovery_pairs_use_two_commands_and_a_synthetic_quote_correction() {
    for (failed, corrected) in [
        ("malformed_file_recovery", "malformed_file_corrected"),
        ("malformed_stdin_recovery", "malformed_stdin_corrected"),
    ] {
        let mut failed_case = cases()
            .into_iter()
            .find(|case| case.id == failed)
            .unwrap_or_else(|| panic!("missing recovery fixture"));
        let corrected_case = cases()
            .into_iter()
            .find(|case| case.id == corrected)
            .unwrap_or_else(|| panic!("missing corrected fixture"));
        execute(&failed_case);
        if failed_case.binary == "rprintenv" {
            let file = failed_case
                .files
                .get_mut(".env")
                .unwrap_or_else(|| panic!("missing recovery file"));
            file.push_str("\"\n");
            assert!(failed_case.files == corrected_case.files);
        } else {
            failed_case.stdin_utf8.push_str("\"\n");
            assert!(failed_case.stdin_utf8 == corrected_case.stdin_utf8);
        }
        failed_case.id = corrected_case.id;
        failed_case.expect = corrected_case.expect;
        execute(&failed_case);
        eprintln!("{failed}: recovery_commands=2 correction=close_quote");
    }
}

macro_rules! workflows {
    ($($id:ident),+ $(,)?) => { $(#[test] fn $id() { run(stringify!($id)); })+ };
}

workflows!(
    presence_empty_is_present,
    presence_missing,
    configuration_states,
    targeted_inspection,
    compare_explicit_sources,
    stable_text_fingerprint,
    malformed_file_recovery,
    malformed_file_corrected,
    bare_value_has_no_context,
    json_preserves_diagnostic_context,
    quoted_log_preserves_following_fields,
    header_preserves_scheme_and_other_lines,
    ambiguous_unquoted_value_is_conservative,
    environment_and_files_do_not_affect_filter,
    malformed_stdin_recovery,
    malformed_stdin_corrected,
    ordinary_output_has_no_banner,
    unicode_provider_boundaries,
    unicode_header_case_folding,
);

#[test]
fn every_fixture_has_a_named_test() {
    let source = include_str!("workflows.rs");
    for case in cases() {
        assert!(
            source.contains(&format!("    {},", case.id)),
            "fixture missing a named test"
        );
    }
}

#[test]
fn producer_streams_flow_directly_to_filter_and_pipefail_preserves_failure() {
    for status in [0, 7] {
        let mut command = std::process::Command::new("/bin/bash");
        command.env_clear().arg("-c").arg(
            "set -o pipefail; { printf '%s\\n' 'password=synthetic-secret-lilac-48'; printf '%s\\n' 'status=401' >&2; exit \"$2\"; } 2>&1 | \"$1\""
        ).arg("workflow").arg(env!("CARGO_BIN_EXE_rstr")).arg(status.to_string());
        let output = support::capture(&mut command, b"");
        assert_eq!(output.status.code(), Some(status));
        assert!(output.stdout == b"password=[REDACTED sha256=1d5a8919184510ff]\nstatus=401\n");
        assert!(output.stderr.is_empty());
    }
}
