mod support;

use redact::error::{ErrorKind, SafeError};
use redact::rprintenv::{Failure, policy::Source};
use std::process::Output;

const CANARY: &str = "synthetic-secret-diagnostic-canary-1849";

fn failure(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(CANARY));
    }
    String::from_utf8(output.stderr.clone()).unwrap_or_else(|_| panic!("non-UTF-8 diagnostic"))
}

#[test]
fn invalid_presence_and_source_options_explain_the_specific_recovery() {
    for (arguments, reason, recovery) in [
        (vec!["--exists"], "at least one NAME", "--exists NAME"),
        (
            vec!["--exists", "--json", CANARY],
            "cannot be combined with --json",
            "Remove --json",
        ),
        (
            vec!["--exists", "--allow", CANARY, CANARY],
            "presence checks write no values",
            "Remove disclosure flags",
        ),
        (
            vec!["--exists", "--redact", CANARY, CANARY],
            "presence checks write no values",
            "Remove disclosure flags",
        ),
        (
            vec!["--file", "-"],
            "does not read stdin",
            "Supply --file PATH",
        ),
        (
            vec!["--file", CANARY, "--file", CANARY],
            "duplicate --file source",
            "each explicit path once",
        ),
    ] {
        let output = support::capture(
            support::command("rprintenv")
                .args(arguments)
                .env("API_KEY", CANARY),
            b"",
        );
        let diagnostic = failure(&output);
        assert!(diagnostic.contains(reason));
        assert!(diagnostic.contains(recovery));
    }
}

#[test]
fn missing_values_identify_only_the_known_option_and_required_value() {
    for (flag, placeholder) in [
        ("--file", "PATH"),
        ("--allow", "NAME"),
        ("--redact", "NAME"),
    ] {
        for arguments in [vec![flag], vec![flag, "--json"]] {
            let output = support::capture(
                support::command("rprintenv")
                    .args(arguments)
                    .env("API_KEY", CANARY),
                b"",
            );
            let diagnostic = failure(&output);
            assert!(diagnostic.contains(&format!("{flag} requires a {placeholder}")));
            assert!(diagnostic.contains("Use --help"));
        }
    }
}

#[test]
fn rstr_rejected_arguments_explain_the_stdin_only_interface() {
    for arguments in [vec![CANARY], vec!["--file", CANARY], vec!["--unknown"]] {
        let output = support::capture(
            support::command("rstr")
                .args(arguments)
                .env("API_KEY", CANARY),
            format!("password={CANARY}\n").as_bytes(),
        );
        let diagnostic = failure(&output);
        assert!(diagnostic.contains("rstr reads stdin only"));
        assert!(diagnostic.contains("rstr < FILE"));
        assert!(diagnostic.contains("command 2>&1 | rstr"));
    }
}

#[test]
fn source_categories_and_escaped_paths_survive_without_source_contents() {
    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("fixture setup failed"));
    let encoded = format!("API_KEY={CANARY}\n").into_bytes();
    let mut invalid = encoded;
    invalid.push(0xff);
    std::fs::write(directory.path().join("invalid\n.env"), invalid)
        .unwrap_or_else(|_| panic!("fixture write failed"));
    for (path, reason, recovery) in [
        ("absent\n.env", "file not found", "--file PATH"),
        (".", "not a regular file", "UTF-8 .env file"),
        ("invalid\n.env", "line 2", "Supply UTF-8 input"),
    ] {
        let output = support::capture(
            support::command("rprintenv")
                .current_dir(directory.path())
                .args(["--env", "--file", path])
                .env("API_KEY", CANARY),
            b"",
        );
        let diagnostic = failure(&output);
        let escaped = serde_json::to_string(path).unwrap_or_else(|_| panic!("encoding failed"));
        assert!(diagnostic.starts_with(&format!("rprintenv: {escaped}: ")));
        assert!(diagnostic.contains(reason));
        assert!(diagnostic.contains(recovery));
        assert_eq!(diagnostic.lines().count(), 1);
    }
}

#[cfg(unix)]
#[test]
fn unreadable_file_reports_permission_denied_without_disclosing_other_sources() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap_or_else(|_| panic!("fixture setup failed"));
    let path = directory.path().join("unreadable.env");
    std::fs::write(&path, format!("API_KEY={CANARY}\n"))
        .unwrap_or_else(|_| panic!("fixture write failed"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0))
        .unwrap_or_else(|_| panic!("fixture permissions failed"));
    let output = support::finish(
        support::command("rprintenv")
            .current_dir(directory.path())
            .args(["--env", "--file", "unreadable.env"])
            .env("API_KEY", CANARY),
    );
    let diagnostic = failure(&output);
    assert!(diagnostic.contains("permission denied while reading file"));
    assert!(diagnostic.contains("parent directories"));
}

#[test]
fn stream_failures_keep_global_locations_and_explain_prior_output() {
    let mut error = SafeError::at(ErrorKind::DuplicateName, 4);
    error.previous_line = Some(2);
    let error = error.in_stream(10, true);
    assert_eq!(error.line, Some(13));
    assert_eq!(error.previous_line, Some(11));
    let failure = Failure {
        source: Some(Source::File {
            path: "synthetic\n.env".to_owned(),
        }),
        error,
    };
    assert!(failure.to_string().contains("line 13"));
    assert!(
        failure
            .to_string()
            .contains("previous definition on line 11")
    );
    assert!(
        failure
            .to_string()
            .contains("unfinished record was withheld")
    );
    assert!(std::error::Error::source(&failure).is_none());
    let nested = Some(vec![failure]);
    assert!(!format!("{nested:?}").contains(CANARY));
    let no_location = SafeError::new(ErrorKind::Encoding).in_stream(10, false);
    assert_eq!(no_location.line, Some(10));
    assert!(!no_location.to_string().contains("Earlier filtered output"));
}

#[test]
fn stream_output_failures_do_not_claim_the_current_record_was_withheld() {
    let error = SafeError::new(ErrorKind::Output).in_stream(7, true);
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("line 7"));
    assert!(diagnostic.contains("Some filtered output may already have been written"));
    assert!(diagnostic.contains("Treat stdout as incomplete"));
    assert!(!diagnostic.contains("record was withheld"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn invalid_final_line_has_the_same_global_location_with_or_without_newline() {
    for invalid in *b"\xff\0" {
        for ending in [b"".as_slice(), b"\n"] {
            let mut input = b"status=401\nmetadata:\n  name: public\nvalue: ".to_vec();
            input.extend_from_slice(CANARY.as_bytes());
            input.push(invalid);
            input.extend_from_slice(ending);
            let output = support::capture(&mut support::command("rstr"), &input);
            assert_eq!(output.status.code(), Some(2));
            assert_eq!(output.stdout, b"status=401\n");
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(diagnostic.starts_with("rstr: line 4:"));
            assert!(diagnostic.contains(if invalid == 0 {
                "NUL bytes"
            } else {
                "not UTF-8"
            }));
            assert!(diagnostic.contains(
                "Earlier filtered output was emitted; the unfinished record was withheld."
            ));
            assert!(!diagnostic.contains(CANARY));
        }
    }
}
