mod support;

use serde_json::Value;
use std::ffi::OsString;
use std::process::Output;

const CANARY: &str = "synthetic-secret-private-canary-9853";

fn status(output: &Output, code: i32) {
    assert_eq!(output.status.code(), Some(code));
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(bytes).contains(CANARY),
            "canary disclosed"
        );
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| panic!("invalid JSON"))
}

#[test]
fn allow_redact_order_and_exact_names() {
    for flags in [
        vec!["--allow", "KEY", "--redact", "KEY"],
        vec!["--redact", "KEY", "--allow", "KEY"],
    ] {
        let mut command = support::command("rprintenv");
        command
            .args(flags)
            .args(["--json", "KEY", "KEY_suffix", "key", "EMPTY", "MISSING"])
            .env("KEY", CANARY)
            .env("KEY_suffix", CANARY)
            .env("key", CANARY)
            .env("EMPTY", "");
        let output = support::finish(&mut command);
        status(&output, 1);
        let records = &json(&output)["records"];
        assert_eq!(records[0]["state"], "empty");
        assert_eq!(records[1]["state"], "redacted");
        assert_eq!(records[2]["state"], "redacted");
        assert_eq!(records[3]["state"], "missing");
        assert_eq!(records[4]["state"], "redacted");
    }
    let mut command = support::command("rprintenv");
    command
        .args(["--allow", "PUBLIC", "--json", "PUBLIC"])
        .env("PUBLIC", "ordinary synthetic value");
    let output = support::capture(&mut command, b"");
    status(&output, 0);
    assert_eq!(
        json(&output)["records"][0]["value"],
        "ordinary synthetic value"
    );
}

#[test]
fn source_validation_is_atomic_and_unselected_entries_are_checked() {
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("temp directory failed"));
    std::fs::write(temp.path().join("valid"), "KEY=abc\n")
        .unwrap_or_else(|_| panic!("fixture write failed"));
    let malformed = format!("KEY=abc\nUNSELECTED=\"{CANARY}\\q\"\n");
    std::fs::write(temp.path().join("bad"), malformed)
        .unwrap_or_else(|_| panic!("fixture write failed"));
    let mut command = support::command("rprintenv");
    command
        .current_dir(temp.path())
        .args(["--env", "--file", "valid", "--file", "bad", "KEY"])
        .env("KEY", CANARY)
        .env("RUST_BACKTRACE", "1");
    let output = support::capture(&mut command, b"");
    status(&output, 2);
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("line 2") && error.contains("unsupported escape"));
    assert!(!error.contains("UNSELECTED="));
}

#[test]
fn sources_do_not_merge_or_read_implicit_files() {
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("temp directory failed"));
    std::fs::write(temp.path().join(".env"), format!("KEY={CANARY}\n"))
        .unwrap_or_else(|_| panic!("fixture write failed"));
    std::fs::write(temp.path().join("selected"), "EMPTY=\n")
        .unwrap_or_else(|_| panic!("fixture write failed"));
    let mut command = support::command("rprintenv");
    command.current_dir(temp.path()).args(["--json", "KEY"]);
    let output = support::capture(&mut command, b"");
    status(&output, 1);
    assert_eq!(json(&output)["records"][0]["state"], "missing");
    let mut command = support::command("rprintenv");
    command
        .current_dir(temp.path())
        .args(["--file", "selected", "--json", "KEY"])
        .env("KEY", CANARY);
    let output = support::capture(&mut command, b"");
    status(&output, 1);
    assert_eq!(json(&output)["records"].as_array().map(Vec::len), Some(1));
    assert_eq!(json(&output)["records"][0]["state"], "missing");
}

#[test]
fn usage_errors_are_generic_and_help_avoids_sources() {
    for args in [
        vec![format!("--{CANARY}")],
        vec!["--exists".to_owned()],
        vec!["--exists".to_owned(), "--json".to_owned(), "KEY".to_owned()],
        vec![
            "--exists".to_owned(),
            "--allow".to_owned(),
            "KEY".to_owned(),
            "KEY".to_owned(),
        ],
        vec![
            "--exists".to_owned(),
            "--redact".to_owned(),
            "KEY".to_owned(),
            "KEY".to_owned(),
        ],
        vec!["--file".to_owned(), "-".to_owned()],
        vec![
            "--file".to_owned(),
            CANARY.to_owned(),
            "--file".to_owned(),
            CANARY.to_owned(),
        ],
    ] {
        let mut command = support::command("rprintenv");
        command.args(args).env("RUST_BACKTRACE", "full");
        let output = support::capture(&mut command, b"");
        status(&output, 2);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Use --help"));
    }
    for flag in ["--help", "--version"] {
        let mut command = support::command("rprintenv");
        command
            .args(["--file", "synthetic-nonexistent-file", flag])
            .env("KEY", CANARY);
        let output = support::capture(&mut command, b"");
        status(&output, 0);
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn metadata_and_allowed_values_are_escaped_to_physical_lines() {
    let name = "synthetic\tname\n\u{1b}";
    let value = "ordinary\ttext\n\u{1b}";
    let mut command = support::command("rprintenv");
    command.args(["--allow", name, name]).env(name, value);
    let output = support::capture(&mut command, b"");
    status(&output, 0);
    let line = String::from_utf8(output.stdout).unwrap_or_else(|_| panic!("invalid text"));
    assert_eq!(line.lines().count(), 1);
    assert!(!line.contains('\u{1b}'));
    let fields: Vec<_> = line.trim_end().split('\t').collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(
        serde_json::from_str::<String>(fields[1]).ok().as_deref(),
        Some(name)
    );
    assert_eq!(
        serde_json::from_str::<String>(fields[2]).ok().as_deref(),
        Some(value)
    );
}

#[test]
fn multiline_decoding_matches_environment_and_never_executes() {
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("temp directory failed"));
    std::fs::write(
        temp.path().join("values"),
        "KEY=\"a\r\nb\\t${OTHER}\"\r\nCOMMAND=$(touch synthetic-sentinel)\r\n",
    )
    .unwrap_or_else(|_| panic!("fixture write failed"));
    let mut command = support::command("rprintenv");
    command
        .current_dir(temp.path())
        .args(["--env", "--file", "values", "--json", "KEY"])
        .env("KEY", "a\nb\t${OTHER}");
    let output = support::capture(&mut command, b"");
    status(&output, 0);
    let records = &json(&output)["records"];
    assert_eq!(records[0]["fingerprint"], records[1]["fingerprint"]);
    assert!(!temp.path().join("synthetic-sentinel").exists());
}

#[test]
fn input_errors_and_invalid_encoding_are_safe() {
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("temp directory failed"));
    for (filename, contents) in [
        ("invalid-utf8", vec![0xff]),
        ("nul", b"KEY=synthetic\0canary".to_vec()),
        (
            "duplicate",
            format!("KEY={CANARY}\nKEY={CANARY}\n").into_bytes(),
        ),
    ] {
        std::fs::write(temp.path().join(filename), contents)
            .unwrap_or_else(|_| panic!("fixture write failed"));
        let mut command = support::command("rprintenv");
        command.current_dir(temp.path()).args(["--file", filename]);
        let output = support::capture(&mut command, b"");
        status(&output, 2);
        assert!(output.stdout.is_empty());
    }
    let mut command = support::command("rprintenv");
    command
        .current_dir(temp.path())
        .args(["--file", "nonexistent"]);
    let output = support::capture(&mut command, b"");
    status(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("file not found"));
}

#[cfg(unix)]
#[test]
fn non_unicode_environment_and_arguments_fail_without_echo() {
    use std::os::unix::ffi::OsStringExt;
    for invalid_name in [false, true] {
        let mut command = support::command("rprintenv");
        let invalid = OsString::from_vec(vec![b's', 0xff]);
        if invalid_name {
            command.env(invalid, CANARY);
        } else {
            command.env("KEY", invalid);
        }
        command.arg("--json");
        let output = support::capture(&mut command, b"");
        status(&output, 2);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("UTF-8"));
    }
    let mut command = support::command("rprintenv");
    command.arg(OsString::from_vec(vec![b'-', b'-', 0xff]));
    let output = support::capture(&mut command, b"");
    status(&output, 2);
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn closed_output_pipe_returns_safe_output_failure() {
    use std::process::Stdio;
    // Close-on-exec prevents parallel subprocess tests from keeping a reader alive.
    let (reader, writer) = std::io::pipe().unwrap_or_else(|_| panic!("output pipe setup failed"));
    drop(reader);
    let mut command = support::command("rprintenv");
    command
        .arg("KEY")
        .env("KEY", CANARY)
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped());
    let output = command
        .output()
        .unwrap_or_else(|_| panic!("process failed"));
    status(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not write output"));
}

#[test]
fn presence_requires_each_name_in_each_source_and_fully_validates() {
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("temp directory failed"));
    std::fs::write(temp.path().join("values"), "EMPTY=\nKEY=abc\n")
        .unwrap_or_else(|_| panic!("fixture write failed"));
    for (names, exit) in [(vec!["EMPTY", "KEY"], 0), (vec!["EMPTY", "MISSING"], 1)] {
        let mut command = support::command("rprintenv");
        command
            .current_dir(temp.path())
            .args(["--env", "--file", "values", "--exists"])
            .args(names)
            .env("EMPTY", "")
            .env("KEY", CANARY);
        let output = support::capture(&mut command, b"");
        status(&output, exit);
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
    let mut command = support::command("rprintenv");
    command
        .current_dir(temp.path())
        .args(["--env", "--file", "values", "--exists", "KEY"]);
    let output = support::capture(&mut command, b"");
    status(&output, 1);
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    std::fs::write(
        temp.path().join("values"),
        format!("KEY=abc\nBAD='{CANARY}"),
    )
    .unwrap_or_else(|_| panic!("fixture write failed"));
    let mut command = support::command("rprintenv");
    command
        .current_dir(temp.path())
        .args(["--file", "values", "--exists", "MISSING"]);
    let output = support::capture(&mut command, b"");
    status(&output, 2);
    assert!(output.stdout.is_empty());
}

#[test]
fn selection_deduplicates_sorts_and_keeps_distinct_path_arguments() {
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("temp directory failed"));
    std::fs::write(temp.path().join("values"), "Z=abc\nA=abc\n")
        .unwrap_or_else(|_| panic!("fixture write failed"));
    let mut command = support::command("rprintenv");
    command
        .current_dir(temp.path())
        .args([
            "--env", "--file", "values", "--file", "./values", "--json", "Z", "A", "Z",
        ])
        .env("Z", "abc")
        .env("A", "abc");
    let output = support::capture(&mut command, b"");
    status(&output, 0);
    let data = json(&output);
    let records = data["records"]
        .as_array()
        .unwrap_or_else(|| panic!("no records"));
    assert_eq!(records.len(), 6);
    for pair in records.as_chunks::<2>().0 {
        assert_eq!(pair[0]["name"], "A");
        assert_eq!(pair[1]["name"], "Z");
        assert_eq!(pair[0]["fingerprint"], "ba7816bf8f01cfea");
        assert_eq!(pair[0].as_object().map(|record| record.len()), Some(6));
    }
    assert_eq!(records[0]["source"]["kind"], "environment");
    assert_eq!(records[2]["source"]["path"], "values");
    assert_eq!(records[4]["source"]["path"], "./values");
}

#[test]
fn empty_listing_is_success_and_double_dash_selects_option_like_names() {
    let mut command = support::command("rprintenv");
    command.arg("--env");
    let output = support::capture(&mut command, b"");
    status(&output, 0);
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let mut command = support::command("rprintenv");
    command
        .args(["--json", "--", "--help"])
        .env("--help", CANARY);
    let output = support::capture(&mut command, b"");
    status(&output, 0);
    assert_eq!(json(&output)["records"][0]["name"], "--help");
    assert_eq!(json(&output)["records"][0]["state"], "redacted");
}
