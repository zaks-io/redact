#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Component, Path};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const CANARY: &str = "synthetic-secret-rprintenv-regression-canary";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixtures {
    fixture_version: u8,
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
    expect: Expected,
    hidden_canaries: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    exit_code: i32,
    stdout_utf8: Option<String>,
    stdout_json: Option<Value>,
    stderr_utf8: Option<String>,
    stderr_contains: Option<Vec<String>>,
}

fn execute(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .must();
    child.stdin.take().must().write_all(input).must();
    let mut stdout = child.stdout.take().must();
    let mut stderr = child.stderr.take().must();
    let stdout_thread = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).must();
        output
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).must();
        output
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().must() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(5) {
            child.kill().must();
            child.wait().must();
            panic!("synthetic rprintenv child exceeded five seconds");
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    Output {
        status,
        stdout: stdout_thread.join().must(),
        stderr: stderr_thread.join().must(),
    }
}

fn run(args: &[&str], environment: &[(&str, &str)]) -> Output {
    let directory = tempfile::tempdir().must();
    execute(
        Command::new(env!("CARGO_BIN_EXE_rprintenv"))
            .env_clear()
            .envs(environment.iter().copied())
            .args(args)
            .current_dir(directory.path()),
        b"",
    )
}

fn assert_safe(output: &Output) {
    assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
}

#[test]
fn named_workflows_and_cross_process_stability() {
    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/rprintenv-workflows.json")).must();
    assert_eq!(fixtures.fixture_version, 1);
    assert!(fixtures.synthetic_only);
    let mut ids = BTreeSet::new();
    let mut stable_output = None;
    let mut count = 0;
    for case in fixtures.cases {
        assert!(ids.insert(case.id.clone()), "duplicate fixture ID");
        assert_eq!(case.binary, "rprintenv");
        assert_ne!(
            case.expect.stdout_utf8.is_some(),
            case.expect.stdout_json.is_some()
        );
        assert_ne!(
            case.expect.stderr_utf8.is_some(),
            case.expect.stderr_contains.is_some()
        );
        let directory = tempfile::tempdir().must();
        for (path, contents) in &case.files {
            assert!(!Path::new(path).is_absolute());
            assert!(
                Path::new(path)
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
            );
            let destination = directory.path().join(path);
            std::fs::create_dir_all(destination.parent().must()).must();
            std::fs::write(destination, contents).must();
        }
        let started = Instant::now();
        let mut command = Command::new(env!("CARGO_BIN_EXE_rprintenv"));
        command
            .env_clear()
            .envs(&case.environment)
            .args(&case.args)
            .current_dir(directory.path());
        let output = execute(&mut command, case.stdin_utf8.as_bytes());
        count += 1;
        let stdout = String::from_utf8(output.stdout).must();
        let stderr = String::from_utf8(output.stderr).must();
        assert_eq!(
            output.status.code(),
            Some(case.expect.exit_code),
            "{}",
            case.id
        );
        if let Some(expected) = case.expect.stdout_utf8 {
            assert_eq!(stdout, expected, "{}", case.id);
        }
        if let Some(expected) = case.expect.stdout_json {
            assert_eq!(
                serde_json::from_str::<Value>(&stdout).must(),
                expected,
                "{}",
                case.id
            );
        }
        if let Some(expected) = case.expect.stderr_utf8 {
            assert_eq!(stderr, expected, "{}", case.id);
        }
        if let Some(expected) = case.expect.stderr_contains {
            for fragment in expected {
                assert!(
                    stderr.contains(&fragment),
                    "{} missing safe diagnostic",
                    case.id
                );
            }
        }
        for canary in case.hidden_canaries {
            assert!(
                !stdout.contains(&canary) && !stderr.contains(&canary),
                "{} leaked synthetic canary",
                case.id
            );
        }
        if case.id == "stable_text_fingerprint" {
            let second = execute(&mut command, b"");
            assert_eq!(stdout.as_bytes(), second.stdout);
            assert_eq!(second.status.code(), Some(0));
            stable_output = Some(stdout.len());
        }
        eprintln!(
            "workflow={} commands=1 elapsed_us={} output_bytes={}",
            case.id,
            started.elapsed().as_micros(),
            stdout.len() + stderr.len()
        );
    }
    assert_eq!(count, 8);
    assert!(stable_output.is_some());
}

#[test]
fn ordinary_listing_and_disclosure_overrides() {
    let environment = [
        ("Z_TOKEN", CANARY),
        ("A_TOKEN", "abc"),
        ("NODE_ENV", "production"),
        ("EMPTY", ""),
    ];
    let output = run(&[], &environment);
    assert_eq!(output.status.code(), Some(0));
    assert_safe(&output);
    let text = String::from_utf8(output.stdout).must();
    assert!(text.starts_with("\"env\"\t\"A_TOKEN\"\t[REDACTED sha256=ba7816bf8f01cfea]\n"));
    assert!(text.contains("\"EMPTY\"\t[EMPTY]\n"));
    assert!(text.contains("\"NODE_ENV\"\t\"production\"\n"));
    assert_eq!(text.lines().count(), 4);
    for args in [
        vec!["--redact", "NODE_ENV", "--allow", "NODE_ENV", "NODE_ENV"],
        vec!["--allow", "NODE_ENV", "--redact", "NODE_ENV", "NODE_ENV"],
    ] {
        let output = run(&args, &environment);
        assert_eq!(output.status.code(), Some(0));
        assert!(
            String::from_utf8(output.stdout)
                .must()
                .contains("[REDACTED sha256=")
        );
    }
    let output = run(
        &["--allow", "A_TOKEN", "--json", "A_TOKEN", "A_TOKEN"],
        &environment,
    );
    let value: Value = serde_json::from_slice(&output.stdout).must();
    assert_eq!(value["records"].as_array().must().len(), 1);
    assert_eq!(value["records"][0]["value"], "abc");
    let unexpected = run(&["NODE_ENV"], &[("NODE_ENV", CANARY)]);
    assert_safe(&unexpected);
}

#[test]
fn sources_are_explicit_separate_and_fully_validated() {
    let directory = tempfile::tempdir().must();
    std::fs::write(directory.path().join(".env"), "FILE_ONLY=abc\nEMPTY=\n").must();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rprintenv"));
    command
        .env_clear()
        .env("ENV_ONLY", CANARY)
        .current_dir(directory.path());
    let output = execute(&mut command, b"");
    assert_safe(&output);
    assert!(
        !String::from_utf8(output.stdout)
            .must()
            .contains("FILE_ONLY")
    );
    command.args(["--file", ".env", "--json", "ENV_ONLY", "FILE_ONLY"]);
    let output = execute(&mut command, b"");
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).must();
    assert_eq!(value["records"][0]["state"], "missing");
    assert_eq!(value["records"][1]["fingerprint"], "ba7816bf8f01cfea");
    std::fs::write(
        directory.path().join("bad.env"),
        format!("UNSELECTED=\"{CANARY}"),
    )
    .must();
    let output = execute(
        Command::new(env!("CARGO_BIN_EXE_rprintenv"))
            .env_clear()
            .current_dir(directory.path())
            .args([
                "--file",
                ".env",
                "--file",
                "bad.env",
                "--exists",
                "FILE_ONLY",
            ]),
        b"",
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_safe(&output);
    let output = execute(
        Command::new(env!("CARGO_BIN_EXE_rprintenv"))
            .env_clear()
            .current_dir(directory.path())
            .args(["--file", ".env", "--exists", "EMPTY", "FILE_ONLY"]),
        b"",
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn usage_and_encoding_failures_never_echo_arguments_or_values() {
    for args in [
        vec!["--exists"],
        vec!["--exists", "--json", "TOKEN"],
        vec!["--exists", "--allow", "TOKEN", "TOKEN"],
        vec!["--exists", "--redact", "TOKEN", "TOKEN"],
        vec!["--file", "-"],
        vec!["--file", "synthetic.env", "--file", "synthetic.env"],
        vec!["--allow"],
        vec!["--unknown", CANARY],
    ] {
        let output = run(&args, &[("TOKEN", CANARY), ("RUST_BACKTRACE", "1")]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_safe(&output);
    }
    let output = run(&["--file", "missing-synthetic.env"], &[("TOKEN", CANARY)]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .must()
            .contains("read failed")
    );
    let directory = tempfile::tempdir().must();
    for contents in [b"TOKEN=\xff".as_slice(), b"TOKEN=secret\0".as_slice()] {
        std::fs::write(directory.path().join("invalid.env"), contents).must();
        let output = execute(
            Command::new(env!("CARGO_BIN_EXE_rprintenv"))
                .env_clear()
                .current_dir(directory.path())
                .args(["--file", "invalid.env"]),
            b"",
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn dotenv_decoding_preserves_values_and_never_executes_shell_syntax() {
    let directory = tempfile::tempdir().must();
    let literal = "$(touch sentinel) $NAME ${NAME} `touch sentinel`";
    let contents =
        format!("A='{literal}'\nB=\"{literal}\"\nC={literal}\nD='  abc  '\nE=\"line1\\nline2\"\n");
    std::fs::write(directory.path().join("synthetic.env"), contents).must();
    let output = execute(
        Command::new(env!("CARGO_BIN_EXE_rprintenv"))
            .env_clear()
            .env("A", literal)
            .env("D", "  abc  ")
            .env("E", "line1\nline2")
            .current_dir(directory.path())
            .args(["--env", "--file", "synthetic.env", "--json", "A", "D", "E"]),
        b"",
    );
    assert_eq!(output.status.code(), Some(0));
    let value: Value = serde_json::from_slice(&output.stdout).must();
    let records = value["records"].as_array().must();
    for index in 0..3 {
        assert_eq!(
            records[index]["fingerprint"],
            records[index + 3]["fingerprint"]
        );
    }
    assert!(!directory.path().join("sentinel").exists());
    for name in ["B", "C"] {
        let output = execute(
            Command::new(env!("CARGO_BIN_EXE_rprintenv"))
                .env_clear()
                .current_dir(directory.path())
                .args(["--file", "synthetic.env", "--allow", name, name]),
            b"",
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(String::from_utf8(output.stdout).must().contains(literal));
    }
    assert!(!directory.path().join("sentinel").exists());
}

#[test]
fn physical_line_escaping_and_help_without_source_reads() {
    let output = run(
        &["--allow", "ODD\t\n\u{1b}", "--", "ODD\t\n\u{1b}"],
        &[("ODD\t\n\u{1b}", "ordinary\t\n\u{1b}")],
    );
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).must();
    assert_eq!(text.lines().count(), 1);
    assert!(!text.contains('\u{1b}'));
    let fields: Vec<_> = text.trim_end().split('\t').collect();
    assert_eq!(
        serde_json::from_str::<String>(fields[1]).must(),
        "ODD\t\n\u{1b}"
    );
    assert_eq!(
        serde_json::from_str::<String>(fields[2]).must(),
        "ordinary\t\n\u{1b}"
    );
    for option in ["--help", "--version"] {
        let output = run(
            &["--file", "missing-synthetic.env", option],
            &[("TOKEN", CANARY)],
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert_safe(&output);
        if option == "--help" {
            let help = String::from_utf8(output.stdout).must();
            for fragment in [
                "stable",
                "--exists includes empty",
                "--json NAME",
                "authentication",
                "guessing",
                "--allow prints full",
            ] {
                assert!(help.contains(fragment));
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn invalid_environment_and_closed_output_pipe_fail_safely() {
    use std::os::unix::ffi::OsStringExt;
    let bad =
        std::ffi::OsString::from_vec(b"synthetic-secret-rprintenv-regression-canary\xff".to_vec());
    for name in [true, false] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rprintenv"));
        command.env_clear().env("TOKEN", CANARY);
        if name {
            command.env(&bad, "ordinary");
        } else {
            command.env("BAD_ENCODING", &bad);
        }
        let output = execute(&mut command, b"");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_safe(&output);
    }
    let (reader, writer) = std::os::unix::net::UnixStream::pair().must();
    drop(reader);
    let descriptor: std::os::fd::OwnedFd = writer.into();
    let child = Command::new(env!("CARGO_BIN_EXE_rprintenv"))
        .env_clear()
        .env("TOKEN", CANARY)
        .stdout(Stdio::from(descriptor))
        .stderr(Stdio::piped())
        .spawn()
        .must();
    let output = child.wait_with_output().must();
    assert_eq!(output.status.code(), Some(2));
    assert_safe(&output);
    assert!(
        String::from_utf8(output.stderr)
            .must()
            .contains("output write failed")
    );
}

#[test]
fn missing_and_empty_states_have_exact_json_fields() {
    let output = run(&["--env", "--json", "EMPTY", "MISSING"], &[("EMPTY", "")]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).must(),
        json!({"schema_version":1,"records":[{"source":{"kind":"environment"},"name":"EMPTY","state":"empty","value":"","fingerprint":null},{"source":{"kind":"environment"},"name":"MISSING","state":"missing","value":null,"fingerprint":null}]})
    );
    let output = run(&["--exists", "EMPTY", "MISSING"], &[("EMPTY", "")]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let output = run(&[], &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}
