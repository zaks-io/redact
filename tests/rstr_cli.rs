use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Component, Path},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

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
    stdout_utf8: String,
    stderr_utf8: Option<String>,
    stderr_contains: Option<Vec<String>>,
}

fn capture(mut child: Child, input: &[u8]) -> Output {
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut data = Vec::new();
        stdout.read_to_end(&mut data).unwrap();
        data
    });
    let err = std::thread::spawn(move || {
        let mut data = Vec::new();
        stderr.read_to_end(&mut data).unwrap();
        data
    });
    child.stdin.take().unwrap().write_all(input).ok();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("synthetic rstr subprocess exceeded ten-second budget");
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    Output {
        status,
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}

fn execute(input: &[u8], args: &[&str]) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_rstr"))
        .env_clear()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    capture(child, input)
}

#[test]
fn workflow_fixtures_exercise_real_binary() {
    for source in [
        include_str!("fixtures/rstr-workflows.json"),
        include_str!("fixtures/context-workflows.json"),
    ] {
        let fixture: Fixtures = serde_json::from_str(source).unwrap();
        assert_eq!(fixture.fixture_version, 1);
        assert!(fixture.synthetic_only);
        let mut ids = BTreeSet::new();
        for case in fixture.cases {
            assert!(ids.insert(case.id.clone()), "duplicate fixture ID");
            assert_eq!(case.binary, "rstr");
            assert_ne!(
                case.expect.stderr_utf8.is_some(),
                case.expect.stderr_contains.is_some()
            );
            let directory = tempfile::tempdir().unwrap();
            for (path, contents) in &case.files {
                assert!(
                    !path.is_empty()
                        && Path::new(path)
                            .components()
                            .all(|part| matches!(part, Component::Normal(_))),
                    "unsafe fixture path"
                );
                let path = directory.path().join(path);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, contents).unwrap();
            }
            let child = Command::new(env!("CARGO_BIN_EXE_rstr"))
                .env_clear()
                .envs(&case.environment)
                .args(&case.args)
                .current_dir(directory.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let output = capture(child, case.stdin_utf8.as_bytes());
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert_eq!(
                output.status.code(),
                Some(case.expect.exit_code),
                "{}",
                case.id
            );
            assert_eq!(stdout, case.expect.stdout_utf8, "{}", case.id);
            if let Some(exact) = case.expect.stderr_utf8 {
                assert_eq!(stderr, exact, "{}", case.id);
            }
            if let Some(parts) = case.expect.stderr_contains {
                for part in parts {
                    assert!(stderr.contains(&part), "{}", case.id);
                }
            }
            if case.expect.exit_code == 0 {
                assert!(stderr.is_empty(), "{}", case.id);
            }
            for canary in case.hidden_canaries {
                assert!(!stdout.contains(&canary), "{}", case.id);
                assert!(!stderr.contains(&canary), "{}", case.id);
            }
        }
    }
}

#[test]
fn rejected_arguments_and_input_never_echo_canaries() {
    let canary = "synthetic-secret-cli-error-canary";
    let output = execute(b"", &[canary]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8(output.stderr).unwrap().contains(canary));
    for input in [
        b"password=synthetic-secret-cli-error-canary\xff".to_vec(),
        b"password=synthetic-secret-cli-error-canary\0".to_vec(),
        vec![b'x'; redact::MAX_INPUT_BYTES + 1],
    ] {
        let output = execute(&input, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8(output.stderr).unwrap().contains(canary));
    }
    for flag in ["--help", "--version"] {
        let output = execute(b"\xff", &[flag]);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn input_and_output_failures_are_sanitized() {
    let directory = std::fs::File::open(".").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rstr"))
        .env_clear()
        .stdin(Stdio::from(directory))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("input read failed")
    );
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rstr"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"password=synthetic-secret-output-canary\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("output write failed"));
    assert!(!error.contains("synthetic-secret-output-canary"));
}

#[test]
fn nested_safe_errors_never_retain_input() {
    let error = redact::filter(b"password=\"synthetic-secret-formatting-canary").unwrap_err();
    for message in [
        format!("{error}"),
        format!("{error:?}"),
        format!("{:?}", Some(error)),
    ] {
        assert!(!message.contains("synthetic-secret-formatting-canary"));
    }
}

#[test]
fn rejected_prefix_near_matches_have_bounded_processing() {
    let ordinary = "xops_".repeat(500_000);
    let canary = "SYNTHETIC_REJECTED_PREFIX_CANARY_0123456789";
    let input = format!("{ordinary}\npassword={canary}\n");
    let output = execute(input.as_bytes(), &[]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "{ordinary}\npassword=[REDACTED sha256={}]\n",
            redact::fingerprint(canary)
        )
    );
}
