#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use std::process::Command;

#[test]
fn file_limit_fails_before_any_source_output() {
    let directory = tempfile::tempdir().must();
    let path = directory.path().join("oversized.env");
    std::fs::write(&path, vec![b'x'; 16_777_217]).must();
    let output = Command::new(env!("CARGO_BIN_EXE_rprintenv"))
        .env_clear()
        .env("API_KEY", "SYNTHETIC_FILE_LIMIT_CANARY")
        .args(["--env", "--file"])
        .arg(path)
        .output()
        .must();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).must();
    assert!(stderr.contains("file exceeds 16 MiB"));
    assert!(!stderr.contains("SYNTHETIC_FILE_LIMIT_CANARY"));
}

#[cfg(unix)]
#[test]
fn special_files_are_rejected_and_regular_symlinks_work() {
    let output = Command::new(env!("CARGO_BIN_EXE_rprintenv"))
        .env_clear()
        .args(["--file", "/dev/zero"])
        .output()
        .must();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .must()
            .contains("not a regular file")
    );
    let directory = tempfile::tempdir().must();
    let path = directory.path().join("synthetic.env");
    let alias = directory.path().join("alias.env");
    std::fs::write(&path, "API_KEY=SYNTHETIC_FILE_LIMIT_CANARY\n").must();
    std::os::unix::fs::symlink(path, &alias).must();
    let output = Command::new(env!("CARGO_BIN_EXE_rprintenv"))
        .env_clear()
        .arg("--file")
        .arg(alias)
        .output()
        .must();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(
        !String::from_utf8(output.stdout)
            .must()
            .contains("SYNTHETIC_FILE_LIMIT_CANARY")
    );
}
