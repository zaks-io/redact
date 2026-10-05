use super::support;
use std::ffi::OsString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::process::Stdio;

const CANARY: &str = "synthetic-secret-lilac-48";

fn safe_failure(output: &std::process::Output) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
}

#[test]
fn rejected_arguments_never_echo_input() {
    for binary in ["rprintenv", "rstr"] {
        for args in [
            vec!["--synthetic-secret-lilac-48"],
            vec!["--file", CANARY, "--unknown"],
        ] {
            let output = support::capture(support::command(binary).args(args), b"");
            safe_failure(&output);
            assert!(String::from_utf8_lossy(&output.stderr).contains("--help"));
        }
    }
}

#[test]
fn encoding_and_nul_fail_without_unchecked_output() {
    for input in [
        b"password=synthetic-secret-lilac-48\n\xff".as_slice(),
        b"password=synthetic-secret-lilac-48\0",
    ] {
        safe_failure(&support::capture(&mut support::command("rstr"), input));
        let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("fixture setup failed"));
        std::fs::write(temp.path().join("input.env"), input)
            .unwrap_or_else(|_| panic!("fixture setup failed"));
        safe_failure(&support::capture(
            support::command("rprintenv")
                .current_dir(temp.path())
                .args(["--file", "input.env"]),
            b"",
        ));
    }
}

#[test]
fn environment_encoding_validates_unselected_values() {
    let invalid = OsString::from_vec(vec![0xff]);
    let output = support::capture(
        support::command("rprintenv")
            .env("INVALID", invalid)
            .env("API_KEY", CANARY)
            .arg("API_KEY"),
        b"",
    );
    safe_failure(&output);
}

#[test]
fn stdin_read_failure_returns_safe_diagnostic() {
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("fixture setup failed"));
    let directory =
        std::fs::File::open(temp.path()).unwrap_or_else(|_| panic!("directory input setup failed"));
    let output = support::finish(support::command("rstr").stdin(Stdio::from(directory)));
    safe_failure(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("read input"));
}

#[test]
fn all_sources_validate_before_any_records_are_written() {
    let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("fixture setup failed"));
    std::fs::write(
        temp.path().join("bad.env"),
        "OTHER=\"synthetic-secret-lilac-48",
    )
    .unwrap_or_else(|_| panic!("fixture setup failed"));
    let output = support::capture(
        support::command("rprintenv")
            .current_dir(temp.path())
            .env("NODE_ENV", "production")
            .args(["--env", "--file", "bad.env", "NODE_ENV"]),
        b"",
    );
    safe_failure(&output);
}

#[test]
fn input_limit_has_exact_boundary_and_no_truncation() {
    let limit = 16 * 1024 * 1024;
    let accepted = vec![b' '; limit];
    let output = support::capture(&mut support::command("rstr"), &accepted);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout == accepted);
    assert!(output.stderr.is_empty());
    let rejected = vec![b' '; limit + 1];
    let output = support::capture(&mut support::command("rstr"), &rejected);
    safe_failure(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("16 MiB"));
}

#[test]
fn interactive_stdin_fails_promptly() {
    let mut master = -1;
    let mut slave = -1;
    // openpty creates terminal descriptors owned only by this synthetic test.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(result, 0, "pseudo-terminal setup failed");
    // Successful openpty returns two fresh descriptors; transfer ownership once.
    let _master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    let output = support::finish(support::command("rstr").stdin(Stdio::from(slave)));
    safe_failure(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Pipe text or redirect a file"));
}

#[test]
fn closed_output_pipe_reports_safe_error() {
    for binary in ["rprintenv", "rstr"] {
        let mut fds = [-1; 2];
        // The private pipe has no readers, making the child's write fail.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        drop(read);
        let temp = tempfile::tempfile().unwrap_or_else(|_| panic!("fixture setup failed"));
        use std::io::{Seek, Write};
        let mut temp = temp;
        temp.write_all(b"password=synthetic-secret-lilac-48\n")
            .unwrap_or_else(|_| panic!("fixture setup failed"));
        temp.rewind()
            .unwrap_or_else(|_| panic!("fixture setup failed"));
        let mut child = support::command(binary)
            .env("API_KEY", CANARY)
            .stdin(Stdio::from(temp))
            .stdout(Stdio::from(write))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|_| panic!("fixture process failed"));
        use wait_timeout::ChildExt;
        match child.wait_timeout(std::time::Duration::from_secs(10)) {
            Ok(Some(_)) => {}
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("output failure test timed out");
            }
        }
        let output = child
            .wait_with_output()
            .unwrap_or_else(|_| panic!("fixture capture failed"));
        safe_failure(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("write output"));
    }
}

#[test]
fn help_and_version_never_read_sources() {
    for binary in ["rprintenv", "rstr"] {
        for flag in ["--help", "--version"] {
            let output = support::capture(
                support::command(binary)
                    .env("INVALID", OsString::from_vec(vec![0xff]))
                    .arg(flag),
                b"\xff",
            );
            assert_eq!(output.status.code(), Some(0));
            assert!(!output.stdout.is_empty());
            assert!(output.stderr.is_empty());
        }
    }
}

#[test]
fn help_never_echoes_caller_supplied_program_name() {
    use std::os::unix::process::CommandExt;
    for binary in ["rprintenv", "rstr"] {
        let output = support::capture(support::command(binary).arg0(CANARY).arg("--help"), b"");
        assert_eq!(output.status.code(), Some(0));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn backtrace_settings_do_not_expose_failure_input() {
    for binary in ["rprintenv", "rstr"] {
        let output = support::capture(
            support::command(binary)
                .env("RUST_BACKTRACE", "full")
                .arg("--synthetic-secret-lilac-48"),
            b"password=synthetic-secret-lilac-48",
        );
        safe_failure(&output);
    }
}
