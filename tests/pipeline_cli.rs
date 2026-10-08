#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use std::process::Command;

#[cfg(unix)]
#[test]
fn terminal_input_is_rejected_without_waiting_for_text() {
    let script = r#"
import os, pty, subprocess, sys
master, slave = pty.openpty()
try:
    output = subprocess.run([sys.argv[1]], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, timeout=5)
    assert output.returncode == 2
    assert output.stdout == b''
    assert b'Pipe text or redirect a file' in output.stderr
finally:
    os.close(master)
    os.close(slave)
"#;
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", script, env!("CARGO_BIN_EXE_rstr")])
        .output()
        .must();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn producer_stdout_and_stderr_are_filtered_before_capture() {
    let script = r#"
import hashlib, subprocess, sys
producer = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdout.write("status=401 password=SYNTHETIC_PIPE_CANARY\\n"); sys.stdout.flush(); sys.stderr.write("Authorization: Bearer SYNTHETIC_PIPE_CANARY\\n")'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={})
output = subprocess.run([sys.argv[1]], stdin=producer.stdout, capture_output=True, env={}, timeout=5)
producer.stdout.close()
assert producer.wait(timeout=5) == 0
assert output.returncode == 0
marker = '[REDACTED sha256=' + hashlib.sha256(b'SYNTHETIC_PIPE_CANARY').hexdigest()[:16] + ']'
digest = hashlib.sha256(b'SYNTHETIC_PIPE_CANARY').hexdigest()[:16]
assert output.stderr.decode() == ('rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\n'
    f'rstr: line 1: sha256={digest}; sensitive field or quoted credential\n'
    f'rstr: line 2: sha256={digest}; authorization header\n')
assert output.stdout.decode() == 'status=401 password=' + marker + '\nAuthorization: Bearer ' + marker + '\n'
assert b'SYNTHETIC_PIPE_CANARY' not in output.stdout + output.stderr
"#;
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", script, env!("CARGO_BIN_EXE_rstr")])
        .output()
        .must();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
