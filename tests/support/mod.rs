use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;
use wait_timeout::ChildExt;

pub fn command(binary: &str) -> Command {
    let path = match binary {
        "rprintenv" => env!("CARGO_BIN_EXE_rprintenv"),
        "rstr" => env!("CARGO_BIN_EXE_rstr"),
        _ => panic!("unsupported test binary"),
    };
    let mut command = Command::new(path);
    command.env_clear();
    command
}

pub fn capture(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("could not launch synthetic test process"));
    let mut stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("missing stdin"));
    let bytes = input.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&bytes));
    let stdout = reader(
        child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("missing stdout")),
    );
    let stderr = reader(
        child
            .stderr
            .take()
            .unwrap_or_else(|| panic!("missing stderr")),
    );
    let status = match child.wait_timeout(Duration::from_secs(10)) {
        Ok(Some(status)) => status,
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("synthetic test process did not finish within 10 seconds");
        }
    };
    let _ = writer.join();
    Output {
        status,
        stdout: stdout
            .join()
            .unwrap_or_else(|_| panic!("stdout reader failed")),
        stderr: stderr
            .join()
            .unwrap_or_else(|_| panic!("stderr reader failed")),
    }
}

pub fn finish(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("could not launch synthetic test process"));
    match child.wait_timeout(Duration::from_secs(10)) {
        Ok(Some(_)) => child
            .wait_with_output()
            .unwrap_or_else(|_| panic!("capture failed")),
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("synthetic test process timed out");
        }
    }
}

fn reader(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .unwrap_or_else(|_| panic!("capture read failed"));
        bytes
    })
}
