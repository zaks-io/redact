use redact::{MAX_INPUT_BYTES, error::SafeError, filter};
use std::io::{self, IsTerminal, Read, Write};

const HELP: &str = "rstr: filter recognizable secrets from stdin\n\nUsage: command 2>&1 | rstr\n       rstr < application.log\n\nOptions: -h, --help; -V, --version\n\nReads stdin only, never the environment or .env files. Input must be UTF-8,\nwithout NUL bytes, and at most 16 MiB. No matches does not prove text is safe;\narbitrary standalone passwords and unsupported encodings may go undetected.\nFingerprints are stable SHA-256 truncated to 16 lowercase hex characters, over\nthe exact removed bytes. Escaping, encoding, and merged spans affect comparisons.\nUse shell pipefail to retain producer failures.\n";

fn run() -> Result<(), SafeError> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "-h" || args[0] == "--help") {
        return write_output(HELP.as_bytes());
    }
    if args.len() == 1 && (args[0] == "-V" || args[0] == "--version") {
        return write_output(concat!("rstr ", env!("CARGO_PKG_VERSION"), "\n").as_bytes());
    }
    if !args.is_empty() {
        return Err(SafeError::new(
            "invalid arguments. Use --help and pipe text through stdin.",
        ));
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(SafeError::new(
            "interactive stdin is unsupported. Pipe text or redirect a file into stdin.",
        ));
    }
    let mut bytes = Vec::new();
    stdin
        .lock()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            SafeError::new("input read failed. Check the producer or redirected input and retry.")
        })?;
    let output = filter(&bytes)?;
    write_output(output.as_bytes())
}

fn write_output(bytes: &[u8]) -> Result<(), SafeError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|_| stdout.flush())
        .map_err(|_| {
            SafeError::new(
                "output write failed. Check the receiving pipe or output destination and retry.",
            )
        })
}

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr().lock(), "rstr: {error}");
        std::process::exit(2);
    }
}
