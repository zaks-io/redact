use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use redact::error::{ErrorKind, SafeError};

#[derive(Parser)]
#[command(
    name = "rstr",
    bin_name = "rstr",
    version,
    about = "Filter recognizable secrets from bounded UTF-8 stdin",
    after_help = "Pipe text or redirect a file. Input limit: 16 MiB. No environment or file lookup.\nDetection needs recognizable structure or context; arbitrary passwords can remain.\nMarkers use the first 16 lowercase SHA-256 hex characters of removed bytes.\nEncoded values and merged or compound credentials hash their original removed bytes.\nExit 0 and zero matches do not prove text is safe. Use command 2>&1 | rstr to include stderr.\nUse shell pipefail when producer failures must affect pipeline status.\nFingerprints permit correlation and dictionary guesses; they are not authentication."
)]
struct Arguments {}

fn run() -> Result<(), SafeError> {
    let Some(Arguments {}) = redact::parse_arguments(std::env::args_os(), &mut io::stdout())?
    else {
        return Ok(());
    };
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(SafeError::new(ErrorKind::Interactive));
    }
    redact::rstr::filter_to_writer(stdin.lock(), io::stdout().lock())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "rstr: {error}");
            ExitCode::from(2)
        }
    }
}
