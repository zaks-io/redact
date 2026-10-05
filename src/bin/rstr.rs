use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use clap::{Command, error::ErrorKind as ClapErrorKind};
use redact::error::{ErrorKind, SafeError};

fn command() -> Command {
    Command::new("rstr").bin_name("rstr").version(env!("CARGO_PKG_VERSION"))
        .about("Filter recognizable secrets from bounded UTF-8 stdin")
        .after_help("Pipe text or redirect a file. Input limit: 16 MiB. No environment or file lookup.\nDetection needs recognizable structure or context; arbitrary passwords can remain.\nMarkers use the first 16 lowercase SHA-256 hex characters of removed bytes.\nEncoded values and merged or compound credentials hash their original removed bytes.\nExit 0 and zero matches do not prove text is safe. Use command 2>&1 | rstr to include stderr.\nUse shell pipefail when producer failures must affect pipeline status.\nFingerprints permit correlation and dictionary guesses; they are not authentication.")
}

fn run() -> Result<(), SafeError> {
    match command().try_get_matches() {
        Ok(_) => (),
        Err(error)
            if matches!(
                error.kind(),
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            ) =>
        {
            io::stdout()
                .lock()
                .write_all(error.to_string().as_bytes())
                .map_err(|_| SafeError::new(ErrorKind::Output))?;
            return Ok(());
        }
        Err(_) => return Err(SafeError::new(ErrorKind::Usage)),
    }
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
