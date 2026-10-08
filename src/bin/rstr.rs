use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use redact::error::{ErrorKind, SafeError};

#[derive(Parser)]
#[command(
    name = "rstr",
    bin_name = "rstr",
    version,
    about = "Stream recognizable-secret filtering from UTF-8 stdin",
    after_help = "Pipe text or redirect a file. No environment or file lookup.\nComplete JSON and ordinary non-YAML log records are filtered before EOF. Unfinished quotes, containers, YAML-like documents, and private keys wait for their boundaries. Ambiguous plain assignments, their continuations, and escaped quoted values overlapping URLs or connection strings can wait for EOF.\nYAML-style logs may hold the remaining stream until --- or EOF: warning:/Error:/INFO: mappings, BuildKit # comments, and - list lines. URLs, clock times, and file locations normally stream as ordinary records.\nPending input limit: 16 MiB. Longer total streams are supported. A later failure can leave earlier filtered output; the unfinished record stays withheld.\nDetection needs recognizable structure or context; arbitrary passwords can remain.\nMarkers use the first 16 lowercase SHA-256 hex characters of removed bytes.\nEncoded values and merged or compound credentials hash their original removed bytes.\nA bounded stderr report gives fingerprints, start lines, and detection evidence after successful filtering. Labels do not establish credential validity. Zero matches stay quiet.\nExit 0 and zero matches do not prove text is safe. Use command 2>&1 | rstr to include stderr.\nUse shell pipefail when producer failures must affect pipeline status.\nFingerprints permit correlation and dictionary guesses; they are not authentication."
)]
struct Arguments {}

fn run() -> Result<(), SafeError> {
    let Some(Arguments {}) = redact::parse_arguments_for(
        std::env::args_os(),
        &mut io::stdout(),
        redact::CommandKind::Rstr,
    )?
    else {
        return Ok(());
    };
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(SafeError::new(ErrorKind::Interactive));
    }
    let report = redact::rstr::filter_to_writer(stdin.lock(), io::stdout().lock())?;
    report.write(&mut io::stderr().lock())
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
