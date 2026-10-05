use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    match redact::rprintenv::run(std::env::args_os(), &mut io::stdout().lock()) {
        Ok(status) => ExitCode::from(status),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "rprintenv: {error}");
            ExitCode::from(2)
        }
    }
}
