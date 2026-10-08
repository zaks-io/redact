use std::ffi::OsString;
use std::io::Write;

use clap::error::{ContextKind, ContextValue, ErrorKind as ClapErrorKind};

use crate::error::{ErrorKind, SafeError};

#[derive(Clone, Copy)]
pub enum CommandKind {
    Rprintenv,
    Rstr,
}

/// Help and version go to `output`; `None` means they were printed and the command is done.
/// Rejected arguments map to a fixed usage error so clap never echoes them.
pub fn parse_arguments<T: clap::Parser>(
    args: impl IntoIterator<Item = OsString>,
    output: &mut impl Write,
) -> Result<Option<T>, SafeError> {
    parse_with_context(args, output, None)
}

/// Command-specific recovery hints never include rejected arguments or parser diagnostics.
pub fn parse_arguments_for<T: clap::Parser>(
    args: impl IntoIterator<Item = OsString>,
    output: &mut impl Write,
    command: CommandKind,
) -> Result<Option<T>, SafeError> {
    parse_with_context(args, output, Some(command))
}

fn parse_with_context<T: clap::Parser>(
    args: impl IntoIterator<Item = OsString>,
    output: &mut impl Write,
    command: Option<CommandKind>,
) -> Result<Option<T>, SafeError> {
    match T::try_parse_from(args) {
        Ok(arguments) => Ok(Some(arguments)),
        Err(error)
            if matches!(
                error.kind(),
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            ) =>
        {
            output
                .write_all(error.to_string().as_bytes())
                .and_then(|()| output.flush())
                .map_err(|_| SafeError::new(ErrorKind::Output))?;
            Ok(None)
        }
        Err(error) => Err(argument_error(&error, command)),
    }
}

fn argument_error(error: &clap::Error, command: Option<CommandKind>) -> SafeError {
    match command {
        Some(CommandKind::Rstr) => SafeError::new(
            "invalid arguments. rstr reads stdin only. Use rstr < FILE or command 2>&1 | rstr. Use --help for supported syntax.",
        ),
        Some(CommandKind::Rprintenv) => {
            if error.kind() == ClapErrorKind::InvalidValue
                && matches!(error.get(ContextKind::InvalidValue), Some(ContextValue::String(value)) if value.is_empty())
                && let Some(ContextValue::String(argument)) = error.get(ContextKind::InvalidArg)
            {
                let message = match argument.as_str() {
                    "--file <PATH>" => Some(
                        "--file requires a PATH. Supply --file PATH to an explicit UTF-8 .env file. Use --help for supported syntax.",
                    ),
                    "--allow <NAME>" => Some(
                        "--allow requires a NAME. Supply --allow NAME for one exact variable name; its full value will be revealed. Use --help for supported syntax.",
                    ),
                    "--redact <NAME>" => Some(
                        "--redact requires a NAME. Supply --redact NAME for one exact variable name. Use --help for supported syntax.",
                    ),
                    _ => None,
                };
                if let Some(message) = message {
                    return SafeError::new(message);
                }
            }
            if error.kind() == ClapErrorKind::InvalidUtf8 {
                return SafeError::new(
                    "arguments contain non-UTF-8 text. Supply UTF-8 variable names and paths. Use --help for supported syntax.",
                );
            }
            SafeError::new(
                "invalid arguments. Select environment names or explicit files with rprintenv [--file PATH] [NAME...]. Use --help for supported syntax.",
            )
        }
        None => SafeError::new(ErrorKind::Usage),
    }
}
