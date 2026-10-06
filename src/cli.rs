use std::ffi::OsString;
use std::io::Write;

use clap::error::ErrorKind as ClapErrorKind;

use crate::error::{ErrorKind, SafeError};

/// Help and version go to `output`; `None` means they were printed and the command is done.
/// Rejected arguments map to a fixed usage error so clap never echoes them.
pub fn parse_arguments<T: clap::Parser>(
    args: impl IntoIterator<Item = OsString>,
    output: &mut impl Write,
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
        Err(_) => Err(SafeError::new(ErrorKind::Usage)),
    }
}
