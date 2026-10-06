//! Stdin-only filtering. Detection and rendering live at the crate root.

use std::io::{Read, Write};

use crate::error::{ErrorKind, SafeError};
use crate::{MAX_INPUT_BYTES, filter};

pub fn read_input(reader: impl Read) -> Result<Vec<u8>, SafeError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SafeError::new(ErrorKind::Input))?;
    Ok(bytes)
}

pub fn filter_to_writer(reader: impl Read, mut writer: impl Write) -> Result<(), SafeError> {
    let output = filter(&read_input(reader)?)?;
    writer
        .write_all(output.as_bytes())
        .and_then(|()| writer.flush())
        .map_err(|_| SafeError::new(ErrorKind::Output))
}
