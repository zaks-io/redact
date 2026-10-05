//! Stdin-only filtering. Core functions accept explicit data for deterministic tests.

use std::io::{Read, Write};
use std::ops::Range;

use crate::error::{ErrorKind, SafeError};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub type Span = Range<usize>;

pub fn validate_input(bytes: &[u8]) -> Result<&str, SafeError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(SafeError::new(ErrorKind::TooLarge));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SafeError::new(ErrorKind::Encoding))?;
    if text.contains('\0') {
        return Err(SafeError::new(ErrorKind::Nul));
    }
    Ok(text)
}

pub fn detect(text: &str) -> Result<Vec<Span>, SafeError> {
    Ok(crate::detect(text)?
        .into_iter()
        .map(|span| span.start..span.end)
        .collect())
}

pub fn merge_spans(text: &str, spans: Vec<Span>) -> Result<Vec<Span>, SafeError> {
    let spans: Vec<_> = spans
        .into_iter()
        .map(|span| crate::Span {
            start: span.start,
            end: span.end,
        })
        .collect();
    Ok(crate::merge_spans(text, &spans)?
        .into_iter()
        .map(|span| span.start..span.end)
        .collect())
}

pub fn render_spans(text: &str, spans: Vec<Span>) -> Result<String, SafeError> {
    let spans: Vec<_> = spans
        .into_iter()
        .map(|span| crate::Span {
            start: span.start,
            end: span.end,
        })
        .collect();
    crate::render_spans(text, &spans)
}

pub fn filter(bytes: &[u8]) -> Result<String, SafeError> {
    crate::filter(bytes)
}

pub fn read_input(reader: impl Read) -> Result<Vec<u8>, SafeError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SafeError::new(ErrorKind::Input))?;
    validate_input(&bytes)?;
    Ok(bytes)
}

pub fn filter_to_writer(reader: impl Read, mut writer: impl Write) -> Result<(), SafeError> {
    let bytes = read_input(reader)?;
    let output = filter(&bytes)?;
    writer
        .write_all(output.as_bytes())
        .and_then(|()| writer.flush())
        .map_err(|_| SafeError::new(ErrorKind::Output))
}
