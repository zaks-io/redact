//! Stdin-only filtering. Core functions accept explicit data for deterministic tests.
mod contexts;
mod providers;

use std::io::{Read, Write};
use std::ops::Range;
use std::sync::LazyLock;

use crate::error::{ErrorKind, SafeError};
use crate::fingerprint::marker;

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
    let mut spans = contexts::detect(text)?;
    spans.extend(providers::detect(text)?);
    merge_spans(text, spans)
}

pub fn merge_spans(text: &str, mut spans: Vec<Span>) -> Result<Vec<Span>, SafeError> {
    for span in &spans {
        if span.start > span.end
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            return Err(SafeError::new(ErrorKind::Detector));
        }
    }
    spans.retain(|span| !span.is_empty());
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    let mut merged: Vec<Span> = Vec::new();
    for span in spans {
        if let Some(previous) = merged.last_mut()
            && span.start < previous.end
        {
            previous.end = previous.end.max(span.end);
        } else {
            merged.push(span);
        }
    }
    Ok(merged)
}

pub fn render_spans(text: &str, spans: Vec<Span>) -> Result<String, SafeError> {
    let spans = merge_spans(text, spans)?;
    let mut output = String::new();
    let mut cursor = 0;
    for span in spans {
        output.push_str(&text[cursor..span.start]);
        output.push_str(&marker(&text.as_bytes()[span.clone()]));
        cursor = span.end;
    }
    output.push_str(&text[cursor..]);
    Ok(output)
}

pub fn filter(bytes: &[u8]) -> Result<String, SafeError> {
    let text = validate_input(bytes)?;
    render_spans(text, detect(text)?)
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

pub(crate) fn pattern(pattern: &str) -> Result<regex::Regex, SafeError> {
    regex::RegexBuilder::new(pattern)
        .size_limit(2 * 1024 * 1024)
        .dfa_size_limit(2 * 1024 * 1024)
        .build()
        .map_err(|_| SafeError::new(ErrorKind::Detector))
}

/// Patterns compile once per process; per-call compilation dominated detector fuzzing.
pub(crate) type Compiled<T> = LazyLock<Result<T, SafeError>>;

pub(crate) fn compiled<T>(cell: &'static Compiled<T>) -> Result<&'static T, SafeError> {
    cell.as_ref()
        .map_err(|_| SafeError::new(ErrorKind::Detector))
}

pub(crate) fn line_number(text: &str, position: usize) -> usize {
    text.as_bytes()[..position]
        .iter()
        .filter(|&&byte| byte == b'\n')
        .count()
        + 1
}

#[cfg(test)]
mod tests {
    use super::pattern;
    use std::error::Error;

    #[test]
    fn detector_initialization_errors_discard_third_party_diagnostics() {
        for expression in [
            "[synthetic-detector-canary",
            "(?:synthetic-detector-canary){1000000000}",
        ] {
            let error = match pattern(expression) {
                Err(error) => error,
                Ok(_) => panic!("synthetic invalid pattern unexpectedly compiled"),
            };
            assert!(
                !format!("{error:?} {error} {:?}", Some(&error))
                    .contains("synthetic-detector-canary")
            );
            assert!(error.source().is_none());
        }
    }
}
