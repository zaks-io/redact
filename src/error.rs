use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Category(&'static str),
    Usage,
    Encoding,
    Nul,
    Input,
    Output,
    SourceNotFound,
    SourcePermissionDenied,
    SourceNotRegular,
    InvalidAssignment,
    DuplicateName,
    UnterminatedQuote,
    InvalidEscape,
    TrailingText,
    TooLarge,
    Interactive,
    Detector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeError {
    pub kind: ErrorKind,
    pub line: Option<usize>,
    pub previous_line: Option<usize>,
    pub earlier_output_emitted: bool,
}

impl SafeError {
    pub fn new(kind: impl Into<ErrorKind>) -> Self {
        Self {
            kind: kind.into(),
            line: None,
            previous_line: None,
            earlier_output_emitted: false,
        }
    }

    pub fn at(kind: impl Into<ErrorKind>, line: usize) -> Self {
        Self {
            line: Some(line),
            ..Self::new(kind)
        }
    }

    /// Locate a record-local failure in the stream using a one-based first line.
    pub fn in_stream(mut self, first_line: usize, earlier_output_emitted: bool) -> Self {
        let offset = first_line.checked_sub(1);
        let line = offset.and_then(|offset| self.line.unwrap_or(1).checked_add(offset));
        let previous_line = match (self.previous_line, offset) {
            (Some(line), Some(offset)) => line.checked_add(offset),
            _ => None,
        };
        if line.is_none() || (self.previous_line.is_some() && previous_line.is_none()) {
            self = Self::new("stream line count overflow. Split the input and retry safely.");
        } else {
            self.line = line;
            self.previous_line = previous_line;
        }
        self.earlier_output_emitted |= earlier_output_emitted;
        self
    }
}

/// One-based line containing `offset`; approved metadata for diagnostics.
pub(crate) fn line_number(text: &[u8], offset: usize) -> usize {
    text[..offset].iter().filter(|byte| **byte == b'\n').count() + 1
}

impl fmt::Display for SafeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(f, "line {line}: ")?;
        }
        if let Some(line) = self.previous_line {
            write!(f, "previous definition on line {line}: ")?;
        }
        f.write_str(match self.kind {
            ErrorKind::Category(category) => category,
            ErrorKind::Usage => "invalid arguments. Use --help for supported syntax.",
            ErrorKind::Encoding => "input is not UTF-8. Supply UTF-8 input and retry.",
            ErrorKind::Nul => "input contains NUL bytes. Supply text without NUL bytes and retry.",
            ErrorKind::Input => {
                "could not read input: input read failed. Check the selected source and its permissions."
            }
            ErrorKind::Output => {
                "could not write output: output write failed. Check the destination; do not retry with raw input."
            }
            ErrorKind::SourceNotFound => {
                "file not found. Check that the explicit path exists and retry with --file PATH."
            }
            ErrorKind::SourcePermissionDenied => {
                "permission denied while reading file. Check read permissions on the file and its parent directories, then retry."
            }
            ErrorKind::SourceNotRegular => {
                "source is not a regular file. Supply an explicit UTF-8 .env file and retry."
            }
            ErrorKind::InvalidAssignment => "invalid assignment. Use NAME=VALUE syntax and retry.",
            ErrorKind::DuplicateName => {
                "duplicate variable name. Keep one definition per source and retry."
            }
            ErrorKind::UnterminatedQuote => {
                "unterminated quoted value. Close the quoted value and retry."
            }
            ErrorKind::InvalidEscape => "unsupported escape. Use a documented escape and retry.",
            ErrorKind::TrailingText => {
                "unexpected text after quoted value. Remove trailing text and retry."
            }
            ErrorKind::TooLarge => {
                "input exceeds 16 MiB. Supply a smaller input through the filter."
            }
            ErrorKind::Interactive => {
                "interactive stdin is unsupported. Pipe text or redirect a file."
            }
            ErrorKind::Detector => {
                "detector failed. Report the version and a synthetic reproduction."
            }
        })?;
        if self.kind == ErrorKind::Output && self.earlier_output_emitted {
            f.write_str(
                " Some filtered output may already have been written. Treat stdout as incomplete.",
            )?;
        } else if self.earlier_output_emitted {
            f.write_str(
                " Earlier filtered output was emitted; the unfinished record was withheld.",
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for SafeError {}

impl From<&'static str> for ErrorKind {
    fn from(category: &'static str) -> Self {
        Self::Category(category)
    }
}
