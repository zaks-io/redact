use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Category(&'static str),
    Usage,
    Encoding,
    Nul,
    Input,
    Output,
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
}

impl SafeError {
    pub fn new(kind: impl Into<ErrorKind>) -> Self {
        Self {
            kind: kind.into(),
            line: None,
            previous_line: None,
        }
    }

    pub fn at(kind: impl Into<ErrorKind>, line: usize) -> Self {
        Self {
            line: Some(line),
            ..Self::new(kind)
        }
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
        })
    }
}

impl std::error::Error for SafeError {}

impl From<&'static str> for ErrorKind {
    fn from(category: &'static str) -> Self {
        Self::Category(category)
    }
}
