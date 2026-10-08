use std::io::Write;

use crate::error::{ErrorKind, SafeError};
use crate::evidence::{Evidence, Redaction};

const MAX_ENTRIES: usize = 8;
const MAX_LABELS: usize = 3;

#[derive(Debug)]
struct Entry {
    fingerprint: String,
    line: usize,
    labels: Vec<Evidence>,
    occurrences: usize,
}

/// Bounded, approved metadata only; it never retains removed input.
#[derive(Debug, Default)]
pub struct RedactionReport {
    total: usize,
    entries: Vec<Entry>,
}

impl RedactionReport {
    pub fn observe(
        &mut self,
        redactions: &[Redaction],
        first_line: usize,
    ) -> Result<(), SafeError> {
        let invalid = || {
            SafeError::new(
                "invalid redaction metadata. Report the version and a synthetic reproduction.",
            )
        };
        for redaction in redactions {
            if redaction.fingerprint.len() != 16
                || !redaction
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                || redaction.labels.is_empty()
                || redaction.labels.windows(2).any(|pair| pair[0] >= pair[1])
                || redaction.line == 0
            {
                return Err(invalid());
            }
            let line = first_line
                .checked_sub(1)
                .and_then(|offset| offset.checked_add(redaction.line))
                .filter(|line| *line > 0)
                .ok_or_else(invalid)?;
            self.total = self.total.checked_add(1).ok_or_else(invalid)?;
            if let Some(entry) = self.entries.iter_mut().find(|entry| {
                entry.fingerprint == redaction.fingerprint && entry.labels == redaction.labels
            }) {
                entry.occurrences = entry.occurrences.checked_add(1).ok_or_else(invalid)?;
            } else if self.entries.len() < MAX_ENTRIES {
                self.entries.push(Entry {
                    fingerprint: redaction.fingerprint.clone(),
                    line,
                    labels: redaction.labels.clone(),
                    occurrences: 1,
                });
            }
        }
        Ok(())
    }

    pub fn write(&self, output: &mut impl Write) -> Result<(), SafeError> {
        if self.total == 0 {
            return Ok(());
        }
        let error = |_| SafeError::new(ErrorKind::Output);
        writeln!(
            output,
            "rstr: {} {}; labels describe local syntax evidence, not credential validity.",
            self.total,
            redaction_word(self.total)
        )
        .map_err(error)?;
        for entry in &self.entries {
            write!(
                output,
                "rstr: line {}: sha256={}; ",
                entry.line, entry.fingerprint
            )
            .map_err(error)?;
            for (index, label) in entry.labels.iter().take(MAX_LABELS).enumerate() {
                if index > 0 {
                    write!(output, " + ").map_err(error)?;
                }
                write!(output, "{}", label.label()).map_err(error)?;
            }
            if entry.labels.len() > MAX_LABELS {
                write!(output, " + other evidence").map_err(error)?;
            }
            if entry.occurrences > 1 {
                write!(output, " ({} occurrences)", entry.occurrences).map_err(error)?;
            }
            writeln!(output).map_err(error)?;
        }
        let shown: usize = self.entries.iter().map(|entry| entry.occurrences).sum();
        if self.total > shown {
            let remaining = self.total - shown;
            writeln!(
                output,
                "rstr: {} more {}; fingerprints remain in output markers.",
                remaining,
                redaction_word(remaining)
            )
            .map_err(error)?;
        }
        output.flush().map_err(error)
    }
}

fn redaction_word(count: usize) -> &'static str {
    if count == 1 {
        "redaction"
    } else {
        "redactions"
    }
}
