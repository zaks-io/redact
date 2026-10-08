use crate::error::SafeError;
use regex::Regex;
use std::{collections::HashSet, sync::OnceLock};

mod holds;
mod syntax;
use holds::HoldReason;
use syntax::Syntax;

pub(super) enum Boundary {
    Complete,
    Hold,
    Document,
    Previous,
}

// Framing retains raw delimiter labels. Keep all nested state opaque too.
pub(super) struct Framer {
    first: bool,
    yaml: bool,
    private: HashSet<String>,
    syntax: Syntax,
}

impl Framer {
    pub(super) fn new() -> Self {
        Self {
            first: true,
            yaml: false,
            private: HashSet::new(),
            syntax: Syntax::default(),
        }
    }

    pub(super) fn discard_prefix(&mut self, end: usize) {
        self.syntax.discard_prefix(end);
    }

    pub(super) fn pending_limit_diagnostic(&self) -> &'static str {
        if !self.private.is_empty() {
            HoldReason::PrivateKey
        } else if self.yaml && !matches!(self.syntax.hold_reason(), HoldReason::Ambiguous) {
            HoldReason::Yaml
        } else {
            self.syntax.hold_reason()
        }
        .diagnostic()
    }

    pub(super) fn line(
        &mut self,
        line: &str,
        record: &[u8],
        start: usize,
    ) -> Result<Boundary, SafeError> {
        if let Some(first_subline) = line.split_inclusive(['\r', '\n']).next() {
            self.syntax.advance_continuation(first_subline);
        }
        self.yaml |= crate::structured::yaml_secret_kind()?.is_match(line)
            || self.syntax.awaiting_delimiter
                && line.bytes().find(|byte| !byte.is_ascii_whitespace()) == Some(b':');
        if !self.yaml
            && self.private.is_empty()
            && self.syntax.awaiting_delimiter
            && self.syntax.structurally_settled()
            && line
                .bytes()
                .find(|byte| !byte.is_ascii_whitespace())
                .is_some_and(|byte| !matches!(byte, b':' | b'='))
        {
            self.first = true;
            self.syntax = Syntax::default();
            return Ok(Boundary::Previous);
        }
        let separator = document_separator(line)?;
        if self.yaml && separator && self.private.is_empty() && self.syntax.structurally_settled() {
            self.syntax = Syntax::default();
            self.scan(line, record, start)?;
            return Ok(Boundary::Document);
        }
        if self.first {
            if line.trim().is_empty() {
                return Ok(Boundary::Hold);
            }
            self.yaml |= yaml_start(line)?;
            self.first = false;
        } else if !self.yaml && self.syntax.awaiting_delimiter && self.syntax.structurally_settled()
        {
            self.yaml = yaml_start(line)?;
        }
        self.scan(line, record, start)?;
        if !self.yaml && self.private.is_empty() && self.syntax.settled() {
            self.first = true;
            self.syntax = Syntax::default();
            Ok(Boundary::Complete)
        } else {
            Ok(Boundary::Hold)
        }
    }

    fn scan(&mut self, line: &str, record: &[u8], start: usize) -> Result<(), SafeError> {
        self.syntax.connection_context(line);
        let matcher = private_markers()?;
        let mut cursor = 0;
        let mut at = 0;
        while let Some(capture) = matcher.captures_at(line, at) {
            let (Some(marker), Some(direction), Some(label)) =
                (capture.get(0), capture.get(1), capture.get(2))
            else {
                return Err(SafeError::new(
                    "stream marker framing failed. Report the version and a synthetic reproduction.",
                ));
            };
            if self.private.is_empty() && marker.start() > cursor {
                self.yaml |= self.syntax.scan(
                    &line[cursor..marker.start()],
                    physical_line_start(line, cursor),
                    record,
                    start + cursor,
                );
            } else if marker.start() > cursor {
                self.syntax.skip_private(&line[cursor..marker.start()]);
            }
            if self.private.is_empty() {
                self.syntax.private_start(record, start + marker.start());
            }
            if direction.as_str() == "BEGIN" {
                self.private.insert(label.as_str().to_owned());
            } else {
                self.private.remove(label.as_str());
            }
            self.syntax.skip_private(&line[cursor..marker.end()]);
            cursor = cursor.max(marker.end());
            // BEGIN can reuse an END marker's closing five dashes.
            at = marker.end().saturating_sub(5).max(marker.start() + 1);
        }
        if self.private.is_empty() {
            self.yaml |= self.syntax.scan(
                &line[cursor..],
                physical_line_start(line, cursor),
                record,
                start + cursor,
            );
        } else {
            self.syntax.skip_private(&line[cursor..]);
        }
        Ok(())
    }
}

fn private_markers() -> Result<&'static Regex, SafeError> {
    static MATCHER: OnceLock<Result<Regex, SafeError>> = OnceLock::new();
    matcher(
        &MATCHER,
        r"-----(BEGIN|END) ([A-Z0-9 ]*?PRIVATE KEY(?: BLOCK)?)-----",
    )
}

fn physical_line_start(line: &str, at: usize) -> bool {
    at == 0 || matches!(line.as_bytes().get(at - 1), Some(b'\r' | b'\n'))
}

fn yaml_start(line: &str) -> Result<bool, SafeError> {
    let trimmed = line.trim_start_matches([' ', '\t']);
    if trimmed.starts_with('#')
        || trimmed.starts_with("%YAML ")
        || trimmed.starts_with("%TAG ")
        || trimmed.starts_with("- ")
        || trimmed.starts_with("-\t")
        || trimmed.trim_end_matches(['\r', '\n']) == "-"
        || trimmed.starts_with("? ")
        || trimmed.starts_with("?\t")
        || trimmed.trim_end_matches(['\r', '\n']) == "?"
        || trimmed.starts_with(':')
        || document_separator(line)?
    {
        return Ok(true);
    }
    Ok(line.contains(':') && colon_shape(line, trimmed))
}

fn colon_shape(line: &str, trimmed: &str) -> bool {
    let bytes = line.as_bytes();
    let mut at = 0;
    let mut depth = 0usize;
    let mut plain_mapping = trimmed
        .as_bytes()
        .first()
        .is_some_and(|byte| !matches!(byte, b'[' | b'{' | b']' | b'}' | b','));
    while at < bytes.len() {
        match bytes[at] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth = depth.saturating_sub(1),
            b':' if depth == 0 && plain_mapping => {
                plain_mapping = false;
                if bytes.get(at + 1).is_none_or(u8::is_ascii_whitespace) {
                    return true;
                }
            }
            quote @ (b'"' | b'\'') if at == 0 || !bytes[at - 1].is_ascii_alphanumeric() => {
                let Ok(end) = crate::context::quoted_end(line, at, quote, false) else {
                    break;
                };
                let (delimiter, _) = crate::context::assignment_delimiter(bytes, end + 1, true);
                if depth == 0 && bytes.get(delimiter) == Some(&b':') {
                    return true;
                }
                at = end + 1;
                continue;
            }
            first if first.is_ascii_alphabetic() || first == b'_' => {
                let start = at;
                at += 1;
                while bytes.get(at).is_some_and(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                }) {
                    at += 1;
                }
                let (delimiter, _) = crate::context::assignment_delimiter(bytes, at, false);
                if depth == 0
                    && bytes.get(delimiter) == Some(&b':')
                    && (crate::context::sensitive_name(&line[start..at])
                        || matches!(&line[start..at], "kind" | "data" | "stringData"))
                {
                    return true;
                }
                continue;
            }
            _ => {}
        }
        at += 1;
    }
    false
}

fn document_separator(line: &str) -> Result<bool, SafeError> {
    Ok(crate::structured::yaml_document_separators()?.is_match(line))
}

fn matcher(
    cell: &'static OnceLock<Result<Regex, SafeError>>,
    pattern: &'static str,
) -> Result<&'static Regex, SafeError> {
    cell.get_or_init(|| {
        regex::RegexBuilder::new(pattern)
            .size_limit(1_048_576)
            .build()
            .map_err(|_| {
                SafeError::new(
                    "stream framing initialization failed. Reinstall the tool and retry with synthetic input.",
                )
            })
    })
    .as_ref()
    .map_err(Clone::clone)
}
