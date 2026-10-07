use super::holds::HoldReason;

#[derive(Default)]
pub(super) struct Syntax {
    quote: Option<OpenQuote>,
    closed_quote: Option<crate::context::ClosedQuote>,
    escaped: bool,
    previous: Option<u8>,
    pub(super) awaiting_delimiter: bool,
    awaiting_value: bool,
    wire_quote: Option<u8>,
    wire_opening: bool,
    wire_slashes: usize,
    known_value: Option<bool>,
    plain_value: Option<bool>,
    embedded_value: bool,
    ambiguous: bool,
    stack: Vec<u8>,
    json: JsonSyntax,
    continuation: Option<usize>,
}

struct OpenQuote {
    byte: u8,
    start: usize,
    candidate: bool,
}

impl Syntax {
    pub(super) fn settled(&self) -> bool {
        self.structurally_settled() && !self.awaiting_delimiter
    }

    pub(super) fn structurally_settled(&self) -> bool {
        self.quote.is_none()
            && self.wire_quote.is_none()
            && self.stack.is_empty()
            && self.json.depth == 0
            && !self.json.quote
            && self.continuation.is_none()
            && !self.awaiting_value
            && !self.ambiguous
    }

    pub(super) fn advance_continuation(&mut self, line: &str) {
        if !self.awaiting_value
            && self
                .continuation
                .is_some_and(|indentation| !crate::context::continues_value(line, indentation))
        {
            self.continuation = None;
        }
    }

    pub(super) fn discard_prefix(&mut self, end: usize) {
        if let Some(quote) = &mut self.quote {
            quote.start = quote.start.saturating_sub(end);
        }
        self.closed_quote = self.closed_quote.take().and_then(|mut quote| {
            if quote.region.start < end {
                return None;
            }
            quote.region.start -= end;
            quote.region.end -= end;
            Some(quote)
        });
    }

    pub(super) fn hold_reason(&self) -> HoldReason {
        if self.ambiguous {
            HoldReason::Ambiguous
        } else if self.quote.is_some() || self.wire_quote.is_some() || self.json.quote {
            HoldReason::Quote
        } else if !self.stack.is_empty() || self.json.depth != 0 {
            HoldReason::Container
        } else {
            HoldReason::Unfinished
        }
    }

    pub(super) fn scan(
        &mut self,
        input: &str,
        mut line_start: bool,
        record: &[u8],
        start: usize,
    ) -> bool {
        let mut offset = 0;
        let mut awaited_colon = false;
        for line in input.split_inclusive(['\r', '\n']) {
            if line_start {
                self.advance_continuation(line);
                awaited_colon |= self.awaiting_delimiter
                    && line.bytes().find(|byte| !byte.is_ascii_whitespace()) == Some(b':');
                if let Some(indentation) = crate::context::yaml_colon_assignment(&input[offset..]) {
                    self.continuation = Some(
                        self.continuation
                            .map_or(indentation, |active| active.min(indentation)),
                    );
                }
            }
            for (at, &byte) in line.as_bytes().iter().enumerate() {
                self.json.byte(byte);
                awaited_colon |= self.byte(byte, record, start + offset + at);
            }
            line_start = line.ends_with(['\r', '\n']);
            offset += line.len();
        }
        awaited_colon
    }

    fn byte(&mut self, byte: u8, record: &[u8], at: usize) -> bool {
        let mapping = self.context_byte(byte, record, at);
        self.previous = Some(byte);
        mapping
    }

    fn context_byte(&mut self, byte: u8, record: &[u8], at: usize) -> bool {
        if let Some(json) = self.plain_value {
            if matches!(byte, b'\r' | b'\n') || json && matches!(byte, b',' | b'}' | b']') {
                self.plain_value = None;
            } else {
                self.ambiguous |= matches!(byte, b'"' | b'\'' | b'{' | b'}' | b'[' | b']');
                return false;
            }
        }
        if let Some(quote) = self.wire_quote {
            if self.wire_opening {
                self.wire_opening = false;
                return false;
            }
            if byte == b'\\' {
                self.wire_slashes += 1;
            } else {
                if byte == quote && self.wire_slashes % 4 == 1 {
                    self.wire_quote = None;
                } else if self.embedded_value {
                    self.ambiguous |= matches!(byte, b'"' | b'\'' | b'{' | b'}' | b'[' | b']');
                }
                self.wire_slashes = 0;
            }
        } else if let Some(quote) = &self.quote {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == quote.byte {
                self.closed_quote = Some(crate::context::ClosedQuote {
                    region: quote.start..at + 1,
                    name: quote.candidate,
                });
                self.awaiting_delimiter = true;
                self.quote = None;
            }
        } else {
            if let Some(json) = self.known_value {
                if matches!(byte, b' ' | b'\t') || json && matches!(byte, b'\r' | b'\n') {
                    return false;
                }
                self.known_value = None;
                if !matches!(byte, b'\r' | b'\n') {
                    self.awaiting_value = false;
                    self.closed_quote = None;
                    match byte {
                        b'\\' if matches!(record.get(at + 1), Some(b'"' | b'\'')) => {
                            self.wire_quote = record.get(at + 1).copied();
                            self.wire_opening = true;
                            return false;
                        }
                        b'"' | b'\'' => {
                            self.quote = Some(OpenQuote {
                                byte,
                                start: at,
                                candidate: false,
                            });
                            return false;
                        }
                        b'{' | b'[' if json => {}
                        _ => {
                            self.plain_value = Some(json);
                            self.ambiguous |= matches!(byte, b'{' | b'}' | b'[' | b']');
                            return false;
                        }
                    }
                }
            }
            if !byte.is_ascii_whitespace() {
                self.awaiting_value = self.awaiting_delimiter && matches!(byte, b':' | b'=');
                self.awaiting_delimiter = false;
            }
            if matches!(byte, b':' | b'=') {
                let mapping = byte == b':'
                    && self.closed_quote.as_ref().is_some_and(|quote| {
                        quote.name
                            && crate::context::assignment_delimiter(record, quote.region.end, true)
                                .0
                                == at
                            && crate::context::yaml_indentation(record, quote.region.start)
                                .is_some()
                            && record[quote.region.clone()]
                                .iter()
                                .any(|byte| matches!(byte, b'\r' | b'\n'))
                    });
                if let Some((name, quoted)) =
                    crate::context::sensitive_assignment(record, at, self.closed_quote.as_ref())
                {
                    self.known_value = Some(quoted && byte == b':' && !self.stack.is_empty());
                    self.embedded_value = crate::context::yaml_indentation(record, name).is_none();
                    if byte == b':'
                        && let Some(indentation) = crate::context::yaml_indentation(record, name)
                    {
                        self.continuation = Some(
                            self.continuation
                                .map_or(indentation, |active| active.min(indentation)),
                        );
                    }
                }
                return mapping;
            }
            match byte {
                b'"' | b'\''
                    if self.previous != Some(b'\\')
                        && !self
                            .previous
                            .is_some_and(|previous| previous.is_ascii_alphanumeric()) =>
                {
                    self.quote = Some(OpenQuote {
                        byte,
                        start: at,
                        candidate: true,
                    });
                }
                b'{' => self.stack.push(b'}'),
                b'[' => self.stack.push(b']'),
                b'}' | b']' if self.stack.last() == Some(&byte) => {
                    self.stack.pop();
                }
                _ => {}
            }
        }
        false
    }
}

// The JSON detector skips double-quoted regions, but single quotes are log text.
// Keep that grammar independent of assignment quoting so wrappers cannot hide objects.
#[derive(Default)]
struct JsonSyntax {
    quote: bool,
    escaped: bool,
    escaped_outside: bool,
    depth: usize,
    first_member: bool,
}

impl JsonSyntax {
    fn byte(&mut self, byte: u8) {
        let quote_starts = crate::structured::json_quote_starts_string(byte, self.escaped_outside);
        self.escaped_outside = byte == b'\\' && !self.escaped_outside;
        if self.first_member && !byte.is_ascii_whitespace() {
            self.first_member = false;
            if !matches!(byte, b'"' | b'}') {
                self.depth = 0;
            }
        }
        if self.quote {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.quote = false;
            }
        } else {
            match byte {
                b'"' if quote_starts => self.quote = true,
                b'{' => {
                    self.first_member = self.depth == 0;
                    self.depth += 1;
                }
                b'}' => self.depth = self.depth.saturating_sub(1),
                _ => {}
            }
        }
    }
}
