use crate::{
    Span,
    error::{DetectorError, ErrorKind, SafeError},
};

mod assignment;
mod embedded;
mod names;
mod values;

pub(crate) use assignment::{
    ClosedQuote, delimiter as assignment_delimiter, sensitive_assignment, yaml_colon_assignment,
};
pub(crate) use names::sensitive_name;
pub(crate) use values::{continues_value, yaml_indentation};

pub(crate) enum RecordEnd {
    Newline,
    NonDelimiter,
    Document,
}

pub(crate) struct Detection {
    pub spans: Vec<Span>,
    pub end: EndState,
}

// Detector continuation metadata contains no input or secret-bearing labels.
#[derive(Default)]
pub(crate) struct EndState {
    containers: usize,
    unmatched_quote: bool,
    pending_value: bool,
    pending_delimiter: bool,
    yaml_continuation: bool,
}

impl EndState {
    pub(crate) fn settled(&self, end: RecordEnd) -> bool {
        self.containers == 0
            && !self.unmatched_quote
            && !self.pending_value
            && (!self.pending_delimiter || !matches!(end, RecordEnd::Newline))
            && (!self.yaml_continuation || matches!(end, RecordEnd::Document))
    }
}

/// Sensitive-name assignments outside `structured` framing; quoted text recurses via `embedded`.
pub(crate) fn detect_with_state(
    input: &str,
    structured: &[Span],
    depth: usize,
) -> Result<Detection, DetectorError> {
    let structured = crate::merge_spans(input, structured)?;
    let mut end_state = EndState::default();
    let spans = detect_assignments(input, &structured, depth, &mut end_state)
        .map_err(|error| error.in_context(depth, end_state.unmatched_quote))?;
    Ok(Detection {
        spans,
        end: end_state,
    })
}

fn detect_assignments(
    input: &str,
    structured: &[Span],
    depth: usize,
    end_state: &mut EndState,
) -> Result<Vec<Span>, DetectorError> {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut at = 0;
    let mut quoted_names_available = [true, true];
    let mut container_depth = 0usize;
    while at < bytes.len() {
        let framing = structured.get(structured.partition_point(|span| span.end <= at));
        if let Some(framing) = framing.filter(|span| span.start <= at && at < span.end) {
            at = framing.end;
            continue;
        }
        let name_start = at;
        let quote = bytes[at];
        let quoted_name = matches!(quote, b'"' | b'\'')
            && (at == 0 || !bytes[at - 1].is_ascii_alphanumeric())
            && (at == 0 || bytes[at - 1] != b'\\');
        let (name, name_end) = if quoted_name && quoted_names_available[usize::from(quote == b'\'')]
        {
            let end = match quoted_end(input, at, quote, false) {
                Ok(end) => end,
                Err(_) => {
                    quoted_names_available[usize::from(quote == b'\'')] = false;
                    end_state.unmatched_quote = true;
                    at += 1;
                    continue;
                }
            };
            let mut delimiter = end + 1;
            while delimiter < bytes.len()
                && matches!(bytes[delimiter], b' ' | b'\t' | b'\r' | b'\n')
            {
                delimiter += 1;
            }
            if delimiter == bytes.len() || !matches!(bytes[delimiter], b'=' | b':') {
                end_state.pending_delimiter |= delimiter == bytes.len();
                spans.extend(embedded::detect(input, at, end, depth)?);
                at = end + 1;
                continue;
            }
            let name = if quote == b'"' {
                serde_json::from_str::<String>(&input[at..=end]).ok()
            } else {
                Some(input[at + 1..end].to_owned())
            };
            at = end + 1;
            (name, at)
        } else if let Some(end) = assignment::plain_name_end(bytes, at) {
            at = end;
            (Some(input[name_start..at].to_owned()), at)
        } else {
            match bytes[at] {
                b'{' | b'[' => container_depth += 1,
                b'}' | b']' => container_depth = container_depth.saturating_sub(1),
                _ => {}
            }
            at += 1;
            continue;
        };
        let Some(name) = name else {
            continue;
        };
        let (delimiter, quote_framing) = assignment::delimiter(bytes, name_end, quoted_name);
        if delimiter == bytes.len() || !matches!(bytes[delimiter], b'=' | b':') {
            continue;
        }
        let json = quote_framing && bytes[delimiter] == b':' && container_depth > 0;
        let mut value = delimiter + 1;
        while value < bytes.len()
            && (matches!(bytes[value], b' ' | b'\t')
                || json && matches!(bytes[value], b'\r' | b'\n'))
        {
            value += 1;
        }
        if !sensitive_name(&name) {
            continue;
        }
        if value == bytes.len() {
            end_state.pending_value = true;
            continue;
        }
        if bytes[delimiter] == b':'
            && matches!(bytes[value], b'\n' | b'\r' | b'#')
            && let Some(continuation) = values::yaml_indented_value(input, name_start, value)
                .map_err(DetectorError::input)?
        {
            end_state.yaml_continuation |= continuation.open;
            if let Some(span) = continuation.span {
                at = span.end;
                spans.push(span);
                continue;
            }
        }
        if matches!(bytes[value], b'\n' | b'\r') {
            continue;
        }
        if bytes[value] == b'\\' && matches!(bytes.get(value + 1), Some(b'"' | b'\'')) {
            let end = values::escaped_quoted_end(input, value).map_err(DetectorError::input)?;
            if end > value + 2 {
                spans.push(value + 2..end);
            }
            at = end + 2;
        } else if matches!(bytes[value], b'"' | b'\'') {
            let end = quoted_end(input, value, bytes[value], true).map_err(DetectorError::input)?;
            if json && bytes[value] == b'"' {
                serde_json::from_str::<String>(&input[value..=end]).map_err(|_| {
                    DetectorError::input(SafeError::new(
                        "invalid quoted JSON value. Correct its string escapes and retry.",
                    ))
                })?;
            } else if bytes[value] == b'"' {
                let mut cursor = value + 1;
                while cursor < end {
                    if bytes[cursor] == b'\\' {
                        cursor += 1;
                        if !matches!(bytes[cursor], b'\\' | b'"' | b'n' | b'r' | b't') {
                            return Err(DetectorError::input(SafeError::new(
                                "unsupported quoted-value escape. Use documented escapes and retry.",
                            )));
                        }
                    }
                    cursor += 1;
                }
            }
            if end > value + 1 {
                spans.push(value + 1..end);
            }
            at = end + 1;
        } else if json && matches!(bytes[value], b'{' | b'[') {
            let end = values::balanced_end(input, value).map_err(DetectorError::input)?;
            spans.push(value..end);
            at = end;
        } else if bytes[delimiter] == b':'
            && let Some(block) =
                values::yaml_block_end(input, name_start, value).map_err(DetectorError::input)?
        {
            end_state.yaml_continuation |= block.open;
            spans.push(value..block.end);
            at = block.end;
        } else {
            let mut end = value;
            while end < bytes.len()
                && !matches!(bytes[end], b'\n' | b'\r')
                && !(json && matches!(bytes[end], b',' | b'}' | b']'))
            {
                end += 1;
            }
            if !json
                && bytes[delimiter] == b':'
                && let Some(continuation) = values::yaml_indented_value(input, name_start, value)
                    .map_err(DetectorError::input)?
            {
                end_state.yaml_continuation |= continuation.open;
                if let Some(span) = continuation.span {
                    end = span.end;
                }
            }
            if end > value {
                spans.push(value..end);
            }
            at = end;
        }
    }
    end_state.containers = container_depth;
    Ok(spans)
}

pub(crate) fn quoted_end(
    input: &str,
    start: usize,
    quote: u8,
    fail: bool,
) -> Result<usize, SafeError> {
    let bytes = input.as_bytes();
    let mut at = start + 1;
    while at < bytes.len() {
        if bytes[at] == quote {
            return Ok(at);
        }
        if bytes[at] == b'\\' {
            at += 1;
        }
        at += 1;
    }
    let kind = if fail {
        ErrorKind::UnterminatedQuote
    } else {
        ErrorKind::Category("invalid quoted field")
    };
    Err(SafeError::at(
        kind,
        crate::error::line_number(input.as_bytes(), start),
    ))
}

#[cfg(test)]
mod tests;
