use crate::{Span, error::SafeError};

mod embedded;
mod names;
mod values;

pub(crate) use names::sensitive_name;

pub fn detect(input: &str) -> Result<Vec<Span>, SafeError> {
    let structured = crate::structured::detect_with_contexts(input)?;
    detect_with_structured(input, &structured.contexts)
}

pub(crate) fn detect_with_structured(
    input: &str,
    structured: &[Span],
) -> Result<Vec<Span>, SafeError> {
    scan(input, structured, 0)
}

fn scan(input: &str, structured: &[Span], depth: usize) -> Result<Vec<Span>, SafeError> {
    let structured = crate::merge_spans(input, structured)?;
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
        } else if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            at += 1;
            while at < bytes.len()
                && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'_' | b'-' | b'.'))
            {
                at += 1;
            }
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
        let closing_quote = !quoted_name && matches!(bytes.get(name_end), Some(b'"' | b'\''));
        let escaped_closing = !quoted_name
            && bytes.get(name_end) == Some(&b'\\')
            && matches!(bytes.get(name_end + 1), Some(b'"' | b'\''));
        let mut delimiter =
            name_end + usize::from(closing_quote) + 2 * usize::from(escaped_closing);
        while delimiter < bytes.len()
            && (matches!(bytes[delimiter], b' ' | b'\t')
                || quoted_name && matches!(bytes[delimiter], b'\r' | b'\n'))
        {
            delimiter += 1;
        }
        if delimiter == bytes.len() || !matches!(bytes[delimiter], b'=' | b':') {
            continue;
        }
        let json = (quoted_name || closing_quote || escaped_closing)
            && bytes[delimiter] == b':'
            && container_depth > 0;
        let mut value = delimiter + 1;
        while value < bytes.len()
            && (matches!(bytes[value], b' ' | b'\t')
                || json && matches!(bytes[value], b'\r' | b'\n'))
        {
            value += 1;
        }
        if !sensitive_name(&name) || value == bytes.len() {
            continue;
        }
        if bytes[delimiter] == b':'
            && matches!(bytes[value], b'\n' | b'\r' | b'#')
            && let Some(span) = values::yaml_indented_value(input, name_start, value)?
        {
            at = span.end;
            spans.push(span);
            continue;
        }
        if matches!(bytes[value], b'\n' | b'\r') {
            continue;
        }
        if bytes[value] == b'\\' && matches!(bytes.get(value + 1), Some(b'"' | b'\'')) {
            let end = values::escaped_quoted_end(input, value)?;
            if end > value + 2 {
                spans.push(Span {
                    start: value + 2,
                    end,
                });
            }
            at = end + 2;
        } else if matches!(bytes[value], b'"' | b'\'') {
            let end = quoted_end(input, value, bytes[value], true)?;
            if end > value + 1 {
                spans.push(Span {
                    start: value + 1,
                    end,
                });
            }
            at = end + 1;
        } else if json && matches!(bytes[value], b'{' | b'[') {
            let end = values::balanced_end(input, value)?;
            spans.push(Span { start: value, end });
            at = end;
        } else if bytes[delimiter] == b':'
            && let Some(end) = values::yaml_block_end(input, name_start, value)?
        {
            spans.push(Span { start: value, end });
            at = end;
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
                && let Some(continuation) = values::yaml_indented_value(input, name_start, value)?
            {
                end = continuation.end;
            }
            if end > value {
                spans.push(Span { start: value, end });
            }
            at = end;
        }
    }
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
    let line = input[..start].bytes().filter(|byte| *byte == b'\n').count() + 1;
    let category = if fail {
        "unterminated quoted value. Close the quoted value and retry."
    } else {
        "invalid quoted field"
    };
    Err(SafeError::at_line(category, line))
}
