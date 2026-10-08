use crate::error::SafeError;

const VALUE_LIMIT: usize = 1_048_576;

pub(super) struct BlockEnd {
    pub end: usize,
    pub open: bool,
}

pub(super) struct IndentedValue {
    pub span: Option<crate::Span>,
    pub open: bool,
}

pub(super) fn balanced_end(input: &str, start: usize) -> Result<usize, SafeError> {
    let bytes = input.as_bytes();
    let mut stack = Vec::new();
    let mut at = start;
    while at < bytes.len() {
        if at - start > VALUE_LIMIT {
            return Err(SafeError::new(
                "sensitive container exceeds parsing limit. Split input and retry.",
            ));
        }
        match bytes[at] {
            b'"' | b'\'' => at = super::quoted_end(input, at, bytes[at], true)?,
            b'{' | b'[' => {
                if stack.len() >= 64 {
                    return Err(SafeError::new(
                        "sensitive container exceeds nesting limit. Reduce nesting and retry.",
                    ));
                }
                stack.push(if bytes[at] == b'{' { b'}' } else { b']' });
            }
            b'}' | b']' => {
                if stack.pop() != Some(bytes[at]) {
                    return Err(SafeError::new(
                        "malformed sensitive container. Correct its delimiters and retry.",
                    ));
                }
                if stack.is_empty() {
                    return Ok(at + 1);
                }
            }
            _ => {}
        }
        at += 1;
    }
    Err(SafeError::new(
        "unterminated sensitive container. Close its delimiters and retry.",
    ))
}

pub(super) fn yaml_block_end(
    input: &str,
    name: usize,
    value: usize,
) -> Result<Option<BlockEnd>, SafeError> {
    let bytes = input.as_bytes();
    if !matches!(bytes[value], b'|' | b'>') {
        return Ok(None);
    }
    let Some(indentation) = yaml_indentation(bytes, name) else {
        return Ok(None);
    };
    let header_end = input[value..]
        .find(['\r', '\n'])
        .map_or(input.len(), |at| at + value);
    let header = input[value + 1..header_end]
        .split('#')
        .next()
        .unwrap_or("")
        .trim();
    if !header
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'+' | b'-'))
    {
        return Ok(None);
    }
    let mut cursor = next_line(bytes, header_end);
    let mut end = header_end;
    while cursor < input.len() {
        let line_end = input[cursor..]
            .find(['\r', '\n'])
            .map_or(input.len(), |at| cursor + at);
        let line = &input[cursor..line_end];
        if !continues_value(line, indentation) {
            break;
        }
        end = line_end;
        cursor = next_line(bytes, line_end);
        if end - value > VALUE_LIMIT {
            return Err(SafeError::new(
                "sensitive block exceeds parsing limit. Split input and retry.",
            ));
        }
    }
    if end > value && bytes[end - 1] == b'\r' {
        end -= 1;
    }
    Ok(Some(BlockEnd {
        end,
        open: cursor == input.len(),
    }))
}

pub(super) fn yaml_indented_value(
    input: &str,
    name: usize,
    value: usize,
) -> Result<Option<IndentedValue>, SafeError> {
    let bytes = input.as_bytes();
    let Some(indentation) = yaml_indentation(bytes, name) else {
        return Ok(None);
    };
    let Some(header_end) = input[value..].find(['\r', '\n']).map(|at| value + at) else {
        return Ok(None);
    };
    let mut cursor = next_line(bytes, header_end);
    let mut start = None;
    let mut end = cursor;
    while cursor < input.len() {
        let line_end = input[cursor..]
            .find(['\r', '\n'])
            .map_or(input.len(), |at| cursor + at);
        let line = &input[cursor..line_end];
        let leading = line
            .bytes()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        if !line.trim().is_empty() {
            if !continues_value(line, indentation) {
                break;
            }
            start.get_or_insert(cursor + leading);
        }
        end = line_end;
        cursor = next_line(bytes, line_end);
        if end - header_end > VALUE_LIMIT {
            return Err(SafeError::new(
                "sensitive block exceeds parsing limit. Split input and retry.",
            ));
        }
    }
    if end > header_end && bytes[end - 1] == b'\r' {
        end -= 1;
    }
    Ok(Some(IndentedValue {
        span: start.map(|start| start..end),
        open: cursor == input.len(),
    }))
}

pub(crate) fn yaml_indentation(bytes: &[u8], name: usize) -> Option<usize> {
    let mut at = name;
    loop {
        let before_spaces = at;
        while at > 0 && matches!(bytes[at - 1], b' ' | b'\t') {
            at -= 1;
        }
        if at == 0 || matches!(bytes[at - 1], b'\r' | b'\n') {
            return Some(name - at);
        }
        if at < before_spaces
            && bytes[at - 1] == b'-'
            && (at == 1 || matches!(bytes[at - 2], b' ' | b'\t' | b'\r' | b'\n'))
        {
            at -= 1;
        } else {
            return None;
        }
    }
}

pub(crate) fn continues_value(line: &str, indentation: usize) -> bool {
    line.trim().is_empty()
        || line
            .bytes()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count()
            > indentation
}

fn next_line(bytes: &[u8], end: usize) -> usize {
    if bytes.get(end) == Some(&b'\r') && bytes.get(end + 1) == Some(&b'\n') {
        end + 2
    } else {
        (end + 1).min(bytes.len())
    }
}

pub(super) fn escaped_quoted_end(input: &str, start: usize) -> Result<usize, SafeError> {
    let bytes = input.as_bytes();
    let quote = bytes[start + 1];
    let mut at = start + 2;
    while at < bytes.len() {
        if bytes[at] != b'\\' {
            at += 1;
            continue;
        }
        let slash = at;
        while at < bytes.len() && bytes[at] == b'\\' {
            at += 1;
        }
        if bytes.get(at) == Some(&quote) && (at - slash) % 4 == 1 {
            return Ok(at - 1);
        }
        if at < bytes.len() {
            at += 1;
        }
    }
    Err(SafeError::new(
        "unterminated escaped quoted value. Close its escaped quote and retry.",
    ))
}
