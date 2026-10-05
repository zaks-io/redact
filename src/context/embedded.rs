use crate::{Span, error::SafeError};

/// Map detected decoded string spans back to their exact source escape bytes.
pub(super) fn detect(
    input: &str,
    start: usize,
    end: usize,
    depth: usize,
) -> Result<Vec<Span>, SafeError> {
    let quoted = &input[start..=end];
    if input.as_bytes()[start] != b'"' {
        return raw_contents(input, start, end, depth);
    }
    let Ok(decoded) = serde_json::from_str::<String>(quoted) else {
        return raw_contents(input, start, end, depth);
    };
    let spans = nested(&decoded, depth)?;
    if spans.is_empty() {
        return Ok(Vec::new());
    }
    let mut offsets = vec![0; decoded.len() + 1];
    let mut raw = start + 1;
    for (at, character) in decoded.char_indices() {
        offsets[at] = raw;
        let byte = input
            .as_bytes()
            .get(raw)
            .copied()
            .ok_or_else(mapping_error)?;
        raw += if byte == b'\\' {
            if input.as_bytes().get(raw + 1) == Some(&b'u') {
                if character as u32 > 0xffff { 12 } else { 6 }
            } else {
                2
            }
        } else {
            character.len_utf8()
        };
        offsets[at + character.len_utf8()] = raw;
    }
    if raw != end {
        return Err(mapping_error());
    }
    spans
        .into_iter()
        .map(|span| {
            Ok(Span {
                start: *offsets.get(span.start).ok_or_else(mapping_error)?,
                end: *offsets.get(span.end).ok_or_else(mapping_error)?,
            })
        })
        .collect()
}

fn raw_contents(
    input: &str,
    start: usize,
    end: usize,
    depth: usize,
) -> Result<Vec<Span>, SafeError> {
    Ok(nested(&input[start + 1..end], depth)?
        .into_iter()
        .map(|span| Span {
            start: start + 1 + span.start,
            end: start + 1 + span.end,
        })
        .collect())
}

fn nested(input: &str, depth: usize) -> Result<Vec<Span>, SafeError> {
    if depth >= 32 {
        return Err(SafeError::new(
            "quoted input exceeds nesting limit. Reduce nested quoting and retry.",
        ));
    }
    let detection = crate::structured::detect_with_contexts(input)?;
    let mut spans = detection.spans;
    spans.extend(super::scan(input, &detection.contexts, depth + 1)?);
    spans.extend(crate::providers::detect(input)?);
    crate::merge_spans(input, &spans)
}

fn mapping_error() -> SafeError {
    SafeError::new("quoted input mapping failed. Retry with a supported UTF-8 quoted value.")
}
