use crate::error::{ErrorKind, SafeError};
use crate::{context, fingerprint, providers, structured};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Byte range of removed input; always on UTF-8 boundaries once validated.
pub type Span = std::ops::Range<usize>;

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

fn validate(input: &str, span: &Span) -> Result<(), SafeError> {
    if span.start > span.end
        || span.end > input.len()
        || !input.is_char_boundary(span.start)
        || !input.is_char_boundary(span.end)
    {
        return Err(SafeError::new(
            "detector span validation failed. Reinstall the tool and retry with synthetic input.",
        ));
    }
    Ok(())
}

pub fn merge_spans(input: &str, spans: &[Span]) -> Result<Vec<Span>, SafeError> {
    let mut sorted = Vec::with_capacity(spans.len());
    for span in spans {
        validate(input, span)?;
        if !span.is_empty() {
            sorted.push(span.clone());
        }
    }
    sorted.sort_unstable_by_key(|span| (span.start, span.end));
    let mut merged: Vec<Span> = Vec::with_capacity(sorted.len());
    for span in sorted {
        if let Some(last) = merged.last_mut()
            && span.start < last.end
        {
            last.end = last.end.max(span.end);
            continue;
        }
        merged.push(span);
    }
    Ok(merged)
}

pub fn detect(input: &str) -> Result<Vec<Span>, SafeError> {
    detect_at_depth(input, 0)
}

/// Every detector family over one input; quoted text re-enters at a greater depth.
pub(crate) fn detect_at_depth(input: &str, depth: usize) -> Result<Vec<Span>, SafeError> {
    let detection = structured::detect_with_contexts(input)?;
    let mut spans = detection.spans;
    spans.extend(context::detect(input, &detection.contexts, depth)?);
    spans.extend(providers::detect(input)?);
    merge_spans(input, &spans)
}

pub fn render_spans(input: &str, spans: &[Span]) -> Result<String, SafeError> {
    let spans = merge_spans(input, spans)?;
    let mut output = String::new();
    let mut cursor = 0;
    for span in spans {
        output.push_str(&input[cursor..span.start]);
        output.push_str("[REDACTED sha256=");
        output.push_str(&fingerprint(&input[span.clone()]));
        output.push(']');
        cursor = span.end;
    }
    output.push_str(&input[cursor..]);
    Ok(output)
}

pub fn filter(bytes: &[u8]) -> Result<String, SafeError> {
    let input = validate_input(bytes)?;
    render_spans(input, &detect(input)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthetic::*;
    use proptest::prelude::*;
    use std::error::Error;

    #[test]
    fn fingerprint_and_union() {
        assert_eq!(fingerprint("abc"), "ba7816bf8f01cfea");
        assert_eq!(
            merge_spans("abcdef", &[0..3, 2..5, 5..6]).must(),
            vec![0..5, 5..6]
        );
        let inside_character: Span = 1..2;
        assert!(render_spans("é", &[inside_character]).is_err());
    }

    proptest! {
        #[test]
        fn sensitive_fields_never_leak(value in "[A-Za-z0-9_./+~=-]{1,256}") {
            let input = format!("status=401 password=\"{value}\" host=example.test\n");
            let expected = format!("status=401 password=\"[REDACTED sha256={}]\" host=example.test\n", fingerprint(&value));
            prop_assert_eq!(filter(input.as_bytes()).must(), expected);
        }
        #[test]
        fn arbitrary_input_errors_are_safe(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            if let Err(error) = filter(&bytes) {
                prop_assert!(!error.to_string().contains("panicked"));
                prop_assert!(error.source().is_none());
            }
        }
        #[test]
        fn union_matches_byte_oracle(pairs in prop::collection::vec((0usize..128,0usize..128),0..64)) {
            let input = "x".repeat(128);
            let spans:Vec<_> = pairs.iter().map(|&(a,b)| a.min(b)..a.max(b)).collect();
            let merged = merge_spans(&input, &spans).must();
            for index in 0..128 {
                prop_assert_eq!(spans.iter().any(|s| s.contains(&index)), merged.iter().any(|s| s.contains(&index)));
            }
            prop_assert!(merged.windows(2).all(|s| s[0].end<=s[1].start));
        }
    }
}
