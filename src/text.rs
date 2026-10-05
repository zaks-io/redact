use crate::{context, error::SafeError, fingerprint, providers, structured};

pub const MAX_INPUT_BYTES: usize = 16_777_216;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

fn validate(input: &str, span: Span) -> Result<(), SafeError> {
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
    for &span in spans {
        validate(input, span)?;
        if span.start != span.end {
            sorted.push(span);
        }
    }
    sorted.sort_unstable_by_key(|s| (s.start, s.end));
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
    let detection = structured::detect_with_contexts(input)?;
    let mut spans = detection.spans;
    spans.extend(context::detect_with_structured(input, &detection.contexts)?);
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
        output.push_str(&fingerprint(&input[span.start..span.end]));
        output.push(']');
        cursor = span.end;
    }
    output.push_str(&input[cursor..]);
    Ok(output)
}

pub fn filter(bytes: &[u8]) -> Result<String, SafeError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(SafeError::new(
            "input exceeds 16 MiB. Supply a smaller bounded input and retry.",
        ));
    }
    let input = std::str::from_utf8(bytes)
        .map_err(|_| SafeError::new("input is not UTF-8. Supply UTF-8 text and retry."))?;
    if input.contains('\0') {
        return Err(SafeError::new(
            "input contains NUL bytes. Supply UTF-8 text without NUL bytes and retry.",
        ));
    }
    render_spans(input, &detect(input)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::error::Error;

    #[test]
    fn fingerprint_and_union() {
        assert_eq!(fingerprint("abc"), "ba7816bf8f01cfea");
        assert_eq!(
            merge_spans(
                "abcdef",
                &[
                    Span { start: 0, end: 3 },
                    Span { start: 2, end: 5 },
                    Span { start: 5, end: 6 }
                ]
            )
            .unwrap(),
            vec![Span { start: 0, end: 5 }, Span { start: 5, end: 6 }]
        );
        assert!(render_spans("é", &[Span { start: 1, end: 2 }]).is_err());
    }

    proptest! {
        #[test]
        fn sensitive_fields_never_leak(value in "[A-Za-z0-9_./+~=-]{1,256}") {
            let input = format!("status=401 password=\"{value}\" host=example.test\n");
            let expected = format!("status=401 password=\"[REDACTED sha256={}]\" host=example.test\n", fingerprint(&value));
            prop_assert_eq!(filter(input.as_bytes()).unwrap(), expected);
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
            let spans:Vec<_> = pairs.iter().map(|&(a,b)| Span {start:a.min(b),end:a.max(b)}).collect();
            let merged = merge_spans(&input, &spans).unwrap();
            for index in 0..128 {
                prop_assert_eq!(spans.iter().any(|s| s.start<=index && index<s.end), merged.iter().any(|s| s.start<=index && index<s.end));
            }
            prop_assert!(merged.windows(2).all(|s| s[0].end<=s[1].start));
        }
    }
}
