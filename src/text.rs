use crate::error::{ErrorKind, SafeError};
use crate::evidence::{Evidence, Filtered, Finding, Redaction};
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
    Ok(
        merge_findings(input, &detect_findings(input, depth)?.findings)?
            .into_iter()
            .map(|finding| finding.span)
            .collect(),
    )
}

struct Detection {
    findings: Vec<Finding>,
    context_end: context::EndState,
    json_end: structured::JsonEndState,
}

fn detect_findings(input: &str, depth: usize) -> Result<Detection, SafeError> {
    let detection = structured::detect_with_contexts(input)?;
    let mut findings = detection.findings;
    let context = context::detect_with_state(input, &detection.contexts, depth)?;
    findings.extend(context.spans.into_iter().map(|span| Finding {
        span,
        label: Evidence::SensitiveFieldOrQuotedCredential,
    }));
    findings.extend(providers::detect(input)?);
    Ok(Detection {
        findings,
        context_end: context.end,
        json_end: detection.json_end,
    })
}

struct MergedFinding {
    span: Span,
    labels: Vec<Evidence>,
}

fn merge_findings(input: &str, findings: &[Finding]) -> Result<Vec<MergedFinding>, SafeError> {
    let mut sorted = Vec::with_capacity(findings.len());
    for finding in findings {
        validate(input, &finding.span)?;
        if !finding.span.is_empty() {
            sorted.push(finding);
        }
    }
    sorted.sort_unstable_by_key(|finding| (finding.span.start, finding.span.end, finding.label));
    let mut merged: Vec<MergedFinding> = Vec::with_capacity(sorted.len());
    for finding in sorted {
        if let Some(last) = merged.last_mut()
            && finding.span.start < last.span.end
        {
            last.span.end = last.span.end.max(finding.span.end);
            last.labels.push(finding.label);
            continue;
        }
        merged.push(MergedFinding {
            span: finding.span.clone(),
            labels: vec![finding.label],
        });
    }
    for finding in &mut merged {
        finding.labels.sort_unstable();
        finding.labels.dedup();
    }
    Ok(merged)
}

fn append_marker(output: &mut String, input: &str, span: &Span) -> String {
    let hash = fingerprint(&input[span.clone()]);
    output.push_str("[REDACTED sha256=");
    output.push_str(&hash);
    output.push(']');
    hash
}

pub fn render_spans(input: &str, spans: &[Span]) -> Result<String, SafeError> {
    let spans = merge_spans(input, spans)?;
    let mut output = String::new();
    let mut cursor = 0;
    for span in spans {
        output.push_str(&input[cursor..span.start]);
        append_marker(&mut output, input, &span);
        cursor = span.end;
    }
    output.push_str(&input[cursor..]);
    Ok(output)
}

pub fn filter(bytes: &[u8]) -> Result<String, SafeError> {
    Ok(filter_with_evidence(bytes)?.output)
}

pub fn filter_with_evidence(bytes: &[u8]) -> Result<Filtered, SafeError> {
    let input = validate_input(bytes)?;
    render_findings(input, bytes, &detect_findings(input, 0)?.findings)
}

pub(crate) fn filter_candidate(
    bytes: &[u8],
    boundary: context::RecordEnd,
) -> Result<Option<Filtered>, SafeError> {
    let input = validate_input(bytes)?;
    let detection = match detect_findings(input, 0) {
        Ok(detection) => detection,
        Err(error) if error.kind.can_complete() => return Ok(None),
        Err(error) => return Err(error),
    };
    if !detection.context_end.settled(boundary) || !detection.json_end.settled() {
        return Ok(None);
    }
    render_findings(input, bytes, &detection.findings).map(Some)
}

fn render_findings(input: &str, bytes: &[u8], findings: &[Finding]) -> Result<Filtered, SafeError> {
    let findings = merge_findings(input, findings)?;
    let mut output = String::new();
    let mut redactions = Vec::with_capacity(findings.len());
    let mut cursor = 0;
    let mut line = 1;
    for finding in findings {
        output.push_str(&input[cursor..finding.span.start]);
        line += bytes[cursor..finding.span.start]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
        let hash = append_marker(&mut output, input, &finding.span);
        redactions.push(Redaction {
            fingerprint: hash,
            line,
            labels: finding.labels,
        });
        line += bytes[finding.span.clone()]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
        cursor = finding.span.end;
    }
    output.push_str(&input[cursor..]);
    Ok(Filtered { output, redactions })
}

#[cfg(test)]
#[path = "text/candidate_tests.rs"]
mod candidate_tests;

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

    #[test]
    fn invalid_evidence_spans_fail_before_rendering() {
        let findings = [Finding {
            span: 1..2,
            label: Evidence::PrivateKey,
        }];
        let error = merge_findings("é SYNTHETIC_CANARY", &findings).must_err();
        assert!(!format!("{:?} {error}", Some(vec![error.clone()])).contains("SYNTHETIC_CANARY"));
        assert!(error.source().is_none());
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

        #[test]
        fn evidence_union_keeps_existing_spans_and_all_contributing_labels(
            pairs in prop::collection::vec((0usize..128,0usize..128, any::<bool>()),0..64)
        ) {
            let input = "x".repeat(128);
            let findings: Vec<_> = pairs.iter().map(|&(a, b, provider)| Finding {
                span: a.min(b)..a.max(b),
                label: if provider { Evidence::GithubTokenFormat } else { Evidence::AuthHeader },
            }).collect();
            let spans: Vec<_> = findings.iter().map(|finding| finding.span.clone()).collect();
            let merged = merge_findings(&input, &findings).must();
            prop_assert_eq!(merged.iter().map(|finding| finding.span.clone()).collect::<Vec<_>>(), merge_spans(&input, &spans).must());
            for finding in merged {
                let mut labels: Vec<_> = findings.iter()
                    .filter(|source| !source.span.is_empty() && source.span.start < finding.span.end && finding.span.start < source.span.end)
                    .map(|source| source.label).collect();
                labels.sort_unstable();
                labels.dedup();
                prop_assert_eq!(finding.labels, labels);
            }
        }
    }
}
