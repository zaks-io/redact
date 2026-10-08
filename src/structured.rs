use crate::evidence::{Evidence, Finding};
use crate::{Span, error::SafeError};

const STRUCTURE_LIMIT: usize = 1_048_576;

macro_rules! pattern {
    ($source:literal) => {{
        static MATCHER: std::sync::OnceLock<Result<regex::Regex, crate::error::SafeError>> =
            std::sync::OnceLock::new();
        MATCHER
            .get_or_init(|| {
                regex::RegexBuilder::new($source)
                    .size_limit(1_048_576)
                    .build()
                    .map_err(|_| {
                        crate::error::SafeError::new("structured detector initialization failed")
                    })
            })
            .as_ref()
            .map_err(Clone::clone)
    }};
}

mod containers;
mod jose;
mod urls;
pub(crate) use urls::connection_context;

pub(crate) fn yaml_document_separators() -> Result<&'static regex::Regex, SafeError> {
    pattern!(r"(?m)^---[ \t]*(?:#.*)?\r?$")
}

pub(crate) fn yaml_secret_kind() -> Result<&'static regex::Regex, SafeError> {
    pattern!(r#"(?m)^[ \t]*["']?kind["']?[ \t]*:[ \t]*["']?Secret["']?[ \t]*(?:#.*)?\r?$"#)
}

pub(crate) fn json_quote_starts_string(byte: u8, escaped_outside: bool) -> bool {
    byte == b'"' && !escaped_outside
}

pub(crate) struct Detection {
    pub findings: Vec<Finding>,
    pub contexts: Vec<Span>,
}

pub(crate) fn detect_with_contexts(input: &str) -> Result<Detection, SafeError> {
    let mut spans = Vec::new();
    let mut findings = Vec::new();
    let mut contexts = Vec::new();
    authentication(input, &mut spans, &mut contexts)?;
    let mut start = tag(&spans, 0, Evidence::AuthHeader, &mut findings);
    let mut private_spans = Vec::new();
    private_blocks(input, &mut private_spans)?;
    spans.extend_from_slice(&private_spans);
    start = tag(&spans, start, Evidence::PrivateKey, &mut findings);
    contexts.extend_from_slice(&private_spans);
    urls::urls(input, &mut spans, &mut contexts)?;
    start = tag(&spans, start, Evidence::UrlCredentials, &mut findings);
    urls::connections(input, &mut spans, &mut contexts)?;
    start = tag(&spans, start, Evidence::ConnectionString, &mut findings);
    jose::detect(input, &mut spans)?;
    start = tag(&spans, start, Evidence::JoseFormat, &mut findings);
    let container_start = spans.len();
    containers::json_containers(input, &private_spans, &mut spans)?;
    start = tag(&spans, start, Evidence::CredentialContainer, &mut findings);
    containers::kubernetes_yaml(input, &mut spans)?;
    tag(&spans, start, Evidence::KubernetesSecret, &mut findings);
    contexts.extend_from_slice(&spans[container_start..]);
    Ok(Detection { findings, contexts })
}

fn tag(spans: &[Span], start: usize, label: Evidence, findings: &mut Vec<Finding>) -> usize {
    findings.extend(
        spans[start..]
            .iter()
            .cloned()
            .map(|span| Finding { span, label }),
    );
    spans.len()
}

fn authentication(
    input: &str,
    spans: &mut Vec<Span>,
    contexts: &mut Vec<Span>,
) -> Result<(), SafeError> {
    let matcher = pattern!(
        r"(?im)\b(?:proxy-)?authorization[ \t]*:[ \t]*(?:bearer|basic|bot)[ \t]+([^\r\n]*)"
    )?;
    let mut quoted = Vec::new();
    let mut at = 0;
    let mut available = [true, true];
    while at < input.len() {
        let quote = input.as_bytes()[at];
        let kind = usize::from(quote == b'\'');
        if matches!(quote, b'"' | b'\'') && available[kind] {
            match crate::context::quoted_end(input, at, quote, false) {
                Ok(end) => {
                    quoted.push(at..end);
                    at = end;
                }
                Err(_) => available[kind] = false,
            }
        }
        at += 1;
    }
    for capture in matcher.captures_iter(input) {
        if let Some(value) = capture.get(1) {
            let Some(header) = capture.get(0) else {
                continue;
            };
            let mut end = value.start() + value.as_str().trim_end_matches([' ', '\t']).len();
            if let Some(region) =
                quoted.get(quoted.partition_point(|region| region.end <= header.start()))
                && region.start < header.start()
                && header.start() < region.end
            {
                end = end.min(region.end);
            }
            if end > value.start() {
                spans.push(value.start()..end);
            }
            contexts.push(header.start()..end.max(value.start()));
        }
    }
    Ok(())
}

fn private_blocks(input: &str, spans: &mut Vec<Span>) -> Result<(), SafeError> {
    let matcher = pattern!(r"-----BEGIN ([A-Z0-9 ]*?PRIVATE KEY(?: BLOCK)?)-----")?;
    let end_matcher = pattern!(r"-----END ([A-Z0-9 ]*?PRIVATE KEY(?: BLOCK)?)-----")?;
    let mut endings = std::collections::HashMap::<&str, Vec<(usize, usize)>>::new();
    for capture in end_matcher.captures_iter(input) {
        if let (Some(marker), Some(label)) = (capture.get(0), capture.get(1)) {
            endings
                .entry(label.as_str())
                .or_default()
                .push((marker.start(), marker.end()));
        }
    }
    for capture in matcher.captures_iter(input) {
        let (Some(begin), Some(label)) = (capture.get(0), capture.get(1)) else {
            continue;
        };
        let end = endings.get(label.as_str()).and_then(|markers| {
            markers.get(markers.partition_point(|marker| marker.0 < begin.end()))
        });
        let Some((_, end)) = end else {
            return Err(SafeError::at(
                "unterminated private-key block. Add its matching END marker and retry.",
                crate::error::line_number(input.as_bytes(), begin.start()),
            ));
        };
        spans.push(begin.start()..*end);
    }

    Ok(())
}
