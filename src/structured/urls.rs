use crate::{Span, context::sensitive_name, error::SafeError};

pub(super) fn urls(
    input: &str,
    spans: &mut Vec<Span>,
    contexts: &mut Vec<Span>,
) -> Result<(), SafeError> {
    let matcher = pattern!(r#"[A-Za-z][A-Za-z0-9+.-]*:(?://|\\/\\/)[^\s\x00-\x1f<>"']+"#)?;
    let field_pattern = pattern!(r"[?&#;,]([^?&#;,/=]+)=")?;
    for matched in matcher.find_iter(input) {
        let mut url = matched.as_str();
        let opener = input.as_bytes().get(matched.start().wrapping_sub(1));
        let closer = match opener {
            Some(b'[') => Some(']'),
            Some(b'(') => Some(')'),
            Some(b'{') => Some('}'),
            _ => None,
        };
        if let Some(closer) = closer {
            let without_punctuation = url.trim_end_matches([',', '.', ';']);
            if let Some(unwrapped) = without_punctuation.strip_suffix(closer) {
                url = unwrapped;
            }
        }
        let raw_url = url;
        contexts.push(Span {
            start: matched.start(),
            end: matched.start() + raw_url.len(),
        });
        let escaped = raw_url
            .contains("\\/")
            .then(|| slash_unescape(raw_url))
            .transpose()?;
        let url = escaped
            .as_ref()
            .map_or(raw_url, |(decoded, _)| decoded.as_str());
        let boundary = |index: usize| {
            matched.start()
                + escaped
                    .as_ref()
                    .map_or(index, |(_, offsets)| offsets[index])
        };
        let Some(scheme_end) = url.find("://") else {
            continue;
        };
        let authority_start = scheme_end + 3;
        let authority_end = url[authority_start..]
            .find(['/', '?', '#'])
            .map_or(url.len(), |at| authority_start + at);
        let authority = &url[authority_start..authority_end];
        if let Some(at) = authority.rfind('@') {
            spans.push(Span {
                start: boundary(authority_start),
                end: boundary(authority_start + at),
            });
        }
        let host_port = authority.rsplit('@').next().unwrap_or("");
        let host = if host_port.starts_with('[') {
            host_port
                .split_once(']')
                .map_or(host_port, |(host, _)| host)
        } else {
            host_port
                .split_once(':')
                .map_or(host_port, |(host, _)| host)
        }
        .trim_end_matches('.')
        .to_ascii_lowercase();
        let path_end = url.find(['?', '#']).unwrap_or(url.len());
        let path = &url[authority_end..path_end.max(authority_end)];
        if matches!(host.as_str(), "hooks.slack.com" | "hooks.slack-gov.com")
            && path.starts_with("/services/")
            && path[10..]
                .split('/')
                .filter(|part| !part.is_empty())
                .count()
                >= 3
        {
            spans.push(Span {
                start: matched.start(),
                end: matched.start() + raw_url.len(),
            });
            continue;
        }
        let bot_start = if path.starts_with("/bot") {
            Some(4)
        } else if path.starts_with("/file/bot") {
            Some(9)
        } else {
            None
        };
        if host == "api.telegram.org"
            && let Some(bot_start) = bot_start
        {
            let token_end = path[bot_start..]
                .find('/')
                .map_or(path.len(), |at| at + bot_start);
            let token = &path[bot_start..token_end];
            if let Some((id, body)) = token.split_once(':')
                && !id.is_empty()
                && id.bytes().all(|byte| byte.is_ascii_digit())
                && !body.is_empty()
            {
                spans.push(Span {
                    start: boundary(authority_end + bot_start),
                    end: boundary(authority_end + token_end),
                });
            }
        }
        let fields: Vec<_> = field_pattern
            .captures_iter(&url[authority_end..])
            .filter_map(|capture| {
                let complete = capture.get(0)?;
                let name = capture.get(1)?;
                let decoded = percent_encoding::percent_decode_str(name.as_str())
                    .decode_utf8()
                    .ok()?;
                Some((
                    decoded.into_owned(),
                    authority_end + complete.start(),
                    authority_end + complete.end(),
                ))
            })
            .collect();
        let azure_sas = fields
            .iter()
            .any(|field| field.0.eq_ignore_ascii_case("sv"))
            && fields.iter().any(|field| {
                ["se", "sp", "sr", "ss", "srt"]
                    .iter()
                    .any(|name| field.0.eq_ignore_ascii_case(name))
            });
        let hard_delimiters: Vec<_> = url
            .bytes()
            .enumerate()
            .filter_map(|(index, byte)| matches!(byte, b'&' | b'#').then_some(index))
            .collect();
        let mut hard_cursor = hard_delimiters.len();
        let mut hard_end = url.len();
        for index in (0..fields.len()).rev() {
            let (name, _, start) = &fields[index];
            while hard_cursor > 0 && hard_delimiters[hard_cursor - 1] >= *start {
                hard_cursor -= 1;
                hard_end = hard_delimiters[hard_cursor];
            }
            let next_field = fields.get(index + 1).map_or(url.len(), |field| field.1);
            let end = hard_end.min(next_field);
            let signed = [
                "x-amz-credential",
                "x-amz-signature",
                "x-amz-security-token",
            ]
            .iter()
            .any(|expected| name.eq_ignore_ascii_case(expected))
                || azure_sas && name.eq_ignore_ascii_case("sig");
            if end > *start && (signed || sensitive_name(name)) {
                spans.push(Span {
                    start: boundary(*start),
                    end: boundary(end),
                });
            }
        }
    }
    Ok(())
}

pub(super) fn connections(
    input: &str,
    spans: &mut Vec<Span>,
    contexts: &mut Vec<Span>,
) -> Result<(), SafeError> {
    let fields = pattern!(r"(?i)\b(accountkey|sharedaccesssignature|password)[ \t]*=[ \t]*")?;
    let mut offset = 0;
    for line in input.split_inclusive('\n') {
        let lower = line.to_ascii_lowercase();
        let azure = lower.contains("accountname=")
            || lower.contains("defaultendpointsprotocol=")
            || lower.contains("sharedaccesssignature=");
        let postgres = [
            "host=",
            "dbname=",
            "user=",
            "port=",
            "hostaddr=",
            "sslmode=",
        ]
        .iter()
        .filter(|name| lower.contains(**name))
        .count()
            >= 2;
        if !azure && !postgres {
            offset += line.len();
            continue;
        }
        for matched in fields.captures_iter(line) {
            let Some(field) = matched.get(0) else {
                continue;
            };
            let value = offset + field.end();
            if value == input.len() {
                continue;
            }
            let bytes = input.as_bytes();
            if matches!(bytes[value], b'\'' | b'"') {
                let end = crate::context::quoted_end(input, value, bytes[value], true)?;
                if end > value + 1 {
                    spans.push(Span {
                        start: value + 1,
                        end,
                    });
                    contexts.push(Span {
                        start: offset + field.start(),
                        end: end + 1,
                    });
                }
            } else {
                let mut end = value;
                while end < offset + line.len()
                    && !matches!(bytes[end], b'\r' | b'\n')
                    && !(azure && bytes[end] == b';')
                    && !(postgres && bytes[end].is_ascii_whitespace())
                {
                    if postgres && bytes[end] == b'\\' && end + 1 < offset + line.len() {
                        end += 1;
                    }
                    end += 1;
                }
                if end > value {
                    spans.push(Span { start: value, end });
                    contexts.push(Span {
                        start: offset + field.start(),
                        end,
                    });
                }
            }
        }
        offset += line.len();
    }
    Ok(())
}

fn slash_unescape(input: &str) -> Result<(String, Vec<usize>), SafeError> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len() + 1);
    let mut at = 0;
    while at < bytes.len() {
        offsets.push(at);
        if bytes[at] == b'\\' && bytes.get(at + 1) == Some(&b'/') {
            at += 1;
        }
        decoded.push(bytes[at]);
        at += 1;
    }
    offsets.push(bytes.len());
    // Removing only ASCII escape bytes preserves the original UTF-8 sequence.
    let text = String::from_utf8(decoded).map_err(|_| {
        SafeError::new("URL escape decoding failed. Correct its encoding and retry.")
    })?;
    Ok((text, offsets))
}
