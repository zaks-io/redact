use crate::{
    Span,
    error::{DetectorError, SafeError},
};

mod parameters;

pub(super) struct Frame {
    start: usize,
    end: usize,
    parameters_start: usize,
}

pub(super) fn urls(
    input: &str,
    spans: &mut Vec<Span>,
    contexts: &mut Vec<Span>,
) -> Result<(), SafeError> {
    let matcher = pattern!(r"[A-Za-z][A-Za-z0-9+.-]*:(?://|\\/\\/)")?;
    let schemes: Vec<_> = matcher.find_iter(input).collect();
    let boundaries: Vec<_> = input
        .char_indices()
        .filter_map(|(index, ch)| {
            (ch.is_whitespace()
                || ch.is_control()
                || matches!(ch, '<' | '>' | '"' | '\'' | '{' | '}'))
            .then_some(index)
        })
        .collect();
    let mut frames = Vec::with_capacity(schemes.len());
    for (index, matched) in schemes.iter().enumerate() {
        let full_end = boundaries
            .get(boundaries.partition_point(|end| *end < matched.end()))
            .copied()
            .unwrap_or(input.len());
        let local_end = schemes
            .get(index + 1)
            .map_or(full_end, |next| full_end.min(next.start()));
        let mut raw_url = &input[matched.start()..local_end];
        let opener = input.as_bytes().get(matched.start().wrapping_sub(1));
        let closer = match opener {
            Some(b'[') => Some(']'),
            Some(b'(') => Some(')'),
            _ => None,
        };
        if local_end == full_end
            && let Some(closer) = closer
        {
            let unpunctuated = raw_url.trim_end_matches([',', '.', ';']);
            if let Some(unwrapped) = unpunctuated.strip_suffix(closer) {
                raw_url = unwrapped;
            }
        }
        let end = if local_end == full_end {
            matched.start() + raw_url.len()
        } else {
            full_end
        };
        contexts.push(matched.start()..end);
        let escaped = raw_url
            .contains("\\/")
            .then(|| slash_unescape(raw_url))
            .transpose()?;
        let url = escaped
            .as_ref()
            .map_or(raw_url, |(decoded, _)| decoded.as_str());
        let boundary = |offset: usize| {
            matched.start()
                + escaped
                    .as_ref()
                    .map_or(offset, |(_, offsets)| offsets[offset])
        };
        let Some(scheme_end) = url.find("://") else {
            continue;
        };
        let authority_start = scheme_end + 3;
        let first_delimiter = url[authority_start..]
            .find(['/', '?', '#'])
            .map_or(url.len(), |offset| authority_start + offset);
        let authority = &url[authority_start..first_delimiter];
        let userinfo_end = authority
            .rfind('@')
            .map(|offset| authority_start + offset)
            .or_else(|| {
                if authority.starts_with('[') {
                    return None;
                }
                let (_, password) = authority.split_once(':')?;
                if !password.is_empty() && password.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                url[first_delimiter..]
                    .find('@')
                    .map(|offset| first_delimiter + offset)
            });
        if let Some(at) = userinfo_end {
            spans.push(boundary(authority_start)..boundary(at));
        }
        let host_start = userinfo_end.map_or(authority_start, |at| at + 1);
        let host_end = url[host_start..]
            .find(['/', '?', '#'])
            .map_or(url.len(), |offset| host_start + offset);
        let host_port = &url[host_start..host_end];
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
        frames.push(Frame {
            start: matched.start(),
            end,
            parameters_start: boundary(host_end),
        });
        let path_end = url[host_end..]
            .find(['?', '#'])
            .map_or(url.len(), |offset| host_end + offset);
        let path = &url[host_end..path_end];
        if matches!(host.as_str(), "hooks.slack.com" | "hooks.slack-gov.com")
            && path.starts_with("/services/")
            && path[10..]
                .split('/')
                .filter(|part| !part.is_empty())
                .count()
                >= 3
        {
            spans.push(matched.start()..end);
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
                .map_or(path.len(), |offset| bot_start + offset);
            if let Some((id, body)) = path[bot_start..token_end].split_once(':')
                && !id.is_empty()
                && id.bytes().all(|byte| byte.is_ascii_digit())
                && !body.is_empty()
            {
                spans.push(boundary(host_end + bot_start)..boundary(host_end + token_end));
            }
        }
    }
    parameters::detect(input, &frames, spans)?;
    Ok(())
}

pub(crate) fn connection_context(line: &str) -> (bool, bool) {
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
    (azure, postgres)
}

pub(super) fn connections(
    input: &str,
    spans: &mut Vec<Span>,
    contexts: &mut Vec<Span>,
) -> Result<(), DetectorError> {
    let fields = pattern!(r"(?i)\b(accountkey|sharedaccesssignature|password)[ \t]*=[ \t]*")?;
    let mut offset = 0;
    for line in input.split_inclusive('\n') {
        let (azure, postgres) = connection_context(line);
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
                let end = crate::context::quoted_end(input, value, bytes[value], true)
                    .map_err(DetectorError::input)?;
                if end > value + 1 {
                    spans.push(value + 1..end);
                    contexts.push(offset + field.start()..end + 1);
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
                    spans.push(value..end);
                    contexts.push(offset + field.start()..end);
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
