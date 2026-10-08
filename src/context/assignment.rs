use std::ops::Range;

use super::{quoted_end, sensitive_name, values::yaml_indentation};

pub(crate) struct ClosedQuote {
    pub region: Range<usize>,
    pub name: bool,
}

pub(super) fn plain_name_end(bytes: &[u8], start: usize) -> Option<usize> {
    if !bytes
        .get(start)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        end += 1;
    }
    Some(end)
}

pub(crate) fn delimiter(bytes: &[u8], name_end: usize, quoted_name: bool) -> (usize, bool) {
    let closing_quote = !quoted_name && matches!(bytes.get(name_end), Some(b'"' | b'\''));
    let escaped_closing = !quoted_name
        && bytes.get(name_end) == Some(&b'\\')
        && matches!(bytes.get(name_end + 1), Some(b'"' | b'\''));
    let mut at = name_end + usize::from(closing_quote) + 2 * usize::from(escaped_closing);
    while bytes.get(at).is_some_and(|byte| {
        matches!(byte, b' ' | b'\t') || quoted_name && matches!(byte, b'\r' | b'\n')
    }) {
        at += 1;
    }
    (at, quoted_name || closing_quote || escaped_closing)
}

/// Only forward-paired quotes can establish a quoted name; other closers use plain syntax.
pub(crate) fn sensitive_assignment(
    bytes: &[u8],
    at: usize,
    quoted_name: Option<&ClosedQuote>,
) -> Option<(usize, bool)> {
    if !matches!(bytes.get(at), Some(b':' | b'=')) {
        return None;
    }
    let mut end = at;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let closing = bytes[end - 1];
    if matches!(closing, b'"' | b'\'') {
        let escaped_closing = end > 1 && bytes[end - 2] == b'\\';
        if !escaped_closing && let Some(quote) = quoted_name.filter(|quote| quote.region.end == end)
        {
            if !quote.name {
                return None;
            }
            let region = &quote.region;
            let raw = std::str::from_utf8(bytes.get(region.clone())?).ok()?;
            if raw.len() < 2 || raw.as_bytes().first() != Some(&closing) {
                return None;
            }
            let name = if closing == b'"' {
                serde_json::from_str::<String>(raw).ok()
            } else {
                Some(raw[1..raw.len() - 1].to_owned())
            };
            return (name.as_deref().is_some_and(sensitive_name)
                && delimiter(bytes, end, true).0 == at)
                .then_some((region.start, true));
        }
        end -= 1 + usize::from(escaped_closing);
    }
    let mut start = end;
    while start > 0
        && (bytes[start - 1].is_ascii_alphanumeric()
            || matches!(bytes[start - 1], b'_' | b'-' | b'.'))
    {
        start -= 1;
    }
    while start < end && !(bytes[start].is_ascii_alphabetic() || bytes[start] == b'_') {
        start += 1;
    }
    let name = std::str::from_utf8(&bytes[start..end]).ok()?;
    let (actual_delimiter, quoted) = delimiter(bytes, end, false);
    (sensitive_name(name) && actual_delimiter == at).then_some((start, quoted))
}

/// Preserve every indentation-based continuation accepted by the context detector.
pub(crate) fn yaml_colon_assignment(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut start = 0;
    while bytes.get(start).is_some_and(|byte| {
        matches!(byte, b' ' | b'\t')
            || *byte == b'-'
                && bytes
                    .get(start + 1)
                    .is_some_and(|next| matches!(next, b' ' | b'\t'))
    }) {
        start += 1;
    }
    let indentation = yaml_indentation(bytes, start)?;
    let quoted = matches!(bytes.get(start), Some(b'"' | b'\''));
    let (name, end) = if quoted {
        let Ok(end) = quoted_end(line, start, bytes[start], false) else {
            return None;
        };
        let name = if bytes[start] == b'"' {
            serde_json::from_str::<String>(&line[start..=end]).ok()
        } else {
            Some(line[start + 1..end].to_owned())
        };
        (name, end + 1)
    } else {
        let end = plain_name_end(bytes, start)?;
        (Some(line[start..end].to_owned()), end)
    };
    let (at, _) = delimiter(bytes, end, quoted);
    (bytes.get(at) == Some(&b':') && name.as_deref().is_some_and(sensitive_name))
        .then_some(indentation)
}

#[cfg(test)]
mod tests {
    use super::{ClosedQuote, sensitive_assignment};
    use crate::synthetic::*;

    #[test]
    fn values_require_supported_sensitive_names_and_forward_paired_quotes() {
        for prefix in [
            "password=",
            "password : ",
            "password\"=",
            "password\\\":",
            "password'=",
            "password\\'=",
            "\"password\"\n=",
            "'api key'\r\n:",
            "\"api\\u005fkey\" =",
        ] {
            let at = prefix.rfind([':', '=']).must();
            let region = prefix.starts_with(['"', '\'']).then(|| ClosedQuote {
                region: 0..prefix.rfind(['"', '\'']).must() + 1,
                name: true,
            });
            assert!(sensitive_assignment(prefix.as_bytes(), at, region.as_ref()).is_some());
        }
        for prefix in [
            "note=",
            "xpassword=",
            "password ",
            "password,",
            "'ordinary value'=",
            "\"ordinary_passwordness\"=",
            "\"ordinary\\npassword\"=",
            "password\n=",
        ] {
            let at = prefix.rfind([':', '=']).unwrap_or(prefix.len());
            let region = prefix.starts_with(['"', '\'']).then(|| ClosedQuote {
                region: 0..prefix.rfind(['"', '\'']).must() + 1,
                name: true,
            });
            assert!(sensitive_assignment(prefix.as_bytes(), at, region.as_ref()).is_none());
        }
        let sensitive_plain = "[ 'a 'x,password'=";
        assert!(
            sensitive_assignment(
                sensitive_plain.as_bytes(),
                sensitive_plain.len() - 1,
                Some(&ClosedQuote {
                    region: 2..6,
                    name: true
                })
            )
            .is_some()
        );
        let ordinary_plain = "'a 'shared access signature'=";
        assert!(
            sensitive_assignment(
                ordinary_plain.as_bytes(),
                ordinary_plain.len() - 1,
                Some(&ClosedQuote {
                    region: 0..4,
                    name: true
                })
            )
            .is_none()
        );
        for (start, end) in [(0, 0), (0, 1), (1, 1), (9, 2), (0, usize::MAX), (1, 9)] {
            let input = "'password'=";
            let quote = ClosedQuote {
                region: start..end,
                name: true,
            };
            let result = sensitive_assignment(input.as_bytes(), input.len() - 1, Some(&quote));
            assert!(result.is_some());
        }
        for (start, end) in [(12, 10), (10, 10), (9, 10), (1, 10)] {
            let input = "'password'=";
            let quote = ClosedQuote {
                region: start..end,
                name: true,
            };
            assert!(
                sensitive_assignment(input.as_bytes(), input.len() - 1, Some(&quote)).is_none()
            );
        }
        for input in [
            "'='",
            "é'=",
            "'=",
            "😀'=",
            "\"=",
            "'password'=",
            "'password'= ",
        ] {
            let at = input.rfind('=').must();
            let end = input[..at].trim_end().len();
            let quote = ClosedQuote {
                region: end.saturating_sub(1)..end,
                name: true,
            };
            assert!(sensitive_assignment(input.as_bytes(), at, Some(&quote)).is_none());
        }
    }
}
