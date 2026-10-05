use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use super::{Compiled, Span, compiled, line_number, pattern};
use crate::error::{ErrorKind, SafeError};

static ARMOR: Compiled<Regex> = LazyLock::new(|| {
    pattern(
        r"-----((?:BEGIN|END)) (PRIVATE KEY|ENCRYPTED PRIVATE KEY|RSA PRIVATE KEY|DSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----",
    )
});
static HEADER: Compiled<Regex> = LazyLock::new(|| {
    pattern(
        r"(?im)(?:^|\b)(?:proxy-authorization|authorization)[ \t]*:[ \t]*(?:bearer|basic)[ \t]+",
    )
});
static SCHEME: Compiled<Regex> = LazyLock::new(|| pattern(r"[A-Za-z][A-Za-z0-9+.-]*://"));
static PARAMETER: Compiled<Regex> = LazyLock::new(|| pattern(r#"[?&]([^\s<>"'{}?&#=]*)="#));
// The leading boundary is checked in code: consuming it here let a preceding
// `label:` field swallow the separator that the following sensitive name needs.
static ASSIGNMENT: Compiled<Regex> =
    LazyLock::new(|| pattern(r"([A-Za-z_][A-Za-z0-9_-]*)[ \t]*[=:]"));

/// Lowercase snake_case form: hyphens become underscores and camelCase or
/// acronym boundaries gain one, so `accessToken` and `APIKey` reach the suffix rules.
fn normalized(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut output = String::with_capacity(name.len() + 4);
    for (index, &ch) in chars.iter().enumerate() {
        if ch.is_ascii_uppercase() && index > 0 {
            let previous = chars[index - 1];
            let lower_follows = chars.get(index + 1).is_some_and(char::is_ascii_lowercase);
            if previous.is_ascii_lowercase()
                || previous.is_ascii_digit()
                || (previous.is_ascii_uppercase() && lower_follows)
            {
                output.push('_');
            }
        }
        output.push(if ch == '-' {
            '_'
        } else {
            ch.to_ascii_lowercase()
        });
    }
    output
}

// Both forms are checked: camelCase splitting finds `accessToken`, while the plain
// lowercase form keeps arbitrary casing such as `PassWord` matching `password`.
pub(super) fn sensitive(name: &str) -> bool {
    let plain = name.to_ascii_lowercase().replace('-', "_");
    let split = normalized(name);
    [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "secret_key",
        "private_key",
        "client_secret",
        "credential",
        "credentials",
        "authorization",
        "account_key",
        "shared_access_signature",
        "private_key_data",
    ]
    .iter()
    .any(|suffix| {
        [&plain, &split]
            .iter()
            .any(|name| *name == suffix || name.ends_with(&format!("_{suffix}")))
    })
}

pub(super) fn detect(text: &str) -> Result<Vec<Span>, SafeError> {
    let mut spans = Vec::new();
    let mut structured = BTreeMap::new();
    private_keys(text, &mut spans, &mut structured)?;
    let mut json_contents = BTreeMap::new();
    json_fields(text, &mut spans, &mut structured, &mut json_contents)?;
    headers(text, &mut spans, &mut structured, &json_contents)?;
    urls(text, &mut spans, &mut structured)?;
    assignments(text, &mut spans, &structured, &json_contents)?;
    Ok(spans)
}

fn protected(position: usize, structured: &BTreeMap<usize, usize>) -> bool {
    structured
        .range(..=position)
        .next_back()
        .is_some_and(|(_, end)| position < *end)
}

fn content_end(contents: &BTreeMap<usize, usize>, position: usize) -> Option<usize> {
    contents
        .range(..=position)
        .next_back()
        .and_then(|(_, end)| (position < *end).then_some(*end))
}

fn protect(structured: &mut BTreeMap<usize, usize>, mut region: Span) {
    if let Some((&start, &end)) = structured.range(..=region.start).next_back()
        && region.start <= end
    {
        region.start = start;
        region.end = region.end.max(end);
        structured.remove(&start);
    }
    while let Some((&start, &end)) = structured.range(region.start..).next() {
        if start > region.end {
            break;
        }
        region.end = region.end.max(end);
        structured.remove(&start);
    }
    structured.insert(region.start, region.end);
}

fn private_keys(
    text: &str,
    spans: &mut Vec<Span>,
    structured: &mut BTreeMap<usize, usize>,
) -> Result<(), SafeError> {
    let armor = compiled(&ARMOR)?;
    let mut beginnings = Vec::new();
    let mut endings: BTreeMap<&str, Vec<Span>> = BTreeMap::new();
    for captures in armor.captures_iter(text) {
        let (Some(full), Some(direction), Some(label)) =
            (captures.get(0), captures.get(1), captures.get(2))
        else {
            return Err(SafeError::new(ErrorKind::Detector));
        };
        if direction.as_str() == "BEGIN" {
            beginnings.push((full.range(), label.as_str()));
        } else {
            endings
                .entry(label.as_str())
                .or_default()
                .push(full.range());
        }
    }
    // Index END boundaries once so many overlapping BEGIN candidates stay bounded.
    for (begin, label) in beginnings {
        let end = endings
            .get(label)
            .and_then(|candidates| {
                candidates.get(candidates.partition_point(|end| end.start < begin.end))
            })
            .ok_or_else(|| {
                SafeError::at(ErrorKind::UnterminatedKey, line_number(text, begin.start))
            })?;
        let span = begin.start..end.end;
        spans.push(span.clone());
        protect(structured, span);
    }
    Ok(())
}

// Single quotes are literal; JSON and double-quoted log values use escaped quotes.
fn quoted_end(text: &str, start: usize, quote: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' if quote == b'"' => cursor += 2,
            byte if byte == quote => return Some(cursor),
            _ => cursor += 1,
        }
    }
    None
}

fn skip_space(text: &str, mut cursor: usize) -> usize {
    while text
        .as_bytes()
        .get(cursor)
        .is_some_and(u8::is_ascii_whitespace)
    {
        cursor += 1;
    }
    cursor
}

fn json_fields(
    text: &str,
    spans: &mut Vec<Span>,
    structured: &mut BTreeMap<usize, usize>,
    json_contents: &mut BTreeMap<usize, usize>,
) -> Result<(), SafeError> {
    let mut cursor = 0;
    while cursor < text.len() {
        if text.as_bytes()[cursor] != b'"' || protected(cursor, structured) {
            cursor += 1;
            continue;
        }
        let Some(key_end) = quoted_end(text, cursor, b'"') else {
            break;
        };
        let after = skip_space(text, key_end + 1);
        if text.as_bytes().get(after) != Some(&b':') {
            cursor = key_end + 1;
            continue;
        }
        let name: String = match serde_json::from_str(&text[cursor..=key_end]) {
            Ok(name) => name,
            Err(_) => {
                cursor = key_end + 1;
                continue;
            }
        };
        let value_start = skip_space(text, after + 1);
        if text.as_bytes().get(value_start) == Some(&b'"') {
            let Some(value_end) = quoted_end(text, value_start, b'"') else {
                if sensitive(&name) {
                    return Err(SafeError::at(
                        ErrorKind::UnterminatedQuote,
                        line_number(text, value_start),
                    ));
                }
                break;
            };
            if sensitive(&name) {
                // Validate escapes without forwarding serde's input-bearing diagnostic.
                serde_json::from_str::<String>(&text[value_start..=value_end]).map_err(|_| {
                    SafeError::at(ErrorKind::InvalidEscape, line_number(text, value_start))
                })?;
                spans.push(value_start + 1..value_end);
            }
            if sensitive(&name) {
                protect(structured, cursor..value_end + 1);
            } else {
                protect(structured, cursor..value_start + 1);
                protect(structured, value_end..value_end + 1);
                json_contents.insert(value_start + 1, value_end);
            }
            cursor = value_end + 1;
        } else {
            cursor = key_end + 1;
        }
    }
    Ok(())
}

fn headers(
    text: &str,
    spans: &mut Vec<Span>,
    structured: &mut BTreeMap<usize, usize>,
    json_contents: &BTreeMap<usize, usize>,
) -> Result<(), SafeError> {
    let header = compiled(&HEADER)?;
    let endings: Vec<_> = text
        .bytes()
        .enumerate()
        .filter_map(|(i, byte)| matches!(byte, b'\r' | b'\n').then_some(i))
        .collect();
    for found in header.find_iter(text) {
        if protected(found.start(), structured) {
            continue;
        }
        let physical_end = endings
            .get(endings.partition_point(|end| *end < found.end()))
            .copied()
            .unwrap_or(text.len());
        let end = content_end(json_contents, found.start())
            .unwrap_or(physical_end)
            .min(physical_end);
        let trimmed = text[found.end()..end].trim_end_matches([' ', '\t']);
        spans.push(found.end()..found.end() + trimmed.len());
        protect(structured, found.start()..end);
    }
    Ok(())
}

fn decode_name(name: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(name.len());
    let mut cursor = 0;
    while cursor < name.len() {
        if name.as_bytes()[cursor] == b'%' {
            let pair = name.get(cursor + 1..cursor + 3)?;
            bytes.push(u8::from_str_radix(pair, 16).ok()?);
            cursor += 3;
        } else {
            bytes.push(name.as_bytes()[cursor]);
            cursor += 1;
        }
    }
    String::from_utf8(bytes).ok()
}

fn urls(
    text: &str,
    spans: &mut Vec<Span>,
    structured: &mut BTreeMap<usize, usize>,
) -> Result<(), SafeError> {
    let scheme = compiled(&SCHEME)?;
    let mut boundaries = Vec::new();
    let mut value_boundaries = Vec::new();
    let mut questions = Vec::new();
    let mut fragments = Vec::new();
    let mut ats = Vec::new();
    for (position, ch) in text.char_indices() {
        let boundary = ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\'' | '{' | '}');
        if boundary {
            boundaries.push(position);
        }
        if boundary || matches!(ch, '&' | '#') {
            value_boundaries.push(position);
        }
        if ch == '?' {
            questions.push(position);
        }
        if ch == '#' {
            fragments.push(position);
        }
        if ch == '@' {
            ats.push(position);
        }
    }
    let next = |positions: &[usize], start: usize| {
        positions
            .get(positions.partition_point(|position| *position < start))
            .copied()
            .unwrap_or(text.len())
    };
    let mut queries = BTreeMap::new();
    for found in scheme.find_iter(text) {
        let end = next(&boundaries, found.end());
        let authority_start = found.end();
        let delimiter = text[authority_start..end]
            .find(['/', '?', '#'])
            .map_or(end, |i| authority_start + i);
        let userinfo_end = text[authority_start..delimiter]
            .rfind('@')
            .map(|at| authority_start + at)
            .or_else(|| {
                let at = next(&ats, delimiter);
                unencoded_userinfo(text, authority_start..delimiter, (at < end).then_some(at))
            });
        if let Some(at) = userinfo_end {
            spans.push(authority_start..at);
        }
        let host_start = userinfo_end.map_or(authority_start, |at| at + 1);
        let fragment = next(&fragments, host_start).min(end);
        let query = next(&questions, host_start);
        if query < fragment {
            protect(&mut queries, query..fragment);
        }
        protect(structured, found.start()..end);
    }
    // Every scheme and query-name start is visited independently on original text.
    // Indexed boundaries avoid repeatedly scanning the suffix of nested URLs.
    let parameter = compiled(&PARAMETER)?;
    for captures in parameter.captures_iter(text) {
        let (Some(full), Some(name)) = (captures.get(0), captures.get(1)) else {
            return Err(SafeError::new(ErrorKind::Detector));
        };
        if protected(full.start(), &queries)
            && decode_name(name.as_str()).is_some_and(|name| sensitive(&name))
        {
            spans.push(full.end()..next(&value_boundaries, full.end()));
        }
    }
    Ok(())
}

// Hand-written URIs often leave `/`, `?` or `#` unencoded inside a password. When
// `user:` precedes the first delimiter and is not a numeric port, user information
// runs to the first later `@`. A digits-only password before a delimiter still
// reads as a port. A bracketed IPv6 host has no user information before it. The
// caller supplies the indexed `@` so nested URIs stay linear.
fn unencoded_userinfo(text: &str, authority: Span, at: Option<usize>) -> Option<usize> {
    if text[authority.clone()].starts_with('[') {
        return None;
    }
    let colon = authority.start + text[authority.clone()].find(':')?;
    let after = &text[colon + 1..authority.end];
    let port = !after.is_empty() && after.bytes().all(|byte| byte.is_ascii_digit());
    if port { None } else { at }
}

fn assignments(
    text: &str,
    spans: &mut Vec<Span>,
    structured: &BTreeMap<usize, usize>,
    json_contents: &BTreeMap<usize, usize>,
) -> Result<(), SafeError> {
    let endings: Vec<_> = text
        .bytes()
        .enumerate()
        .filter_map(|(i, byte)| matches!(byte, b'\r' | b'\n').then_some(i))
        .collect();
    let assignment = compiled(&ASSIGNMENT)?;
    let mut quoted_regions = BTreeMap::new();
    for captures in assignment.captures_iter(text) {
        let (Some(full), Some(name)) = (captures.get(0), captures.get(1)) else {
            return Err(SafeError::new(ErrorKind::Detector));
        };
        // A leading `-` or `--` marks a flag name; only a preceding word character
        // means the match began inside a longer identifier.
        let inside_word = name.start() > 0 && {
            let previous = text.as_bytes()[name.start() - 1];
            previous.is_ascii_alphanumeric() || previous == b'_'
        };
        if inside_word
            || !sensitive(name.as_str())
            || protected(name.start(), structured)
            || protected(name.start(), &quoted_regions)
        {
            continue;
        }
        let start = full.end() + text[full.end()..].len()
            - text[full.end()..].trim_start_matches([' ', '\t']).len();
        let boundary = content_end(json_contents, name.start()).unwrap_or(text.len());
        if start >= boundary {
            continue;
        }
        if let Some(&quote @ (b'\'' | b'"')) = text.as_bytes().get(start) {
            let end = quoted_end(&text[..boundary], start, quote).ok_or_else(|| {
                SafeError::at(
                    ErrorKind::UnterminatedQuote,
                    line_number(text, name.start()),
                )
            })?;
            if quote == b'"' {
                let bytes = text.as_bytes();
                let mut cursor = start + 1;
                while cursor < end {
                    if bytes[cursor] == b'\\' {
                        cursor += 1;
                        if !matches!(bytes[cursor], b'\\' | b'"' | b'n' | b'r' | b't') {
                            return Err(SafeError::at(
                                ErrorKind::InvalidEscape,
                                line_number(text, name.start()),
                            ));
                        }
                    }
                    cursor += 1;
                }
            }
            spans.push(start + 1..end);
            protect(&mut quoted_regions, start..end + 1);
        } else {
            let physical_end = endings
                .get(endings.partition_point(|end| *end < start))
                .copied()
                .unwrap_or(text.len());
            let end = content_end(json_contents, name.start())
                .unwrap_or(physical_end)
                .min(physical_end);
            spans.push(start..end);
        }
    }
    Ok(())
}
