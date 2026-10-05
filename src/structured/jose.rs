use super::STRUCTURE_LIMIT;
use crate::{Span, error::SafeError};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

pub(super) fn detect(input: &str, spans: &mut Vec<Span>) -> Result<(), SafeError> {
    // Matching the entire dot-delimited candidate prevents partial inner-JWT output.
    let matcher = pattern!(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]*")?;
    for matched in matcher.find_iter(input) {
        let token = matched.as_str();
        let parts: Vec<_> = token.split('.').take(6).collect();
        if parts.len() < 3 {
            continue;
        }
        if parts[0].len() > 65_536 {
            return Err(SafeError::new(
                "token header exceeds parsing limit. Split input and retry.",
            ));
        }
        let Ok(header) = URL_SAFE_NO_PAD.decode(parts[0]) else {
            continue;
        };
        let Ok(header) = serde_json::from_slice::<Value>(&header) else {
            continue;
        };
        if !header.is_object() || !header.get("alg").is_some_and(Value::is_string) {
            continue;
        }
        let count = if header.get("enc").is_some_and(Value::is_string) {
            5
        } else {
            3
        };
        if parts.len() < count {
            continue;
        }
        if count == 5 && (parts[2].is_empty() || parts[4].is_empty()) {
            continue;
        }
        if parts[..count].iter().any(|part| {
            !part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        }) {
            continue;
        }
        let required_length =
            parts[..count].iter().map(|part| part.len()).sum::<usize>() + count - 1;
        // Recognized containers protect opaque format extensions as well as known segments.
        let length = token.trim_end_matches('.').len().max(required_length);
        if length > STRUCTURE_LIMIT {
            return Err(SafeError::new(
                "credential token exceeds parsing limit. Split input and retry.",
            ));
        }
        spans.push(Span {
            start: matched.start(),
            end: matched.start() + length,
        });
    }
    Ok(())
}
