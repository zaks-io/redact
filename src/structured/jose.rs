use super::STRUCTURE_LIMIT;
use crate::{
    Span,
    error::{ErrorKind, SafeError},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

pub(super) fn detect(input: &str, spans: &mut Vec<Span>) -> Result<(), SafeError> {
    let matcher = pattern!(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]*")?;
    for matched in matcher.find_iter(input) {
        let token = matched.as_str();
        let mut start = 0;
        while start < token.len() {
            let header_end = token[start..]
                .find('.')
                .map_or(token.len(), |end| start + end);
            if header_end == token.len() {
                break;
            }
            if header_end - start > 65_536 {
                return Err(SafeError::new(
                    "token header exceeds parsing limit. Split input and retry.",
                ));
            }
            let header = URL_SAFE_NO_PAD.decode(&token[start..header_end]);
            let parsed = match header {
                Ok(header) => {
                    check_json_depth(&header)?;
                    serde_json::from_slice::<JoseHeader>(&header).ok()
                }
                Err(_) => None,
            };
            if let Some(header) = parsed.filter(|header| header.algorithm) {
                let parts: Vec<_> = token[start..].split('.').take(5).collect();
                let count = if header.encrypted { 5 } else { 3 };
                if parts.len() >= count
                    && (count == 3 || !parts[2].is_empty() && !parts[4].is_empty())
                {
                    let required_length =
                        parts[..count].iter().map(|part| part.len()).sum::<usize>() + count - 1;
                    let length = token[start..]
                        .trim_end_matches('.')
                        .len()
                        .max(required_length);
                    if length > STRUCTURE_LIMIT {
                        return Err(SafeError::new(
                            "credential token exceeds parsing limit. Split input and retry.",
                        ));
                    }
                    if count == 3
                        && let Ok(payload) = URL_SAFE_NO_PAD.decode(parts[1])
                    {
                        check_json_depth(&payload)?;
                    }
                    spans.push(Span {
                        start: matched.start() + start,
                        end: matched.start() + start + length,
                    });
                    break;
                }
            }
            start = header_end + 1;
        }
    }
    Ok(())
}

struct JoseHeader {
    algorithm: bool,
    encrypted: bool,
}

impl<'de> Deserialize<'de> for JoseHeader {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HeaderVisitor;
        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = JoseHeader;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JOSE header object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut header = JoseHeader {
                    algorithm: false,
                    encrypted: false,
                };
                while let Some(name) = map.next_key::<String>()? {
                    match name.as_str() {
                        "alg" => header.algorithm |= map.next_value::<Value>()?.is_string(),
                        "enc" => header.encrypted |= map.next_value::<Value>()?.is_string(),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(header)
            }
        }
        deserializer.deserialize_map(HeaderVisitor)
    }
}

fn check_json_depth(bytes: &[u8]) -> Result<(), SafeError> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > 64 {
                    return Err(SafeError::new(ErrorKind::Detector));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}
