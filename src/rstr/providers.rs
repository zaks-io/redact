use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use regex::Regex;
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;
use std::fmt;
use std::sync::LazyLock;

use super::{Compiled, Span, compiled, pattern};
use crate::error::{ErrorKind, SafeError};

#[derive(Deserialize)]
struct Inventory {
    rules: Vec<Rule>,
    aws: AwsRule,
    body_pattern: String,
}
#[derive(Deserialize)]
struct Rule {
    prefixes: Vec<String>,
}
#[derive(Deserialize)]
struct AwsRule {
    pattern: String,
}

struct Detectors {
    prefixes: Vec<String>,
    prefix: Regex,
    body: Regex,
    aws: Regex,
    jwt_run: Regex,
}

static DETECTORS: Compiled<Detectors> = LazyLock::new(|| {
    let inventory: Inventory = serde_json::from_str(include_str!("../../rules/providers.json"))
        .map_err(|_| SafeError::new(ErrorKind::Detector))?;
    let mut prefixes: Vec<String> = inventory
        .rules
        .into_iter()
        .flat_map(|rule| rule.prefixes)
        .collect();
    // A prefix occurrence overlapping an earlier one starts after a prefix character,
    // which token_boundary rejects. That keeps non-overlapping prefix search complete.
    if prefixes.iter().any(|prefix| {
        prefix.is_empty()
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    }) {
        return Err(SafeError::new(ErrorKind::Detector));
    }
    prefixes.sort_by_key(|prefix| std::cmp::Reverse(prefix.len()));
    let alternation: Vec<String> = prefixes
        .iter()
        .map(|prefix| regex::escape(prefix))
        .collect();
    Ok(Detectors {
        prefix: pattern(&alternation.join("|"))?,
        body: pattern(&inventory.body_pattern)?,
        aws: pattern(&inventory.aws.pattern)?,
        jwt_run: pattern(r"[A-Za-z0-9_.-]+")?,
        prefixes,
    })
});

fn token_boundary(text: &str, start: usize) -> bool {
    start == 0
        || !text.as_bytes()[start - 1].is_ascii_alphanumeric()
            && !matches!(text.as_bytes()[start - 1], b'_' | b'-' | b'.')
}

pub(super) fn detect(text: &str) -> Result<Vec<Span>, SafeError> {
    let detectors = compiled(&DETECTORS)?;
    let mut spans = Vec::new();
    // Bodies are maximal runs, so any start inside the previous run shares its end.
    let mut run = 0..0;
    for found in detectors.prefix.find_iter(text) {
        if !token_boundary(text, found.start()) {
            continue;
        }
        if !run.contains(&found.end()) {
            run = match detectors.body.find_at(text, found.end()) {
                Some(body) if body.start() == found.end() => body.range(),
                _ => continue,
            };
        }
        let candidate = &text[found.start()..run.end];
        if !detectors.prefixes.iter().any(|prefix| prefix == candidate) {
            spans.push(found.start()..run.end);
        }
    }
    for found in detectors.aws.find_iter(text) {
        if token_boundary(text, found.start())
            && text
                .as_bytes()
                .get(found.end())
                .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        {
            spans.push(found.range());
        }
    }
    for run in detectors.jwt_run.find_iter(text) {
        jwt_windows(text, run.range(), &mut spans)?;
    }
    Ok(spans)
}

// Any three consecutive dot segments of a run can be a compact JWS, so a dotted
// label before the token or punctuation after it cannot hide the credential.
fn jwt_windows(text: &str, run: Span, spans: &mut Vec<Span>) -> Result<(), SafeError> {
    let mut segments = Vec::new();
    let mut start = run.start;
    for (offset, byte) in text[run.clone()].bytes().enumerate() {
        if byte == b'.' {
            segments.push(start..run.start + offset);
            start = run.start + offset + 1;
        }
    }
    segments.push(start..run.end);
    for window in segments.windows(3) {
        let [header, payload, signature] = window else {
            return Err(SafeError::new(ErrorKind::Detector));
        };
        if header.is_empty() || payload.is_empty() {
            continue;
        }
        if is_jws(&text[header.clone()], &text[payload.clone()])? {
            spans.push(header.start..signature.end);
        }
    }
    Ok(())
}

fn is_jws(header: &str, payload: &str) -> Result<bool, SafeError> {
    let Ok(header) = URL_SAFE_NO_PAD.decode(header) else {
        return Ok(false);
    };
    check_json_depth(&header)?;
    if !serde_json::from_slice::<JoseObject>(&header).is_ok_and(|header| header.string_alg) {
        return Ok(false);
    }
    let Ok(payload) = URL_SAFE_NO_PAD.decode(payload) else {
        return Ok(false);
    };
    check_json_depth(&payload)?;
    Ok(serde_json::from_slice::<JoseObject>(&payload).is_ok())
}

/// A JSON object read through a typed map visitor. `serde_json::Value` with
/// `arbitrary_precision` reinterprets an object whose first key is its private
/// number marker, which would let such a payload pass as a non-object.
struct JoseObject {
    string_alg: bool,
}

impl<'de> Deserialize<'de> for JoseObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = JoseObject;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JoseObject, A::Error> {
                let mut string_alg = false;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "alg" {
                        string_alg |= map.next_value::<Value>()?.is_string();
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(JoseObject { string_alg })
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

// Stay below serde's recursion budget without interpreting braces inside strings.
fn check_json_depth(bytes: &[u8]) -> Result<(), SafeError> {
    const MAX_JSON_DEPTH: usize = 64;
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
                if depth > MAX_JSON_DEPTH {
                    return Err(SafeError::new(ErrorKind::Detector));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => (),
        }
    }
    Ok(())
}
