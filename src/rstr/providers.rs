use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;

use super::{Span, pattern};
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

fn token_boundary(text: &str, start: usize) -> bool {
    start == 0
        || !text.as_bytes()[start - 1].is_ascii_alphanumeric()
            && !matches!(text.as_bytes()[start - 1], b'_' | b'-' | b'.')
}

pub(super) fn detect(text: &str) -> Result<Vec<Span>, SafeError> {
    let inventory: Inventory = serde_json::from_str(include_str!("../../rules/providers.json"))
        .map_err(|_| SafeError::new(ErrorKind::Detector))?;
    let prefixes: Vec<&str> = inventory
        .rules
        .iter()
        .flat_map(|rule| rule.prefixes.iter().map(String::as_str))
        .collect();
    let mut spans = Vec::new();
    for rule in &inventory.rules {
        for prefix in &rule.prefixes {
            let regex = pattern(&format!(
                "{}{}",
                regex::escape(prefix),
                inventory.body_pattern
            ))?;
            for found in regex.find_iter(text) {
                if token_boundary(text, found.start()) && !prefixes.contains(&found.as_str()) {
                    spans.push(found.range());
                }
            }
        }
    }
    for found in pattern(&inventory.aws.pattern)?.find_iter(text) {
        if token_boundary(text, found.start())
            && text
                .as_bytes()
                .get(found.end())
                .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        {
            spans.push(found.range());
        }
    }
    let jwt = pattern(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")?;
    for found in jwt.find_iter(text) {
        if !token_boundary(text, found.start())
            || text.as_bytes().get(found.end()).is_some_and(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.')
            })
        {
            continue;
        }
        let mut parts = found.as_str().split('.');
        let (Some(header), Some(payload), Some(_signature)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(SafeError::new(ErrorKind::Detector));
        };
        let (Ok(header), Ok(payload)) = (
            URL_SAFE_NO_PAD.decode(header),
            URL_SAFE_NO_PAD.decode(payload),
        ) else {
            continue;
        };
        check_json_depth(&header)?;
        check_json_depth(&payload)?;
        let (Ok(Value::Object(header)), Ok(Value::Object(_))) = (
            serde_json::from_slice::<Value>(&header),
            serde_json::from_slice::<Value>(&payload),
        ) else {
            continue;
        };
        if header.get("alg").is_some_and(Value::is_string) {
            spans.push(found.range());
        }
    }
    Ok(spans)
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
