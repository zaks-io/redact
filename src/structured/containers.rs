use super::STRUCTURE_LIMIT;
use crate::{Span, error::SafeError};
use serde_json::Value;

pub(super) fn json_containers(input: &str, spans: &mut Vec<Span>) -> Result<(), SafeError> {
    let bytes = input.as_bytes();
    let mut stack = Vec::new();
    let mut at = 0;
    let mut quoted_regions_available = true;
    while at < bytes.len() {
        match bytes[at] {
            b'"' if quoted_regions_available => {
                match crate::context::quoted_end(input, at, b'"', false) {
                    Ok(end) => at = end,
                    Err(_) => quoted_regions_available = false,
                }
            }
            b'{' => {
                if stack.is_empty() {
                    let mut first = at + 1;
                    while first < bytes.len() && bytes[first].is_ascii_whitespace() {
                        first += 1;
                    }
                    if !bytes
                        .get(first)
                        .is_some_and(|byte| matches!(byte, b'"' | b'}'))
                    {
                        at += 1;
                        continue;
                    }
                }
                if stack.len() >= 64 {
                    return Err(SafeError::new(
                        "structured input exceeds nesting limit. Reduce nesting and retry.",
                    ));
                }
                stack.push(at);
            }
            b'}' => {
                if let Some(start) = stack.pop() {
                    let object = &input[start..=at];
                    if object.len() > STRUCTURE_LIMIT {
                        if credential_object_hint(object) {
                            return Err(SafeError::new(
                                "credential container exceeds parsing limit. Split input and retry.",
                            ));
                        }
                    } else {
                        match parse_object(object) {
                            Ok(value) => {
                                if private_object(&value) {
                                    spans.push(start..at + 1);
                                }
                            }
                            Err(_) if credential_object_hint(object) => {
                                return Err(SafeError::new(
                                    "malformed credential container. Correct its JSON structure and retry.",
                                ));
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            _ => {}
        }
        at += 1;
    }
    if let Some(start) = stack.first()
        && credential_object_hint(&input[*start..])
    {
        return Err(SafeError::new(
            "unterminated credential container. Close the JSON object and retry.",
        ));
    }
    Ok(())
}

fn parse_object(input: &str) -> Result<Value, serde_json::Error> {
    struct UniqueMembers;
    impl<'de> serde::de::Visitor<'de> for UniqueMembers {
        type Value = Value;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object with unique members")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
            let mut object = serde_json::Map::new();
            while let Some(name) = access.next_key::<String>()? {
                if object.contains_key(&name) {
                    return Err(serde::de::Error::custom("duplicate object member"));
                }
                object.insert(name, access.next_value::<Value>()?);
            }
            Ok(Value::Object(object))
        }
    }
    let mut parser = serde_json::Deserializer::from_str(input);
    let object = serde::Deserializer::deserialize_map(&mut parser, UniqueMembers)?;
    parser.end()?;
    Ok(object)
}

fn credential_object_hint(object: &str) -> bool {
    let bytes = object.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'"' {
            at += 1;
            continue;
        }
        let Ok(end) = crate::context::quoted_end(object, at, b'"', false) else {
            break;
        };
        let key = serde_json::from_str::<String>(&object[at..=end]).ok();
        let mut delimiter = end + 1;
        while delimiter < bytes.len() && bytes[delimiter].is_ascii_whitespace() {
            delimiter += 1;
        }
        if delimiter < bytes.len() && bytes[delimiter] == b':' {
            match key.as_deref() {
                Some("kty" | "auths") => return true,
                Some("kind") => {
                    let mut value = delimiter + 1;
                    while value < bytes.len() && bytes[value].is_ascii_whitespace() {
                        value += 1;
                    }
                    if value < bytes.len() && bytes[value] == b'"' {
                        if let Ok(end) = crate::context::quoted_end(object, value, b'"', false) {
                            if serde_json::from_str::<String>(&object[value..=end])
                                .ok()
                                .as_deref()
                                == Some("Secret")
                            {
                                return true;
                            }
                        } else if object[value..].starts_with("\"Secret") {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        at = end + 1;
    }
    false
}

fn private_object(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.get("kind").and_then(Value::as_str) == Some("Secret")
        && (object.contains_key("data") || object.contains_key("stringData"))
    {
        return true;
    }
    if object.contains_key("auths") {
        return true;
    }
    object.contains_key("kty")
        && ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|name| object.contains_key(*name))
}

pub(super) fn kubernetes_yaml(input: &str, spans: &mut Vec<Span>) -> Result<(), SafeError> {
    let kind =
        pattern!(r#"(?m)^[ \t]*["']?kind["']?[ \t]*:[ \t]*["']?Secret["']?[ \t]*(?:#.*)?\r?$"#)?;
    let data = pattern!(r#"(?m)^[ \t]*["']?(?:data|stringData)["']?[ \t]*:[ \t]*"#)?;
    let separators = pattern!(r"(?m)^---[ \t]*(?:#.*)?\r?$")?;
    let mut start = 0;
    for end in separators
        .find_iter(input)
        .map(|marker| marker.start())
        .chain(std::iter::once(input.len()))
    {
        let document = &input[start..end];
        if kind.is_match(document) && data.is_match(document) {
            if document.len() > STRUCTURE_LIMIT {
                return Err(SafeError::new(
                    "credential container exceeds parsing limit. Split input and retry.",
                ));
            }
            spans.push(start..end);
        }
        start = end;
    }
    Ok(())
}
