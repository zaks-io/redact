use crate::{CANARY, hash};
use redact::rprintenv::policy::{Policy, Record, Source, State, disclose};
use redact::rprintenv::render::render;
use redact::secret::SecretString;
use serde_json::{Value, json};

pub struct Case<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
    pub path: &'a str,
    pub flags: u8,
}

pub fn decode(data: &[u8]) -> Option<Case<'_>> {
    let (&flags, rest) = data.split_first()?;
    let mut parts = rest.splitn(3, |byte| *byte == 0);
    let name = std::str::from_utf8(parts.next()?).ok()?;
    let value = std::str::from_utf8(parts.next().unwrap_or_default()).ok()?;
    let path = std::str::from_utf8(parts.next().unwrap_or_default()).ok()?;
    Some(Case {
        name,
        value: (flags & 4 == 0).then_some(value),
        path,
        flags,
    })
}

pub fn options(case: &Case<'_>) -> Policy {
    let mut policy = Policy::default();
    if case.flags & 1 != 0 {
        policy.allow.insert(case.name.to_owned());
    }
    if case.flags & 2 != 0 {
        policy.redact.insert(case.name.to_owned());
    }
    if case.flags & 8 != 0 {
        policy.allow.insert(format!("{}suffix", case.name));
    }
    if case.flags & 16 != 0 {
        policy.redact.insert(format!("{}suffix", case.name));
    }
    policy
}

fn allowed(name: &str, value: &str) -> bool {
    let table: &[(&str, &[&str])] = &[
        ("NODE_ENV", &["development", "test", "production"]),
        ("RUST_BACKTRACE", &["0", "1", "full"]),
        ("RUST_LIB_BACKTRACE", &["0", "1", "full"]),
        ("CI", &["true", "false", "0", "1"]),
        ("NO_COLOR", &["1"]),
        ("FORCE_COLOR", &["0", "1", "2", "3"]),
        ("CLICOLOR", &["0", "1"]),
        ("CLICOLOR_FORCE", &["0", "1"]),
    ];
    table
        .iter()
        .any(|(key, values)| name == *key && values.contains(&value))
}

pub fn expected(name: &str, value: Option<&str>, policy: &Policy) -> (&'static str, Value, Value) {
    match value {
        None => ("missing", Value::Null, Value::Null),
        Some("") => ("empty", json!(""), Value::Null),
        Some(value)
            if !policy.redact.contains(name)
                && (policy.allow.contains(name) || allowed(name, value)) =>
        {
            ("visible", json!(value), Value::Null)
        }
        Some(value) => ("redacted", Value::Null, json!(hash(value.as_bytes()))),
    }
}

pub fn check_record(record: &Record, value: Option<&str>, policy: &Policy) {
    let (state, expected_value, expected_hash) = expected(&record.name, value, policy);
    let valid = match &record.state {
        State::Missing => state == "missing",
        State::Empty => state == "empty",
        State::Visible(value) => state == "visible" && expected_value == value.as_str(),
        State::Redacted(hash) => state == "redacted" && expected_hash == hash.as_str(),
    };
    assert!(valid, "disclosure policy oracle failed");
}

pub fn outputs_match(record: &Record, value: Option<&str>, policy: &Policy) -> bool {
    let (state, value, fingerprint) = expected(&record.name, value, policy);
    let source = match &record.source {
        Source::Environment => json!({"kind": "environment"}),
        Source::File { path } => json!({"kind": "file", "path": path}),
    };
    let expected_json = json!({"schema_version": 1, "records": [{
        "source": source, "name": record.name, "state": state,
        "value": value, "fingerprint": fingerprint,
    }]});
    let mut actual_json = Vec::new();
    if render(std::slice::from_ref(record), true, &mut actual_json).is_err() {
        return false;
    }
    if serde_json::from_slice::<Value>(&actual_json).ok() != Some(expected_json) {
        return false;
    }
    let Ok(source) = serde_json::to_string(&record.source.label()) else {
        return false;
    };
    let Ok(name) = serde_json::to_string(&record.name) else {
        return false;
    };
    let field = match state {
        "missing" => "[UNSET]".to_owned(),
        "empty" => "[EMPTY]".to_owned(),
        "redacted" => format!(
            "[REDACTED sha256={}]",
            fingerprint.as_str().unwrap_or_default()
        ),
        _ => value.to_string(),
    };
    let expected_text = format!("{source}\t{name}\t{field}\n");
    let mut actual_text = Vec::new();
    render(std::slice::from_ref(record), false, &mut actual_text).is_ok()
        && actual_text == expected_text.as_bytes()
}

pub fn exercise(case: &Case<'_>, rendering: bool) {
    let policy = options(case);
    let secret = case.value.map(|value| SecretString::new(value.to_owned()));
    let source = if case.flags & 32 == 0 {
        Source::Environment
    } else {
        Source::File {
            path: case.path.to_owned(),
        }
    };
    let record = disclose(source, case.name.to_owned(), secret.as_ref(), &policy);
    check_record(&record, case.value, &policy);
    if rendering {
        assert!(
            outputs_match(&record, case.value, &policy),
            "rendering oracle failed"
        );
    }
    let first = SecretString::new(CANARY.to_owned());
    let second = SecretString::new(format!("{CANARY}-changed"));
    let default_policy = Policy::default();
    for value in [&first, &second] {
        let hidden = disclose(
            Source::Environment,
            "SYNTHETIC_CANARY".to_owned(),
            Some(value),
            &default_policy,
        );
        check_record(&hidden, Some(value.as_str()), &default_policy);
        assert!(
            outputs_match(&hidden, Some(value.as_str()), &default_policy),
            "hidden mutation oracle failed"
        );
        let changed_source = disclose(
            Source::File {
                path: "synthetic.env".to_owned(),
            },
            "OTHER_SYNTHETIC_NAME".to_owned(),
            Some(value),
            &default_policy,
        );
        match (&hidden.state, &changed_source.state) {
            (State::Redacted(a), State::Redacted(b)) => {
                assert!(a == b, "source changed fingerprint")
            }
            _ => panic!("default hiding failed"),
        }
        assert!(
            !format!("{hidden:?}").contains(CANARY),
            "nested debug exposed value"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_detects_deliberate_disclosure_defect() {
        let policy = Policy::default();
        let value = SecretString::new(CANARY.to_owned());
        let mut record = disclose(
            Source::Environment,
            "SECRET".to_owned(),
            Some(&value),
            &policy,
        );
        assert!(
            outputs_match(&record, Some(CANARY), &policy),
            "valid record rejected"
        );
        record.state = State::Visible(SecretString::new(CANARY.to_owned()));
        assert!(
            !outputs_match(&record, Some(CANARY), &policy),
            "oracle missed deliberately exposed value"
        );
    }
}
