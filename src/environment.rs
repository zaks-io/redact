use crate::{error::SafeError, fingerprint};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Raw values have deliberately opaque formatting, including when nested.
pub struct RawVariables(BTreeMap<String, String>);

impl fmt::Debug for RawVariables {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawVariables([opaque])")
    }
}

impl RawVariables {
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(pairs.into_iter().collect())
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
    pub fn contains_key(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    Environment,
    File { path: String },
}

impl Source {
    fn label(&self) -> String {
        match self {
            Self::Environment => "env".to_owned(),
            Self::File { path } => format!("file:{path}"),
        }
    }
}

#[derive(Debug)]
pub struct Snapshot {
    pub source: Source,
    pub values: RawVariables,
}

#[derive(Debug, Default)]
pub struct Options {
    pub include_environment: bool,
    pub files: Vec<String>,
    pub allow: BTreeSet<String>,
    pub redact: BTreeSet<String>,
    pub names: BTreeSet<String>,
    pub exists: bool,
    pub json: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Missing,
    Empty,
    Redacted,
    Visible,
}

/// Only policy-approved values cross this serialization boundary.
#[derive(Serialize)]
pub struct SafeRecord {
    pub source: Source,
    pub name: String,
    pub state: State,
    pub value: Option<String>,
    pub fingerprint: Option<String>,
}

impl fmt::Debug for SafeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeRecord")
            .field("source", &self.source)
            .field("name", &self.name)
            .field("state", &self.state)
            .field("value", &"[opaque]")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

pub fn decision(
    name: &str,
    value: Option<&str>,
    allow: &BTreeSet<String>,
    redact: &BTreeSet<String>,
) -> State {
    match value {
        None => State::Missing,
        Some("") => State::Empty,
        Some(_) if redact.contains(name) => State::Redacted,
        Some(_) if allow.contains(name) => State::Visible,
        Some(value) if builtin_allowed(name, value) => State::Visible,
        Some(_) => State::Redacted,
    }
}

fn builtin_allowed(name: &str, value: &str) -> bool {
    match name {
        "NODE_ENV" => matches!(value, "development" | "test" | "production"),
        "RUST_BACKTRACE" | "RUST_LIB_BACKTRACE" => matches!(value, "0" | "1" | "full"),
        "CI" => matches!(value, "true" | "false" | "0" | "1"),
        "NO_COLOR" => value == "1",
        "FORCE_COLOR" => matches!(value, "0" | "1" | "2" | "3"),
        "CLICOLOR" | "CLICOLOR_FORCE" => matches!(value, "0" | "1"),
        _ => false,
    }
}

pub fn sanitize(snapshots: &[Snapshot], options: &Options) -> Vec<SafeRecord> {
    let mut records = Vec::new();
    for snapshot in snapshots {
        let names: Vec<&str> = if options.names.is_empty() {
            snapshot.values.iter().map(|(name, _)| name).collect()
        } else {
            options.names.iter().map(String::as_str).collect()
        };
        for name in names {
            let raw = snapshot.values.get(name);
            let state = decision(name, raw, &options.allow, &options.redact);
            records.push(SafeRecord {
                source: snapshot.source.clone(),
                name: name.to_owned(),
                state,
                value: if matches!(state, State::Visible | State::Empty) {
                    raw.map(str::to_owned)
                } else {
                    None
                },
                fingerprint: if state == State::Redacted {
                    raw.map(fingerprint)
                } else {
                    None
                },
            });
        }
    }
    records
}

pub fn render_text(records: &[SafeRecord]) -> Result<String, SafeError> {
    let mut output = String::new();
    for record in records {
        let source = encode(&record.source.label())?;
        let name = encode(&record.name)?;
        let value = match record.state {
            State::Missing => "[UNSET]".to_owned(),
            State::Empty => "[EMPTY]".to_owned(),
            State::Visible => encode(
                record
                    .value
                    .as_deref()
                    .ok_or_else(|| SafeError::new("invalid approved output record."))?,
            )?,
            State::Redacted => format!(
                "[REDACTED sha256={}]",
                record
                    .fingerprint
                    .as_deref()
                    .ok_or_else(|| SafeError::new("invalid approved output record."))?
            ),
        };
        output.push_str(&format!("{source}\t{name}\t{value}\n"));
    }
    Ok(output)
}

pub fn render_json(records: &[SafeRecord]) -> Result<String, SafeError> {
    #[derive(Serialize)]
    struct Listing<'a> {
        schema_version: u8,
        records: &'a [SafeRecord],
    }
    let mut output = encode(&Listing {
        schema_version: 1,
        records,
    })?;
    output.push('\n');
    Ok(output)
}

fn encode(value: &(impl Serialize + ?Sized)) -> Result<String, SafeError> {
    serde_json::to_string(value)
        .map_err(|_| SafeError::new("output encoding failed. Retry with supported UTF-8 input."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn allowlist_is_narrow_and_redaction_wins() {
        for (name, values) in [
            ("NODE_ENV", vec!["development", "test", "production"]),
            ("RUST_BACKTRACE", vec!["0", "1", "full"]),
            ("RUST_LIB_BACKTRACE", vec!["0", "1", "full"]),
            ("CI", vec!["true", "false", "0", "1"]),
            ("NO_COLOR", vec!["1"]),
            ("FORCE_COLOR", vec!["0", "1", "2", "3"]),
            ("CLICOLOR", vec!["0", "1"]),
            ("CLICOLOR_FORCE", vec!["0", "1"]),
        ] {
            for value in values {
                assert_eq!(
                    decision(name, Some(value), &BTreeSet::new(), &BTreeSet::new()),
                    State::Visible
                );
            }
            assert_eq!(
                decision(
                    name,
                    Some("synthetic-secret-canary"),
                    &BTreeSet::new(),
                    &BTreeSet::new()
                ),
                State::Redacted
            );
            assert_eq!(
                decision(
                    &name.to_lowercase(),
                    Some("1"),
                    &BTreeSet::new(),
                    &BTreeSet::new()
                ),
                State::Redacted
            );
        }
        let flag = BTreeSet::from(["TOKEN".to_owned()]);
        assert_eq!(
            decision("TOKEN", Some("synthetic"), &flag, &flag),
            State::Redacted
        );
        assert_eq!(decision("TOKEN", Some(""), &flag, &flag), State::Empty);
        assert_eq!(decision("TOKEN", None, &flag, &flag), State::Missing);
        assert_eq!(
            decision("TOKEN_SUFFIX", Some("synthetic"), &flag, &BTreeSet::new()),
            State::Redacted
        );
    }

    #[test]
    fn nested_raw_formatting_is_opaque() {
        let snapshot = Snapshot {
            source: Source::Environment,
            values: RawVariables::from_pairs([(
                "TOKEN".to_owned(),
                "synthetic-secret-canary".to_owned(),
            )]),
        };
        assert!(!format!("{snapshot:?}").contains("synthetic-secret-canary"));
        let records = sanitize(&[snapshot], &Options::default());
        assert!(!format!("{records:?}").contains("synthetic-secret-canary"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        #[test]
        fn hidden_values_only_change_fingerprints(value in any::<String>()) {
            let snapshots = [Snapshot { source: Source::Environment, values: RawVariables::from_pairs([("TOKEN".to_owned(), value.clone())]) }];
            let records = sanitize(&snapshots, &Options::default());
            let json: serde_json::Value = serde_json::from_str(&render_json(&records).unwrap()).unwrap();
            if value.is_empty() {
                prop_assert_eq!(json["records"][0]["state"].as_str(), Some("empty"));
            } else {
                prop_assert_eq!(json["records"][0]["value"].clone(), serde_json::Value::Null);
                let expected_fingerprint = fingerprint(&value);
                prop_assert_eq!(records[0].fingerprint.as_deref(), Some(expected_fingerprint.as_str()));
                prop_assert_eq!(render_text(&records).unwrap(), format!("\"env\"\t\"TOKEN\"\t[REDACTED sha256={}]\n", fingerprint(&value)));
            }
        }
    }
}
