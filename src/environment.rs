use crate::{
    error::SafeError,
    rprintenv::{policy, render},
    secret::SecretString,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub use policy::Source;

/// Compatibility inputs use the same opaque secret type as the command.
pub struct RawVariables(BTreeMap<String, SecretString>);

impl fmt::Debug for RawVariables {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawVariables([opaque])")
    }
}

impl RawVariables {
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(name, value)| (name, SecretString::new(value)))
                .collect(),
        )
    }
    pub(crate) fn from_secrets(values: BTreeMap<String, SecretString>) -> Self {
        Self(values)
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(SecretString::as_str)
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

/// Compatibility records contain only values approved by the shared policy.
#[derive(Serialize)]
pub struct SafeRecord {
    pub source: Source,
    pub name: String,
    pub state: State,
    pub value: Option<String>,
    pub fingerprint: Option<String>,
}

impl fmt::Debug for SafeRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeRecord")
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
    let secret = value.map(|value| SecretString::new(value.to_owned()));
    let record = policy::disclose(
        Source::Environment,
        name.to_owned(),
        secret.as_ref(),
        &policy::Policy {
            allow: allow.clone(),
            redact: redact.clone(),
        },
    );
    state(&record.state)
}

fn state(state: &policy::State) -> State {
    match state {
        policy::State::Missing => State::Missing,
        policy::State::Empty => State::Empty,
        policy::State::Redacted(_) => State::Redacted,
        policy::State::Visible(_) => State::Visible,
    }
}

pub fn sanitize(snapshots: &[Snapshot], options: &Options) -> Vec<SafeRecord> {
    let policy = policy::Policy {
        allow: options.allow.clone(),
        redact: options.redact.clone(),
    };
    let mut records = Vec::new();
    for snapshot in snapshots {
        let names: Vec<&str> = if options.names.is_empty() {
            snapshot.values.iter().map(|(name, _)| name).collect()
        } else {
            options.names.iter().map(String::as_str).collect()
        };
        for name in names {
            let approved = policy::disclose(
                snapshot.source.clone(),
                name.to_owned(),
                snapshot.values.0.get(name),
                &policy,
            );
            let (value, fingerprint) = match &approved.state {
                policy::State::Visible(value) => (Some(value.as_str().to_owned()), None),
                policy::State::Redacted(hash) => (None, Some(hash.clone())),
                policy::State::Empty => (Some(String::new()), None),
                policy::State::Missing => (None, None),
            };
            records.push(SafeRecord {
                state: state(&approved.state),
                source: approved.source,
                name: approved.name,
                value,
                fingerprint,
            });
        }
    }
    records
}

pub fn render_text(records: &[SafeRecord]) -> Result<String, SafeError> {
    render_records(records, false)
}
pub fn render_json(records: &[SafeRecord]) -> Result<String, SafeError> {
    render_records(records, true)
}

fn render_records(records: &[SafeRecord], json: bool) -> Result<String, SafeError> {
    let approved = records
        .iter()
        .map(|record| {
            let state = match record.state {
                State::Missing => policy::State::Missing,
                State::Empty => policy::State::Empty,
                State::Visible => policy::State::Visible(SecretString::new(
                    record.value.as_ref().ok_or_else(invalid_record)?.clone(),
                )),
                State::Redacted => policy::State::Redacted(
                    record
                        .fingerprint
                        .as_ref()
                        .ok_or_else(invalid_record)?
                        .clone(),
                ),
            };
            Ok(policy::Record {
                source: record.source.clone(),
                name: record.name.clone(),
                state,
            })
        })
        .collect::<Result<Vec<_>, SafeError>>()?;
    let mut bytes = Vec::new();
    render::render(&approved, json, &mut bytes)?;
    String::from_utf8(bytes).map_err(|_| invalid_record())
}

fn invalid_record() -> SafeError {
    SafeError::new("invalid approved output record.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint;
    use crate::synthetic::*;
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
            let json: serde_json::Value = serde_json::from_str(&render_json(&records).must()).must();
            if value.is_empty() {
                prop_assert_eq!(json["records"][0]["state"].as_str(), Some("empty"));
            } else {
                prop_assert_eq!(json["records"][0]["value"].clone(), serde_json::Value::Null);
                let expected_fingerprint = fingerprint(&value);
                prop_assert_eq!(records[0].fingerprint.as_deref(), Some(expected_fingerprint.as_str()));
                prop_assert_eq!(render_text(&records).must(), format!("\"env\"\t\"TOKEN\"\t[REDACTED sha256={}]\n", fingerprint(&value)));
            }
        }
    }
}
