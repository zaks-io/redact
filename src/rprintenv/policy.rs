use crate::fingerprint::fingerprint;
use crate::secret::SecretString;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Source {
    Environment,
    File { path: String },
}

impl Source {
    pub fn label(&self) -> String {
        match self {
            Self::Environment => "env".to_owned(),
            Self::File { path } => format!("file:{path}"),
        }
    }
}

#[derive(Debug, Default)]
pub struct Policy {
    pub allow: BTreeSet<String>,
    pub redact: BTreeSet<String>,
}

#[derive(Debug)]
pub enum State {
    Visible(SecretString),
    Redacted(String),
    Empty,
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedactionReason {
    DefaultPolicy,
    ExplicitRedact,
}

#[derive(Debug)]
pub struct Record {
    pub source: Source,
    pub name: String,
    pub state: State,
    pub redaction_reason: Option<RedactionReason>,
}

pub fn disclose(
    source: Source,
    name: String,
    value: Option<&SecretString>,
    policy: &Policy,
) -> Record {
    let state = match value {
        None => State::Missing,
        Some(value) if value.as_str().is_empty() => State::Empty,
        Some(value) => {
            if !policy.redact.contains(&name)
                && (policy.allow.contains(&name) || built_in_allowed(&name, value.as_str()))
            {
                State::Visible(SecretString::new(value.as_str().to_owned()))
            } else {
                State::Redacted(fingerprint(value.as_str()))
            }
        }
    };
    let redaction_reason = match &state {
        State::Redacted(_) if policy.redact.contains(&name) => {
            Some(RedactionReason::ExplicitRedact)
        }
        State::Redacted(_) => Some(RedactionReason::DefaultPolicy),
        _ => None,
    };
    Record {
        source,
        name,
        state,
        redaction_reason,
    }
}

fn built_in_allowed(name: &str, value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn allowlist_checks_name_and_value() {
        let groups = [
            ("NODE_ENV", vec!["development", "test", "production"]),
            ("RUST_BACKTRACE", vec!["0", "1", "full"]),
            ("RUST_LIB_BACKTRACE", vec!["0", "1", "full"]),
            ("CI", vec!["true", "false", "0", "1"]),
            ("NO_COLOR", vec!["1"]),
            ("FORCE_COLOR", vec!["0", "1", "2", "3"]),
            ("CLICOLOR", vec!["0", "1"]),
            ("CLICOLOR_FORCE", vec!["0", "1"]),
        ];
        for (name, values) in groups {
            for value in values {
                assert!(built_in_allowed(name, value));
                let secret = SecretString::new(value.to_owned());
                let record = disclose(
                    Source::Environment,
                    name.to_owned(),
                    Some(&secret),
                    &Policy::default(),
                );
                assert!(matches!(record.state, State::Visible(_)));
            }
            assert!(!built_in_allowed(name, "synthetic-secret"));
            assert!(!built_in_allowed(&name.to_lowercase(), "1"));
            let secret = SecretString::new("synthetic-secret".to_owned());
            let record = disclose(
                Source::Environment,
                name.to_owned(),
                Some(&secret),
                &Policy::default(),
            );
            assert!(matches!(record.state, State::Redacted(_)));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x5eed),
            ..ProptestConfig::default()
        })]
        #[test]
        fn redact_wins_and_debug_is_opaque(value in ".{1,128}") {
            let policy = Policy {
                allow: BTreeSet::from(["KEY".to_owned()]),
                redact: BTreeSet::from(["KEY".to_owned()]),
            };
            let secret = SecretString::new(value.clone());
            let record = disclose(Source::Environment, "KEY".to_owned(), Some(&secret), &policy);
            match record.state {
                State::Redacted(hash) => prop_assert_eq!(hash, fingerprint(&value)),
                _ => prop_assert!(false, "redaction precedence failed"),
            }
        }

        #[test]
        fn independent_policy_and_rendering_oracle(
            value in ".{0,128}",
            present in any::<bool>(),
            allow in any::<bool>(),
            redact in any::<bool>(),
            builtin in any::<bool>(),
        ) {
            let name = if builtin { "NODE_ENV" } else { "UNKNOWN" };
            let policy = Policy {
                allow: if allow { BTreeSet::from([name.to_owned()]) } else { BTreeSet::new() },
                redact: if redact { BTreeSet::from([name.to_owned()]) } else { BTreeSet::new() },
            };
            let secret = SecretString::new(value.clone());
            let records = [disclose(Source::Environment, name.to_owned(), present.then_some(&secret), &policy)];
            let expected = if !present { "missing" }
                else if value.is_empty() { "empty" }
                else if !redact && (allow || (builtin && ["development", "test", "production"].contains(&value.as_str()))) { "visible" }
                else { "redacted" };
            let mut json_bytes = Vec::new();
            let mut text_bytes = Vec::new();
            prop_assert!(crate::rprintenv::render::render(&records, true, &mut json_bytes).is_ok());
            prop_assert!(crate::rprintenv::render::render(&records, false, &mut text_bytes).is_ok());
            let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).map_err(|_| TestCaseError::fail("JSON parse failed"))?;
            let record = &parsed["records"][0];
            prop_assert_eq!(record["state"].as_str(), Some(expected));
            let display = match expected {
                "missing" => {
                    prop_assert!(record["value"].is_null() && record["fingerprint"].is_null());
                    "[UNSET]".to_owned()
                }
                "empty" => {
                    prop_assert_eq!(record["value"].as_str(), Some(""));
                    prop_assert!(record["fingerprint"].is_null());
                    "[EMPTY]".to_owned()
                }
                "visible" => {
                    prop_assert_eq!(record["value"].as_str(), Some(value.as_str()));
                    prop_assert!(record["fingerprint"].is_null());
                    serde_json::to_string(&value).map_err(|_| TestCaseError::fail("encoding failed"))?
                }
                _ => {
                    prop_assert!(record["value"].is_null());
                    let hash = fingerprint(&value);
                    prop_assert_eq!(record["fingerprint"].as_str(), Some(hash.as_str()));
                    format!("[REDACTED sha256={hash}]")
                }
            };
            let expected_text = format!("\"env\"\t\"{name}\"\t{display}\n");
            prop_assert_eq!(text_bytes, expected_text.as_bytes());
        }

        #[test]
        fn hidden_value_output_contains_only_fingerprint(value in ".{1,128}") {
            let policy = Policy::default();
            let mut previous = None;
            for raw in [&value, &format!("{value}synthetic-mutation")] {
                let secret = SecretString::new(raw.clone());
                let records = [disclose(Source::Environment, "KEY".to_owned(), Some(&secret), &policy)];
                let mut bytes = Vec::new();
                prop_assert!(crate::rprintenv::render::render(&records, true, &mut bytes).is_ok());
                let mut parsed: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| TestCaseError::fail("JSON parse failed"))?;
                let hash = fingerprint(raw);
                prop_assert_eq!(parsed["records"][0]["fingerprint"].as_str(), Some(hash.as_str()));
                parsed["records"][0]["fingerprint"] = serde_json::Value::Null;
                if let Some(previous) = previous {
                    prop_assert_eq!(parsed.clone(), previous);
                }
                previous = Some(parsed);
            }
        }
    }
}
