use crate::{
    error::SafeError,
    evidence::{Evidence, Finding},
};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct Inventory {
    version: u32,
    body_pattern: String,
    boundary: String,
    rules: Vec<PrefixRule>,
    aws: PatternRule,
    patterns: Vec<PatternRule>,
}

#[derive(Deserialize)]
struct PrefixRule {
    id: String,
    label: Evidence,
    prefixes: Vec<String>,
}

#[derive(Deserialize)]
struct PatternRule {
    id: String,
    label: Evidence,
    pattern: String,
    boundary_pattern: String,
}

struct Detectors {
    prefix_matcher: Regex,
    patterns: Vec<(Regex, Evidence)>,
    prefixes: BTreeMap<String, Evidence>,
    ordered_prefixes: Vec<String>,
}

fn compile(pattern: &str, boundary: &str) -> Result<Regex, ()> {
    let bounded = [boundary, "(", pattern, ")"].concat();
    RegexBuilder::new(&bounded)
        .size_limit(1_048_576)
        .dfa_size_limit(1_048_576)
        .build()
        .map_err(|_| ())
}

fn initialize(source: &str) -> Result<Detectors, ()> {
    let inventory: Inventory = serde_json::from_str(source).map_err(|_| ())?;
    if inventory.version != 1 || inventory.rules.is_empty() {
        return Err(());
    }
    let mut prefixes = BTreeMap::new();
    for rule in inventory.rules {
        if rule.prefixes.is_empty() || rule.label.provider_rule_id() != Some(rule.id.as_str()) {
            return Err(());
        }
        for prefix in rule.prefixes {
            if prefix.is_empty()
                || !prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                || prefixes.insert(prefix, rule.label).is_some()
            {
                return Err(());
            }
        }
    }
    let mut ordered_prefixes: Vec<_> = prefixes.keys().cloned().collect();
    ordered_prefixes.sort_by_key(|prefix| std::cmp::Reverse(prefix.len()));
    let alternatives: Vec<_> = ordered_prefixes
        .iter()
        .map(|prefix| regex::escape(prefix))
        .collect();
    let pattern = format!("(?:{}){}", alternatives.join("|"), inventory.body_pattern);
    let prefix_matcher = compile(&pattern, &inventory.boundary)?;
    let mut patterns = Vec::new();
    for rule in std::iter::once(inventory.aws).chain(inventory.patterns) {
        if rule.label.provider_rule_id() != Some(rule.id.as_str()) {
            return Err(());
        }
        patterns.push((compile(&rule.pattern, &rule.boundary_pattern)?, rule.label));
    }
    Ok(Detectors {
        prefix_matcher,
        patterns,
        prefixes,
        ordered_prefixes,
    })
}

fn initialization_error() -> SafeError {
    SafeError::new(
        "detector initialization failed. Reinstall the tool and retry with synthetic input.",
    )
}

pub(crate) fn detect(input: &str) -> Result<Vec<Finding>, SafeError> {
    static DETECTORS: OnceLock<Result<Detectors, ()>> = OnceLock::new();
    let detectors = DETECTORS
        .get_or_init(|| initialize(include_str!("../rules/providers.json")))
        .as_ref()
        .map_err(|_| initialization_error())?;
    let mut findings = Vec::new();
    // Boundary checks precede open-ended tails, keeping rejected hints linear.
    for capture in detectors.prefix_matcher.captures_iter(input) {
        if let Some(found) = capture.get(1) {
            // A bare specific marker must not fall back to a generic sk- match.
            if detectors.prefixes.contains_key(found.as_str()) {
                continue;
            }
            let label = detectors
                .ordered_prefixes
                .iter()
                .find(|prefix| found.as_str().starts_with(prefix.as_str()))
                .and_then(|prefix| detectors.prefixes.get(prefix))
                .copied()
                .ok_or_else(initialization_error)?;
            findings.push(Finding {
                span: found.start()..found.end(),
                label,
            });
        }
    }
    for (matcher, label) in &detectors.patterns {
        for capture in matcher.captures_iter(input) {
            if let Some(found) = capture.get(1) {
                findings.push(Finding {
                    span: found.start()..found.end(),
                    label: *label,
                });
            }
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_initialization_is_an_opaque_operational_error() {
        let mut fixture: serde_json::Value =
            serde_json::from_str(include_str!("../rules/providers.json"))
                .unwrap_or_else(|_| panic!("synthetic registry setup failed"));
        fixture["body_pattern"] = "[".into();
        assert!(initialize(&fixture.to_string()).is_err());
        fixture["body_pattern"] = "[A-Za-z0-9]+".into();
        fixture["rules"][0]["prefixes"][0] = "".into();
        assert!(initialize(&fixture.to_string()).is_err());
    }

    #[test]
    fn missing_unknown_or_misassigned_labels_fail_initialization() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../rules/providers.json"))
                .unwrap_or_else(|_| panic!("synthetic registry setup failed"));
        for group in ["rules", "patterns", "aws"] {
            for replacement in [
                None,
                Some("SYNTHETIC_LABEL_CANARY"),
                Some("auth-header"),
                Some("npm-token-format"),
            ] {
                let mut changed = fixture.clone();
                let rule = if group == "aws" {
                    &mut changed[group]
                } else {
                    &mut changed[group][0]
                };
                if let Some(label) = replacement {
                    rule["label"] = label.into();
                } else if let Some(rule) = rule.as_object_mut() {
                    rule.remove("label");
                }
                assert!(initialize(&changed.to_string()).is_err());
            }
        }
        assert!(
            !format!("{:?} {}", initialization_error(), initialization_error())
                .contains("SYNTHETIC_LABEL_CANARY")
        );
    }
}
