use crate::{Span, error::SafeError};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::BTreeSet;
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
    prefixes: Vec<String>,
}

#[derive(Deserialize)]
struct PatternRule {
    pattern: String,
    boundary_pattern: String,
}

struct Detectors {
    matchers: Vec<Regex>,
    prefixes: BTreeSet<String>,
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
    let mut prefixes = BTreeSet::new();
    for rule in inventory.rules {
        if rule.prefixes.is_empty() {
            return Err(());
        }
        for prefix in rule.prefixes {
            if prefix.is_empty()
                || !prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                || !prefixes.insert(prefix)
            {
                return Err(());
            }
        }
    }
    let mut ordered: Vec<_> = prefixes.iter().collect();
    ordered.sort_by_key(|prefix| std::cmp::Reverse(prefix.len()));
    let alternatives: Vec<_> = ordered.iter().map(|prefix| regex::escape(prefix)).collect();
    let pattern = format!("(?:{}){}", alternatives.join("|"), inventory.body_pattern);
    let mut matchers = vec![compile(&pattern, &inventory.boundary)?];
    for rule in std::iter::once(inventory.aws).chain(inventory.patterns) {
        matchers.push(compile(&rule.pattern, &rule.boundary_pattern)?);
    }
    Ok(Detectors { matchers, prefixes })
}

pub fn detect(input: &str) -> Result<Vec<Span>, SafeError> {
    static DETECTORS: OnceLock<Result<Detectors, ()>> = OnceLock::new();
    let detectors = DETECTORS
        .get_or_init(|| initialize(include_str!("../rules/providers.json")))
        .as_ref()
        .map_err(|_| {
            SafeError::new(
                "detector initialization failed. Reinstall the tool and retry with synthetic input.",
            )
        })?;
    let mut spans = Vec::new();
    for matcher in &detectors.matchers {
        // Boundary checks precede open-ended tails, keeping rejected hints linear.
        for capture in matcher.captures_iter(input) {
            if let Some(found) = capture.get(1) {
                // A bare specific marker must not fall back to a generic sk- match.
                if detectors.prefixes.contains(found.as_str()) {
                    continue;
                }
                spans.push(found.start()..found.end());
            }
        }
    }
    Ok(spans)
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
}
