use crate::{Span, error::SafeError};
use regex::Regex;
use std::sync::OnceLock;

// Prefix evidence is pinned to the primary-source inventory checked 2026-10-04.
// Tails are deliberately open-ended so format evolution cannot leak a suffix.
const PREFIX_PATTERN: &str = concat!(
    r"(?:github_pat_|gh[pousr]_|glpat-|gloas-|gldt-|glrtr?-|glcbt-|glptt-|glft-|glimt-|glagent-|glwt-|glsoat-|glffct-|",
    r"npm_|pypi-|hf_|sk-proj-|sk-admin-|sk-ant-admin|sk-ant-api03-|sk-|",
    r"sk_test_|sk_live_|sk_org_|rk_test_|rk_live_|whsec_|",
    r"xoxe\.xapp-|xoxe\.xoxb-|xoxe\.xoxp-|xoxe-|xoxb-|xoxp-|xwfp-|xapp-|",
    r"hvs\.|hvb\.|hvr\.|ops_|vcp_|lin_api_|lin_oauth_|ntn_|secret_|",
    r"dop_v1_|doo_v1_|dor_v1_|pul-|glc_|NRAK|cfk_|cfut_|cfat_|sb_secret_)",
    r"[A-Za-z0-9_./+~=-]+"
);

const TOKEN_BOUNDARY: &str = r"(?:^|[^\p{Alphabetic}\p{Number}_.+-])";

fn compiled(
    slot: &'static OnceLock<Result<Regex, ()>>,
    pattern: &str,
    boundary: &str,
) -> Result<&'static Regex, SafeError> {
    slot.get_or_init(|| {
        let bounded = [boundary, "(", pattern, ")"].concat();
        Regex::new(&bounded).map_err(|_| ())
    })
    .as_ref()
    .map_err(|_| {
        SafeError::new(
            "detector initialization failed. Reinstall the tool and retry with synthetic input.",
        )
    })
}

pub fn detect(input: &str) -> Result<Vec<Span>, SafeError> {
    static PREFIXES: OnceLock<Result<Regex, ()>> = OnceLock::new();
    static SENDGRID: OnceLock<Result<Regex, ()>> = OnceLock::new();
    static AWS: OnceLock<Result<Regex, ()>> = OnceLock::new();
    static VERIFIERS: OnceLock<Result<Regex, ()>> = OnceLock::new();
    let rules = [
        compiled(&PREFIXES, PREFIX_PATTERN, TOKEN_BOUNDARY)?,
        compiled(
            &SENDGRID,
            r"SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_./+~=-]+",
            TOKEN_BOUNDARY,
        )?,
        compiled(
            &AWS,
            r"(?:AKIA|ASIA)[A-Za-z0-9]{16}[A-Za-z0-9_./+~=-]*",
            TOKEN_BOUNDARY,
        )?,
        compiled(
            &VERIFIERS,
            // A verifier dollar marker establishes its own boundary, including adjacency.
            r"(?:\$2b\$|\$argon2(?:id|i|d)\$)[A-Za-z0-9$=,./+_-]+",
            "",
        )?,
    ];
    let mut spans = Vec::new();
    for rule in rules {
        // Reject boundary-invalid hints before scanning an open-ended body.
        for capture in rule.captures_iter(input) {
            if let Some(found) = capture.get(1) {
                spans.push(Span {
                    start: found.start(),
                    end: found.end(),
                });
            }
        }
    }
    Ok(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_initialization_is_a_safe_operational_error() {
        static INVALID: OnceLock<Result<Regex, ()>> = OnceLock::new();
        let error = compiled(&INVALID, "[", TOKEN_BOUNDARY).unwrap_err();
        assert!(error.to_string().contains("detector initialization failed"));
        assert!(!format!("{error} {error:?}").contains("regex parse"));
    }
}
