use crate::hash;
use redact::rstr::{detect, filter};

const PREFIXES: &[&str] = &[
    "ghp_",
    "github_pat_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "gloas-",
    "gldt-",
    "glrt-",
    "glrtr-",
    "glcbt-",
    "glptt-",
    "glft-",
    "glimt-",
    "glagent-",
    "glwt-",
    "glsoat-",
    "glffct-",
    "npm_",
    "pypi-",
    "hf_",
    "sk-proj-",
    "sk-admin-",
    "sk-ant-admin",
    "sk-ant-api03-",
    "sk-",
    "sk_test_",
    "sk_live_",
    "sk_org_",
    "rk_test_",
    "rk_live_",
    "whsec_",
    "xoxb-",
    "xoxp-",
    "xwfp-",
    "xapp-",
    "xoxe.xapp-",
    "xoxe.xoxb-",
    "xoxe.xoxp-",
    "xoxe-",
    "hvs.",
    "hvb.",
    "hvr.",
    "ops_",
    "vcp_",
    "lin_api_",
    "lin_oauth_",
    "ntn_",
    "secret_",
    "dop_v1_",
    "doo_v1_",
    "dor_v1_",
    "pul-",
    "glc_",
    "NRAK",
    "cfk_",
    "cfut_",
    "cfat_",
    "sb_secret_",
];

pub fn generated_credentials(data: &[u8]) {
    let suffix: String = data
        .iter()
        .take(256)
        .map(|b| char::from(b'A' + b % 26))
        .collect();
    let prefix = PREFIXES[data.first().copied().unwrap_or_default() as usize % PREFIXES.len()];
    let secret = format!("{prefix}SYNTHETIC_FUZZ_CANARY_{suffix}");
    let before = "status=failed [";
    let after = "] retry=2\n";
    let input = format!("{before}{secret}{after}");
    let spans = detect(&input);
    assert!(spans.is_ok(), "supported provider shape rejected");
    if let Ok(spans) = spans {
        let expected: Vec<_> = std::iter::once(before.len()..before.len() + secret.len()).collect();
        assert!(
            spans == expected,
            "provider original-byte span oracle failed"
        );
    }
    let expected = format!(
        "{before}[REDACTED sha256={}]{after}",
        hash(secret.as_bytes())
    );
    let output = filter(input.as_bytes());
    assert!(output.is_ok(), "provider filter failed");
    if let Ok(output) = output {
        assert!(
            output == expected,
            "complete provider removal oracle failed"
        );
    }
    let secret = format!("SYNTHETIC_FUZZ_CANARY_mutated_{suffix}");
    let fields = [
        "GEMINI_API_KEY",
        "AccountKey",
        "privateKeyData",
        "_authToken",
        "AWS_SESSION_TOKEN",
        "client_secret",
        "refresh_token",
        "apiToken",
        "dbPassword",
        "spring.datasource.password",
        "sslpassword",
    ];
    let field = fields[data.last().copied().unwrap_or_default() as usize % fields.len()];
    let input = format!("{{\"{field}\":\"{secret}\",\"status\":\"failed\"}}");
    let expected = format!(
        "{{\"{field}\":\"[REDACTED sha256={}]\",\"status\":\"failed\"}}",
        hash(secret.as_bytes())
    );
    let output = filter(input.as_bytes());
    assert!(output.is_ok(), "contextual format mutation rejected");
    if let Ok(output) = output {
        assert!(
            output == expected,
            "contextual format mutation disclosed data"
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn generated_prefix_set_covers_the_active_registry() {
        let registry: serde_json::Value =
            serde_json::from_str(include_str!("../../rules/providers.json"))
                .unwrap_or_else(|_| panic!("synthetic provider registry setup failed"));
        let expected: std::collections::BTreeSet<_> = registry["rules"]
            .as_array()
            .unwrap_or_else(|| panic!("synthetic prefix registry missing"))
            .iter()
            .flat_map(|rule| {
                rule["prefixes"]
                    .as_array()
                    .unwrap_or_else(|| panic!("synthetic prefix list missing"))
            })
            .map(|prefix| {
                prefix
                    .as_str()
                    .unwrap_or_else(|| panic!("synthetic prefix invalid"))
            })
            .collect();
        assert_eq!(
            super::PREFIXES
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
    }

    #[test]
    fn every_supported_prefix_has_a_generated_whole_span_oracle() {
        for index in 0..super::PREFIXES.len() {
            super::generated_credentials(&[index as u8]);
        }
    }
}
