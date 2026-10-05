use proptest::prelude::*;
use redact::{filter, fingerprint};

// Each prefix is public evidence from the inventory, never a live token fixture.
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

#[test]
fn all_prefix_variants_protect_complete_evolving_bodies() {
    for prefix in PREFIXES {
        for body in [
            "SYNTHETIC",
            "SYNTHETIC-extended_suffix.with+padding/==",
            &"SYNTHETIC".repeat(128),
        ] {
            let token = format!("{prefix}{body}");
            let input = format!("status=401 [{token}], host=example.test\r\n");
            let expected = format!(
                "status=401 [[REDACTED sha256={}]], host=example.test\r\n",
                fingerprint(&token)
            );
            assert_eq!(
                filter(input.as_bytes()).unwrap(),
                expected,
                "prefix {prefix}"
            );
        }
    }
}

#[test]
fn near_prefixes_and_public_material_pass_unchanged() {
    for input in [
        "ordinary_ghp_SYNTHETIC",
        "ghp_",
        "sk",
        "pk_live_SYNTHETIC_PUBLIC",
        "pk_test_SYNTHETIC_PUBLIC",
        "sb_publishable_SYNTHETIC_PUBLIC",
        "apikey_SYNTHETIC_RESOURCE_ID",
        "AC00000000000000000000000000000000",
        "SK00000000000000000000000000000000",
        "550e8400-e29b-41d4-a716-446655440000",
        "signature=ordinary-public-metadata",
        "tokenizer=ordinary",
    ] {
        assert_eq!(filter(input.as_bytes()).unwrap(), input);
    }
}

#[test]
fn rejected_outer_hints_do_not_conceal_tokens_or_url_path_credentials() {
    let token = "ghp_SYNTHETIC_CREDENTIAL_CANARY_0123456789";
    for (before, after) in [
        ("devops_ref=", "\n"),
        ("GET /v1/hooks/", " HTTP/1.1\n"),
        ("ignoredops_bad=", ", status=401\n"),
    ] {
        let input = format!("{before}{token}{after}");
        assert_eq!(
            filter(input.as_bytes()).unwrap(),
            format!("{before}[REDACTED sha256={}]{after}", fingerprint(token))
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn prefix_mutations_preserve_whole_spans(index in 0usize..PREFIXES.len(), suffix in "[A-Za-z0-9_./+~=-]{1,512}") {
        let value = format!("{}SYNTHETIC_{suffix}", PREFIXES[index]);
        let input = format!("before {value} after\n");
        prop_assert_eq!(filter(input.as_bytes()).unwrap(), format!("before [REDACTED sha256={}] after\n", fingerprint(&value)));
    }
    #[test]
    fn unknown_and_malformed_provider_values_stay_hidden(value in "[^\"\\\\\n\r\x00]{1,256}") {
        let input = serde_json::json!({"GEMINI_API_KEY":value,"status":401}).to_string();
        let expected_value = serde_json::to_string(&value).unwrap();
        let raw_span = &expected_value[1..expected_value.len()-1];
        let expected = format!("{{\"GEMINI_API_KEY\":\"[REDACTED sha256={}]\",\"status\":401}}",fingerprint(raw_span));
        prop_assert_eq!(filter(input.as_bytes()).unwrap(), expected);
    }
}
