#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redact::rprintenv::policy::{Policy, RedactionReason, Source, disclose};
use redact::rprintenv::render::render;
use redact::secret::SecretString;
use redact::{Evidence, filter, filter_with_evidence, fingerprint};
use std::collections::BTreeSet;
use std::error::Error;

#[test]
fn overlapping_matches_union_evidence_without_changing_markers() {
    let credential = "ghp_SYNTHETIC_EVIDENCE_CANARY";
    for (input, labels) in [
        (
            format!("Authorization: Bearer {credential}\n"),
            vec![Evidence::AuthHeader, Evidence::GithubTokenFormat],
        ),
        (
            format!("password=\"{credential}\" host=example.test\n"),
            vec![
                Evidence::SensitiveFieldOrQuotedCredential,
                Evidence::GithubTokenFormat,
            ],
        ),
    ] {
        let filtered = filter_with_evidence(input.as_bytes()).must();
        assert_eq!(filtered.output, filter(input.as_bytes()).must());
        assert_eq!(filtered.redactions.len(), 1);
        let redaction = &filtered.redactions[0];
        assert_eq!(redaction.fingerprint, fingerprint(credential));
        assert_eq!(redaction.line, 1);
        assert_eq!(redaction.labels, labels);
        assert!(
            filtered
                .output
                .contains(&format!("[REDACTED sha256={}]", redaction.fingerprint))
        );
    }
}

#[test]
fn provider_labels_follow_longest_prefix_without_inventing_attribution() {
    for (prefix, expected) in [
        ("sk-", Evidence::GenericSecretKeyFormat),
        ("sk-proj-", Evidence::OpenaiKeyFormat),
        ("sk-admin-", Evidence::OpenaiKeyFormat),
        ("sk-ant-api03-", Evidence::AnthropicKeyFormat),
        ("sk-ant-admin", Evidence::AnthropicKeyFormat),
        ("glpat-", Evidence::GitlabAccessTokenFormat),
        ("xoxe.xoxb-", Evidence::SlackRotationFormat),
        ("xoxe.xapp-", Evidence::SlackTokenFormat),
    ] {
        let credential = format!("{prefix}SYNTHETIC_EVIDENCE_CANARY");
        let filtered = filter_with_evidence(credential.as_bytes()).must();
        assert_eq!(filtered.redactions.len(), 1);
        assert_eq!(filtered.redactions[0].labels, vec![expected]);
        assert_eq!(filtered.redactions[0].fingerprint, fingerprint(&credential));
    }
    assert!(Evidence::GenericSecretKeyFormat.label().contains("unknown"));
    assert!(!Evidence::GenericSecretKeyFormat.label().contains("OpenAI"));
    let gitlab = Evidence::GitlabAccessTokenFormat.label();
    for unsupported_claim in ["personal", "project", "group", "valid", "active"] {
        assert!(!gitlab.contains(unsupported_claim));
    }
}

#[test]
fn structured_families_describe_the_matches_that_created_their_spans() {
    let jose = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#),
        URL_SAFE_NO_PAD.encode(br#"{"sub":"SYNTHETIC_EVIDENCE_CANARY"}"#),
        URL_SAFE_NO_PAD.encode(b"SYNTHETIC_SIGNATURE")
    );
    for (input, expected) in [
        (
            "postgres://user:SYNTHETIC_EVIDENCE_CANARY@example.test/db".to_owned(),
            Evidence::UrlCredentials,
        ),
        (
            "host=example.test dbname=test password=SYNTHETIC_EVIDENCE_CANARY".to_owned(),
            Evidence::ConnectionString,
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_EVIDENCE_CANARY\n-----END PRIVATE KEY-----"
                .to_owned(),
            Evidence::PrivateKey,
        ),
        (jose, Evidence::JoseFormat),
        (
            r#"{"auths":{"example.test":{"auth":"SYNTHETIC_EVIDENCE_CANARY"}}}"#.to_owned(),
            Evidence::CredentialContainer,
        ),
        (
            "apiVersion: v1\nkind: Secret\nstringData:\n  key: SYNTHETIC_EVIDENCE_CANARY\n"
                .to_owned(),
            Evidence::KubernetesSecret,
        ),
    ] {
        let filtered = filter_with_evidence(input.as_bytes()).must();
        assert_eq!(filtered.redactions.len(), 1);
        assert_eq!(filtered.redactions[0].labels, vec![expected]);
        assert!(!filtered.output.contains("SYNTHETIC_EVIDENCE_CANARY"));
    }
}

#[test]
fn multiline_unions_keep_exact_bytes_and_original_start_lines() {
    let container =
        "{\n\"auths\":{\"example.test\":{\"auth\":\"ghp_SYNTHETIC_EVIDENCE_CANARY\"}}\n}";
    let input = format!("ordinary\n{container}\nnext\nnpm_SYNTHETIC_SECOND\n");
    let filtered = filter_with_evidence(input.as_bytes()).must();
    assert_eq!(filtered.redactions.len(), 2);
    assert_eq!(filtered.redactions[0].line, 2);
    assert_eq!(filtered.redactions[0].fingerprint, fingerprint(container));
    assert_eq!(
        filtered.redactions[0].labels,
        vec![Evidence::CredentialContainer, Evidence::GithubTokenFormat]
    );
    assert_eq!(filtered.redactions[1].line, 6);
    assert_eq!(
        filtered.redactions[1].labels,
        vec![Evidence::NpmTokenFormat]
    );
}

#[test]
fn escaped_nested_matches_do_not_claim_unsupported_context() {
    let input = r#"{"message":"\u0067hp_SYNTHETIC_EVIDENCE_CANARY"}"#;
    let filtered = filter_with_evidence(input.as_bytes()).must();
    assert_eq!(filtered.redactions.len(), 1);
    assert_eq!(
        filtered.redactions[0].labels,
        vec![Evidence::SensitiveFieldOrQuotedCredential]
    );
    assert_eq!(
        filtered.redactions[0].fingerprint,
        fingerprint(r"\u0067hp_SYNTHETIC_EVIDENCE_CANARY")
    );
}

#[test]
fn evidence_debug_and_detector_failures_never_format_input() {
    let input = b"ordinary SYNTHETIC_UNDETECTED_CANARY\npassword=SYNTHETIC_EVIDENCE_CANARY\n";
    let nested = Some(vec![filter_with_evidence(input).must()]);
    let debug = format!("{nested:?}");
    assert!(!debug.contains("SYNTHETIC_UNDETECTED_CANARY"));
    assert!(!debug.contains("SYNTHETIC_EVIDENCE_CANARY"));
    assert!(debug.contains("[opaque]"));
    for input in [
        b"password=\"SYNTHETIC_EVIDENCE_CANARY".as_slice(),
        b"-----BEGIN PRIVATE KEY-----\nSYNTHETIC_EVIDENCE_CANARY".as_slice(),
        br#"{"auths":{"auth":"SYNTHETIC_EVIDENCE_CANARY"},}"#.as_slice(),
        b"SYNTHETIC_EVIDENCE_CANARY\xff".as_slice(),
    ] {
        let error = filter_with_evidence(input).must_err();
        assert!(
            !format!("{:?} {error}", Some(vec![error.clone()]))
                .contains("SYNTHETIC_EVIDENCE_CANARY")
        );
        assert!(error.source().is_none());
    }
}

#[test]
fn bundled_labels_are_a_closed_static_vocabulary() {
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../rules/providers.json")).must();
    let rules = inventory["rules"].as_array().must();
    let patterns = inventory["patterns"].as_array().must();
    for rule in rules.iter().chain(patterns).chain([&inventory["aws"]]) {
        let evidence: Evidence = serde_json::from_value(rule["label"].clone()).must();
        let label = evidence.label();
        assert!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        );
        assert!(!label.contains('[') && !label.contains(']'));
        assert!(!label.contains("SYNTHETIC"));
        assert!(!label.contains("valid credential") && !label.contains("active credential"));
    }
    for rejected in ["SYNTHETIC_CANARY", "github-token-format\npassword=canary"] {
        assert!(serde_json::from_value::<Evidence>(serde_json::json!(rejected)).is_err());
    }
}

#[test]
fn environment_reasons_follow_disclosure_policy_and_json_schema() {
    let value = SecretString::new("SYNTHETIC_EVIDENCE_CANARY".to_owned());
    let empty = SecretString::new(String::new());
    let ordinary = SecretString::new("production".to_owned());
    let explicit = Policy {
        allow: BTreeSet::from(["KEY".to_owned()]),
        redact: BTreeSet::from(["KEY".to_owned()]),
    };
    let mut records = vec![
        disclose(
            Source::Environment,
            "UNKNOWN".to_owned(),
            Some(&value),
            &Policy::default(),
        ),
        disclose(
            Source::Environment,
            "KEY".to_owned(),
            Some(&value),
            &explicit,
        ),
        disclose(
            Source::Environment,
            "NODE_ENV".to_owned(),
            Some(&ordinary),
            &Policy::default(),
        ),
        disclose(
            Source::Environment,
            "EMPTY".to_owned(),
            Some(&empty),
            &explicit,
        ),
        disclose(Source::Environment, "MISSING".to_owned(), None, &explicit),
    ];
    assert_eq!(
        records[0].redaction_reason,
        Some(RedactionReason::DefaultPolicy)
    );
    assert_eq!(
        records[1].redaction_reason,
        Some(RedactionReason::ExplicitRedact)
    );
    let changed = SecretString::new("SYNTHETIC_CHANGED_FORMATLESS_VALUE".to_owned());
    records.push(disclose(
        Source::Environment,
        "UNKNOWN".to_owned(),
        Some(&changed),
        &Policy::default(),
    ));
    assert_eq!(records[0].redaction_reason, records[5].redaction_reason);
    let mut json = Vec::new();
    render(&records, true, &mut json).must();
    let json: serde_json::Value = serde_json::from_slice(&json).must();
    assert_eq!(json["schema_version"], 2);
    assert_eq!(json["records"][0]["redaction_reason"], "default-policy");
    assert_eq!(json["records"][1]["redaction_reason"], "explicit-redact");
    for record in json["records"].as_array().must().iter().skip(2).take(3) {
        assert!(record["redaction_reason"].is_null());
    }
    assert_ne!(
        json["records"][0]["fingerprint"],
        json["records"][5]["fingerprint"]
    );
    let mut text = Vec::new();
    render(&records, false, &mut text).must();
    let text = String::from_utf8(text).must();
    assert!(text.lines().all(|line| line.split('\t').count() == 3));
    assert!(text.contains(&format!(
        "[REDACTED sha256={}]",
        fingerprint(value.as_str())
    )));
    assert!(!text.contains("default-policy") && !text.contains("explicit-redact"));
    assert!(!format!("{:?}", Some(records)).contains("SYNTHETIC_EVIDENCE_CANARY"));
}
