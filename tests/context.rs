#[path = "support/redaction_report.rs"]
mod report;

#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use proptest::prelude::*;
use redact::{filter, fingerprint};

const CANARY: &str = "SYNTHETIC_CONTEXT_CREDENTIAL_CANARY_0123456789";

fn marker(value: &str) -> String {
    format!("[REDACTED sha256={}]", fingerprint(value))
}

#[test]
fn names_cover_camel_case_dotted_paths_and_explicit_provider_fields() {
    for name in [
        "apiToken",
        "dbPassword",
        "spring.datasource.password",
        "sslpassword",
        "AccountKey",
        "privateKeyData",
        "SharedAccessSignature",
        "AWSSecretAccessKey",
        "AWSSessionToken",
        "auth.clientSecret",
        "secretAccessKey",
    ] {
        let input = format!("{name}=\"{CANARY}\" status=401\n");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("{name}=\"{}\" status=401\n", marker(CANARY)),
            "{name}"
        );
    }
    for input in [
        "tokenizer=public",
        "apiTokenizer=public",
        "spring.datasource.host=public",
        "privateKeyId=public",
    ] {
        assert_eq!(filter(input.as_bytes()).must(), input);
    }
}

#[test]
fn quoted_python_names_and_pretty_json_preserve_neighboring_context() {
    for quote in ['\'', '"'] {
        let input = format!(
            "{{{quote}password{quote}: {quote}{CANARY}{quote}, {quote}status{quote}: 401}}"
        );
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!(
                "{{{quote}password{quote}: {quote}{}{quote}, {quote}status{quote}: 401}}",
                marker(CANARY)
            )
        );
    }
    let input = format!("{{\"password\"\r\n:\r\n\"{CANARY}\",\"status\":401}}");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            "{{\"password\"\r\n:\r\n\"{}\",\"status\":401}}",
            marker(CANARY)
        )
    );
}

#[test]
fn sensitive_nested_json_values_are_removed_completely() {
    for value in [
        format!("[\"{CANARY}\",{{\"nested\":\"{CANARY}\"}}]"),
        format!("{{\"first\":\"{CANARY}\",\"second\":[\"{CANARY}\"]}}"),
        format!("{{\"escaped\":\"value\\\"{CANARY}\"}}"),
    ] {
        let input = format!("{{\"password\":{value},\"status\":401}}");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("{{\"password\":{},\"status\":401}}", marker(&value))
        );
    }
    for input in [
        format!("{{\"password\":[\"{CANARY}\",\"suffix\""),
        format!("{{\"password\":{{\"nested\":\"{CANARY}\""),
        format!("{{\"password\":[\"{CANARY}\"}}"),
    ] {
        let error = filter(input.as_bytes()).must_err();
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }
}

#[test]
fn ordinary_quoted_messages_are_checked_for_embedded_assignments() {
    let input = format!("message=\"password={CANARY}\" host=public\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("message=\"password={}\" host=public\n", marker(CANARY))
    );
    let input = format!("{{\"message\":\"apiToken={CANARY}\",\"status\":401}}");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            "{{\"message\":\"apiToken={}\",\"status\":401}}",
            marker(CANARY)
        )
    );
    let input = format!("message='dbPassword={CANARY}' status=401");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("message='dbPassword={}' status=401", marker(CANARY))
    );
}

#[test]
fn embedded_json_escapes_hash_exact_source_bytes() {
    let raw_secret = r#"synthetic\\\"secret"#;
    let input = r#"{"message":"password=\"synthetic\\\"secret\" host=public","status":401}"#;
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            r#"{{"message":"password=\"{}\" host=public","status":401}}"#,
            marker(raw_secret)
        )
    );
    let input = r#"{"message":"password=synthetic\u002dsecret","status":401}"#;
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            r#"{{"message":"password={}","status":401}}"#,
            marker(r"synthetic\u002dsecret")
        )
    );
    let input = r#"{"message":"password=synthetic\ud83d\udd11secret","status":401}"#;
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            r#"{{"message":"password={}","status":401}}"#,
            marker(r"synthetic\ud83d\udd11secret")
        )
    );
    let input =
        format!(r#"{{"message":"{{\"apiToken\":\"{CANARY}\",\"status\":401}}","host":"public"}}"#);
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            r#"{{"message":"{{\"apiToken\":\"{}\",\"status\":401}}","host":"public"}}"#,
            marker(CANARY)
        )
    );
}

#[test]
fn jose_prefixes_do_not_authorize_sensitive_assignment_suffixes() {
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#),
        URL_SAFE_NO_PAD.encode(br#"{"sub":"synthetic"}"#),
        URL_SAFE_NO_PAD.encode("synthetic-signature")
    );
    for separator in ["!", ":", "$", " "] {
        let value = format!("{token}{separator}{CANARY}");
        let input = format!("password={value}\n");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("password={}\n", marker(&value))
        );
    }
}

#[test]
fn indented_sensitive_yaml_blocks_preserve_following_public_fields() {
    for style in ["|", ">-", "|2+"] {
        let value = format!("{style}\n  {CANARY}\n  synthetic-secret-suffix");
        let input = format!("password: {value}\nstatus: 401\n");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("password: {}\nstatus: 401\n", marker(&value))
        );
    }
    let value = format!("|\r\n    {CANARY}");
    let input = format!("  apiToken: {value}\r\n  host: public\r\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("  apiToken: {}\r\n  host: public\r\n", marker(&value))
    );
}

#[test]
fn ordinary_unmatched_quotes_are_preserved_and_sensitive_quotes_fail() {
    for input in [
        "ordinary log: she said \"hello",
        "ordinary log: she said 'hello",
        "public '\\\"\\\"\\\"",
        "public \"no sensitive assignment",
    ] {
        assert_eq!(filter(input.as_bytes()).must(), input);
    }
    for input in [
        format!("ordinary \"prefix password='{CANARY}"),
        format!("password=\"{CANARY}"),
        format!("'password': '{CANARY}"),
    ] {
        let error = filter(input.as_bytes()).must_err();
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }
    let input = format!("status=401;password={CANARY};host=public");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            "status=401;password={}",
            marker(&format!("{CANARY};host=public"))
        )
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn embedded_context_mutations_keep_source_fingerprints(value in "[A-Za-z0-9_./+~=-]{1,256}") {
        let input = format!("{{\"message\":\"dbPassword={value}\",\"status\":401}}");
        prop_assert_eq!(filter(input.as_bytes()).must(), format!("{{\"message\":\"dbPassword={}\",\"status\":401}}", marker(&value)));
    }
}

#[test]
fn reviewed_contexts_work_through_real_cli_with_safe_errors() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let nested = format!("[\"{CANARY}\",{{\"nested\":\"{CANARY}\"}}]");
    let block = format!("|\n  {CANARY}\n  synthetic-suffix");
    let cases = [
        (
            format!("message=\"dbPassword={CANARY}\" host=public"),
            Some(format!(
                "message=\"dbPassword={}\" host=public",
                marker(CANARY)
            )),
        ),
        (
            format!("{{'apiToken':'{CANARY}','status':401}}"),
            Some(format!("{{'apiToken':'{}','status':401}}", marker(CANARY))),
        ),
        (
            format!("{{\"password\":{nested},\"status\":401}}"),
            Some(format!(
                "{{\"password\":{},\"status\":401}}",
                marker(&nested)
            )),
        ),
        (
            format!("password: {block}\nstatus: 401\n"),
            Some(format!("password: {}\nstatus: 401\n", marker(&block))),
        ),
        (format!("{{\"password\":[\"{CANARY}\",\"suffix\""), None),
    ];
    for (input, expected) in cases {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rstr"))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .must();
        child.stdin.take().must().write_all(input.as_bytes()).must();
        let started = Instant::now();
        while child.try_wait().must().is_none() {
            if started.elapsed() > Duration::from_secs(5) {
                child.kill().must();
                child.wait().must();
                panic!("synthetic context CLI test exceeded five seconds");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let output = child.wait_with_output().must();
        if let Some(expected) = expected {
            assert_eq!(output.status.code(), Some(0));
            assert_eq!(output.stdout, expected.as_bytes());
            report::assert_report(&output.stdout, &output.stderr);
        } else {
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(!String::from_utf8(output.stderr).must().contains(CANARY));
        }
    }
}

#[test]
fn unmarked_indented_values_are_protected_and_genuine_empty_values_remain_empty() {
    let value = format!("{CANARY}\n    synthetic-suffix");
    let input = format!("password:\n  {value}\nstatus: 401\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("password:\n  {}\nstatus: 401\n", marker(&value))
    );
    let input = format!("\"password\":\n  {value}\nstatus: 401\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("\"password\":\n  {}\nstatus: 401\n", marker(&value))
    );
    let value = format!("first: {CANARY}\r\n    second: synthetic-suffix");
    let input = format!("  apiToken:\r\n    {value}\r\n  host: public\r\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            "  apiToken:\r\n    {}\r\n  host: public\r\n",
            marker(&value)
        )
    );
    for input in [
        "password:\nstatus: 401\n",
        "  password:\r\n  host: public\r\n",
        "password:\n\nstatus: 401\n",
    ] {
        assert_eq!(filter(input.as_bytes()).must(), input);
    }
    let input = format!(
        "password:\n  {CANARY}{}\nstatus: 401\n",
        "x".repeat(1_048_576)
    );
    let error = filter(input.as_bytes()).must_err();
    assert!(error.to_string().contains("parsing limit"));
    assert!(!format!("{error:?} {error}").contains(CANARY));
}
