#[path = "support/redaction_report.rs"]
mod report;

#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use redact::{filter, fingerprint};

fn marker(input: &str) -> String {
    format!("[REDACTED sha256={}]", fingerprint(input))
}

fn cli(input: &str, expected: Option<&str>) {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_rstr"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .must();
    child.stdin.take().must().write_all(input.as_bytes()).must();
    let output = child.wait_with_output().must();
    if let Some(expected) = expected {
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, expected.as_bytes());
        report::assert_report(&output.stdout, &output.stderr);
    } else {
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            !String::from_utf8(output.stderr)
                .must()
                .contains("SYNTHETIC_PRIVATE_CANARY")
        );
    }
}

#[test]
fn url_fragments_and_mixed_fields_hide_exact_values() {
    let secret = "SYNTHETIC_CREDENTIAL_CANARY_0123456789";
    for (before, after) in [
        ("https://app.example.test/cb#access_token=", "&state=public"),
        ("url=https://example.test/x,token=", ""),
        ("https://h.example.test/x?a=1;token=", ";status=public"),
        (
            "https://api.example.test/v1/items?apiToken=",
            "&status=public",
        ),
        (
            "https://api.example.test/v1/items?accessKey=",
            "&status=public",
        ),
        ("https://api.example.test/?%61pi%54oken=", "&status=public"),
        (
            "https://api.example.test/?token=",
            "&unassigned&status=public",
        ),
    ] {
        let input = format!("{before}{secret}{after}");
        let expected = format!("{before}{}{after}", marker(secret));
        assert_eq!(filter(input.as_bytes()).must(), expected);
        cli(&input, Some(&expected));
    }
    for suffix in [";unassigned", ",unassigned", "/unassigned=value"] {
        let value = format!("{secret}{suffix}");
        let input = format!("https://api.example.test/?token={value}&status=public");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!(
                "https://api.example.test/?token={}&status=public",
                marker(&value)
            )
        );
    }
    let input = format!("PASSWORD=https://public.example.test/path?token={secret}&status=public");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("PASSWORD={}", marker(&input[9..]))
    );
}

#[test]
fn raw_braces_are_ordinary_but_credential_objects_fail_closed() {
    for input in [
        "{".repeat(65),
        "ordinary {fragment\n".repeat(100),
        "{{{{{\"kind\":\"Pod\",}".to_owned(),
    ] {
        assert_eq!(filter(input.as_bytes()).must(), input);
        cli(&input, Some(&input));
    }
    let deep = format!(
        "{}{{\"kty\":\"RSA\",\"d\":\"SYNTHETIC_PRIVATE_CANARY\"}}{}",
        "{\"nested\":".repeat(65),
        "}".repeat(65)
    );
    let error = filter(deep.as_bytes()).must_err();
    assert!(error.to_string().contains("nesting limit"));
    cli(&deep, None);
    assert!(!format!("{error} {error:?}").contains("SYNTHETIC_PRIVATE_CANARY"));
    for input in [
        r#"{"kty":"RSA","d":"SYNTHETIC_PRIVATE_CANARY",}"#,
        r#"{"auths":"SYNTHETIC_PRIVATE_CANARY""#,
    ] {
        let error = filter(input.as_bytes()).must_err();
        assert!(!format!("{error} {error:?}").contains("SYNTHETIC_PRIVATE_CANARY"));
    }
}

#[test]
fn dense_url_fields_remain_bounded_and_preserve_public_fields() {
    let fields = "status=public&apiToken=SYNTHETIC_PRIVATE_CANARY;".repeat(4096);
    let input = format!("https://example.test/?{fields}status=public");
    let expected_fields = format!(
        "status=public&apiToken={};",
        marker("SYNTHETIC_PRIVATE_CANARY")
    )
    .repeat(4096);
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("https://example.test/?{expected_fields}status=public")
    );
}
