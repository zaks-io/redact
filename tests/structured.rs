#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redact::{filter, fingerprint};

fn replacement(value: &str) -> String {
    format!("[REDACTED sha256={}]", fingerprint(value))
}

#[test]
fn headers_keep_schemes_and_neighbors() {
    for scheme in ["Bearer", "bAsIc", "Bot"] {
        let input = format!(
            "Proxy-Authorization: {scheme} synthetic+opaque/~.payload==\nX-Request-ID: public\n"
        );
        let expected = format!(
            "Proxy-Authorization: {scheme} {}\nX-Request-ID: public\n",
            replacement("synthetic+opaque/~.payload==")
        );
        assert_eq!(filter(input.as_bytes()).must(), expected);
    }
}

#[test]
fn assignments_preserve_json_escapes_and_neighboring_fields() {
    let input = r#"{"pass\u0077ord":"synthetic\"secret","status":401}"#;
    let expected = format!(
        r#"{{"pass\u0077ord":"{}","status":401}}"#,
        replacement(r#"synthetic\"secret"#)
    );
    assert_eq!(filter(input.as_bytes()).must(), expected);
    for name in [
        "AccountKey",
        "privateKeyData",
        "SharedAccessSignature",
        "_authToken",
        "AWS_SESSION_TOKEN",
    ] {
        let input = format!("{name}=\"synthetic-secret\" host=public\n");
        let expected = format!(
            "{name}=\"{}\" host=public\n",
            replacement("synthetic-secret")
        );
        assert_eq!(filter(input.as_bytes()).must(), expected);
    }
}

#[test]
fn urls_decode_names_once_and_keep_public_context() {
    let input = "postgresql://user:synthetic%40secret@host.example/db?pass%77ord=synthetic%2Fsecret&status=401#public";
    let expected = format!(
        "postgresql://{}@host.example/db?pass%77ord={}&status=401#public",
        replacement("user:synthetic%40secret"),
        replacement("synthetic%2Fsecret")
    );
    assert_eq!(filter(input.as_bytes()).must(), expected);
    assert_eq!(
        filter(b"https://host.example/?sig=public&status=401").must(),
        "https://host.example/?sig=public&status=401"
    );
    let sas = "https://host.example/blob?sv=2026&sp=r&sig=synthetic%2Fsignature&se=expiry";
    let expected = format!(
        "https://host.example/blob?sv=2026&sp=r&sig={}&se=expiry",
        replacement("synthetic%2Fsignature")
    );
    assert_eq!(filter(sas.as_bytes()).must(), expected);
}

#[test]
fn connection_dialects_preserve_fields() {
    let input = "host=public dbname=public password='synthetic\\\'secret' port=5432";
    let expected = format!(
        "host=public dbname=public password='{}' port=5432",
        replacement("synthetic\\'secret")
    );
    assert_eq!(filter(input.as_bytes()).must(), expected);
    let input = "AccountName=public;AccountKey=synthetic-secret;EndpointSuffix=public";
    let expected = format!(
        "AccountName=public;AccountKey={};EndpointSuffix=public",
        replacement("synthetic-secret")
    );
    assert_eq!(filter(input.as_bytes()).must(), expected);
}

#[test]
fn jose_supports_nonstandard_header_prefix_and_empty_segments() {
    let jws = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{ "alg":"none"}"#),
        URL_SAFE_NO_PAD.encode("synthetic-payload")
    );
    let input = format!("value ({jws}), status=200");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("value ({}), status=200", replacement(&jws))
    );
    let jwe = format!(
        "{}..aXY..dGFn",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"dir","enc":"A256GCM"}"#)
    );
    assert_eq!(filter(jwe.as_bytes()).must(), replacement(&jwe));
}

#[test]
fn private_containers_are_complete_and_public_containers_survive() {
    for label in [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "DSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ] {
        let container =
            format!("-----BEGIN {label}-----\nsynthetic-private-material\n-----END {label}-----");
        assert_eq!(filter(container.as_bytes()).must(), replacement(&container));
        let broken = format!("-----BEGIN {label}-----\nsynthetic-private-material");
        let error = filter(broken.as_bytes()).must_err();
        assert!(!format!("{error:?} {error}").contains("synthetic-private-material"));
    }
    let public =
        "-----BEGIN CERTIFICATE-----\nsynthetic-public-material\n-----END CERTIFICATE-----";
    assert_eq!(filter(public.as_bytes()).must(), public);
    let jwk = r#"{"kty":"RSA","n":"public","e":"AQAB"}"#;
    assert_eq!(filter(jwk.as_bytes()).must(), jwk);
    let private = r#"{"kty":"EC","x":"public","d":"synthetic-private"}"#;
    assert_eq!(filter(private.as_bytes()).must(), replacement(private));
}

#[test]
fn malformed_recognized_containers_fail_without_secret_diagnostics() {
    for input in [
        r#"{"kty":"RSA","d":"synthetic-private",}"#,
        r#"{"kty":"RSA","d":"synthetic-private","kty":"unsupported"}"#,
        r#"{"k\u0074y":"EC","d":"synthetic-private",}"#,
        r#"{"auths":{"registry":{"auth":"synthetic-private"}},}"#,
        "password=\"synthetic-private",
    ] {
        let error = filter(input.as_bytes()).must_err();
        assert!(!format!("{error:?} {error}").contains("synthetic-private"));
    }
}

#[test]
fn encoded_configs_protect_whole_containers() {
    for input in [
        r#"{"kind":"Secret","data":{"custom":"c3ludGhldGljLXNlY3JldA=="}}"#,
        r#"{"auths":{"registry":{"auth":"c3ludGhldGljOnNlY3JldA=="}}}"#,
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: public\ndata:\n  custom: c3ludGhldGljLXNlY3JldA==\n",
    ] {
        assert_eq!(filter(input.as_bytes()).must(), replacement(input));
    }
}

#[test]
fn adversarial_structures_fail_safely_or_remove_complete_spans() {
    let nested_begins = format!(
        "{}synthetic-private\n-----END PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\n".repeat(2048)
    );
    assert_eq!(
        filter(nested_begins.as_bytes()).must(),
        replacement(&nested_begins)
    );
    let oversized_token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        "A".repeat(1_048_576)
    );
    let error = filter(oversized_token.as_bytes()).must_err();
    assert!(error.to_string().contains("parsing limit"));
    assert_eq!(filter("{".repeat(65).as_bytes()).must(), "{".repeat(65));
}

#[test]
fn uri_wrappers_do_not_change_credential_fingerprints() {
    let url = "https://hooks.slack.com/services/SYNTHETIC/LOCAL/FIXTURE";
    for (open, close) in [("[", "]"), ("(", "),"), ("{", "};")] {
        let input = format!("before {open}{url}{close} after");
        let expected = format!("before {open}{}{close} after", replacement(url));
        assert_eq!(filter(input.as_bytes()).must(), expected);
    }
    let input = "https://[::1]/?token=synthetic),.";
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("https://[::1]/?token={}", replacement("synthetic),."))
    );
}

#[test]
fn yaml_document_separators_require_complete_markers() {
    let input = "kind: Secret\ndata:\n  value: synthetic-secret\n---synthetic-secret-suffix\n";
    assert_eq!(filter(input.as_bytes()).must(), replacement(input));
    let first = "kind: Secret\ndata:\n  value: synthetic-secret\n";
    let input = format!("{first}--- # public document\nkind: ConfigMap\ndata:\n  value: public\n");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            "{}--- # public document\nkind: ConfigMap\ndata:\n  value: public\n",
            replacement(first)
        )
    );
}

#[test]
fn evolved_jose_segments_are_not_released_as_unknown_suffixes() {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let token = format!("{header}.c3ludGhldGlj.c2ln.extra.synthetic.secret.suffix");
    assert_eq!(filter(token.as_bytes()).must(), replacement(&token));
    let framed = format!("({token}.)");
    assert_eq!(
        filter(framed.as_bytes()).must(),
        format!("({}.)", replacement(&token))
    );
}

#[test]
fn reviewed_boundaries_protect_cli_canaries() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let canary = "SYNTHETIC_CREDENTIAL_CANARY_0123456789";
    let marker = replacement(canary);
    let yaml = format!("apiVersion: v1\r\nkind: Secret\r\ndata:\r\n  value: {canary}\r\n");
    let slack = format!("https://hooks.slack.com:443/services/SYNTHETIC/LOCAL/{canary}");
    let cases = [
        (
            format!("{{\"password\":\n\"{canary}\",\"status\":401}}"),
            format!("{{\"password\":\n\"{marker}\",\"status\":401}}"),
        ),
        (
            format!("{{\"password\"\r\n:\r\n\"{canary}\",\"status\":401}}"),
            format!("{{\"password\"\r\n:\r\n\"{marker}\",\"status\":401}}"),
        ),
        (yaml.clone(), replacement(&yaml)),
        (slack.clone(), replacement(&slack)),
        (
            format!("https://api.telegram.org:443/bot123:{canary}/getMe"),
            format!(
                "https://api.telegram.org:443/bot{}/getMe",
                replacement(&format!("123:{canary}"))
            ),
        ),
        (
            format!("https://user:{canary}@[::1]:443/path"),
            format!(
                "https://{}@[::1]:443/path",
                replacement(&format!("user:{canary}"))
            ),
        ),
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
        let output = child.wait_with_output().must();
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty());
        assert!(
            !output
                .stdout
                .windows(canary.len())
                .any(|window| window == canary.as_bytes())
        );
    }
    // Unquoted assignments retain their physical-line boundaries.
    assert_eq!(
        filter(b"password=\npublic-context\n").must(),
        "password=\npublic-context\n"
    );
}

#[test]
fn recognized_context_survives_malformed_container_shapes() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let canary = "SYNTHETIC_CREDENTIAL_CANARY_0123456789";
    let assignment = format!("status=401;password={canary};host=public");
    let cases = [
        (
            assignment.clone(),
            format!(
                "status=401;password={}",
                replacement(&format!("{canary};host=public"))
            ),
        ),
        (format!("{{\"auths\":\"{canary}\"}}"), String::new()),
        (format!("{{\"auths\":[\"{canary}\"]}}"), String::new()),
        (
            format!("{{\"kty\":[\"RSA\"],\"d\":\"{canary}\"}}"),
            String::new(),
        ),
        (
            format!("{{\"kty\":\"evolved\",\"k\":\"{canary}\"}}"),
            String::new(),
        ),
        (
            format!("\"kind\": \"Secret\"\n\"data\":\n  value: {canary}\n"),
            String::new(),
        ),
    ];
    for (input, expected) in cases {
        let expected = if expected.is_empty() {
            replacement(&input)
        } else {
            expected
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
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn unterminated_escaped_quotes_have_bounded_cli_processing() {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let canary = "SYNTHETIC_CREDENTIAL_CANARY_0123456789";
    let input = format!(
        "\"{} password={canary}",
        "\\\"".repeat((redact::MAX_INPUT_BYTES - 128) / 2)
    );
    assert!(input.len() < redact::MAX_INPUT_BYTES);
    let stdout_file = tempfile::NamedTempFile::new().must();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rstr"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(stdout_file.reopen().must())
        .stderr(Stdio::piped())
        .spawn()
        .must();
    let started = Instant::now();
    child.stdin.take().must().write_all(input.as_bytes()).must();
    loop {
        if child.try_wait().must().is_some() {
            break;
        }
        if started.elapsed() > Duration::from_secs(10) {
            child.kill().must();
            let _ = child.wait();
            panic!("unterminated quoted input exceeded its finite processing bound");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().must();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = std::fs::read_to_string(stdout_file.path()).must();
    let expected = format!(
        "\"{} password={}",
        "\\\"".repeat((redact::MAX_INPUT_BYTES - 128) / 2),
        replacement(canary)
    );
    assert_eq!(stdout, expected);
    assert!(!stdout.contains(canary));
}

#[test]
fn structured_review_delta_preserves_real_framing() {
    let canary = "SYNTHETIC_CREDENTIAL_CANARY_0123456789";
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let jwt = format!("{header}.c3ludGhldGlj.");
    for separator in ["!", ":", "$", " "] {
        let secret = format!("{jwt}{separator}{canary}");
        let input = format!("password={secret}");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("password={}", replacement(&secret))
        );
    }
    let input = format!(r#"{{"message":"Authorization: Bearer {canary}", "status":401}}"#);
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            r#"{{"message":"Authorization: Bearer {}", "status":401}}"#,
            replacement(canary)
        )
    );
    let input = format!("https://api.telegram.org/file/bot123:{canary}/documents/public.txt");
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            "https://api.telegram.org/file/bot{}/documents/public.txt",
            replacement(&format!("123:{canary}"))
        )
    );
    let input = format!(r#"{{"url":"postgres:\/\/app:{canary}@example.test/db"}}"#);
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            r#"{{"url":"postgres:\/\/{}@example.test/db"}}"#,
            replacement(&format!("app:{canary}"))
        )
    );
    let input =
        format!("-----BEGIN FUTURE PRIVATE KEY-----\n{canary}\n-----END FUTURE PRIVATE KEY-----");
    assert_eq!(filter(input.as_bytes()).must(), replacement(&input));
    assert_eq!(
        filter(br#"ordinary {"kind":"Pod",} diagnostic"#).must(),
        r#"ordinary {"kind":"Pod",} diagnostic"#
    );
    assert_eq!(
        filter(b"ordinary log: she said \"hello").must(),
        "ordinary log: she said \"hello"
    );
}
