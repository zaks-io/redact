use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use proptest::prelude::*;
use redact::fingerprint::marker;
use redact::rstr::{MAX_INPUT_BYTES, detect, filter, filter_to_writer, merge_spans, render_spans};

const CANARY: &str = "synthetic-canary-orchid-72";

trait Must<T> {
    fn must(self) -> T;
}
impl<T, E> Must<T> for Result<T, E> {
    fn must(self) -> T {
        self.unwrap_or_else(|_| panic!("synthetic test operation failed"))
    }
}
impl<T> Must<T> for Option<T> {
    fn must(self) -> T {
        self.unwrap_or_else(|| panic!("synthetic test setup missing value"))
    }
}
trait MustErr<E> {
    fn must_err(self) -> E;
}
impl<T, E> MustErr<E> for Result<T, E> {
    fn must_err(self) -> E {
        match self {
            Err(error) => error,
            Ok(_) => panic!("expected synthetic test failure"),
        }
    }
}

fn run(input: &[u8], arguments: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rstr"))
        .env_clear()
        .env("RUST_BACKTRACE", "1")
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .must();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    child.wait_with_output().must()
}

#[test]
fn context_boundaries_and_exact_hashing() {
    for (input, expected) in [
        (
            format!("{{\"password\":\"{CANARY}\",\"status\":401}}\r\n"),
            format!(
                "{{\"password\":\"{}\",\"status\":401}}\r\n",
                marker(CANARY.as_bytes())
            ),
        ),
        (
            format!("password='{CANARY}' host=example.test\n"),
            format!(
                "password='{}' host=example.test\n",
                marker(CANARY.as_bytes())
            ),
        ),
        (
            format!("PASSWORD=\"{CANARY}\" host=example.test"),
            format!(
                "PASSWORD=\"{}\" host=example.test",
                marker(CANARY.as_bytes())
            ),
        ),
        (
            format!("Proxy-Authorization: bAsIc {CANARY}\t\r\n"),
            format!(
                "Proxy-Authorization: bAsIc {}\t\r\n",
                marker(CANARY.as_bytes())
            ),
        ),
        (
            format!(
                "https://user:{CANARY}@example.test/path?%70assword={CANARY}&status=401#fragment"
            ),
            format!(
                "https://{}@example.test/path?%70assword={}&status=401#fragment",
                marker(format!("user:{CANARY}").as_bytes()),
                marker(CANARY.as_bytes())
            ),
        ),
        (
            format!("password={CANARY} host=example.test\n"),
            format!(
                "password={}\n",
                marker(format!("{CANARY} host=example.test").as_bytes())
            ),
        ),
    ] {
        assert_eq!(filter(input.as_bytes()).must(), expected);
        let output = run(input.as_bytes(), &[]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn escaped_json_names_and_values_and_multiline_quotes() {
    let input = r#"{"pass\u0077ord":"synthetic\"escaped\\canary","status":401}"#;
    let value = r#"synthetic\"escaped\\canary"#;
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            r#"{{"pass\u0077ord":"{}","status":401}}"#,
            marker(value.as_bytes())
        )
    );
    let input = "password=\"synthetic\nmultiline秘密\" status=401\n";
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!(
            "password=\"{}\" status=401\n",
            marker("synthetic\nmultiline秘密".as_bytes())
        )
    );
}

#[test]
fn each_provider_prefix_uses_whole_candidate_and_preserves_neighbors() {
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../rules/providers.json")).must();
    for rule in inventory["rules"].as_array().must() {
        for prefix in rule["prefixes"].as_array().must() {
            let prefix = prefix.as_str().must();
            let token = format!("{prefix}synthetic_ABC-0123456789_extended_suffix");
            let input = format!("before ({token}) after\n");
            assert_eq!(
                filter(input.as_bytes()).must(),
                format!("before ({}) after\n", marker(token.as_bytes()))
            );
            let near_match = format!("not{prefix}synthetic");
            assert_eq!(filter(near_match.as_bytes()).must(), near_match);
            assert_eq!(filter(prefix.as_bytes()).must(), prefix);
            let malformed_in_context =
                format!("API_KEY=\"{prefix}秘密 malformed body\" status=401");
            assert!(
                !filter(malformed_in_context.as_bytes())
                    .must()
                    .contains("秘密")
            );
        }
    }
    for token in [
        "AKIASYNTHETIC12345678",
        "ASIASYNTHETIC12345678",
        "AKIAsynthetic12345678",
        "ASIAsynthetic123456789longtail",
    ] {
        assert_eq!(filter(token.as_bytes()).must(), marker(token.as_bytes()));
    }
    assert_eq!(
        filter(b"AKIAsynthetic12345678_tail").must(),
        "AKIAsynthetic12345678_tail"
    );
    let long = format!("ghs_12345_{}", "synthetic".repeat(80));
    assert_eq!(filter(long.as_bytes()).must(), marker(long.as_bytes()));
}

#[test]
fn negative_and_malformed_provider_candidates_are_not_validity_checks() {
    for input in [
        "pk_live_syntheticPublic",
        "pk_test_syntheticPublic",
        "tokenizer=synthetic",
        "https://example.test/path?q=ordinary",
        "AKIAshort",
        "prefixghp_synthetic",
        "-----BEGIN PUBLIC KEY-----\nsynthetic\n-----END PUBLIC KEY-----",
        "-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----",
    ] {
        assert_eq!(filter(input.as_bytes()).must(), input);
    }
    assert_eq!(
        filter(b"API_KEY=\"unknown custom opaque secret\"").must(),
        format!("API_KEY=\"{}\"", marker(b"unknown custom opaque secret"))
    );
}

#[test]
fn private_container_variants_and_missing_end_fail_safely() {
    assert!(filter(b"-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\nsynthetic\n-----END RSA PRIVATE KEY-----").is_err());
    for label in [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ] {
        let block = format!("-----BEGIN {label}-----\n{CANARY}\n-----END {label}-----");
        let input = format!("before\n{block}\nafter\n");
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!("before\n{}\nafter\n", marker(block.as_bytes()))
        );
        let output = run(format!("-----BEGIN {label}-----\n{CANARY}").as_bytes(), &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
    }
}

#[test]
fn jwt_requires_json_objects_and_alg_without_eyj_or_signature_assumptions() {
    let header = URL_SAFE_NO_PAD.encode(b" {\"alg\":\"none\"}");
    let payload = URL_SAFE_NO_PAD.encode(format!("{{\"synthetic\":\"{CANARY}\"}}"));
    let token = format!("{header}.{payload}.");
    assert_eq!(filter(token.as_bytes()).must(), marker(token.as_bytes()));
    let malformed_signature = format!("{header}.{payload}.A");
    assert_eq!(
        filter(malformed_signature.as_bytes()).must(),
        marker(malformed_signature.as_bytes())
    );
    let token = format!("{header}.{payload}.c3ludGhldGlj");
    assert_eq!(filter(token.as_bytes()).must(), marker(token.as_bytes()));
    for token in [
        "abc.def.ghi",
        "e30.e30.",
        "e30.W10.",
        &format!("{header}.{payload}.c3ludGhldGlj.extra"),
    ] {
        assert_eq!(filter(token.as_bytes()).must(), token);
    }
}

#[test]
fn usage_encoding_and_quote_failures_have_no_output_or_canary() {
    for input in [
        format!("password=\"{CANARY}"),
        format!("password=\"{CANARY}\\q\""),
        format!("{{\"password\":\"{CANARY}"),
        format!("{{\"password\":\"{CANARY}\\q\"}}"),
    ] {
        let output = run(input.as_bytes(), &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
    }
    for input in [&b"\xff"[..], &b"password=synthetic\0"[..]] {
        let output = run(input, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    for argument in [CANARY, "--file", "--env", "--allow", "--redact", "--json"] {
        let output = run(b"", &[argument]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
    }
}

struct FailedRead;
impl Read for FailedRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other(CANARY))
    }
}
struct FailedWrite;
impl Write for FailedWrite {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other(CANARY))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other(CANARY))
    }
}

#[test]
fn read_write_detector_faults_and_limit_have_safe_errors() {
    let mut output = Vec::new();
    let error = filter_to_writer(FailedRead, &mut output).must_err();
    assert!(output.is_empty());
    assert!(!format!("{error:?} {error}").contains(CANARY));
    let error = filter_to_writer(format!("password={CANARY}").as_bytes(), FailedWrite).must_err();
    assert!(!format!("{error:?} {error}").contains(CANARY));
    let error = render_spans("秘密", std::iter::once(1..2).collect()).must_err();
    assert!(!format!("{error:?} {error}").contains("秘密"));
    assert!(filter(&vec![b'x'; MAX_INPUT_BYTES + 1]).is_err());
    assert_eq!(filter(b"").must(), "");
    assert_eq!(
        filter(b"ordinary\r\nwithout appended newline").must(),
        "ordinary\r\nwithout appended newline"
    );
}

#[test]
fn overlapping_and_adjacent_spans_hash_original_union_once() {
    assert_eq!(
        merge_spans("abcdef", vec![0..3, 2..5, 5..6]).must(),
        vec![0..5, 5..6]
    );
    assert_eq!(
        render_spans("abcdef", vec![0..3, 2..5, 5..6]).must(),
        format!("{}{}", marker(b"abcde"), marker(b"f"))
    );
    let input = "password=ghp_synthetic-token\n";
    assert_eq!(
        filter(input.as_bytes()).must(),
        format!("password={}\n", marker(b"ghp_synthetic-token"))
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, rng_seed: proptest::test_runner::RngSeed::Fixed(0x5eed), failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn arbitrary_bytes_fail_safely_without_panicking(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        if let Err(error) = filter(&bytes) {
            let diagnostic = format!("{error:?} {error}");
            prop_assert!(diagnostic.len() < 300);
        }
    }
    #[test]
    fn unicode_sensitive_quoted_values_match_independent_oracle(value in "[a-zA-Z0-9秘密é _-]{0,80}") {
        let input = format!("before password=\"{value}\" status=401\r\n");
        let replacement = if value.is_empty() { String::new() } else { marker(value.as_bytes()) };
        prop_assert_eq!(filter(input.as_bytes()).must(), format!("before password=\"{replacement}\" status=401\r\n"));
        for span in detect(&input).must() {
            prop_assert!(span.end <= input.len());
            prop_assert!(input.is_char_boundary(span.start) && input.is_char_boundary(span.end));
        }
    }
}

struct SplitRead<'a> {
    input: &'a [u8],
    position: usize,
    split: usize,
}
impl Read for SplitRead<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let end = if self.position < self.split {
            self.split
        } else {
            self.input.len()
        };
        let size = (end - self.position).min(buffer.len());
        buffer[..size].copy_from_slice(&self.input[self.position..self.position + size]);
        self.position += size;
        Ok(size)
    }
}

#[test]
fn input_boundaries_do_not_change_unicode_or_multiline_filtering() {
    for input in [
        "password=\"synthetic秘密\né\" status=401\r\n",
        "-----BEGIN PRIVATE KEY-----\nsynthetic秘密\n-----END PRIVATE KEY-----\r\n",
    ] {
        let expected = filter(input.as_bytes()).must();
        for split in 0..=input.len() {
            let reader = SplitRead {
                input: input.as_bytes(),
                position: 0,
                split,
            };
            let mut output = Vec::new();
            filter_to_writer(reader, &mut output).must();
            assert_eq!(output, expected.as_bytes());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, rng_seed: proptest::test_runner::RngSeed::Fixed(0x5eed), failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn overlap_union_matches_graph_components(pairs in prop::collection::vec((0usize..32, 0usize..32), 0..16)) {
        let input = "abcdefghijklmnopqrstuvwxyzABCDEF";
        let spans: Vec<_> = pairs.into_iter().map(|(a,b)| a.min(b)..a.max(b)).filter(|span| !span.is_empty()).collect();
        let actual = merge_spans(input, spans.clone()).must();
        let mut seen = vec![false; spans.len()];
        let mut expected = Vec::new();
        for root in 0..spans.len() {
            if seen[root] { continue; }
            seen[root] = true;
            let mut pending = vec![root];
            let mut component = spans[root].clone();
            while let Some(index) = pending.pop() {
                for neighbor in 0..spans.len() {
                    if !seen[neighbor] && spans[index].start < spans[neighbor].end && spans[neighbor].start < spans[index].end {
                        seen[neighbor] = true;
                        pending.push(neighbor);
                        component.start = component.start.min(spans[neighbor].start);
                        component.end = component.end.max(spans[neighbor].end);
                    }
                }
            }
            expected.push(component);
        }
        expected.sort_by_key(|span| span.start);
        prop_assert_eq!(actual, expected);
    }
}

#[test]
fn uri_credentials_detects_required_schemes() {
    for scheme in [
        "postgres",
        "postgresql",
        "mongodb",
        "mongodb+srv",
        "redis",
        "rediss",
    ] {
        let input = format!(
            "{scheme}://synthetic-user:{CANARY}@example.test:1234/db?access_token={CANARY}&status=401"
        );
        assert_eq!(
            filter(input.as_bytes()).must(),
            format!(
                "{scheme}://{}@example.test:1234/db?access_token={}&status=401",
                marker(format!("synthetic-user:{CANARY}").as_bytes()),
                marker(CANARY.as_bytes())
            )
        );
        let ordinary = format!("{scheme}://example.test:1234/db?status=401");
        assert_eq!(filter(ordinary.as_bytes()).must(), ordinary);
    }
}

#[test]
fn coverage_ledger_maps_every_researched_family_and_shipped_evidence() {
    let ledger: serde_json::Value =
        serde_json::from_str(include_str!("../rules/coverage.json")).must();
    let entries = ledger["entries"].as_object().must();
    let row = regex::Regex::new(r"(?m)^\| ([a-z][a-z0-9-]+) \|").must();
    let mut inventory = std::collections::BTreeSet::new();
    for text in [
        include_str!("../docs/secret-formats/providers.md"),
        include_str!("../docs/secret-formats/cloud.md"),
        include_str!("../docs/secret-formats/structures.md"),
    ] {
        for captures in row.captures_iter(text) {
            inventory.insert(captures[1].to_owned());
        }
    }
    assert_eq!(inventory, entries.keys().cloned().collect());
    for entry in entries.values() {
        if entry["status"].as_str().must().starts_with("shipped") {
            assert!(!entry["rule"].as_str().must().is_empty());
            for test in entry["tests"].as_array().must() {
                assert!(include_str!("rstr.rs").contains(&format!("fn {}(", test.as_str().must())));
            }
        }
    }
}

#[test]
fn nested_original_uri_candidates_and_json_diagnostics_preserve_context() {
    for prefix in [
        "https://public.test/redirect=",
        "https://public.test/?next=",
    ] {
        let input = format!("{prefix}https://user:{CANARY}@private.test/path");
        let expected = format!(
            "{prefix}https://{}@private.test/path",
            marker(format!("user:{CANARY}").as_bytes())
        );
        let output = run(input.as_bytes(), &[]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty());
    }
    let nested = format!("https://outer.test/?password=https://user:{CANARY}@inner.test");
    assert_eq!(
        filter(nested.as_bytes()).must(),
        format!(
            "https://outer.test/?password={}",
            marker(format!("https://user:{CANARY}@inner.test").as_bytes())
        )
    );
    let message = format!("{{\"message\":\"password={CANARY}\",\"status\":401}}");
    let output = run(message.as_bytes(), &[]);
    assert_eq!(
        output.stdout,
        format!(
            "{{\"message\":\"password={}\",\"status\":401}}",
            marker(CANARY.as_bytes())
        )
        .as_bytes()
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let repeated = format!("{}\n", " password=synthetic".repeat(8_000));
    assert_eq!(
        filter(repeated.as_bytes()).must(),
        format!(
            " password={}\n",
            marker(&repeated.as_bytes()[10..repeated.len() - 1])
        )
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, rng_seed: proptest::test_runner::RngSeed::Fixed(0x5eed), failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn nested_uri_candidate_boundaries_hide_complete_user_information(depth in 1usize..24, value in "synthetic-[a-z0-9]{1,32}") {
        let prefix = "https://public.test/redirect=".repeat(depth);
        let input = format!("{prefix}https://user:{value}@private.test/path?status=401");
        prop_assert_eq!(filter(input.as_bytes()).must(), format!("{prefix}https://{}@private.test/path?status=401", marker(format!("user:{value}").as_bytes())));
    }
}

#[test]
fn quoted_assignments_cannot_close_outside_enclosing_json_string() {
    let input = format!("{{\"message\":\"password='{CANARY}\",\"status\":\"later'\"}}");
    let output = run(input.as_bytes(), &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
    for input in [
        r#"{"message":"password=","status":401}"#,
        r#"{"message":"Authorization: Bearer ","status":401}"#,
    ] {
        assert_eq!(filter(input.as_bytes()).must(), input);
    }
}

#[test]
fn separate_json_headers_each_preserve_their_scheme() {
    let input = r#"{"a":"Authorization: Bearer synthetic-one","b":"Authorization: Bearer synthetic-two","status":401}"#;
    let expected = format!(
        r#"{{"a":"Authorization: Bearer {}","b":"Authorization: Bearer {}","status":401}}"#,
        marker(b"synthetic-one"),
        marker(b"synthetic-two")
    );
    assert_eq!(filter(input.as_bytes()).must(), expected);
    let output = run(input.as_bytes(), &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, expected.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn jwt_json_representation_limits_never_allow_unchecked_passthrough() {
    let ordinary_header = br#"{"alg":"none"}"#;
    let numeric_header = br#"{"alg":"none","synthetic":1e9999}"#;
    let numeric_payload = br#"{"synthetic":1e9999}"#;
    for header in [ordinary_header.as_slice(), numeric_header.as_slice()] {
        let token = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(numeric_payload)
        );
        let output = run(token.as_bytes(), &[]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, marker(token.as_bytes()).as_bytes());
        assert!(output.stderr.is_empty());
    }
    let nested = format!("{}\"{CANARY}\"{}", "{\"a\":".repeat(150), "}".repeat(150));
    let nested_header = format!(r#"{{"alg":"none","meta":{nested}}}"#);
    for (header, payload) in [
        (ordinary_header.as_slice(), nested.as_bytes()),
        (nested_header.as_bytes(), numeric_payload.as_slice()),
    ] {
        let token = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let output = run(token.as_bytes(), &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "rstr: detector failed. Report the version and a synthetic reproduction.\n"
        );
    }
    let braces = serde_json::to_vec(&serde_json::json!({"synthetic": "{[\\\"".repeat(150)})).must();
    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(ordinary_header),
        URL_SAFE_NO_PAD.encode(braces)
    );
    assert_eq!(filter(token.as_bytes()).must(), marker(token.as_bytes()));
}
