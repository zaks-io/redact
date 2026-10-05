use redact::environment::{Options, RawVariables, Snapshot, Source, State};
use redact::{Span, environment};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub fn hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn policy(name: &str, value: Option<&str>, allow: bool, redact: bool) -> State {
    let Some(value) = value else {
        return State::Missing;
    };
    if value.is_empty() {
        return State::Empty;
    }
    if redact {
        return State::Redacted;
    }
    if allow {
        return State::Visible;
    }
    let approved = match name {
        "NODE_ENV" => ["development", "test", "production"].contains(&value),
        "RUST_BACKTRACE" | "RUST_LIB_BACKTRACE" => ["0", "1", "full"].contains(&value),
        "CI" => ["true", "false", "0", "1"].contains(&value),
        "NO_COLOR" => value == "1",
        "FORCE_COLOR" => ["0", "1", "2", "3"].contains(&value),
        "CLICOLOR" | "CLICOLOR_FORCE" => ["0", "1"].contains(&value),
        _ => false,
    };
    if approved {
        State::Visible
    } else {
        State::Redacted
    }
}

pub fn flags(bits: u8, name: &str) -> Options {
    Options {
        allow: if bits & 1 != 0 {
            BTreeSet::from([name.to_owned()])
        } else {
            BTreeSet::new()
        },
        redact: if bits & 2 != 0 {
            BTreeSet::from([name.to_owned()])
        } else {
            BTreeSet::new()
        },
        ..Options::default()
    }
}

pub fn check_render(name: &str, value: &str, bits: u8) {
    let options = flags(bits, name);
    let expected = policy(name, Some(value), bits & 1 != 0, bits & 2 != 0);
    let snapshot = Snapshot {
        source: Source::Environment,
        values: RawVariables::from_pairs([(name.to_owned(), value.to_owned())]),
    };
    let records = environment::sanitize(&[snapshot], &options);
    let text = environment::render_text(&records).unwrap();
    let json = environment::render_json(&records).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let state = match expected {
        State::Missing => "missing",
        State::Empty => "empty",
        State::Redacted => "redacted",
        State::Visible => "visible",
    };
    let expected_hash = (expected == State::Redacted).then(|| hash(value));
    assert!(render_oracle::matches_record(
        name,
        value,
        state,
        expected_hash.as_deref(),
        &text,
        &json
    ));
    let record = &parsed["records"][0];
    assert_eq!(record["name"], name);
    assert_eq!(record["state"], state);
    match expected {
        State::Redacted => {
            assert!(record["value"].is_null());
            assert_eq!(record["fingerprint"], hash(value));
            assert!(text.contains(&format!("[REDACTED sha256={}]", hash(value))));
            if name == "SECRET" && value.starts_with("SYNTHETIC_FUZZ_CANARY_") {
                assert!(!oracle::leaks_canary(&text, value));
                assert!(!oracle::leaks_canary(&json, value));
                let escaped = serde_json::to_string(value).unwrap();
                assert!(!json.contains(&escaped));
            }
        }
        State::Visible | State::Empty => {
            assert_eq!(record["value"], value);
            assert!(record["fingerprint"].is_null());
        }
        State::Missing => unreachable!(),
    }
}

pub fn reference_union(input: &str, spans: &[Span]) -> Vec<Span> {
    let mut begins = vec![0usize; input.len() + 1];
    let mut ends = vec![0usize; input.len() + 1];
    for span in spans {
        if span.start < span.end {
            begins[span.start] += 1;
            ends[span.end] += 1;
        }
    }
    let mut output = Vec::new();
    let mut active = 0;
    let mut start = None;
    for index in 0..=input.len() {
        active -= ends[index];
        if active == 0
            && let Some(begin) = start.take()
        {
            output.push(Span {
                start: begin,
                end: index,
            });
        }
        if begins[index] > 0 && start.is_none() {
            start = Some(index);
        }
        active += begins[index];
    }
    output
}

pub fn reference_render(input: &str, spans: &[Span]) -> String {
    let mut result = String::new();
    let mut previous = 0;
    for span in reference_union(input, spans) {
        result.push_str(&input[previous..span.start]);
        result.push_str(&format!(
            "[REDACTED sha256={}]",
            hash(&input[span.start..span.end])
        ));
        previous = span.end;
    }
    result.push_str(&input[previous..]);
    result
}

pub fn format_fixture(data: &[u8]) -> Option<(String, String, i64)> {
    static FIXTURES: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    let fixtures = FIXTURES.get_or_init(|| {
        serde_json::from_str(include_str!("../tests/fixtures/secret-formats.json")).unwrap()
    });
    let cases = fixtures["cases"].as_array().unwrap();
    let index = data
        .iter()
        .take(8)
        .fold(0usize, |n, b| n.wrapping_mul(257).wrapping_add(*b as usize))
        % cases.len();
    let case = &cases[index];
    Some((
        case["input"].as_str()?.to_owned(),
        case["expected_stdout"].as_str()?.to_owned(),
        case["expected_exit"].as_i64()?,
    ))
}

pub mod oracle;

pub mod render_oracle;

pub fn check_fixture_oracles(data: &[u8]) {
    let (input, expected, exit) = format_fixture(data).unwrap();
    check_fixture(&input, &expected, exit);
    static CONTEXT: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    let context = CONTEXT.get_or_init(|| {
        serde_json::from_str(include_str!("../tests/fixtures/context-workflows.json")).unwrap()
    });
    let cases = context["cases"].as_array().unwrap();
    let index = data
        .iter()
        .rev()
        .take(8)
        .fold(0usize, |n, b| n.wrapping_mul(257).wrapping_add(*b as usize))
        % cases.len();
    let case = &cases[index];
    check_fixture(
        case["stdin_utf8"].as_str().unwrap(),
        case["expect"]["stdout_utf8"].as_str().unwrap(),
        case["expect"]["exit_code"].as_i64().unwrap(),
    );
    // A checked-in seed also replays its own exact oracle, rather than relying
    // only on the arbitrary input's span consistency or sampled fixture index.
    static EXACT: std::sync::OnceLock<std::collections::HashMap<String, (String, i64)>> =
        std::sync::OnceLock::new();
    let exact = EXACT.get_or_init(|| {
        let formats: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/secret-formats.json")).unwrap();
        let mut map = std::collections::HashMap::new();
        for case in formats["cases"].as_array().unwrap() {
            insert_oracle(
                &mut map,
                case["input"].as_str().unwrap(),
                case["expected_stdout"].as_str().unwrap(),
                case["expected_exit"].as_i64().unwrap(),
            );
        }
        for case in cases {
            insert_oracle(
                &mut map,
                case["stdin_utf8"].as_str().unwrap(),
                case["expect"]["stdout_utf8"].as_str().unwrap(),
                case["expect"]["exit_code"].as_i64().unwrap(),
            );
        }
        map
    });
    if let Ok(input) = std::str::from_utf8(data)
        && let Some((expected, exit)) = exact.get(input)
    {
        check_fixture(input, expected, *exit);
    }
}

fn insert_oracle(
    map: &mut std::collections::HashMap<String, (String, i64)>,
    input: &str,
    expected: &str,
    exit: i64,
) {
    let next = (expected.to_owned(), exit);
    if let Some(previous) = map.insert(input.to_owned(), next.clone()) {
        assert_eq!(
            previous, next,
            "duplicate fixture input has conflicting independent oracles"
        );
    }
}

fn check_fixture(input: &str, expected: &str, exit: i64) {
    match redact::filter(input.as_bytes()) {
        Ok(output) => {
            assert_eq!(exit, 0);
            assert_eq!(output, expected);
        }
        Err(error) => {
            assert_eq!(exit, 2);
            assert!(expected.is_empty());
            let diagnostic = format!("{error} {error:?}");
            assert!(!diagnostic.contains("CREDENTIAL_CANARY_"));
            assert!(!diagnostic.contains("SYNTHETIC_FUZZ_CANARY_"));
        }
    }
}
