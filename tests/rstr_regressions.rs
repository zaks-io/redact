//! Deterministic replays of confirmed rstr disclosure findings, using synthetic canaries.
#[allow(dead_code, reason = "shared harness; this suite only pipes stdin")]
mod support;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redact::fingerprint::marker;
use redact::rstr::filter;

const CANARY: &str = "synthetic-canary-heron-41";

fn m(secret: &str) -> String {
    marker(secret.as_bytes())
}

/// Assert the library and the real binary (cleared environment) agree on exact output.
fn assert_filters(cases: &[(String, String)]) {
    for (input, expected) in cases {
        let library = filter(input.as_bytes())
            .unwrap_or_else(|_| panic!("synthetic regression input rejected"));
        assert!(
            &library == expected,
            "library output differs for a synthetic regression"
        );
        let output = support::capture(&mut support::command("rstr"), input.as_bytes());
        assert_eq!(output.status.code(), Some(0));
        assert!(
            output.stdout == expected.as_bytes(),
            "binary output differs for a synthetic regression"
        );
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
    }
}

fn unchanged(inputs: &[&str]) -> Vec<(String, String)> {
    inputs
        .iter()
        .map(|input| ((*input).to_owned(), (*input).to_owned()))
        .collect()
}

fn jws() -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{CANARY}"}}"#));
    format!("{header}.{payload}.c3ludGhldGlj")
}

#[test]
fn log_field_after_label_or_flag_dashes_is_redacted() {
    let mut cases: Vec<(String, String)> = [
        "env: DB_PASSWORD=",
        "DEBUG: token=",
        "error: password: ",
        "x:DB_PASSWORD=",
        "level=info msg: api_key=",
        "mysql --password=",
        "curl --api-key=",
        "run -token=",
    ]
    .iter()
    .map(|prefix| {
        (
            format!("{prefix}{CANARY}\nstatus=401\n"),
            format!("{prefix}{}\nstatus=401\n", m(CANARY)),
        )
    })
    .collect();
    cases.extend(unchanged(&["status: 401 tokenizer=bpe\n"]));
    assert_filters(&cases);
}

#[test]
fn jwt_inside_dotted_runs_is_redacted_without_neighbors() {
    let token = jws();
    let mut cases: Vec<(String, String)> = [
        ("cookie.", " end"),
        ("v1.", ""),
        ("token is ", "."),
        ("", ".extra"),
    ]
    .iter()
    .map(|(before, after)| {
        (
            format!("{before}{token}{after}"),
            format!("{before}{}{after}", m(&token)),
        )
    })
    .collect();
    // serde_json's arbitrary_precision Value treats this first key as a number marker.
    let marker_payload = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(format!(
            r#"{{"$serde_json::private::Number":"123","sub":"{CANARY}"}}"#
        ))
    );
    cases.push((
        format!("cookie.{marker_payload} end"),
        format!("cookie.{} end", m(&marker_payload)),
    ));
    cases.extend(unchanged(&[
        "v1.2.3 release.notes.md a.b.c",
        "e30.e30.e30.e30",
    ]));
    assert_filters(&cases);
}

#[test]
fn rejected_provider_prefix_does_not_hide_a_later_candidate() {
    let key = format!("sk-{CANARY}");
    assert_filters(&[
        (
            format!("disk-usage={key}\n"),
            format!("disk-usage={}\n", m(&key)),
        ),
        (
            format!("task-runner/{key} ok\n"),
            format!("task-runner/{} ok\n", m(&key)),
        ),
        (
            format!("ask-ordinary {key}"),
            format!("ask-ordinary {}", m(&key)),
        ),
    ]);
}

#[test]
fn repeated_candidates_stay_linear_within_the_subprocess_timeout() {
    // Quadratic rescans of these shapes would exceed the support harness timeout.
    let size = 1024 * 1024;
    for unit in ["sk-a/", "a.", "e30.", "a://", "u:p#a://", "a: "] {
        let input = format!("x{}", unit.repeat(size / unit.len()));
        let output = support::capture(&mut support::command("rstr"), input.as_bytes());
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn camel_case_and_provider_field_spellings_are_sensitive() {
    let mut cases = vec![
        (
            format!(
                r#"{{"accessToken":"{CANARY}","refreshToken":"{CANARY}x","clientSecret":"{CANARY}y","maxTokens":512,"tokenizer":"bpe"}}"#
            ),
            format!(
                r#"{{"accessToken":"{}","refreshToken":"{}","clientSecret":"{}","maxTokens":512,"tokenizer":"bpe"}}"#,
                m(CANARY),
                m(&format!("{CANARY}x")),
                m(&format!("{CANARY}y"))
            ),
        ),
        (
            format!(
                r#"{{"AccessKeyId":"public-id","SecretAccessKey":"{CANARY}","SessionToken":"{CANARY}z"}}"#
            ),
            format!(
                r#"{{"AccessKeyId":"public-id","SecretAccessKey":"{}","SessionToken":"{}"}}"#,
                m(CANARY),
                m(&format!("{CANARY}z"))
            ),
        ),
        (
            format!(r#"{{"privateKeyData":"{CANARY}","inputTokens":"12"}}"#),
            format!(r#"{{"privateKeyData":"{}","inputTokens":"12"}}"#, m(CANARY)),
        ),
        (
            format!("//registry.npmjs.org/:_authToken={CANARY}\n"),
            format!("//registry.npmjs.org/:_authToken={}\n", m(CANARY)),
        ),
        (
            format!("APIKey: {CANARY}\nX-Api-Key: {CANARY}\n"),
            format!("APIKey: {}\nX-Api-Key: {}\n", m(CANARY), m(CANARY)),
        ),
        (
            format!("https://app.test/cb?accessToken={CANARY}&state=ok"),
            format!("https://app.test/cb?accessToken={}&state=ok", m(CANARY)),
        ),
        // Unquoted connection-string values stay conservative through the line ending.
        (
            format!("AccountName=public;AccountKey={CANARY};EndpointSuffix=core.windows.net\n"),
            format!(
                "AccountName=public;AccountKey={}\n",
                m(&format!("{CANARY};EndpointSuffix=core.windows.net"))
            ),
        ),
        (
            format!("SharedAccessSignature={CANARY}\n"),
            format!("SharedAccessSignature={}\n", m(CANARY)),
        ),
        // Arbitrary casing that camelCase splitting alone would break apart.
        (
            format!("PassWord={CANARY}\n{{\"PassWord\":\"{CANARY}\"}}\n"),
            format!(
                "PassWord={}\n{{\"PassWord\":\"{}\"}}\n",
                m(CANARY),
                m(CANARY)
            ),
        ),
    ];
    cases.extend(unchanged(&[
        r#"{"maxTokens":512,"tokenCount":"3","isTokenizer":"yes"}"#,
    ]));
    assert_filters(&cases);
}

#[test]
fn uri_passwords_with_unencoded_delimiters_hide_complete_user_information() {
    let mut cases: Vec<(String, String)> = ["#", "/", "?"]
        .iter()
        .map(|delimiter| {
            let userinfo = format!("user:pa{delimiter}{CANARY}");
            (
                format!("postgres://{userinfo}@db.test/app?sslmode=require"),
                format!("postgres://{}@db.test/app?sslmode=require", m(&userinfo)),
            )
        })
        .collect();
    let userinfo = format!(":p?{CANARY}");
    cases.push((
        format!("redis://{userinfo}@cache.test:6379"),
        format!("redis://{}@cache.test:6379", m(&userinfo)),
    ));
    let userinfo = format!("user:p#{CANARY}");
    cases.push((
        format!("postgres://{userinfo}@[::1]:5432/app"),
        format!("postgres://{}@[::1]:5432/app", m(&userinfo)),
    ));
    cases.extend(unchanged(&[
        "https://[::1]:3000/users/bob@example.test",
        "https://[2001:db8::1]/@author",
        "https://registry.npmjs.org/@scope/pkg",
        "http://localhost:3000/users/bob@example.test",
        "http://localhost:3000?email=bob@example.test",
        "https://medium.test/@author/post",
    ]));
    assert_filters(&cases);
}
