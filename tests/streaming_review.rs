#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use proptest::prelude::*;
use redact::{error::SafeError, filter, fingerprint, rstr::filter_to_writer};
use std::{
    io::{self, Read},
    process::Command,
};

const CANARY: &str = "SYNTHETIC_REVIEW_CANARY_0123456789";

struct Chunks<'a> {
    input: &'a [u8],
    position: usize,
    ends: Vec<usize>,
    size: usize,
}

impl Read for Chunks<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let end = self
            .ends
            .iter()
            .copied()
            .find(|end| *end > self.position)
            .unwrap_or(self.input.len());
        let count = (end - self.position).min(bytes.len()).min(self.size);
        bytes[..count].copy_from_slice(&self.input[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

#[derive(PartialEq, Eq)]
struct Outcome {
    output: Vec<u8>,
    report: Vec<u8>,
    error: Option<SafeError>,
}

fn streamed(input: &[u8], ends: Vec<usize>, size: usize) -> Outcome {
    let mut output = Vec::new();
    let mut report = Vec::new();
    let error = match filter_to_writer(
        Chunks {
            input,
            position: 0,
            ends,
            size,
        },
        &mut output,
    ) {
        Ok(metadata) => {
            metadata.write(&mut report).must();
            None
        }
        Err(error) => Some(error),
    };
    Outcome {
        output,
        report,
        error,
    }
}

fn line_ends(input: &[u8]) -> Vec<usize> {
    input
        .iter()
        .enumerate()
        .filter_map(|(at, byte)| (*byte == b'\n').then_some(at + 1))
        .collect()
}

fn review_cases() -> Vec<String> {
    vec![
        format!("{{\npassword: A}}\n  {CANARY}\n"),
        format!("x=[1,\npassword:A]\n  {CANARY}\n"),
        format!("password\\\": A \\\"!\n   {CANARY}\n"),
        format!("password\\\": A \\\"\n   {CANARY}\n"),
        format!("password':A\n  {CANARY}\n"),
        format!("password\\':A\n  {CANARY}\n"),
        format!("x=1\rpassword\":A\n  {CANARY}\n"),
        format!("[1/2]\rpassword\": A\n  {CANARY}\n"),
        format!("a \\\"b\\\" \rpassword:A\n  {CANARY}\n"),
        format!("x=1\rpassword\":|\n  {CANARY}\n"),
        format!(
            "payload='{{\n  \"kid\": \"synthetic team's key\",\n  \"kty\": \"oct\",\n  \"k\": \"{CANARY}\"\n}}'\n"
        ),
        format!(
            "INFO request body='{{\n  \"kid\": \"synthetic team's key\",\n  \"kty\": \"oct\",\n  \"k\": \"{CANARY}\"\n}}'\n"
        ),
        format!(
            "payload='{{\n  \"metadata\": {{\"annotations\": {{\"note\": \"synthetic team's\"}}}},\n  \"kind\": \"Secret\",\n  \"data\": {{\"tls.crt\": \"{CANARY}\"}}\n}}'\n"
        ),
        format!(
            "cfg='{{\n  \"note\": \"synthetic team's\",\n  \"auths\": {{\"registry.example\": {{\"auth\": \"{CANARY}\"}}}}\n}}'\n"
        ),
        format!("kind: Secret\n---\r\r\ndata:\n  tls.crt: {CANARY}\n"),
        format!("a\"b\nc\" {{\"kty\":\"oct\",\"k\":\"{CANARY}\"}}\n"),
        format!("body='{{\n \"kid\": \"synthetic team's\",\n \"password\": A}}\n  {CANARY}\n"),
        format!("note \"x\nkind: Secret\ny\"\ndata:\n  tls.crt: {CANARY}\n"),
        format!("[1/2]\rpassword\":|\n  {CANARY}\n"),
    ]
}

#[test]
fn complete_review_fixtures_are_covered_by_the_actual_batch_oracle() {
    for (case, input) in review_cases().iter().enumerate() {
        let output = filter(input.as_bytes()).must();
        assert!(
            !output.contains(CANARY),
            "batch did not cover review case {case}"
        );
    }
}

#[test]
fn reviewed_leaks_preserve_batch_removed_bytes_under_every_split() {
    for (case, input) in review_cases().iter().enumerate() {
        let expected = filter(input.as_bytes()).must();
        assert!(
            !expected.contains(CANARY),
            "batch oracle did not cover synthetic case {case}"
        );
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
        for split in 0..=input.len() {
            let result = streamed(input.as_bytes(), vec![split], usize::MAX);
            assert!(
                result.error.is_none(),
                "review case {case} failed at split {split}"
            );
            assert!(
                result.output == expected.as_bytes(),
                "review case {case} changed at split {split}"
            );
            assert!(
                result == whole,
                "review case {case} changed metadata at split {split}"
            );
        }
        for size in [1, 2, 3, 7, 31, 4096] {
            let result = streamed(input.as_bytes(), Vec::new(), size);
            assert!(
                result.error.is_none() && result.output == expected.as_bytes(),
                "review case {case} changed at size {size}"
            );
        }
        let result = streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX);
        assert!(
            result.error.is_none() && result.output == expected.as_bytes(),
            "review case {case} changed for line reads"
        );
    }
}

#[test]
fn earlier_ordinary_records_keep_separate_context_from_a_held_kind_wrapper() {
    let prefix = "status=200 request=synthetic\n";
    let wrapper = format!("note \"x\nkind: Secret\ny\"\ndata:\n  tls.crt: {CANARY}\n");
    let expected = format!("{prefix}{}", filter(wrapper.as_bytes()).must());
    assert!(!expected.contains(CANARY));
    let input = format!("{prefix}{wrapper}");
    let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
    for split in 0..=input.len() {
        let result = streamed(input.as_bytes(), vec![split], usize::MAX);
        assert!(
            result.error.is_none() && result.output == expected.as_bytes(),
            "held wrapper changed its record context at split {split}"
        );
        assert!(
            result == whole,
            "held wrapper result changed with read timing"
        );
    }
}

#[test]
fn multiline_json_key_preserves_the_batch_continuation_context() {
    let continuation = "SYNTHETIC_ORDINARY_CONTINUATION";
    let input = format!("{{\n\"password\"\n: {CANARY}}}\n  {continuation}\n");
    let expected = filter(input.as_bytes()).must();
    assert!(!expected.contains(CANARY));
    assert!(expected.contains(continuation));
    assert!(expected.contains(&format!("sha256={}", fingerprint(CANARY))));
    let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
    for split in 0..=input.len() {
        let result = streamed(input.as_bytes(), vec![split], usize::MAX);
        assert!(
            result.error.is_none() && result.output == expected.as_bytes(),
            "multiline JSON key changed at split {split}"
        );
        assert!(
            result == whole,
            "multiline JSON key changed metadata across chunks"
        );
    }
    for size in [1, 2, 7, 31] {
        assert!(streamed(input.as_bytes(), Vec::new(), size) == whole);
    }
}

#[test]
fn continuation_hashes_cover_the_exact_complete_secret_span() {
    let input = format!("{{\npassword: A}}\n  {CANARY}\n");
    let expected = format!(
        "{{\npassword: [REDACTED sha256={}]\n",
        fingerprint(format!("A}}\n  {CANARY}"))
    );
    assert!(filter(input.as_bytes()).must() == expected);
    let result = streamed(input.as_bytes(), line_ends(input.as_bytes()), 1);
    assert!(result.error.is_none() && result.output == expected.as_bytes());
}

#[test]
fn separator_acceptance_matches_batch_with_one_or_two_carriage_returns() {
    for cr in ["\r", "\r\r"] {
        let input = format!("kind: Secret\n---{cr}\ndata:\n  tls.crt: {CANARY}\n");
        let expected = filter(input.as_bytes()).must();
        for size in [1, 7, usize::MAX] {
            let result = streamed(input.as_bytes(), Vec::new(), size);
            assert!(result.error.is_none() && result.output == expected.as_bytes());
        }
    }
}

#[test]
fn shrunk_wire_name_sequence_has_one_result_for_every_read_boundary() {
    let input = "password\\\":\npassword\\\":\n ,\n".as_bytes();
    let expected = streamed(input, Vec::new(), usize::MAX);
    for split in 0..=input.len() {
        assert!(
            streamed(input, vec![split], usize::MAX) == expected,
            "shrunk synthetic sequence changed at split {split}"
        );
    }
    for size in [1, 2, 3, 7] {
        assert!(
            streamed(input, Vec::new(), size) == expected,
            "shrunk synthetic sequence changed at size {size}"
        );
    }
}

fn structured_case() -> impl Strategy<Value = String> {
    (
        0usize..4,
        0usize..5,
        0usize..6,
        1usize..8,
        "[a-z0-9秘密é_-]{1,24}",
    )
        .prop_map(|(context, closer, value, indentation, tail)| {
            let (prefix, suffix) =
                [("", ""), ("{\n", "}"), ("x=[1,\n", "]"), ("x=1\r", "")][context];
            let closer = ["", "\"", "'", "\\\"", "\\'"][closer];
            let value = ["A", "A \\\"!", "A \\\"", "|", ">", "A\"!"][value];
            format!(
                "{prefix}password{closer}:{value}{suffix}\n{}{CANARY}_{tail}\n",
                " ".repeat(indentation)
            )
        })
}

fn json_log_case() -> impl Strategy<Value = String> {
    (0usize..3, prop::sample::select(vec!["payload=", "INFO request body=", "cfg="]), 0usize..4, "[a-z0-9秘密é_-]{1,24}").prop_map(
        |(kind, prefix, blanks, tail)| {
            let body = match kind {
                0 => format!("\"kid\": \"synthetic team's key\",\n  \"kty\": \"oct\",\n  \"k\": \"{CANARY}_{tail}\""),
                1 => format!("\"metadata\": {{\"annotations\": {{\"note\": \"synthetic team's\"}}}},\n  \"kind\": \"Secret\",\n  \"data\": {{\"tls.crt\": \"{CANARY}_{tail}\"}}"),
                _ => format!("\"note\": \"synthetic team's\",\n  \"auths\": {{\"registry.example\": {{\"auth\": \"{CANARY}_{tail}\"}}}}"),
            };
            format!("{prefix}'{{\n{}  {body}\n}}'\n", "\n".repeat(blanks))
        },
    )
}

fn token_records() -> impl Strategy<Value = String> {
    let token = prop::sample::select(vec![
        "password:",
        "password\":",
        "password\\\":",
        "password=",
        "x=1",
        "\r",
        "A",
        "}",
        "]",
        "{",
        "[",
        "'",
        "\"",
        "synthetic team's",
        "kind: Secret",
        "data:",
        "|",
        "!",
        "\\\"",
        ",",
        CANARY,
    ]);
    prop::collection::vec((0usize..3, prop::collection::vec(token, 1..5)), 2..6).prop_map(|lines| {
        lines
            .into_iter()
            .map(|(indent, tokens)| format!("{}{}\n", " ".repeat(indent), tokens.concat()))
            .collect()
    })
}

fn pem_tail_case(header: usize, label: usize, tail: &str, indent: usize) -> String {
    let header = [
        "x=[1,\npassword:A]\n",
        "{\npassword: A}\n",
        "x=1\rpassword\":A\n",
    ][header];
    let label = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"][label];
    let padding = " ".repeat(indent);
    format!(
        "{header}{padding}-----BEGIN {label}-----\n{padding}MIIsynthetic\n{padding}-----END {label}-----{tail}\n{padding}{CANARY}\n"
    )
}

fn cr_name_case(quote: char, spacing: &str, value: &str, indent: usize) -> String {
    format!(
        "[1/2]\r{quote}password{quote}{spacing}:{value}\n{}{CANARY}\n",
        " ".repeat(indent)
    )
}

fn assert_complete_batch_record(input: &str) {
    let expected = filter(input.as_bytes()).must();
    assert!(
        !expected.contains(CANARY),
        "synthetic fixture is not batch-hidden"
    );
    let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
    assert!(
        whole.error.is_none() && whole.output == expected.as_bytes(),
        "synthetic record differs from batch"
    );
    for split in 0..=input.len() {
        assert!(
            streamed(input.as_bytes(), vec![split], usize::MAX) == whole,
            "synthetic record changed at split {split}"
        );
    }
    for size in [1, 2, 7, 31] {
        assert!(
            streamed(input.as_bytes(), Vec::new(), size) == whole,
            "synthetic record changed at read size {size}"
        );
    }
    assert!(
        streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX) == whole,
        "synthetic record changed for per-line reads"
    );
}

fn forward_quoted_assignment_cases() -> Vec<String> {
    let mut cases = Vec::new();
    for opening in ['{', '['] {
        for ending in ["\n", "\r\n"] {
            for spacing in ["\n", "\r\n", " \t\r\n\t", "\n\n"] {
                cases.push(format!(
                    "\\\"{opening}password\\\":{spacing}{CANARY}{ending}"
                ));
            }
            for spacing in ["", " ", "\t"] {
                cases.push(format!(
                    "\\\"{opening}password\\\"={spacing}{CANARY}{ending}"
                ));
            }
        }
    }
    cases
}

#[test]
fn wire_closing_names_keep_forward_looking_assignment_values_in_one_record() {
    for input in forward_quoted_assignment_cases() {
        assert_complete_batch_record(&input);
    }
}

#[test]
fn pem_end_tail_punctuators_never_end_an_indented_sensitive_value() {
    for tail in b'!'..=b'~' {
        if tail.is_ascii_punctuation() {
            assert_complete_batch_record(&pem_tail_case(0, 0, &char::from(tail).to_string(), 2));
        }
    }
    for (header, label, tail) in [(1, 1, ","), (2, 2, "x"), (0, 0, "")] {
        assert_complete_batch_record(&pem_tail_case(header, label, tail, 2));
    }
}

#[test]
fn quoted_sensitive_names_keep_continuations_when_colons_follow_carriage_returns() {
    for quote in ['\"', '\''] {
        for spacing in ["\r", " \r ", "\t\r\t"] {
            for value in [" A", " |", " >", ""] {
                assert_complete_batch_record(&cr_name_case(quote, spacing, value, 2));
            }
        }
    }
}

#[test]
fn held_wire_assignments_do_not_hide_later_well_formed_json_credentials() {
    let wire = format!("{CANARY}_WIRE");
    for object in credential_objects(CANARY) {
        let input = format!("note:\npassword=\\\"{wire}\\\"\n{object}\n");
        let expected = format!(
            "note:\npassword=\\\"[REDACTED sha256={}]\\\"\n[REDACTED sha256={}]\n",
            fingerprint(&wire),
            fingerprint(&object)
        );
        assert!(
            filter(input.as_bytes()).must() == expected,
            "batch wire grammar missed a later real JSON container"
        );
        assert_complete_batch_record(&input);
    }
}

fn credential_objects(secret: &str) -> [String; 4] {
    let value = serde_json::to_string(secret).must();
    [
        format!("{{\"kty\":\"oct\",\"k\":{value}}}"),
        format!("{{\n  \"kid\": \"synthetic key\",\n  \"kty\": \"oct\",\n  \"k\": {value}\n}}"),
        format!("{{\"auths\":{{\"registry.example\":{{\"auth\":{value}}}}}}}"),
        format!("{{\"data\":{{\"tls.crt\":{value}}},\"kind\":\"Secret\"}}"),
    ]
}

#[test]
fn opaque_private_key_bodies_do_not_hide_later_json_credentials_in_held_records() {
    for body_quote in ["", "\"", "'", "\\\"", "\"'", "\"]}"] {
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{CANARY}_PEM {body_quote}\n-----END PRIVATE KEY-----"
        );
        for object in credential_objects(CANARY) {
            for prefix in ["note:\n", ""] {
                let input = format!("{prefix}{pem}\n{object}\n");
                let expected = format!(
                    "{prefix}[REDACTED sha256={}]\n[REDACTED sha256={}]\n",
                    fingerprint(&pem),
                    fingerprint(&object)
                );
                assert!(
                    filter(input.as_bytes()).must() == expected,
                    "opaque PEM body changed later JSON detection"
                );
                assert_complete_batch_record(&input);
            }
        }
    }
}

#[test]
fn valid_json_credentials_with_private_key_strings_keep_the_full_container_fingerprint() {
    for body_quote in ["", "\"", "'", "\\\"", "\"'", "\"]}"] {
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{CANARY}_PEM {body_quote}\n-----END PRIVATE KEY-----"
        );
        for object in credential_objects(&pem) {
            assert!(
                serde_json::from_str::<serde_json::Value>(&object).is_ok(),
                "synthetic embedded PEM fixture is not valid JSON"
            );
            let input = format!("note:\n{object}\n");
            let expected = format!("note:\n[REDACTED sha256={}]\n", fingerprint(&object));
            assert!(
                filter(input.as_bytes()).must() == expected,
                "embedded PEM failed or changed merged container fingerprint"
            );
            assert_complete_batch_record(&input);
        }
    }
}

#[derive(serde::Deserialize)]
struct ReviewRecord {
    name: String,
    family: String,
    input: String,
    expected: String,
    protected: Vec<String>,
}

fn fourth_review_records() -> Vec<ReviewRecord> {
    serde_json::from_str(r###"[
{"name":"A multiline single-quoted name, block scalar","input":"'x\n.password': |\n  SYNTHCANA1\n  SYNTHCANA2\n","expected":"'x\n.password': [REDACTED sha256=40afe69b16608efb]\n","protected":["SYNTHCANA1","SYNTHCANA2"],"family":"multiline"},
{"name":"B multiline single-quoted name, plain + continuation","input":"'x\n.password': value\n  SYNTHCANB1\n  SYNTHCANB2\n","expected":"'x\n.password': [REDACTED sha256=1504a35e8d45b073]\n","protected":["SYNTHCANB1","SYNTHCANB2"],"family":"multiline"},
{"name":"C multiline name, second line indented 1","input":"'my\n password': value\n SYNTHCANC1\n SYNTHCANC2\n","expected":"'my\n password': [REDACTED sha256=6ce257f131624018]\n","protected":["SYNTHCANC1","SYNTHCANC2"],"family":"multiline"},
{"name":"C2 multiline name, second line indented 4","input":"'my\n    password': value\n  SYNTHCANC3\n  SYNTHCANC4\n","expected":"'my\n    password': [REDACTED sha256=8fbc76199de710c0]\n","protected":["SYNTHCANC3","SYNTHCANC4"],"family":"multiline"},
{"name":"D control single-line quoted name block","input":"'x.password': |\n  SYNTHCAND1\n  SYNTHCAND2\n","expected":"'x.password': [REDACTED sha256=c562df0b9ad17cd4]\n","protected":["SYNTHCAND1","SYNTHCAND2"],"family":"multiline"},
{"name":"D2 control double-quoted multiline name (serde rejects)","input":"\"x\n.password\": |\n  SYNTHCAND3\n","expected":"\"x\n.password\": |\n  SYNTHCAND3\n","protected":[],"family":"multiline"},
{"name":"D3 multiline single-quoted name, colon then next-line value","input":"'x\n.password':\n  SYNTHCAND4\n  SYNTHCAND5\n","expected":"'x\n.password':\n  [REDACTED sha256=d7c8d30275f95f52]\n","protected":["SYNTHCAND4","SYNTHCAND5"],"family":"multiline"},
{"name":"E wire parity false negative, bracket record","input":"[ 'a 'x,password'=\\\"]\\\"\n\"token\":\n\"SYNTHCANE1\"\n]\n","expected":"[ 'a 'x,password'=\\\"[REDACTED sha256=cfae0d4248f7142f]\\\"\n\"token\":\n\"[REDACTED sha256=6187cb3db0b244c2]\"\n]\n","protected":["SYNTHCANE1"],"family":"wire"},
{"name":"E2 same with slash name","input":"[ 'a 'x/password'=\\\"]\\\"\n\"token\":\n\"SYNTHCANE2\"\n]\n","expected":"[ 'a 'x/password'=\\\"[REDACTED sha256=cfae0d4248f7142f]\\\"\n\"token\":\n\"[REDACTED sha256=585f1663f6ff75a9]\"\n]\n","protected":["SYNTHCANE2"],"family":"wire"},
{"name":"E3 parity false negative, brace + json container value","input":"{ 'a 'x,password'=\\\"}\\\"\n\"token\": {\n\"k\": \"SYNTHCANE3\"\n}\n}\n","expected":"{ 'a 'x,password'=\\\"[REDACTED sha256=d10b36aa74a59bcf]\\\"\n\"token\": [REDACTED sha256=b60eade35baf0c12]\n}\n","protected":["SYNTHCANE3"],"family":"wire"},
{"name":"F control known wire hides closer","input":"[ password=\\\"]\\\"\n\"token\":\n\"SYNTHCANF1\"\n]\n","expected":"[ password=\\\"[REDACTED sha256=cfae0d4248f7142f]\\\"\n\"token\":\n\"[REDACTED sha256=3baa46f54ee73347]\"\n]\n","protected":["SYNTHCANF1"],"family":"wire"},
{"name":"G plain value apostrophe hides bracket","input":"token=x 'y\n[ 1 '\n\"token\":\n\"SYNTHCANG1\"\n]\n","expected":"token=[REDACTED sha256=68f7107f4a8736e8]\n[ 1 '\n\"token\":\n\"[REDACTED sha256=2467a9c58e63af96]\"\n]\n","protected":["SYNTHCANG1"],"family":"plain"},
{"name":"H plain value dquote hides bracket","input":"token=x \"y\n[ 1 \"\n\"token\":\n\"SYNTHCANH1\"\n]\n","expected":"token=[REDACTED sha256=512b0cc1126faf82]\n[ 1 \"\n\"token\":\n\"[REDACTED sha256=13200fcffd2e5af0]\"\n]\n","protected":["SYNTHCANH1"],"family":"plain"},
{"name":"I wire false positive exact-list name hides opener","input":"'a 'shared access signature'=\\\"{\\\"\n\"token\":\n\"SYNTHCANI1\"\n}\n","expected":"'a 'shared access signature'=\\\"{\\\"\n\"token\":\n\"[REDACTED sha256=9680fcb30d2a4490]\"\n}\n","protected":["SYNTHCANI1"],"family":"wire"},
{"name":"R1 round3 PEM END trailing text","input":"x=[1,\npassword:A]\n  -----BEGIN PRIVATE KEY-----\n  M\n  -----END PRIVATE KEY-----.\n  SYNTHCANR1\n","expected":"x=[1,\npassword:[REDACTED sha256=7e030c591f2ac20a]\n","protected":["SYNTHCANR1"],"family":"prior"},
{"name":"R2 round3 CR quoted name colon","input":"[1/2]\r\"password\"\r: A\n  SYNTHCANR2\n","expected":"[1/2]\r\"password\"\r: [REDACTED sha256=ffaac2ece621e29e]\n","protected":["SYNTHCANR2"],"family":"prior"},
{"name":"R3 round3 wire then JWK","input":"password=\\\"wirevalue\\\"\n{\"kty\":\"oct\",\"k\":\"SYNTHCANR3\"}\n","expected":"password=\\\"[REDACTED sha256=dd11522488f34327]\\\"\n[REDACTED sha256=767dd7bebfed4f6d]\n","protected":["SYNTHCANR3"],"family":"wire"},
{"name":"R4 URL first line then JWK","input":"Server listening on http://localhost:3000\npassword=\\\"w\\\"\n{\"kty\":\"oct\",\"k\":\"SYNTHCANR4\"}\n","expected":"Server listening on http://localhost:3000\npassword=\\\"[REDACTED sha256=50e721e49c013f00]\\\"\n[REDACTED sha256=14f7667cfdf5b28f]\n","protected":["SYNTHCANR4"],"family":"wire"},
{"name":"J1 json newline value block header, bracket","input":"[\n\"api_key\":\n|\n ]\n\tSYNTHCANJ1\n","expected":"[\n\"api_key\":\n[REDACTED sha256=72c005f3a06e5b20]\n","protected":["SYNTHCANJ1"],"family":"delayed"},
{"name":"J2 pretty-ish object, block header on next line","input":"{\n  \"password\":\n  |\n    }\n    SYNTHCANJ2\n","expected":"{\n  \"password\":\n  [REDACTED sha256=770ac0d748d3ab58]\n","protected":["SYNTHCANJ2"],"family":"delayed"},
{"name":"J3 comment header on next line","input":"[\n\"api_key\":\n# note\n ]\n\tSYNTHCANJ3\n","expected":"[\n\"api_key\":\n# note\n [REDACTED sha256=aec2c451c3018d2a]\n","protected":["SYNTHCANJ3"],"family":"delayed"},
{"name":"J4 closer later, block lines indented","input":"[\n\"api_key\":\n|\n  SYNTHCANJ4\n]\n  SYNTHCANJ5\n","expected":"[\n\"api_key\":\n[REDACTED sha256=1cb3ad8c214602c4]\n]\n  SYNTHCANJ5\n","protected":["SYNTHCANJ4"],"family":"delayed"},
{"name":"J5 log prefix then object","input":"INFO {\n\"token\":\n>\n }\n SYNTHCANJ6\n","expected":"INFO {\n\"token\":\n[REDACTED sha256=6fa43417fa0cda8f]\n","protected":["SYNTHCANJ6"],"family":"delayed"},
{"name":"G-record bracket record alone (apostrophe)","input":"[ 1 '\n\"token\":\n\"SYNTHCANG2\"\n]\n","expected":"[ 1 '\n\"token\":\n\"[REDACTED sha256=d0b80f696a3fa0b0]\"\n]\n","protected":["SYNTHCANG2"],"family":"plain"},
{"name":"H-record bracket record alone (dquote)","input":"[ 1 \"\n\"token\":\n\"SYNTHCANH2\"\n]\n","expected":"[ 1 \"\n\"token\":\n\"[REDACTED sha256=12bdb4b7e5389491]\"\n]\n","protected":["SYNTHCANH2"],"family":"plain"},
{"name":"I-record without wire prefix","input":"{\n\"token\":\n\"SYNTHCANI2\"\n}\n","expected":"{\n\"token\":\n\"[REDACTED sha256=bff2d8c4e2600cb6]\"\n}\n","protected":["SYNTHCANI2"],"family":"wire"},
{"name":"E-record minimal json multi-line in brackets","input":"[\n\"token\":\n\"SYNTHCANE4\"\n]\n","expected":"[\n\"token\":\n\"[REDACTED sha256=0a63a0d0aa00477b]\"\n]\n","protected":["SYNTHCANE4"],"family":"wire"},
{"name":"A-live realistic-ish wrapped key","input":"'db\n.password': |\n  SYNTHCANA3\n","expected":"'db\n.password': [REDACTED sha256=40effc37aa603df5]\n","protected":["SYNTHCANA3"],"family":"multiline"},
{"name":"A-variant equals delimiter (no continuation expected)","input":"'x\n.password'= SYNTHCANA4\n","expected":"'x\n.password'= [REDACTED sha256=7e375fadc0ad9d98]\n","protected":["SYNTHCANA4"],"family":"multiline"},
{"name":"A-variant multi-line name inside sequence","input":"- 'x\n  .password': |\n    SYNTHCANA5\n","expected":"- 'x\n  .password': [REDACTED sha256=0b2628f1a6fcffad]\n","protected":["SYNTHCANA5"],"family":"multiline"},
{"name":"K1 password with $' then multi-line quoted token (fail-closed difference)","input":"password=pa$$'word\ntoken='SYNTHCANK1\nSYNTHCANK2'\n","expected":"password=[REDACTED sha256=8b44799834a4ffb1]\ntoken='[REDACTED sha256=d229aa1e82845bea]'\n","protected":["SYNTHCANK1","SYNTHCANK2"],"family":"plain"},
{"name":"K2 control without the apostrophe","input":"password=pa$$word\ntoken='SYNTHCANK3\nSYNTHCANK4'\n","expected":"password=[REDACTED sha256=6a158d9847a80e99]\ntoken='[REDACTED sha256=3a63fed167cc8e51]'\n","protected":["SYNTHCANK3","SYNTHCANK4"],"family":"plain"},
{"name":"Full contextual residual 9","input":"|Bob'spassword\\\":\npassword=password: ,[\n{\\\"\n  data:password\":\rSYNTHETICCANARYZQ7\n","expected":"|Bob'spassword\\\":\npassword=[REDACTED sha256=6b2f79d44a25defc]\n{\\\"\n  data:password\":\r[REDACTED sha256=7cefddf332486189]\n","protected":["SYNTHETICCANARYZQ7"],"family":"wire"},
{"name":"Full contextual residual 33","input":"\\\"\n 'password\\\":!\n {\"SYNTHETICCANARYZQ7]\n Bob'sdata:]\n  \"password:password:\n","expected":"\\\"\n 'password\\\":[REDACTED sha256=dcda2e7d20eea00f]'sdata:]\n  \"password:[REDACTED sha256=c304787445ce7cab]\n","protected":["SYNTHETICCANARYZQ7"],"family":"wire"},
{"name":"wire-opener-ordinary-closer-container","input":"{\\\"\n  data:password\":\rSYNTHETICCANARYZQ7\n","expected":"{\\\"\n  data:password\":\r[REDACTED sha256=7cefddf332486189]\n","protected":["SYNTHETICCANARYZQ7"],"family":"wire"},
{"name":"wire-opener-ordinary-closer-field","input":"{\\\"\n  password\":\rSYNTHETICCANARYZQ7\n","expected":"{\\\"\n  password\":\r[REDACTED sha256=7cefddf332486189]\n","protected":["SYNTHETICCANARYZQ7"],"family":"wire"},
{"name":"wire-opener-ordinary-closer-inline","input":"{\\\"\n  data:password\": SYNTHETICCANARYZQ7\n","expected":"{\\\"\n  data:password\": [REDACTED sha256=7cefddf332486189]\n","protected":["SYNTHETICCANARYZQ7"],"family":"wire"},
{"name":"quoted-name-prefix","input":"\\\"\n 'password\\\":!\n {\"SYNTHETICCANARYZQ7]\n Bob'sdata:]\n  \"password:password:\n","expected":"\\\"\n 'password\\\":[REDACTED sha256=dcda2e7d20eea00f]'sdata:]\n  \"password:[REDACTED sha256=c304787445ce7cab]\n","protected":["SYNTHETICCANARYZQ7"],"family":"wire"},
{"name":"URL query suffix overlap","input":"https://example.test/?token=x&public=ok 'tail\n[\n\"token\":\n\"SYNTHETIC_REVIEW_CANARY_0123456789\"\n]\n","expected":"https://example.test/?token=[REDACTED sha256=2d711642b726b044]&public=ok 'tail\n[\n\"token\":\n\"[REDACTED sha256=fce6ae659b1d7d5e]\"\n]\n","protected":["SYNTHETIC_REVIEW_CANARY_0123456789"],"family":"plain"},
{"name":"Connection field quote overlap","input":"Server=synthetic;Password=x'y;Database=test\n[\n\"token\":\n\"SYNTHETIC_REVIEW_CANARY_0123456789\"\n]\n","expected":"Server=synthetic;Password=[REDACTED sha256=d0e5224208162abb]\n[\n\"token\":\n\"[REDACTED sha256=fce6ae659b1d7d5e]\"\n]\n","protected":["SYNTHETIC_REVIEW_CANARY_0123456789"],"family":"plain"},
{"name":"Authentication field quote overlap","input":"Authorization: Bearer token=x 'tail\n[\n\"token\":\n\"SYNTHETIC_REVIEW_CANARY_0123456789\"\n]\n","expected":"Authorization: Bearer [REDACTED sha256=d8733b7f1937258b]\n[\n\"token\":\n\"[REDACTED sha256=fce6ae659b1d7d5e]\"\n]\n","protected":["SYNTHETIC_REVIEW_CANARY_0123456789"],"family":"plain"},
{"name":"Wire URL query ampersand boundary","input":"https://example.test/?token=\\\"opaque&public=ok\\\"\n[\n\"token\":\n\"SYNTHETIC_REVIEW_CANARY_0123456789\"\n]\n","expected":"https://example.test/?token=[REDACTED sha256=a9253dc8529dd214]\"opaque&public=ok\\\"\n[\n\"token\":\n\"[REDACTED sha256=fce6ae659b1d7d5e]\"\n]\n","protected":["SYNTHETIC_REVIEW_CANARY_0123456789"],"family":"plain"},
{"name":"Wire URL query literal closer","input":"https://example.test/?token=\\\"]&public=ok\\\"\n[\n\"token\":\n\"SYNTHETIC_REVIEW_CANARY_0123456789\"\n]\n","expected":"https://example.test/?token=[REDACTED sha256=a9253dc8529dd214]\"]&public=ok\\\"\n[\n\"token\":\n\"[REDACTED sha256=fce6ae659b1d7d5e]\"\n]\n","protected":["SYNTHETIC_REVIEW_CANARY_0123456789"],"family":"plain"}
]"###).must()
}

fn assert_pinned_review_record(case: &ReviewRecord) {
    let batch = match filter(case.input.as_bytes()) {
        Ok(output) => output,
        Err(_) => panic!("batch rejected synthetic review fixture {}", case.name),
    };
    assert!(
        batch == case.expected,
        "batch changed exact spans for {}",
        case.name
    );
    for canary in &case.protected {
        assert!(
            !batch.contains(canary),
            "batch did not protect a synthetic review canary"
        );
    }
    let whole = streamed(case.input.as_bytes(), Vec::new(), usize::MAX);
    assert!(
        whole.error.is_none() && whole.output == case.expected.as_bytes(),
        "stream changed exact spans for {}",
        case.name
    );
    for split in 0..=case.input.len() {
        assert!(
            streamed(case.input.as_bytes(), vec![split], usize::MAX) == whole,
            "{} changed at split {split}",
            case.name
        );
    }
    for size in [1, 2, 7, 31, 4096] {
        assert!(
            streamed(case.input.as_bytes(), Vec::new(), size) == whole,
            "{} changed at read size {size}",
            case.name
        );
    }
    assert!(
        streamed(
            case.input.as_bytes(),
            line_ends(case.input.as_bytes()),
            usize::MAX
        ) == whole,
        "{} changed with line reads",
        case.name
    );
}

fn check_review_family(family: &str) {
    for case in fourth_review_records()
        .iter()
        .filter(|case| case.family == family)
    {
        assert_pinned_review_record(case);
    }
}

#[test]
fn fourth_review_multiline_names_preserve_exact_batch_spans_and_controls() {
    check_review_family("multiline");
}

#[test]
fn fourth_review_delayed_headers_preserve_exact_batch_spans_and_controls() {
    check_review_family("delayed");
}

#[test]
fn fourth_review_plain_value_punctuation_and_structured_overlaps_preserve_batch_spans() {
    check_review_family("plain");
}

#[test]
fn fourth_review_forward_quote_pairing_and_unknown_wire_quotes_preserve_batch_spans() {
    check_review_family("wire");
    check_review_family("prior");
}

fn pin_synthetic_values(input: String, values: Vec<String>) -> (String, String) {
    let mut expected = String::new();
    let mut remaining = input.as_str();
    for value in values {
        let (prefix, tail) = remaining.split_once(&value).must();
        expected.push_str(prefix);
        expected.push_str(&format!("[REDACTED sha256={}]", fingerprint(&value)));
        remaining = tail;
    }
    expected.push_str(remaining);
    (input, expected)
}

fn multiline_name_record(
    quote: char,
    eol: &str,
    layout: (usize, usize, usize, bool),
    header: usize,
    gap: &str,
    tail: &str,
) -> (String, String) {
    let (opening_indent, closing_indent, extra, sequence) = layout;
    let sequence = if sequence { "- " } else { "" };
    let name = format!("my{eol}{}.password", " ".repeat(closing_indent));
    let name = if quote == '"' {
        serde_json::to_string(&name).must()
    } else {
        format!("'{name}'")
    };
    let prefix = format!("{}{sequence}{name}{gap}:{gap}", " ".repeat(opening_indent));
    let padding = " ".repeat(opening_indent + sequence.len() + extra);
    let first = format!("{CANARY}_{tail}_A");
    let second = format!("{CANARY}_{tail}_B");
    let body = format!("{padding}{first}{eol}{padding}{second}");
    let header = ["|", ">", "synthetic-head", ""][header];
    let input = format!("{prefix}{header}{eol}{body}{eol}");
    let removed = if header.is_empty() {
        format!("{first}{eol}{padding}{second}")
    } else {
        format!("{header}{eol}{body}")
    };
    pin_synthetic_values(input, vec![removed])
}

fn delayed_header_record(
    quote: char,
    eol: &str,
    layout: (usize, usize, usize),
    header: usize,
    gap: &str,
    tail: &str,
) -> (String, String) {
    let (container, indent, extra) = layout;
    let (prefix, closer, name) = [
        ("[", "]", "api_key"),
        ("{", "}", "password"),
        ("INFO {", "}", "token"),
    ][container];
    let name_padding = " ".repeat(indent);
    let padding = " ".repeat(indent + extra);
    let header = ["|", ">", "# synthetic note"][header];
    let secret = format!("{CANARY}_{tail}");
    let input = format!(
        "{prefix}{eol}{name_padding}{quote}{name}{quote}{gap}:{gap}{eol}{name_padding}{header}{eol}{padding}{closer}{eol}{padding}{secret}{eol}"
    );
    let removed = if header.starts_with('#') {
        format!("{closer}{eol}{padding}{secret}")
    } else {
        format!("{header}{eol}{padding}{closer}{eol}{padding}{secret}")
    };
    pin_synthetic_values(input, vec![removed])
}

fn plain_punctuation_record(
    variant: usize,
    quote: char,
    eol: &str,
    delimiter: &str,
    tail: &str,
) -> (String, String) {
    let secret = format!("{CANARY}_{tail}");
    if variant == 3 {
        let first = format!("pa$${quote}word");
        let body = format!("{secret}{eol}{secret}_TAIL");
        let input = format!("password={first}{eol}token={quote}{body}{quote}{eol}");
        return pin_synthetic_values(input, vec![first, body]);
    }
    let raw = match variant {
        0 => format!("x {quote}y"),
        1 => format!("x [{quote}y"),
        _ => format!("x {{{quote}y"),
    };
    let input =
        format!("token{delimiter}{raw}{eol}[ 1 {quote}{eol}\"token\":{eol}\"{secret}\"{eol}]{eol}");
    pin_synthetic_values(input, vec![raw, secret])
}

fn forward_pairing_record(
    variant: usize,
    quote: char,
    eol: &str,
    separator: &str,
    delimiter: char,
    gap: &str,
    tail: &str,
) -> (String, String) {
    let secret = format!("{CANARY}_{tail}");
    if variant == 1 {
        let input = format!(
            "{quote}a {quote}shared access signature{quote}{gap}{delimiter}{gap}\\\"{{\\\"{eol}\"token\":{eol}\"{secret}\"{eol}}}{eol}"
        );
        return pin_synthetic_values(input, vec![secret]);
    }
    let name = match variant {
        0 => format!("{quote}a {quote}x{separator}password{quote}"),
        2 => "password".to_owned(),
        _ => format!("{quote}password{quote}"),
    };
    let input = format!(
        "[ {name}{gap}{delimiter}{gap}\\\"]\\\"{eol}\"token\":{eol}\"{secret}\"{eol}]{eol}"
    );
    pin_synthetic_values(input, vec!["]".to_owned(), secret])
}

fn fourth_review_grammar() -> impl Strategy<Value = (String, String)> {
    (
        0usize..4,
        0usize..4,
        prop::sample::select(vec!['\'', '"']),
        prop::sample::select(vec!["\n", "\r\n"]),
        (0usize..3, 0usize..8, 1usize..6, any::<bool>()),
        prop::sample::select(vec!["", " ", "\t"]),
        prop::sample::select(vec![",", "/"]),
        prop::sample::select(vec![':', '=']),
        "[a-z0-9秘密é_-]{1,16}",
    )
        .prop_map(
            |(family, variant, quote, eol, layout, gap, separator, delimiter, tail)| match family {
                0 => multiline_name_record(quote, eol, layout, variant, gap, &tail),
                1 => delayed_header_record(
                    quote,
                    eol,
                    (variant % 3, layout.0, layout.2),
                    variant % 3,
                    gap,
                    &tail,
                ),
                2 => plain_punctuation_record(
                    variant,
                    quote,
                    eol,
                    if delimiter == '=' { "=" } else { " : " },
                    &tail,
                ),
                _ => forward_pairing_record(variant, quote, eol, separator, delimiter, gap, &tail),
            },
        )
}

#[derive(serde::Deserialize)]
struct FifthReviewRecord {
    #[serde(flatten)]
    record: ReviewRecord,
    withhold: bool,
}

#[derive(serde::Deserialize)]
struct ReviewFailure {
    name: String,
    input: String,
    canaries: Vec<String>,
}

fn fifth_review_records() -> Vec<FifthReviewRecord> {
    serde_json::from_str(r###"[
{"name":"B1 continuation bracket pops container, JSON-mode tail","family":"B","input":"[\npassword: a\n ]\nx\n\"token\":\n\"SYNCANB1\"\n]\n","expected":"[\npassword: [REDACTED sha256=92d80e1bc0c58f80]\nx\n\"token\":\n\"[REDACTED sha256=3291632a2ee78218]\"\n]\n","protected":["SYNCANB1"],"withhold":true},
{"name":"B2 block scalar line pops container","family":"B","input":"[\npassword: |\n ]\nx\n\"token\":\n\"SYNCANB2\"\n]\n","expected":"[\npassword: [REDACTED sha256=cbee5301206b6c2c]\nx\n\"token\":\n\"[REDACTED sha256=307950fa9bbe00f6]\"\n]\n","protected":["SYNCANB2"],"withhold":true},
{"name":"B3 newline value line pops container","family":"B","input":"[\npassword:\n ]\nx\n\"token\":\n\"SYNCANB3\"\n]\n","expected":"[\npassword:\n [REDACTED sha256=cfae0d4248f7142f]\nx\n\"token\":\n\"[REDACTED sha256=157e59727cbe7424]\"\n]\n","protected":["SYNCANB3"],"withhold":true},
{"name":"B4 continuation quote flips parity","family":"B","input":"[\npassword: a\n  'x\n[\n'\n]\n token':\n\"SYNCANB4\"\n]\n]\n","expected":"[\npassword: [REDACTED sha256=a56bc440d04e44af]\n[\n'\n]\n token':\n\"[REDACTED sha256=b223dfc140f56c1f]\"\n]\n]\n","protected":["SYNCANB4"],"withhold":true},
{"name":"B0 control: same without container","family":"B","input":"password: a\n ]\nx\n\"token\":\n\"SYNCANB0\"\n","expected":"password: [REDACTED sha256=92d80e1bc0c58f80]\nx\n\"token\":\n\"SYNCANB0\"\n","protected":[],"withhold":false},
{"name":"B0b control: continuation without bracket","family":"B","input":"[\npassword: a\n b\nx\n\"token\":\n\"SYNCANB5\"\n]\n","expected":"[\npassword: [REDACTED sha256=91b3097f7eef76e9]\nx\n\"token\":\n\"[REDACTED sha256=66e3e5657f0fbf63]\"\n]\n","protected":["SYNCANB5"],"withhold":false},
{"name":"A1 postgres line-start wire value, bracket after context end","family":"A","input":"password=\\\"a [x\\\" host=h dbname=d\n\"token\":\n\"SYNCANA1\"\n]\n","expected":"password=[REDACTED sha256=290522c611c697fe] [x\\\" host=h dbname=d\n\"token\":\n\"[REDACTED sha256=7da9188336fd4a08]\"\n]\n","protected":["SYNCANA1"],"withhold":true},
{"name":"A2 azure line-start wire value","family":"A","input":"AccountKey=\\\"a;[x\\\";AccountName=n\n\"token\":\n\"SYNCANA2\"\n]\n","expected":"AccountKey=[REDACTED sha256=290522c611c697fe];[x\\\";AccountName=n\n\"token\":\n\"[REDACTED sha256=1226d52bf1cd6bc7]\"\n]\n","protected":["SYNCANA2"],"withhold":true},
{"name":"A0 control: wire value bracket no connection","family":"A","input":"password=\\\"a [x\\\" note\n\"token\":\n\"SYNCANA0\"\n]\n","expected":"password=\\\"[REDACTED sha256=7b7e25b95a61e941]\\\" note\n\"token\":\n\"SYNCANA0\"\n]\n","protected":[],"withhold":false},
{"name":"C1 json flag mismatch via [} then plain value ends at ]","family":"C","input":"[}\n'token': a] 'x\n'\n password': v\n SYNCANC1\n","expected":"[}\n'token': [REDACTED sha256=2553003aed6cd71d]\n'\n password': [REDACTED sha256=e3588f7f0f65e9b6]\n","protected":["SYNCANC1"],"withhold":true},
{"name":"B5 json-mode | header then block line pops container","family":"B","input":"[\n\"api_key\":\n|\n ]\nx\n\"token\":\n\"SYNCANB6\"\n]\n","expected":"[\n\"api_key\":\n[REDACTED sha256=cbee5301206b6c2c]\nx\n\"token\":\n\"[REDACTED sha256=75b418a0e25249b9]\"\n]\n","protected":["SYNCANB6"],"withhold":true},
{"name":"B6 json-mode # header","family":"B","input":"[\n\"api_key\":\n# n\n ]\nx\n\"token\":\n\"SYNCANB7\"\n]\n","expected":"[\n\"api_key\":\n# n\n [REDACTED sha256=cfae0d4248f7142f]\nx\n\"token\":\n\"[REDACTED sha256=0da241e6b8b075f3]\"\n]\n","protected":["SYNCANB7"],"withhold":true},
{"name":"B7 dash-prefixed sensitive mapping in container","family":"B","input":"[\n- password: a\n   ]\nx\nsee http://h/x[\n\"token\":\n\"SYNCANB8\"\n]\nafter\n","expected":"[\n- password: [REDACTED sha256=a277badc9d96d0cb]\nx\nsee http://h/x[\n\"token\":\n\"[REDACTED sha256=d76dec2741ccc572]\"\n]\nafter\n","protected":["SYNCANB8"],"withhold":true},
{"name":"B8 continuation opens quote (no container), quoted-name tail","family":"B","input":"{\npassword: a\n  'x\n}\n'\n}\n token':\n\"SYNCANB9\"\n}\n","expected":"{\npassword: [REDACTED sha256=a56bc440d04e44af]\n}\n'\n}\n token':\n\"SYNCANB9\"\n}\n","protected":[],"withhold":true},
{"name":"C2 URL bracket json mismatch, plain value ends at ]","family":"C","input":"see http://h/x[\n'token': a] 'x\n'\n password': v\n SYNCANC2\n","expected":"see http://h/x[\n'token': [REDACTED sha256=2553003aed6cd71d]\n'\n password': [REDACTED sha256=19afff100d99599a]\n","protected":["SYNCANC2"],"withhold":true},
{"name":"C0 control: [} then value without trailing quote","family":"C","input":"[}\n'token': a] x\n password': v\n SYNCANC0\n","expected":"[}\n'token': [REDACTED sha256=54fcfb81f2331ce5]\n","protected":["SYNCANC0"],"withhold":false},
{"name":"A3 dash postgres wire","family":"A","input":"- password=\\\"a [x\\\" host=h dbname=d\nsee http://h/x[\n\"token\":\n\"SYNCANA3\"\n]\nafter\n","expected":"- password=[REDACTED sha256=290522c611c697fe] [x\\\" host=h dbname=d\nsee http://h/x[\n\"token\":\n\"[REDACTED sha256=5b7ef98edb8b4de9]\"\n]\nafter\n","protected":["SYNCANA3"],"withhold":true},
{"name":"A4 postgres wire with quote after context end","family":"A","input":"password=\\\"a 'x\\\" host=h dbname=d\n'\n password': v\n SYNCANA4\n","expected":"password=[REDACTED sha256=290522c611c697fe] 'x\\\" host=h dbname=d\n'\n password': [REDACTED sha256=4c94485e0c21ae6c]\n SYNCANA4\n","protected":[],"withhold":true},
{"name":"CL json-flag mismatch, live tail","family":"C","input":"see http://h/x[\n'token': a] '\n[\n'\nx\nsee http://h/x[\n\"token\":\n\"SYNCANCL\"\n]\nafter\n","expected":"see http://h/x[\n'token': [REDACTED sha256=944b821f83790a60]\n[\n'\nx\nsee http://h/x[\n\"token\":\n\"[REDACTED sha256=f20d1c77d1fa463d]\"\n]\nafter\n","protected":["SYNCANCL"],"withhold":true},
{"name":"CL0 control: no trailing quote after ]","family":"C","input":"see http://h/x[\n'token': a] q\n[\nq\nx\nsee http://h/x[\n\"token\":\n\"SYNCANC9\"\n]\n]\nafter\n","expected":"see http://h/x[\n'token': [REDACTED sha256=9ccba56e4b5e0190]\n[\nq\nx\nsee http://h/x[\n\"token\":\n\"[REDACTED sha256=74bb4ee3928c50e5]\"\n]\n]\nafter\n","protected":["SYNCANC9"],"withhold":false},
{"name":"D1 known_value survives private block, quote after END","family":"D","input":"password=-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY----- 'token': \\\"a 'q\\\"\n'\n password': v\n SYNCAND1\n","expected":"password=[REDACTED sha256=ebaa958246477fae] 'token': \\\"[REDACTED sha256=929bcf27168cc00b]\\\"\n'\n password': [REDACTED sha256=fd4471a34c2d24f0]\n","protected":["SYNCAND1"],"withhold":true},
{"name":"D2 same, live tail via URL bracket","family":"D","input":"[\npassword=-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY----- 'token': \\\"a ]\\\"\nx\nsee http://h/x[\n\"token\":\n\"SYNCAND2\"\n]\nafter\n","expected":"[\npassword=[REDACTED sha256=ebaa958246477fae] 'token': \\\"[REDACTED sha256=927fca517a95f1e8]\\\"\nx\nsee http://h/x[\n\"token\":\n\"[REDACTED sha256=273ad4a999f2bcdd]\"\n]\nafter\n","protected":["SYNCAND2"],"withhold":true},
{"name":"D0 control: no private block","family":"D","input":"password=x 'token': \\\"a 'q\\\"\n'\n password': v\n SYNCAND0\n","expected":"password=[REDACTED sha256=41d7216796925d79]\n'\n password': [REDACTED sha256=8346517c6d19243d]\n","protected":["SYNCAND0"],"withhold":false},
{"name":"BL continuation ] then URL-bracket tail record","family":"B","input":"[\npassword: a\n ]\nx\nsee http://h/x[\n\"token\":\n\"SYNCANBL\"\n]\nafter\n","expected":"[\npassword: [REDACTED sha256=92d80e1bc0c58f80]\nx\nsee http://h/x[\n\"token\":\n\"[REDACTED sha256=f472031d20c576e7]\"\n]\nafter\n","protected":["SYNCANBL"],"withhold":true},
{"name":"AL postgres wire bracket then URL-bracket tail","family":"A","input":"password=\\\"a [x\\\" host=h dbname=d\nsee http://h/x[\n\"token\":\n\"SYNCANAL\"\n]\nafter\n","expected":"password=[REDACTED sha256=290522c611c697fe] [x\\\" host=h dbname=d\nsee http://h/x[\n\"token\":\n\"[REDACTED sha256=14f5af925bbe9ed0]\"\n]\nafter\n","protected":["SYNCANAL"],"withhold":true},
{"name":"TL control: tail alone","family":"T","input":"see http://h/x[\n\"token\":\n\"SYNCANTL\"\n]\nafter\n","expected":"see http://h/x[\n\"token\":\n\"SYNCANTL\"\n]\nafter\n","protected":[],"withhold":false},
{"name":"TL2 control: real container then tail","family":"T","input":"[\nsee http://h/x[\n\"token\":\n\"SYNCANT2\"\n]\n]\nafter\n","expected":"[\nsee http://h/x[\n\"token\":\n\"[REDACTED sha256=bc82152ab63a1c47]\"\n]\n]\nafter\n","protected":["SYNCANT2"],"withhold":false},
{"name":"fuzz5-52.json availability 2","family":"K","input":"password=\\\"a '\\\" host=h dbname=d\n}\n{\n\"a\": 1,\n'x\n token': \n  'x\nx\npassword: v\n SYNTHR5004551T0\nsee http://h/x[\n\"token\":\n\"SYNTHR5004551T1\"\n]\nafter\n","expected":"password=[REDACTED sha256=290522c611c697fe] '\\\" host=h dbname=d\n}\n{\n\"a\": 1,\n'x\n token': \n  [REDACTED sha256=bda486ab1e8e6cc1]\nx\npassword: [REDACTED sha256=3adbfb1242a12f01]\nsee http://h/x[\n\"token\":\n\"SYNTHR5004551T1\"\n]\nafter\n","protected":["SYNTHR5004551T0"],"withhold":false},
{"name":"fuzz5-55.json availability 0","family":"K","input":"{\n\"token\":\n>\n 'x\n}\nsee http://h/x[\npassword='\n}\n'token'=\\\"SYNTHR5001143T0\\\"\n","expected":"{\n\"token\":\n[REDACTED sha256=c6a0caa48f59b9dc]\n}\nsee http://h/x[\npassword='[REDACTED sha256=804f89fc0ec98c98]'token'=\\\"[REDACTED sha256=19417b81b391b0b5]\\\"\n","protected":["SYNTHR5001143T0"],"withhold":false},
{"name":"fuzz5-55.json availability 1","family":"K","input":"AccountKey=\\\"a;'\\\";AccountName=n\n}\ntoken='x\nx\n\"token\":\n\"SYNTHR5004106T0\"\n]\n","expected":"AccountKey=[REDACTED sha256=290522c611c697fe];'\\\";AccountName=n\n}\ntoken='x\nx\n\"token\":\n\"SYNTHR5004106T0\"\n]\n","protected":[],"withhold":false}
]"###).must()
}

fn fifth_review_failures() -> Vec<ReviewFailure> {
    serde_json::from_str(r###"[
{"name":"fuzz5-52.json batch-fail 0","input":"[\nAccountKey=\\\"a;'\\\";AccountName=n\n]\n{\n\"a\": 1,\npassword=\\\"a 'x\\\" host=h dbname=d\nx\n'token'=\\\"SYNTHR5001244T0\\\"\n","canaries":["SYNTHR5001244T0"]},
{"name":"fuzz5-52.json batch-fail 1","input":"{\npassword=\\\"a a] 'x\\\" host=h dbname=d\n}\nx [\nAccountKey=\\\"a;a] 'x\\\";AccountName=n\n\n'token'=\\\"SYNTHR5003294T0\\\"\n'\n password': v\n SYNTHR5003294T1\n","canaries":["SYNTHR5003294T0","SYNTHR5003294T1"]},
{"name":"fuzz5-54.json batch-fail 0","input":"[}\nAccountKey=\\\"a;a] 'x\\\";AccountName=n\n]\n[}\nAccountKey=\\\"a;'x\\\";AccountName=n\n\npassword: v\n SYNTHR5000293T0\n","canaries":["SYNTHR5000293T0"]},
{"name":"fuzz5-54.json batch-fail 1","input":"see http://h/x[\npassword=\\\"a '\\\" host=h dbname=d\n]\nsee http://h/x[\nAccountKey=\\\"a;'\\\";AccountName=n\n]\n\"token\":\n\"SYNTHR5004976T0\"\n]\n token':\n\"SYNTHR5004976T1\"\n]\n","canaries":["SYNTHR5004976T0","SYNTHR5004976T1"]}
]"###).must()
}

fn check_fifth_review_family(family: &str) {
    for case in fifth_review_records()
        .iter()
        .filter(|case| case.record.family == family)
    {
        assert_pinned_review_record(&case.record);
    }
}

fn assert_review_failure(case: &ReviewFailure) -> Outcome {
    let batch = filter(case.input.as_bytes()).must_err();
    let whole = streamed(case.input.as_bytes(), Vec::new(), usize::MAX);
    let error = whole.error.as_ref().must();
    assert!(
        error.kind == batch.kind,
        "stream did not preserve failed detection for {}",
        case.name
    );
    for canary in &case.canaries {
        assert!(
            !whole
                .output
                .windows(canary.len())
                .any(|bytes| bytes == canary.as_bytes()),
            "failed synthetic record released a canary"
        );
        assert!(
            !format!("{error:?} {error}").contains(canary),
            "failed synthetic record exposed a diagnostic canary"
        );
    }
    for split in 0..=case.input.len() {
        assert!(
            streamed(case.input.as_bytes(), vec![split], usize::MAX) == whole,
            "{} changed at split {split}",
            case.name
        );
    }
    for size in [1, 2, 7, 31, 4096] {
        assert!(
            streamed(case.input.as_bytes(), Vec::new(), size) == whole,
            "{} changed at read size {size}",
            case.name
        );
    }
    assert!(
        streamed(
            case.input.as_bytes(),
            line_ends(case.input.as_bytes()),
            usize::MAX
        ) == whole,
        "{} changed with line reads",
        case.name
    );
    whole
}

#[test]
fn fifth_review_connection_wire_contexts_preserve_exact_batch_spans() {
    check_fifth_review_family("A");
}

#[test]
fn fifth_review_sensitive_continuation_syntax_preserves_exact_batch_spans() {
    check_fifth_review_family("B");
}

#[test]
fn fifth_review_json_depth_mismatches_preserve_exact_batch_spans() {
    check_fifth_review_family("C");
}

#[test]
fn fifth_review_pem_markers_consume_pending_values_without_changing_spans() {
    check_fifth_review_family("D");
}

#[test]
fn fifth_review_controls_and_availability_preserve_exact_batch_results() {
    check_fifth_review_family("T");
    check_fifth_review_family("K");
}

#[test]
fn fifth_review_batch_failures_stay_closed_at_every_read_boundary() {
    for case in fifth_review_failures() {
        assert_review_failure(&case);
    }
}

fn fifth_review_poison(variant: usize, eol: &str) -> String {
    let input = [
        "password=\\\"a [x\\\" host=h dbname=d",
        "AccountKey=\\\"a;[x\\\";AccountName=n",
        "[\npassword: a\n ]\nx",
        "[\npassword: |\n ]\nx",
        "[\n\"api_key\":\n|\n ]\nx",
        "see http://h/x[\n'token': a] '\n[\n'\nx",
        "[\npassword=-----BEGIN RSA PRIVATE KEY-----\nMII synthetic\n-----END RSA PRIVATE KEY----- 'token': \\\"a ]\\\"\nx",
        "password=-----BEGIN RSA PRIVATE KEY-----\nMII synthetic\n-----END RSA PRIVATE KEY----- 'token': \\\"a 'q\\\"\n'\n password': v",
    ][variant];
    input.replace('\n', eol)
}

fn fifth_review_grammar() -> impl Strategy<Value = (String, String)> {
    (
        prop::collection::vec(0usize..8, 1..4),
        prop::sample::select(vec!["\n", "\r\n"]),
        0usize..3,
        prop::sample::select(vec!["token", "api_key", "password"]),
        prop::sample::select(vec!["", " ", "\t"]),
        "[a-z0-9秘密é_-]{1,16}",
    )
        .prop_map(|(poisons, eol, tail_kind, name, gap, suffix)| {
            let canary = format!("{CANARY}_{suffix}");
            let mut input = poisons
                .into_iter()
                .map(|variant| fifth_review_poison(variant, eol))
                .collect::<Vec<_>>()
                .join(eol);
            input.push_str(eol);
            let tail = match tail_kind {
                0 => format!("see http://h/x[{eol}\"{name}\"{gap}:{gap}{eol}\"{canary}\"{eol}]{eol}after{eol}"),
                1 => format!("'{eol} {name}'{gap}:{gap}v{eol} {canary}{eol}"),
                _ => format!("{name}{gap}={gap}'{canary}'{eol}"),
            };
            input.push_str(&tail);
            (input, canary)
        })
}

fn assert_batch_outcome(input: &str, canaries: &[&str]) -> Outcome {
    let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
    match filter(input.as_bytes()) {
        Ok(expected) => {
            assert!(
                whole.error.is_none() && whole.output == expected.as_bytes(),
                "synthetic complete record differs from actual batch"
            );
        }
        Err(batch) => {
            let error = whole.error.as_ref().must();
            assert!(
                error.kind == batch.kind,
                "synthetic batch failure became success"
            );
            for canary in canaries {
                assert!(
                    !whole
                        .output
                        .windows(canary.len())
                        .any(|bytes| bytes == canary.as_bytes()),
                    "batch failure released a synthetic canary"
                );
            }
        }
    }
    for canary in canaries {
        assert!(
            !String::from_utf8_lossy(&whole.report).contains(canary),
            "synthetic metadata exposed a canary"
        );
        if let Some(error) = &whole.error {
            assert!(!format!("{error:?} {error}").contains(canary));
        }
    }
    whole
}

fn private_marker_tail_records() -> Vec<String> {
    let mut records = Vec::new();
    for eol in ["\n", "\r\n", "\r"] {
        for spacing in ["", " ", "\t"] {
            let bodies = [
                format!(
                    "-----BEGIN RSA PRIVATE KEY-----{eol}MII synthetic{eol}-----END RSA PRIVATE KEY-----"
                ),
                "-----END RSA PRIVATE KEY-----".to_owned(),
                format!(
                    "-----END RSA PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----{eol}MII synthetic{eol}-----END RSA PRIVATE KEY-----"
                ),
                format!(
                    "-----BEGIN RSA PRIVATE KEY-----{eol}MII synthetic{eol}-----END RSA PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----{eol}MII synthetic second{eol}-----END RSA PRIVATE KEY-----"
                ),
            ];
            for body in bodies {
                records.push(format!(
                    "[{eol}password={body}{spacing}'token': \\\"a ]\\\"{eol}x{eol}see http://h/x[{eol}\"token\":{eol}\"{CANARY}\"{eol}]{eol}after{eol}"
                ));
                records.push(format!(
                    "password={body}{spacing}'token': \\\"a 'q\\\"{eol}'{eol} password': v{eol} {CANARY}{eol}"
                ));
            }
        }
    }
    records
}

#[test]
fn unmatched_and_overlapping_private_markers_preserve_actual_batch_at_every_boundary() {
    for (index, input) in private_marker_tail_records().into_iter().enumerate() {
        let whole = assert_batch_outcome(&input, &[CANARY]);
        for split in 0..=input.len() {
            assert!(
                streamed(input.as_bytes(), vec![split], usize::MAX) == whole,
                "private marker tail {index} changed at split {split}"
            );
        }
        for size in [1, 2, 7, 31] {
            assert!(
                streamed(input.as_bytes(), Vec::new(), size) == whole,
                "private marker tail {index} changed at size {size}"
            );
        }
        assert!(
            streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX) == whole,
            "private marker tail {index} changed with line reads"
        );
    }
}

fn sixth_review_records() -> Vec<ReviewRecord> {
    serde_json::from_str(r###"[
{"name":"cases_min.json E-eof","family":"E","input":"[ http://h/x]\n\"token\":\n\"SYNCAN6E00\"\n","expected":"[ http://h/x]\n\"token\":\n\"[REDACTED sha256=390cd8aa56b1c5ed]\"\n","protected":["SYNCAN6E00"]},
{"name":"cases_min.json E-live","family":"E","input":"[ http://h/x]\nsee http://h/y[\n\"token\":\n\"SYNCAN6E01\"\n]\nafter\n","expected":"[ http://h/x]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=dbac78995e498b8f]\"\n]\nafter\n","protected":["SYNCAN6E01"]},
{"name":"cases_min.json E-go-list-live","family":"E","input":"targets=[http://a/x http://b/y]\nsee http://h/y[\n\"token\":\n\"SYNCAN6E02\"\n]\nafter\n","expected":"targets=[http://a/x http://b/y]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=1fdec2eea54abbad]\"\n]\nafter\n","protected":["SYNCAN6E02"]},
{"name":"cases_min.json E-control-adjacent","family":"E","input":"[http://h/x]\nsee http://h/y[\n\"token\":\n\"SYNCAN6E03\"\n]\nafter\n","expected":"[http://h/x]\nsee http://h/y[\n\"token\":\n\"SYNCAN6E03\"\n]\nafter\n","protected":[]},
{"name":"cases_min.json E-control-no-url","family":"E","input":"[ h/x]\nsee http://h/y[\n\"token\":\n\"SYNCAN6E04\"\n]\nafter\n","expected":"[ h/x]\nsee http://h/y[\n\"token\":\n\"SYNCAN6E04\"\n]\nafter\n","protected":[]},
{"name":"cases_min.json F-eof","family":"F","input":"[}\n\"password\":\n 'q\n[[\n'\n]\n\"token\":\n\"SYNCAN6F05\"\n","expected":"[}\n\"password\":\n [REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n]\n\"token\":\n\"[REDACTED sha256=be9b666042441199]\"\n","protected":["SYNCAN6F05"]},
{"name":"cases_min.json F-live","family":"F","input":"[}\n\"password\":\n 'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCAN6F06\"\n]\nafter\n","expected":"[}\n\"password\":\n [REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=a06af887b6ebe4da]\"\n]\nafter\n","protected":["SYNCAN6F06"]},
{"name":"cases_min.json F-container-live","family":"F","input":"see http://h/x[\n\"password\": [\n 'q\n[[[\n'\n]\n]\nsee http://h/y[\n\"token\":\n\"SYNCAN6F07\"\n]\nafter\n","expected":"see http://h/x[\n\"password\": [REDACTED sha256=71130c2163f61ce6]\n[[[\n'\n]\n]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=9d2b23ce6b4f3956]\"\n]\nafter\n","protected":["SYNCAN6F07"]},
{"name":"cases_min.json F-control-not-indented","family":"F","input":"[}\n\"password\":\n'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCAN6F08\"\n]\nafter\n","expected":"[}\n\"password\":\n'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCAN6F08\"\n]\nafter\n","protected":[]},
{"name":"cases_min.json F-control-real-container","family":"F","input":"[\n\"password\":\n 'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCAN6F09\"\n]\nafter\n","expected":"[\n\"password\":\n '[REDACTED sha256=99f3ea2c7b20174d]'\n]\nsee http://h/y[\n\"token\":\n\"SYNCAN6F09\"\n]\nafter\n","protected":[]},
{"name":"cases_min.json G-eof","family":"G","input":"[\npassword: a\n -----BEGIN RSA PRIVATE KEY-----MII-----END RSA PRIVATE KEY-----]\nx\n\"token\":\n\"SYNCAN6G10\"\n","expected":"[\npassword: [REDACTED sha256=fd9a2d6295df5085]\nx\n\"token\":\n\"[REDACTED sha256=cb326d9a01bac634]\"\n","protected":["SYNCAN6G10"]},
{"name":"cases_min.json G-live","family":"G","input":"[\npassword: a\n -----BEGIN RSA PRIVATE KEY-----MII-----END RSA PRIVATE KEY-----]\nx\nsee http://h/y[\n\"token\":\n\"SYNCAN6G11\"\n]\nafter\n","expected":"[\npassword: [REDACTED sha256=fd9a2d6295df5085]\nx\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=17a2596bb4db7250]\"\n]\nafter\n","protected":["SYNCAN6G11"]},
{"name":"cases_min.json G-multiline-live","family":"G","input":"[\npassword: |\n -----BEGIN RSA PRIVATE KEY-----\n MII\n -----END RSA PRIVATE KEY----- ]\nx\nsee http://h/y[\n\"token\":\n\"SYNCAN6G12\"\n]\nafter\n","expected":"[\npassword: [REDACTED sha256=681e84f763a9f303]\nx\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=091a30a48a321b8b]\"\n]\nafter\n","protected":["SYNCAN6G12"]},
{"name":"cases_min.json G-control-before-marker","family":"G","input":"[\npassword: a\n ] -----BEGIN RSA PRIVATE KEY-----MII-----END RSA PRIVATE KEY-----\nx\nsee http://h/y[\n\"token\":\n\"SYNCAN6G13\"\n]\nafter\n","expected":"[\npassword: [REDACTED sha256=c28ecb38306a99ff]\nx\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=e6053459c1e6db15]\"\n]\nafter\n","protected":["SYNCAN6G13"]},
{"name":"cases_min.json G-control-no-container","family":"G","input":"password: a\n -----BEGIN RSA PRIVATE KEY-----MII-----END RSA PRIVATE KEY-----]\nx\nsee http://h/y[\n\"token\":\n\"SYNCAN6G14\"\n]\nafter\n","expected":"password: [REDACTED sha256=fd9a2d6295df5085]\nx\nsee http://h/y[\n\"token\":\n\"SYNCAN6G14\"\n]\nafter\n","protected":[]},
{"name":"cases_min.json H-eof","family":"H","input":"x '{\"a\": 1'\n\"password\":\n 'q\n[[\n'\n}\n\"token\":\n\"SYNCAN6H15\"\n","expected":"x '{\"a\": 1'\n\"password\":\n [REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n}\n\"token\":\n\"[REDACTED sha256=55ee4eafb117879b]\"\n","protected":["SYNCAN6H15"]},
{"name":"cases_min.json H-live","family":"H","input":"x '{\"a\": 1'\n\"password\":\n 'q\n[[\n'\n}\nsee http://h/y[\n\"token\":\n\"SYNCAN6H16\"\n]\nafter\n","expected":"x '{\"a\": 1'\n\"password\":\n [REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n}\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=4abca93ec09599d0]\"\n]\nafter\n","protected":["SYNCAN6H16"]},
{"name":"cases_min.json H-control-plain-name","family":"H","input":"x '{\"a\": 1'\npassword:\n 'q\n[[\n'\n}\nsee http://h/y[\n\"token\":\n\"SYNCAN6H17\"\n]\nafter\n","expected":"x '{\"a\": 1'\npassword:\n [REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n}\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=1526882b4e00c096]\"\n]\nafter\n","protected":["SYNCAN6H17"]},
{"name":"cases_url.json U1 URL context hides ] from detector, framer pops; JSON-mode tail","family":"E","input":"[ http://h/x]\n\"token\":\n\"SYNCANU1\"\n","expected":"[ http://h/x]\n\"token\":\n\"[REDACTED sha256=0cb9df275e4e0a79]\"\n","protected":["SYNCANU1"]},
{"name":"cases_url.json U2 same, live URL-bracket tail","family":"E","input":"[ http://h/x]\nsee http://h/y[\n\"token\":\n\"SYNCANU2\"\n]\nafter\n","expected":"[ http://h/x]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=0961ef7e74da3abf]\"\n]\nafter\n","protected":["SYNCANU2"]},
{"name":"cases_url.json U3 bracketed URL list, live tail","family":"E","input":"mirrors=[http://a/x http://b/y]\nsee http://h/y[\n\"token\":\n\"SYNCANU3\"\n]\nafter\n","expected":"mirrors=[http://a/x http://b/y]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=5a470b7f67f55a0c]\"\n]\nafter\n","protected":["SYNCANU3"]},
{"name":"cases_url.json U4 control: [http://h/x] adjacent (closer stripped)","family":"E","input":"[http://h/x]\nsee http://h/y[\n\"token\":\n\"SYNCANU4\"\n]\nafter\n","expected":"[http://h/x]\nsee http://h/y[\n\"token\":\n\"SYNCANU4\"\n]\nafter\n","protected":[]},
{"name":"cases_url.json U5 control: tail alone","family":"E","input":"see http://h/y[\n\"token\":\n\"SYNCANU5\"\n]\nafter\n","expected":"see http://h/y[\n\"token\":\n\"SYNCANU5\"\n]\nafter\n","protected":[]},
{"name":"cases_url.json U6 brace container, URL bracket","family":"E","input":"{ \"a\": [ http://h/x] }\nsee http://h/y[\n\"token\":\n\"SYNCANU6\"\n]\nafter\n","expected":"{ \"a\": [ http://h/x] }\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=3080e202c49fa902]\"\n]\nafter\n","protected":["SYNCANU6"]},
{"name":"cases_url.json U7 log-ish: urls list then pretty JSON body (plain sensitive next line)","family":"E","input":"INFO targets [primary http://db/a backup http://db/b]\nbody: {\n\"password\":\n\"SYNCANU7\"\n}\n","expected":"INFO targets [primary http://db/a backup http://db/b]\nbody: {\n\"password\":\n\"[REDACTED sha256=5146d11be7b7c955]\"\n}\n","protected":["SYNCANU7"]},
{"name":"cases_url.json U8 json-mode next-line block value after URL ]","family":"E","input":"[ http://h/x]\nsee http://h/y[\n\"api_key\":\n|\n SYNCANU8\n]\nafter\n","expected":"[ http://h/x]\nsee http://h/y[\n\"api_key\":\n[REDACTED sha256=b329c335561a9a24]\n]\nafter\n","protected":["SYNCANU8"]},
{"name":"cases_residual.json P1 B residual: post-END tail on a continuation line pops container","family":"G","input":"[\npassword: a\n  -----BEGIN RSA PRIVATE KEY-----\n  MII\n  -----END RSA PRIVATE KEY----- ]\nx\nsee http://h/y[\n\"token\":\n\"SYNCANP1\"\n]\nafter\n","expected":"[\npassword: [REDACTED sha256=2fbb36dfc5886ed9]\nx\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=61037a70b48371b5]\"\n]\nafter\n","protected":["SYNCANP1"]},
{"name":"cases_residual.json P1c control: no ] after END","family":"G","input":"[\npassword: a\n  -----BEGIN RSA PRIVATE KEY-----\n  MII\n  -----END RSA PRIVATE KEY----- b\nx\n]\nsee http://h/y[\n\"token\":\n\"SYNCANP1C\"\n]\nafter\n","expected":"[\npassword: [REDACTED sha256=4e699e4fc132d40e]\nx\n]\nsee http://h/y[\n\"token\":\n\"SYNCANP1C\"\n]\nafter\n","protected":[]},
{"name":"cases_residual.json P2 B residual: one-line private block on continuation line, tail ]","family":"G","input":"[\npassword: a\n  -----BEGIN RSA PRIVATE KEY-----MII-----END RSA PRIVATE KEY----- ]\nx\nsee http://h/y[\n\"token\":\n\"SYNCANP2\"\n]\nafter\n","expected":"[\npassword: [REDACTED sha256=83041b072006dc61]\nx\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=22accfa43f54265d]\"\n]\nafter\n","protected":["SYNCANP2"]},
{"name":"cases_residual.json W1 B residual: quoted-name newline value, first continuation line opens quote (JsonSyntax-held record)","family":"H","input":"x '{\"a\": 1'\n\"password\":\n 'q\n[[\n'\n}\nsee http://h/y[\n\"token\":\n\"SYNCANW1\"\n]\nafter\n","expected":"x '{\"a\": 1'\n\"password\":\n [REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n}\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=b08abac3103e16af]\"\n]\nafter\n","protected":["SYNCANW1"]},
{"name":"cases_residual.json W2 C residual: framer JSON mode via URL [, next-line quoted value in YAML continuation","family":"F","input":"see http://h/x[\n\"password\":\n 'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCANW2\"\n]\nafter\n","expected":"see http://h/x[\n\"password\":\n [REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=82b4222d8b548827]\"\n]\nafter\n","protected":["SYNCANW2"]},
{"name":"cases_residual.json W2c control: value line not indented","family":"F","input":"see http://h/x[\n\"password\":\n'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCANW2C\"\n]\nafter\n","expected":"see http://h/x[\n\"password\":\n'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCANW2C\"\n]\nafter\n","protected":[]},
{"name":"cases_residual.json W3 C residual: framer JSON mode via [}, next-line quoted value","family":"F","input":"[}\n\"password\":\n 'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCANW3\"\n]\nafter\n","expected":"[}\n\"password\":\n [REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=5a483bee52e0ba72]\"\n]\nafter\n","protected":["SYNCANW3"]},
{"name":"cases_eol.json E-crlf","family":"E","input":"[ http://h/x]\r\nsee http://h/y[\r\n\"token\":\r\n\"SYNCAN6ECRLF\"\r\n]\r\nafter\r\n","expected":"[ http://h/x]\r\nsee http://h/y[\r\n\"token\":\r\n\"[REDACTED sha256=3509f8c767028c5b]\"\r\n]\r\nafter\r\n","protected":["SYNCAN6ECRLF"]},
{"name":"cases_eol.json E-cr","family":"E","input":"[ http://h/x]\rsee http://h/y[\r\"token\":\r\"SYNCAN6ECR\"\r]\rafter\r","expected":"[ http://h/x]\rsee http://h/y[\r\"token\":\r\"[REDACTED sha256=74e478a1e8cf16ee]\"\r]\rafter\r","protected":["SYNCAN6ECR"]},
{"name":"cases_eol.json E-tab","family":"E","input":"[ http://h/x]\nsee http://h/y[\n\"token\":\n\"SYNCAN6ETAB\"\n]\nafter\n","expected":"[ http://h/x]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=f95e8ea570bbcec6]\"\n]\nafter\n","protected":["SYNCAN6ETAB"]},
{"name":"cases_eol.json F-crlf","family":"F","input":"[}\r\n\"password\":\r\n 'q\r\n[[\r\n'\r\n]\r\nsee http://h/y[\r\n\"token\":\r\n\"SYNCAN6FCRLF\"\r\n]\r\nafter\r\n","expected":"[}\r\n\"password\":\r\n [REDACTED sha256=64bc7b400090f5dd]\r\n[[\r\n'\r\n]\r\nsee http://h/y[\r\n\"token\":\r\n\"[REDACTED sha256=27d63a548155ecea]\"\r\n]\r\nafter\r\n","protected":["SYNCAN6FCRLF"]},
{"name":"cases_eol.json F-cr","family":"F","input":"[}\r\"password\":\r 'q\r[[\r'\r]\rsee http://h/y[\r\"token\":\r\"SYNCAN6FCR\"\r]\rafter\r","expected":"[}\r\"password\":\r [REDACTED sha256=64bc7b400090f5dd]\r[[\r'\r]\rsee http://h/y[\r\"token\":\r\"[REDACTED sha256=e490780767f274c1]\"\r]\rafter\r","protected":["SYNCAN6FCR"]},
{"name":"cases_eol.json F-tab","family":"F","input":"[}\n\"password\":\n\t'q\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"SYNCAN6FTAB\"\n]\nafter\n","expected":"[}\n\"password\":\n\t[REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n]\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=c35d64e2a27631f7]\"\n]\nafter\n","protected":["SYNCAN6FTAB"]},
{"name":"cases_eol.json G-crlf","family":"G","input":"[\r\npassword: a\r\n -----BEGIN RSA PRIVATE KEY-----MII-----END RSA PRIVATE KEY-----]\r\nx\r\nsee http://h/y[\r\n\"token\":\r\n\"SYNCAN6GCRLF\"\r\n]\r\nafter\r\n","expected":"[\r\npassword: [REDACTED sha256=6edb2e525aca6b7c]\r\nx\r\nsee http://h/y[\r\n\"token\":\r\n\"[REDACTED sha256=66fe918879986416]\"\r\n]\r\nafter\r\n","protected":["SYNCAN6GCRLF"]},
{"name":"cases_eol.json G-cr","family":"G","input":"[\rpassword: a\r -----BEGIN RSA PRIVATE KEY-----MII-----END RSA PRIVATE KEY-----]\rx\rsee http://h/y[\r\"token\":\r\"SYNCAN6GCR\"\r]\rafter\r","expected":"[\rpassword: [REDACTED sha256=cf922bbac6440e6f]\rx\rsee http://h/y[\r\"token\":\r\"[REDACTED sha256=f5873dce798fb4c9]\"\r]\rafter\r","protected":["SYNCAN6GCR"]},
{"name":"cases_eol.json G-tab","family":"G","input":"[\npassword: a\n\t-----BEGIN RSA PRIVATE KEY-----MII-----END RSA PRIVATE KEY-----]\nx\nsee http://h/y[\n\"token\":\n\"SYNCAN6GTAB\"\n]\nafter\n","expected":"[\npassword: [REDACTED sha256=8a7d175190431751]\nx\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=53e802373c5c26ec]\"\n]\nafter\n","protected":["SYNCAN6GTAB"]},
{"name":"cases_eol.json H-crlf","family":"H","input":"x '{\"a\": 1'\r\n\"password\":\r\n 'q\r\n[[\r\n'\r\n}\r\nsee http://h/y[\r\n\"token\":\r\n\"SYNCAN6HCRLF\"\r\n]\r\nafter\r\n","expected":"x '{\"a\": 1'\r\n\"password\":\r\n [REDACTED sha256=64bc7b400090f5dd]\r\n[[\r\n'\r\n}\r\nsee http://h/y[\r\n\"token\":\r\n\"[REDACTED sha256=b889d30595332ed9]\"\r\n]\r\nafter\r\n","protected":["SYNCAN6HCRLF"]},
{"name":"cases_eol.json H-cr","family":"H","input":"x '{\"a\": 1'\r\"password\":\r 'q\r[[\r'\r}\rsee http://h/y[\r\"token\":\r\"SYNCAN6HCR\"\r]\rafter\r","expected":"x '{\"a\": 1'\r\"password\":\r [REDACTED sha256=64bc7b400090f5dd]\r[[\r'\r}\rsee http://h/y[\r\"token\":\r\"[REDACTED sha256=aad682b99652dc27]\"\r]\rafter\r","protected":["SYNCAN6HCR"]},
{"name":"cases_eol.json H-tab","family":"H","input":"x '{\"a\": 1'\n\"password\":\n\t'q\n[[\n'\n}\nsee http://h/y[\n\"token\":\n\"SYNCAN6HTAB\"\n]\nafter\n","expected":"x '{\"a\": 1'\n\"password\":\n\t[REDACTED sha256=64bc7b400090f5dd]\n[[\n'\n}\nsee http://h/y[\n\"token\":\n\"[REDACTED sha256=59255ae1bf1e8025]\"\n]\nafter\n","protected":["SYNCAN6HTAB"]},
{"name":"cases_eol.json I-crlf","family":"I","input":"[\r\ntoken':\r\n|\r\n ]\r\n SYNCAN6ICRLF\r\nafter\r\n","expected":"[\r\ntoken':\r\n[REDACTED sha256=418c17778b20a102]\r\nafter\r\n","protected":["SYNCAN6ICRLF"]},
{"name":"cases_eol.json I-cr","family":"I","input":"[\rtoken':\r|\r ]\r SYNCAN6ICR\rafter\r","expected":"[\rtoken':\r[REDACTED sha256=498e3a646bb2f231]\rafter\r","protected":["SYNCAN6ICR"]},
{"name":"cases_eol.json I-tab","family":"I","input":"[\ntoken':\n|\n\t]\n\tSYNCAN6ITAB\nafter\n","expected":"[\ntoken':\n[REDACTED sha256=e6719491b32e0fe4]\nafter\n","protected":["SYNCAN6ITAB"]},
{"name":"cases_i.json I-closing-quote-eof","family":"I","input":"[\ntoken':\n|\n ]\n SYNCAN6I00\n","expected":"[\ntoken':\n[REDACTED sha256=95d003cdd70360a4]\n","protected":["SYNCAN6I00"]},
{"name":"cases_i.json I-escaped-closing-eof","family":"I","input":"[\ntoken\\\":\n|\n ]\n SYNCAN6I01\n","expected":"[\ntoken\\\":\n[REDACTED sha256=a37f36c25a1a003d]\n","protected":["SYNCAN6I01"]},
{"name":"cases_i.json I-gt-header","family":"I","input":"[\ntoken':\n>\n ]\n SYNCAN6I02\n","expected":"[\ntoken':\n[REDACTED sha256=9955fe0a03fa8868]\n","protected":["SYNCAN6I02"]},
{"name":"cases_i.json I-comment-header","family":"I","input":"[\ntoken':\n# n\n ]\n SYNCAN6I03\n","expected":"[\ntoken':\n# n\n [REDACTED sha256=f53b166080b7881b]\n","protected":["SYNCAN6I03"]},
{"name":"cases_i.json I-brace-container","family":"I","input":"x {\nclient_secret\\':\n|\n\tq\n }\n    SYNCAN6I04\n","expected":"x {\nclient_secret\\':\n[REDACTED sha256=bc2420d23b02806c]\n","protected":["SYNCAN6I04"]},
{"name":"cases_i.json I-live","family":"I","input":"[\ntoken':\n|\n ]\n SYNCAN6I05\nafter\n","expected":"[\ntoken':\n[REDACTED sha256=c355d74f735f866f]\nafter\n","protected":["SYNCAN6I05"]},
{"name":"cases_i.json I-control-quoted-name","family":"I","input":"[\n\"token\":\n|\n ]\n SYNCAN6I06\n","expected":"[\n\"token\":\n[REDACTED sha256=2be07af48b5b17a5]\n","protected":["SYNCAN6I06"]},
{"name":"cases_i.json I-control-same-line-header","family":"I","input":"[\ntoken': |\n ]\n SYNCAN6I07\n","expected":"[\ntoken': [REDACTED sha256=e571340b6262af42]\n","protected":["SYNCAN6I07"]},
{"name":"cases_i.json I-control-no-container","family":"I","input":"token':\n|\n ]\n SYNCAN6I08\n","expected":"token':\n|\n ]\n SYNCAN6I08\n","protected":[]},
{"name":"fuzz7-71.json token soup 0","family":"E","input":"[\np://]x\"token\":\nSYNTHR7000040T0","expected":"[\np://]x\"token\":\n[REDACTED sha256=35382ef656d64f2b]","protected":["SYNTHR7000040T0"]},
{"name":"fuzz7-71.json token soup 1","family":"E","input":"[ p://]\ntoken\":\nSYNTHR7000064T0","expected":"[ p://]\ntoken\":\n[REDACTED sha256=46c9590864f24e93]","protected":["SYNTHR7000064T0"]},
{"name":"fuzz7-71.json token soup 2","family":"E","input":"[p://]x{}\ntoken\":\nSYNTHR7000109T1","expected":"[p://]x{}\ntoken\":\n[REDACTED sha256=92c70b1d0091ef08]","protected":["SYNTHR7000109T1"]},
{"name":"fuzz7-71.json token soup 3","family":"E","input":"a\"[ p://]\"\nx\"token\":\nSYNTHR7000146T0","expected":"a\"[ p://]\"\nx\"token\":\n[REDACTED sha256=7e2b43664ff9e193]","protected":["SYNTHR7000146T0"]},
{"name":"fuzz7-71.json token soup 4","family":"E","input":"{\\'\"\"\"\"[p://]1}\ntoken\":\nSYNTHR7000195T0","expected":"{\\'\"\"\"\"[p://]1}\ntoken\":\n[REDACTED sha256=5f17fd28f70ab02f]","protected":["SYNTHR7000195T0"]},
{"name":"fuzz7-71.json token soup 5","family":"E","input":"[p://]n\ntoken\":\nSYNTHR7000198T1","expected":"[p://]n\ntoken\":\n[REDACTED sha256=f32c83a9b2d43e90]","protected":["SYNTHR7000198T1"]},
{"name":"fuzz7-71.json token soup 6","family":"E","input":"[p://]a\ntoken\":\nSYNTHR7000204T0","expected":"[p://]a\ntoken\":\n[REDACTED sha256=3bc1af1cc66bc55f]","protected":["SYNTHR7000204T0"]},
{"name":"fuzz7-71.json token soup 7","family":"E","input":"[p://]=\ntoken\":\nSYNTHR7000350T0","expected":"[p://]=\ntoken\":\n[REDACTED sha256=bf007a10619db704]","protected":["SYNTHR7000350T0"]},
{"name":"fuzz7-71.json token soup 8","family":"E","input":"[ p://]\nsecret\":\nSYNTHR7000544T0","expected":"[ p://]\nsecret\":\n[REDACTED sha256=691e166c78757782]","protected":["SYNTHR7000544T0"]},
{"name":"fuzz7-71.json token soup 9","family":"E","input":"[ p://]\ntoken\":\nSYNTHR7000551T0","expected":"[ p://]\ntoken\":\n[REDACTED sha256=6ad3d85d2798ce70]","protected":["SYNTHR7000551T0"]},
{"name":"fuzz7-71.json token soup 10","family":"E","input":"[p://]x\ntoken\":\nSYNTHR7000572T1","expected":"[p://]x\ntoken\":\n[REDACTED sha256=a41787f3a75096ea]","protected":["SYNTHR7000572T1"]},
{"name":"fuzz7-71.json token soup 11","family":"E","input":"[p://]1\ntoken\":\nSYNTHR7000613T0","expected":"[p://]1\ntoken\":\n[REDACTED sha256=719740feb6d1a1b1]","protected":["SYNTHR7000613T0"]},
{"name":"fuzz7-71.json token soup 12","family":"E","input":"[p://]1\ntoken\":\nSYNTHR7000677T0","expected":"[p://]1\ntoken\":\n[REDACTED sha256=268466381da4f1f4]","protected":["SYNTHR7000677T0"]},
{"name":"fuzz7-71.json token soup 13","family":"E","input":"[p://]a\ntoken\":\nSYNTHR7000778T0","expected":"[p://]a\ntoken\":\n[REDACTED sha256=2f4c1bc59bfb3355]","protected":["SYNTHR7000778T0"]},
{"name":"fuzz7-71.json token soup 14","family":"E","input":"[ p://]\ntoken\":\nSYNTHR7000786T0","expected":"[ p://]\ntoken\":\n[REDACTED sha256=fefdefa221d589df]","protected":["SYNTHR7000786T0"]},
{"name":"fuzz7-71.json token soup 15","family":"E","input":"[p://]1\ntoken\":\nSYNTHR7000875T0","expected":"[p://]1\ntoken\":\n[REDACTED sha256=a1115049f34f547f]","protected":["SYNTHR7000875T0"]},
{"name":"fuzzcli2r6-okdiff.json compound continuation 0","family":"I","input":"x {\nclient_secret\\':\n|\n\tSYNTHFY000821L0\n }\n    SYNTHFY000821L0C\nx {\n  user'={\n\"kty\": \"oct\",\n\"k\": \"SYNTHFY000821L1\"\n}\n  db password = SYNTHFY000821L1\n\t}\n","expected":"x {\nclient_secret\\':\n[REDACTED sha256=dd4a8d3d9010daa6]\nx {\n  user'=[REDACTED sha256=b4da67130458ee87]\n  db password = [REDACTED sha256=1cb41842bc55cba5]\n\t}\n","protected":["SYNTHFY000821L0","SYNTHFY000821L0C","SYNTHFY000821L1"]},
{"name":"fuzzcli2r6-okdiff.json compound continuation 1","family":"I","input":"x x=[\nx.password':\n|\n SYNTHFY000995L0\n  api_key = SYNTHFY000995L0\n  ]\n SYNTHFY000995L0C\n","expected":"x x=[\nx.password':\n[REDACTED sha256=db93fb308a00e8a1]\n","protected":["SYNTHFY000995L0","SYNTHFY000995L0C"]},
{"name":"fuzzcli2r6-okdiff.json compound continuation 2","family":"I","input":"INFO {\n    x.password=\\\"SYNTHFY005216L0\"\\\"\nx.password\":\n|\n    SYNTHFY005216L0\n\t}\n[1/2] \\\"\n\t\"api_key\":\n\"SYNTHFY005216L1\"\nx,password\"=SYNTHFY005216L1\n    \\\"\n","expected":"INFO {\n    x.password=\\\"[REDACTED sha256=68e2fc9580e7d69a]\\\"\nx.password\":\n[REDACTED sha256=45f842f513290237]\n[1/2] \\\"\n\t\"api_key\":\n\"[REDACTED sha256=4b615b9693b87a6f]\"\nx,password\"=[REDACTED sha256=4b615b9693b87a6f]\n    \\\"\n","protected":["SYNTHFY005216L0","SYNTHFY005216L1"]}
]"###).must()
}

fn sixth_review_failures() -> Vec<ReviewFailure> {
    serde_json::from_str(r###"[
{"name":"fuzz6-61.json closed batch error 0","input":"see http://h/x[\n\"secret\": [\n  'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'password':\n \"q\n[[\n\"\n}\nsee http://h/y[\n\"token\":\n\"SYNTHR6000065T0\"\n]\nafter\nsee http://h/y[\n\"token\":\n\"SYNTHR6000065T1\"\n]\nafter\n","canaries":["SYNTHR6000065T0","SYNTHR6000065T1"]},
{"name":"fuzz6-61.json closed batch error 1","input":"see http://h/x[\n\"token\": [\n  'q\n[[[\n'\n]\n]\nx http://h/[a\n'token':\n \"q\n[[[\n\"\n]\nsee http://h/y[\n\"api_key\":\n|\n SYNTHR6000361T0\n]\nafter\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6000361T1\"\n}\n]\nafter\n","canaries":["SYNTHR6000361T0","SYNTHR6000361T1"]},
{"name":"fuzz6-61.json closed batch error 2","input":"x http://h/[a\n'password':\n\t'q\n[[[\n'\n]\nx '{\"a\": 1'\n\"token\":\n\t\"q\n[[\n\"\n}\n'\n password': v\n SYNTHR6000545T0\n","canaries":["SYNTHR6000545T0"]},
{"name":"fuzz6-61.json closed batch error 3","input":"x '{\"a\": 1'\n\"api_key\":\n 'q\n[[\n'\n}\nx '{\"a\": 1'\n\"token\":\n \"q\n[[\n\"\n}\n'\n password': v\n SYNTHR6000642T0\n","canaries":["SYNTHR6000642T0"]},
{"name":"fuzz6-61.json closed batch error 4","input":"[http://a/x, http://b/y]\nx http://h/[a\n\"api_key\":\n  \"q\n[[[\n\"\n]\nlog \"token\":\n  \"SYNTHR6000782T0\"\n","canaries":["SYNTHR6000782T0"]},
{"name":"fuzz6-61.json closed batch error 5","input":"x '{\"a\": 1'\n\"api_key\":\n\t\"q\n[[\n\"\n}\n[}\n\"api_key\":\n\t\"q\n[[[\n\"\n]\nsee http://h/y[\n\"token\":\n\"SYNTHR6000870T0\"\n]\nafter\nsee http://h/y[\n\"token\":\n\"SYNTHR6000870T1\"\n]\nafter\n","canaries":["SYNTHR6000870T0","SYNTHR6000870T1"]},
{"name":"fuzz6-61.json closed batch error 6","input":"see http://h/x[\n\"secret\": [\n\t'q\n[[[\n'\n]\n]\n{]\n'secret':\n \"q\n[[[\n\"\n]\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6001129T0\"\n}\n]\nafter\n\"token\":\n\"SYNTHR6001129T1\"\n","canaries":["SYNTHR6001129T0","SYNTHR6001129T1"]},
{"name":"fuzz6-61.json closed batch error 7","input":"[}\n\"secret\":\n  'q\n[[[\n'\n]\nsee http://h/x[\n'token':\n  \"q\n[[[\n\"\n]\nlog \"token\":\n  \"SYNTHR6001298T0\"\n","canaries":["SYNTHR6001298T0"]},
{"name":"fuzz6-61.json closed batch error 8","input":"[}\n'secret': [\n 'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'password':\n\t\"q\n[[\n\"\n}\n'\n password': v\n SYNTHR6001337T0\n","canaries":["SYNTHR6001337T0"]},
{"name":"fuzz6-61.json closed batch error 9","input":"{ \"u\": [ http://h/x] }\nx http://h/[a\n'token':\n  \"q\n[[[\n\"\n]\n\"token\":\n\"SYNTHR6001360T0\"\nlog \"token\":\n  \"SYNTHR6001360T1\"\n","canaries":["SYNTHR6001360T0","SYNTHR6001360T1"]},
{"name":"fuzz6-61.json closed batch error 10","input":"x '{\"a\": 1'\n'secret':\n 'q\n[[\n'\n}\nx '{\"a\": 1'\n\"token\":\n\t\"q\n[[\n\"\n}\nsee http://h/y[\n\"token\":\n\"SYNTHR6001455T0\"\n]\nafter\nsee http://h/y[\n\"api_key\":\n|\n SYNTHR6001455T1\n]\nafter\n","canaries":["SYNTHR6001455T0","SYNTHR6001455T1"]},
{"name":"fuzz6-61.json closed batch error 11","input":"[}\n\"token\": [\n  'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'password':\n  \"q\n[[\n\"\n}\n\"token\":\n\"SYNTHR6001812T0\"\n\"token\":\n\"SYNTHR6001812T1\"\n","canaries":["SYNTHR6001812T0","SYNTHR6001812T1"]},
{"name":"fuzz6-61.json closed batch error 12","input":"{ \"u\": [ http://h/x] }\nx http://h/[a\n\"token\":\n\t\"q\n[[[\n\"\n]\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6001855T0\"\n}\n]\nafter\nsee http://h/y[\n\"token\":\n\"SYNTHR6001855T1\"\n]\nafter\n","canaries":["SYNTHR6001855T0","SYNTHR6001855T1"]},
{"name":"fuzz6-61.json closed batch error 13","input":"[}\n\"token\": [\n 'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n\"secret\":\n \"q\n[[\n\"\n}\nsee http://h/y[\n\"token\":\n\"SYNTHR6001867T0\"\n]\nafter\n","canaries":["SYNTHR6001867T0"]},
{"name":"fuzz6-61.json closed batch error 14","input":"[}\n\"token\":\n \"q\n[[[\n\"\n]\nx '{\"a\": 1'\n'password':\n \"q\n[[\n\"\n}\nsee http://h/y[\n\"token\":\n\"SYNTHR6001981T0\"\n]\nafter\nsee http://h/y[\n\"token\":\n\"SYNTHR6001981T1\"\n]\nafter\n","canaries":["SYNTHR6001981T0","SYNTHR6001981T1"]},
{"name":"fuzz6-61.json closed batch error 15","input":"{ \"u\": [ http://h/x] }\n{]\n'token':\n \"q\n[[[\n\"\n]\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6002059T0\"\n}\n]\nafter\n\"token\":\n\"SYNTHR6002059T1\"\n","canaries":["SYNTHR6002059T0","SYNTHR6002059T1"]},
{"name":"fuzz6-61.json closed batch error 16","input":"[}\n'api_key': [\n  'q\n[[[\n'\n]\n]\nsee http://h/x[\n'token':\n \"q\n[[[\n\"\n]\nlog \"token\":\n  \"SYNTHR6002184T0\"\n","canaries":["SYNTHR6002184T0"]},
{"name":"fuzz6-61.json closed batch error 17","input":"[}\n'api_key': [\n\t'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'token':\n\t\"q\n[[\n\"\n}\n\"token\":\n\"SYNTHR6002237T0\"\n","canaries":["SYNTHR6002237T0"]},
{"name":"fuzz6-61.json closed batch error 18","input":"see http://h/x[\n\"password\": [\n  'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n\"api_key\":\n \"q\n[[\n\"\n}\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6002295T0\"\n}\n]\nafter\n","canaries":["SYNTHR6002295T0"]},
{"name":"fuzz6-61.json closed batch error 19","input":"[ https://h/p] tail\nx http://h/[a\n'password':\n \"q\n[[[\n\"\n]\nx {\n\"secret\":\n  \"SYNTHR6002433T0\"\n}\nx {\n\"secret\":\n  \"SYNTHR6002433T1\"\n}\n","canaries":["SYNTHR6002433T0","SYNTHR6002433T1"]},
{"name":"fuzz6-61.json closed batch error 20","input":"[}\n\"token\": [\n 'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'api_key':\n  \"q\n[[\n\"\n}\n'\n password': v\n SYNTHR6002494T0\n\"token\":\n\"SYNTHR6002494T1\"\n","canaries":["SYNTHR6002494T0","SYNTHR6002494T1"]},
{"name":"fuzz6-61.json closed batch error 21","input":"[ https://h/p] tail\nx '{\"a\": 1'\n'api_key':\n\t\"q\n[[\n\"\n}\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6002562T0\"\n}\n]\nafter\nx {\n\"secret\":\n  \"SYNTHR6002562T1\"\n}\n","canaries":["SYNTHR6002562T0","SYNTHR6002562T1"]},
{"name":"fuzz6-61.json closed batch error 22","input":"[}\n'secret': [\n\t'q\n[[[\n'\n]\n]\n[}\n\"api_key\":\n  \"q\n[[[\n\"\n]\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6002623T0\"\n}\n]\nafter\n","canaries":["SYNTHR6002623T0"]},
{"name":"fuzz6-61.json closed batch error 23","input":"x '{\"a\": 1'\n\"api_key\":\n\t'q\n[[\n'\n}\n[}\n'secret':\n\t\"q\n[[[\n\"\n]\nsee http://h/y[\n\"api_key\":\n|\n SYNTHR6002668T0\n]\nafter\nx {\n\"secret\":\n  \"SYNTHR6002668T1\"\n}\n","canaries":["SYNTHR6002668T0","SYNTHR6002668T1"]},
{"name":"fuzz6-61.json closed batch error 24","input":"[}\n'password': [\n\t'q\n[[[\n'\n]\n]\nsee http://h/x[\n'token':\n \"q\n[[[\n\"\n]\nx {\n\"secret\":\n  \"SYNTHR6002702T0\"\n}\n'\n password': v\n SYNTHR6002702T1\n","canaries":["SYNTHR6002702T0","SYNTHR6002702T1"]},
{"name":"fuzz6-61.json closed batch error 25","input":"[}\n'secret':\n \"q\n[[[\n\"\n]\nx '{\"a\": 1'\n'secret':\n \"q\n[[\n\"\n}\n'\n password': v\n SYNTHR6002752T0\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6002752T1\"\n}\n]\nafter\n","canaries":["SYNTHR6002752T0","SYNTHR6002752T1"]},
{"name":"fuzz6-62.json closed batch error 0","input":"see http://h/x[\n\"secret\": [\n\t'q\n[[[\n'\n]\n]\n{]\n'password':\n\t\"q\n[[[\n\"\n]\nlog \"token\":\n  \"SYNTHR6000063T0\"\n","canaries":["SYNTHR6000063T0"]},
{"name":"fuzz6-62.json closed batch error 1","input":"[}\n'api_key': [\n\t'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'password':\n\t\"q\n[[\n\"\n}\nsee http://h/y[\n\"api_key\":\n|\n SYNTHR6000114T0\n]\nafter\n","canaries":["SYNTHR6000114T0"]},
{"name":"fuzz6-62.json closed batch error 2","input":"see http://h/x[\n'secret': [\n 'q\n[[[\n'\n]\n]\nsee http://h/x[\n'password':\n \"q\n[[[\n\"\n]\nsee http://h/y[\n\"api_key\":\n|\n SYNTHR6000237T0\n]\nafter\n","canaries":["SYNTHR6000237T0"]},
{"name":"fuzz6-62.json closed batch error 3","input":"see http://h/x[\n\"password\":\n \"q\n[[[\n\"\n]\nx '{\"a\": 1'\n'api_key':\n\t\"q\n[[\n\"\n}\nsee http://h/y[\n\"api_key\":\n|\n SYNTHR6000585T0\n]\nafter\n'\n password': v\n SYNTHR6000585T1\n","canaries":["SYNTHR6000585T0","SYNTHR6000585T1"]},
{"name":"fuzz6-62.json closed batch error 4","input":"[}\n'api_key': [\n 'q\n[[[\n'\n]\n]\nx http://h/[a\n\"secret\":\n \"q\n[[[\n\"\n]\nx {\n\"secret\":\n  \"SYNTHR6000730T0\"\n}\n","canaries":["SYNTHR6000730T0"]},
{"name":"fuzz6-62.json closed batch error 5","input":"[}\n\"password\": [\n  'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'token':\n \"q\n[[\n\"\n}\nsee http://h/y[\n\"token\":\n\"SYNTHR6000861T0\"\n]\nafter\n'\n password': v\n SYNTHR6000861T1\n","canaries":["SYNTHR6000861T0","SYNTHR6000861T1"]},
{"name":"fuzz6-62.json closed batch error 6","input":"x http://h/[a\n'secret':\n 'q\n[[[\n'\n]\n{]\n\"password\":\n  \"q\n[[[\n\"\n]\n\"token\":\n\"SYNTHR6001109T0\"\n\"token\":\n\"SYNTHR6001109T1\"\n","canaries":["SYNTHR6001109T0","SYNTHR6001109T1"]},
{"name":"fuzz6-62.json closed batch error 7","input":"{ \"u\": [ http://h/x] }\nsee http://h/x[\n\"password\":\n\t\"q\n[[[\n\"\n]\n'\n password': v\n SYNTHR6001152T0\n","canaries":["SYNTHR6001152T0"]},
{"name":"fuzz6-62.json closed batch error 8","input":"[}\n'token': [\n 'q\n[[[\n'\n]\n]\n{]\n\"api_key\":\n\t\"q\n[[[\n\"\n]\nsee http://h/y[\n\"token\":\n\"SYNTHR6001235T0\"\n]\nafter\nlog \"token\":\n  \"SYNTHR6001235T1\"\n","canaries":["SYNTHR6001235T0","SYNTHR6001235T1"]},
{"name":"fuzz6-62.json closed batch error 9","input":"[ https://h/p] tail\nx '{\"a\": 1'\n\"password\":\n\t\"q\n[[\n\"\n}\nsee http://h/y[\n\"token\":\n\"SYNTHR6001261T0\"\n]\nafter\n\"token\":\n\"SYNTHR6001261T1\"\n","canaries":["SYNTHR6001261T0","SYNTHR6001261T1"]},
{"name":"fuzz6-62.json closed batch error 10","input":"see http://h/x[\n'token': [\n  'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'password':\n  \"q\n[[\n\"\n}\nx {\n\"secret\":\n  \"SYNTHR6001385T0\"\n}\n'\n password': v\n SYNTHR6001385T1\n","canaries":["SYNTHR6001385T0","SYNTHR6001385T1"]},
{"name":"fuzz6-62.json closed batch error 11","input":"{ \"u\": [ http://h/x] }\nsee http://h/x[\n'token':\n \"q\n[[[\n\"\n]\nsee http://h/y[\n\"token\":\n\"SYNTHR6001483T0\"\n]\nafter\nlog \"token\":\n  \"SYNTHR6001483T1\"\n","canaries":["SYNTHR6001483T0","SYNTHR6001483T1"]},
{"name":"fuzz6-62.json closed batch error 12","input":"see http://h/x[\n\"password\":\n\t\"q\n[[[\n\"\n]\n[}\n\"password\":\n  \"q\n[[[\n\"\n]\nlog \"token\":\n  \"SYNTHR6001561T0\"\n","canaries":["SYNTHR6001561T0"]},
{"name":"fuzz6-62.json closed batch error 13","input":"see http://h/x[\n\"secret\": [\n  'q\n[[[\n'\n]\n]\nsee http://h/x[\n'password':\n\t\"q\n[[[\n\"\n]\nsee http://h/y[\n\"token\":\n\"SYNTHR6001679T0\"\n]\nafter\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6001679T1\"\n}\n]\nafter\n","canaries":["SYNTHR6001679T0","SYNTHR6001679T1"]},
{"name":"fuzz6-62.json closed batch error 14","input":"x '{\"a\": 1'\n'token':\n\t'q\n[[\n'\n}\nx '{\"a\": 1'\n'password':\n  \"q\n[[\n\"\n}\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6001724T0\"\n}\n]\nafter\n","canaries":["SYNTHR6001724T0"]},
{"name":"fuzz6-62.json closed batch error 15","input":"[}\n\"api_key\": [\n\t'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n'api_key':\n  \"q\n[[\n\"\n}\nx {\n\"secret\":\n  \"SYNTHR6001968T0\"\n}\n'\n password': v\n SYNTHR6001968T1\n","canaries":["SYNTHR6001968T0","SYNTHR6001968T1"]},
{"name":"fuzz6-62.json closed batch error 16","input":"see http://h/x[\n'secret':\n  'q\n[[[\n'\n]\nx '{\"a\": 1'\n\"api_key\":\n  \"q\n[[\n\"\n}\nsee http://h/y[\n\"api_key\":\n|\n SYNTHR6001974T0\n]\nafter\nx {\n\"secret\":\n  \"SYNTHR6001974T1\"\n}\n","canaries":["SYNTHR6001974T0","SYNTHR6001974T1"]},
{"name":"fuzz6-62.json closed batch error 17","input":"x '{\"a\": 1'\n\"token\":\n  'q\n[[\n'\n}\nx '{\"a\": 1'\n\"api_key\":\n\t\"q\n[[\n\"\n}\n\"token\":\n\"SYNTHR6002155T0\"\n'\n password': v\n SYNTHR6002155T1\n","canaries":["SYNTHR6002155T0","SYNTHR6002155T1"]},
{"name":"fuzz6-62.json closed batch error 18","input":"x '{\"a\": 1'\n'secret':\n  'q\n[[\n'\n}\nx '{\"a\": 1'\n'token':\n  \"q\n[[\n\"\n}\nx {\n\"secret\":\n  \"SYNTHR6002204T0\"\n}\n","canaries":["SYNTHR6002204T0"]},
{"name":"fuzz6-62.json closed batch error 19","input":"x '{\"a\": 1'\n\"secret\":\n\t'q\n[[\n'\n}\nx '{\"a\": 1'\n\"password\":\n \"q\n[[\n\"\n}\n'\n password': v\n SYNTHR6002216T0\n","canaries":["SYNTHR6002216T0"]},
{"name":"fuzz6-62.json closed batch error 20","input":"mirrors=[http://a/x http://b/y]\n{]\n'token':\n  \"q\n[[[\n\"\n]\n\"token\":\n\"SYNTHR6002217T0\"\nsee http://h/y[\n\"token\":\n\"SYNTHR6002217T1\"\n]\nafter\n","canaries":["SYNTHR6002217T0","SYNTHR6002217T1"]},
{"name":"fuzz6-62.json closed batch error 21","input":"{ \"u\": [ http://h/x] }\nx '{\"a\": 1'\n\"secret\":\n \"q\n[[\n\"\n}\n'\n password': v\n SYNTHR6002235T0\nsee http://h/y[\n\"password\": {\n\"inner\": \"SYNTHR6002235T1\"\n}\n]\nafter\n","canaries":["SYNTHR6002235T0","SYNTHR6002235T1"]},
{"name":"fuzz6-62.json closed batch error 22","input":"x http://h/[a\n\"api_key\":\n  'q\n[[[\n'\n]\nx '{\"a\": 1'\n\"api_key\":\n \"q\n[[\n\"\n}\n'\n password': v\n SYNTHR6002254T0\nsee http://h/y[\n\"token\":\n\"SYNTHR6002254T1\"\n]\nafter\n","canaries":["SYNTHR6002254T0","SYNTHR6002254T1"]},
{"name":"fuzz6-62.json closed batch error 23","input":"see http://h/x[\n\"password\": [\n  'q\n[[[\n'\n]\n]\nx http://h/[a\n\"token\":\n \"q\n[[[\n\"\n]\n\"token\":\n\"SYNTHR6002268T0\"\n","canaries":["SYNTHR6002268T0"]},
{"name":"fuzz6-62.json closed batch error 24","input":"x '{\"a\": 1'\n\"secret\":\n 'q\n[[\n'\n}\nx '{\"a\": 1'\n\"password\":\n \"q\n[[\n\"\n}\nx {\n\"secret\":\n  \"SYNTHR6002487T0\"\n}\n","canaries":["SYNTHR6002487T0"]},
{"name":"fuzz6-62.json closed batch error 25","input":"see http://h/x[\n'api_key': [\n\t'q\n[[[\n'\n]\n]\nx '{\"a\": 1'\n\"secret\":\n  \"q\n[[\n\"\n}\nsee http://h/y[\n\"token\":\n\"SYNTHR6002647T0\"\n]\nafter\nx {\n\"secret\":\n  \"SYNTHR6002647T1\"\n}\n","canaries":["SYNTHR6002647T0","SYNTHR6002647T1"]},
{"name":"fuzz6-62.json closed batch error 26","input":"[}\n\"password\":\n 'q\n[[[\n'\n]\n[}\n'token':\n  \"q\n[[[\n\"\n]\n\"token\":\n\"SYNTHR6002694T0\"\n","canaries":["SYNTHR6002694T0"]},
{"name":"fuzz6-62.json closed batch error 27","input":"x '{\"a\": 1'\n\"password\":\n\t'q\n[[\n'\n}\nx http://h/[a\n'token':\n\t\"q\n[[[\n\"\n]\n\"token\":\n\"SYNTHR6002753T0\"\n","canaries":["SYNTHR6002753T0"]},
{"name":"fuzz6-62.json closed batch error 28","input":"[ https://h/p] tail\n{]\n'api_key':\n \"q\n[[[\n\"\n]\nx {\n\"secret\":\n  \"SYNTHR6002947T0\"\n}\n","canaries":["SYNTHR6002947T0"]}
]"###).must()
}

#[test]
fn sixth_review_context_depth_and_continuation_paths_preserve_pinned_batch_spans() {
    for case in sixth_review_records() {
        assert_pinned_review_record(&case);
    }
}

#[test]
fn sixth_review_context_carry_failures_stay_closed_at_every_boundary() {
    for case in sixth_review_failures() {
        assert_review_failure(&case);
    }
}

fn sixth_review_poison(
    variant: usize,
    eol: &str,
    name: &str,
    quote: char,
    indentation: &str,
    header: &str,
    layout: usize,
) -> String {
    let qn = format!("{quote}{name}{quote}");
    let pb = "-----BEGIN RSA PRIVATE KEY-----";
    let pe = "-----END RSA PRIVATE KEY-----";
    let input = match variant {
        0 => [
            "[ http://h/x]",
            "targets=[http://a/x http://b/y]",
            "{ \"a\": [ http://h/x] }",
            "[p://]a",
        ][layout]
            .to_owned(),
        1 => format!("[}}\n{qn}:\n{indentation}{quote}q\n[[\n{quote}\n]\n"),
        2 => format!("see http://h/x[\n{qn}: [\n{indentation}{quote}q\n[[[\n{quote}\n]\n]\n"),
        3 => {
            let body = if layout.is_multiple_of(2) {
                format!("{pb}MII synthetic{pe}")
            } else {
                format!("{pb}\n{indentation}MII synthetic\n{indentation}{pe}")
            };
            let tail = ["]", " ]", " 'x", " ["][layout];
            format!("[\n{name}: {header}\n{indentation}{body}{tail}\nx\n")
        }
        4 => format!("x '{{\"a\": 1'\n{qn}:\n{indentation}{quote}q\n[[\n{quote}\n}}\n"),
        5 => {
            let closing_name = [
                format!("{name}'"),
                format!("{name}\""),
                format!("{name}\\'"),
                format!("{name}\\\""),
            ][layout]
                .clone();
            format!("[\n{closing_name}:\n{header}\n{indentation}]\n")
        }
        6 => "see http://h/x[\n]\n".to_owned(),
        7 => format!("see http://h/x[\n{qn}: a] 'x\n'\n"),
        8 => [
            "password=\\\"a [x\\\" host=h dbname=d",
            "AccountKey=\\\"a;[x\\\";AccountName=n",
            "PASSWORD=\\\"a [x\\\" HOST=h SSLMODE=r",
            "x password=\\\"a ]\\\" user=u port=1",
        ][layout]
            .to_owned(),
        _ => format!("[\n{name}={pb}\nMII synthetic\n{pe} 'token': \\\"a ]\\\"\nx\n"),
    };
    input.replace('\n', eol)
}

fn sixth_review_grammar() -> impl Strategy<Value = (String, String)> {
    (
        prop::collection::vec(0usize..10, 1..4),
        prop::sample::select(vec!["\n", "\r\n", "\r"]),
        prop::sample::select(vec!["token", "api_key", "password", "client_secret"]),
        prop::sample::select(vec!['\'', '"']),
        prop::sample::select(vec![" ", "  ", "\t"]),
        prop::sample::select(vec!["a", "|", ">", "# synthetic"]),
        0usize..4,
        0usize..4,
        "[a-z0-9秘密é_-]{1,16}",
    )
        .prop_map(
            |(variants, eol, name, quote, indentation, header, layout, tail, suffix)| {
                let canary = format!("{CANARY}_{suffix}");
                let mut input = variants
                    .into_iter()
                    .map(|variant| {
                        sixth_review_poison(variant, eol, name, quote, indentation, header, layout)
                    })
                    .collect::<Vec<_>>()
                    .join(eol);
                input.push_str(eol);
                input.push_str(&match tail {
                    0 => format!(
                        "see http://h/y[{eol}\"token\":{eol}\"{canary}\"{eol}]{eol}after{eol}"
                    ),
                    1 => format!("\"token\":{eol}\"{canary}\"{eol}"),
                    2 => format!("x \"token\":{eol}{indentation}\"{canary}\"{eol}"),
                    _ => format!("password: v{eol}{indentation}{canary}{eol}"),
                });
                (input, canary)
            },
        )
}

struct InterruptedPrefix<'a> {
    remaining: &'a [u8],
}

impl Read for InterruptedPrefix<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.remaining.is_empty() {
            return Err(io::Error::other("synthetic stream interruption"));
        }
        let count = self.remaining.len().min(output.len());
        output[..count].copy_from_slice(&self.remaining[..count]);
        self.remaining = &self.remaining[count..];
        Ok(count)
    }
}

fn assert_emitted_boundaries_are_stable_with_supported_probes(input: &str) {
    let probes = [
        format!("\"token\":\n\"{CANARY}_BOUNDARY\"\n"),
        format!("x \"token\":\n  \"{CANARY}_BOUNDARY\"\n"),
        format!(" {CANARY}_BOUNDARY\n"),
    ];
    for end in line_ends(input.as_bytes()) {
        let prefix = &input[..end];
        let Ok(filtered_prefix) = filter(prefix.as_bytes()) else {
            continue;
        };
        let mut emitted = Vec::new();
        let error = filter_to_writer(
            InterruptedPrefix {
                remaining: prefix.as_bytes(),
            },
            &mut emitted,
        )
        .must_err();
        assert!(!format!("{error:?} {error}").contains(CANARY));
        if error.kind != redact::error::ErrorKind::Input {
            assert!(emitted.is_empty(), "failed synthetic prefix emitted input");
            continue;
        }
        assert!(
            filtered_prefix.as_bytes().starts_with(&emitted),
            "interrupted synthetic prefix emitted inconsistent bytes"
        );
        if emitted != filtered_prefix.as_bytes() || emitted.is_empty() {
            continue;
        }
        for probe in &probes {
            let expected = format!("{filtered_prefix}{}", filter(probe.as_bytes()).must());
            assert!(
                filter(format!("{prefix}{probe}").as_bytes())
                    .is_ok_and(|output| output == expected),
                "emitted synthetic boundary retained detector context"
            );
        }
    }
}

#[test]
fn ordinary_emitted_boundaries_are_stable_with_context_sensitive_probes() {
    for input in [
        "status=200 request=synthetic\n",
        "Server listening on http://localhost:3000\n",
        "INFO {\"password\":\"synthetic-secret\",\"status\":200}\n",
        "password=\\\"synthetic bracket [\\\"\n",
        "{\"token\":\"synthetic-secret\",\"password\":\"synthetic-secret\"}\n",
    ] {
        assert_emitted_boundaries_are_stable_with_supported_probes(input);
    }
}

#[test]
fn sixth_review_emitted_boundaries_are_stable_with_context_sensitive_probes() {
    for case in sixth_review_records() {
        assert_emitted_boundaries_are_stable_with_supported_probes(&case.input);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn generated_context_overlap_records_match_batch_and_read_schedules(
        fixture in sixth_review_grammar(),
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let (input, canary) = fixture;
        let whole = assert_batch_outcome(&input, &[&canary]);
        for result in [streamed(input.as_bytes(), Vec::new(), 1), streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX), streamed(input.as_bytes(), schedule(input.as_bytes(), &cuts), size)] {
            prop_assert!(result == whole, "generated overlap changed stdout, report, or safe error with reads");
        }
    }

    #[test]
    fn generated_supported_contexts_emit_only_probe_stable_boundaries(
        fixture in sixth_review_grammar(),
    ) {
        // Authentication-header quote pairing across records is a separate input contract.
        assert_emitted_boundaries_are_stable_with_supported_probes(&fixture.0);
    }

    #[test]
    fn sixth_review_successes_and_failures_preserve_generated_read_schedules(
        index in 0usize..131,
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let input = if index < 76 {
            sixth_review_records().into_iter().nth(index).must().input
        } else {
            sixth_review_failures().into_iter().nth(index - 76).must().input
        };
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
        prop_assert!(streamed(input.as_bytes(), schedule(input.as_bytes(), &cuts), size) == whole, "sixth-review pinned record changed under generated schedules");
    }
}

fn sixth_review_invalid_records() -> Vec<(String, Vec<u8>, usize)> {
    let mut cases = Vec::new();
    for name in ["E-eof", "F-eof", "G-eof", "H-eof", "I-closing-quote-eof"] {
        let case = sixth_review_records()
            .into_iter()
            .find(|case| case.name.split_whitespace().last() == Some(name))
            .must();
        for invalid in [0, 0xff] {
            let mut input = b"ok\n".to_vec();
            input.extend_from_slice(case.input.as_bytes());
            let line = input.iter().filter(|byte| **byte == b'\n').count() + 1;
            input.extend_from_slice(&[invalid, b'\n']);
            cases.push((format!("{name} byte {invalid}"), input, line));
        }
    }
    cases
}

#[test]
fn sixth_review_invalid_records_keep_global_locations_and_only_prior_filtered_output() {
    for (name, input, line) in sixth_review_invalid_records() {
        let whole = streamed(&input, Vec::new(), usize::MAX);
        let error = whole.error.as_ref().must();
        assert!(
            whole.output == b"ok\n" && whole.report.is_empty(),
            "{name} emitted an unfinished record"
        );
        assert_eq!(
            error.line,
            Some(line),
            "{name} changed its global input line"
        );
        assert!(error.earlier_output_emitted);
        assert!(!format!("{error:?} {error}").contains("SYNCAN"));
        for split in 0..=input.len() {
            assert!(
                streamed(&input, vec![split], usize::MAX) == whole,
                "{name} changed at split {split}"
            );
        }
        for size in [1, 2, 7, 31] {
            assert!(
                streamed(&input, Vec::new(), size) == whole,
                "{name} changed at size {size}"
            );
        }
        assert!(
            streamed(&input, line_ends(&input), usize::MAX) == whole,
            "{name} changed with line reads"
        );
    }
}

#[test]
fn sixth_review_cli_failures_match_safe_library_bytes_and_exit_two() {
    let mut cases: Vec<_> = sixth_review_failures()
        .into_iter()
        .map(|case| {
            let whole = streamed(case.input.as_bytes(), Vec::new(), usize::MAX);
            let error = whole.error.must();
            serde_json::json!({
                "input": case.input.into_bytes(),
                "stdout": String::from_utf8(whole.output).must(),
                "stderr": format!("rstr: {error}\n"),
                "canaries": case.canaries
            })
        })
        .collect();
    cases.extend(
        sixth_review_invalid_records()
            .into_iter()
            .map(|(_, input, _)| {
                let whole = streamed(&input, Vec::new(), usize::MAX);
                let error = whole.error.must();
                serde_json::json!({
                    "input": input,
                    "stdout": String::from_utf8(whole.output).must(),
                    "stderr": format!("rstr: {error}\n"),
                    "canaries": ["SYNCAN"]
                })
            }),
    );
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, subprocess, sys
for case in json.loads(sys.argv[2]):
    p = subprocess.run([sys.argv[1]], input=bytes(case['input']), capture_output=True, env={}, timeout=5)
    assert p.returncode == 2, 'detector/input failure did not exit with code 2'
    assert p.stdout == case['stdout'].encode(), 'failed stdout differed from library'
    assert p.stderr == case['stderr'].encode(), 'safe error differed from library'
    assert b'retry' in p.stderr or b'synthetic reproduction' in p.stderr, 'failure omitted recovery guidance'
    for canary in case['canaries']:
        assert canary.encode() not in p.stdout + p.stderr, 'failure disclosed a canary'
"#, env!("CARGO_BIN_EXE_rstr"), &serde_json::to_string(&cases).must()])
        .output()
        .must();
    assert!(
        output.status.success(),
        "sixth-review failure subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn go_url_slices_with_non_neutral_detector_depth_wait_for_eof() {
    let input = "targets=[http://a/x http://b/y]\nGET /a 200\nGET /b 200\n";
    let expected = filter(input.as_bytes()).must();
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import select, subprocess, sys
p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
try:
    for line in sys.argv[2].splitlines(keepends=True):
        p.stdin.write(line.encode()); p.stdin.flush()
        assert not select.select([p.stdout], [], [], .02)[0], 'URL slice released non-neutral detector state'
        assert p.poll() is None, 'URL slice filter exited before EOF'
    p.stdin.close(); p.stdin = None
    out, err = p.communicate(timeout=5)
    assert p.returncode == 0 and out == sys.argv[3].encode() and err == b'', 'held URL slice changed bytes'
finally:
    if p.poll() is None: p.kill(); p.wait()
"#, env!("CARGO_BIN_EXE_rstr"), input, &expected])
        .output()
        .must();
    assert!(
        output.status.success(),
        "Go URL slice subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn schedule(input: &[u8], cuts: &[usize]) -> Vec<usize> {
    let mut ends: Vec<_> = cuts.iter().map(|cut| cut % (input.len() + 1)).collect();
    ends.sort_unstable();
    ends.dedup();
    ends
}

fn generated_pem_tail() -> impl Strategy<Value = String> {
    (
        0usize..3,
        0usize..3,
        1usize..8,
        prop::sample::select(vec![
            "", ".", ",", ":", ";", "x", "\"", "'", "}", "]", "\\", "#", "!", "()", "x:y",
        ]),
    )
        .prop_map(|(header, label, indent, tail)| pem_tail_case(header, label, tail, indent))
}

fn generated_cr_name() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!['\"', '\'']),
        prop::sample::select(vec!["\r", " \r ", "\t\r\t", "\r\r", "\n"]),
        prop::sample::select(vec![" A", " |", " >", "", " # synthetic comment"]),
        1usize..8,
    )
        .prop_map(|(quote, spacing, value, indent)| cr_name_case(quote, spacing, value, indent))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 192, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn generated_contextual_boundaries_are_chunk_invariant(input in structured_case(), size in 2usize..128) {
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
        if let Ok(expected) = filter(input.as_bytes()) {
            prop_assert!(whole.error.is_none() && whole.output == expected.as_bytes(), "generated complete contextual record differs from batch");
        }
        for result in [streamed(input.as_bytes(), Vec::new(), 1), streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX), streamed(input.as_bytes(), Vec::new(), size)] {
            prop_assert!(result == whole, "generated contextual record changed with read chunks");
        }
    }

    #[test]
    fn generated_single_quoted_credentials_match_the_batch_oracle(input in json_log_case(), size in 1usize..128) {
        let expected = filter(input.as_bytes()).must();
        prop_assert!(!expected.contains(CANARY), "generated credential was not covered by batch");
        for result in [streamed(input.as_bytes(), Vec::new(), usize::MAX), streamed(input.as_bytes(), Vec::new(), 1), streamed(input.as_bytes(), line_ends(input.as_bytes()), size)] {
            prop_assert!(result.error.is_none() && result.output == expected.as_bytes(), "generated quoted credential differs from batch");
        }
    }

    #[test]
    fn generated_mixed_syntax_is_chunk_invariant(input in token_records(), size in 2usize..128) {
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
        for result in [streamed(input.as_bytes(), Vec::new(), 1), streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX), streamed(input.as_bytes(), Vec::new(), size)] {
            prop_assert!(result == whole, "generated mixed syntax changed output, evidence, or safe error across read chunks");
        }
    }

    #[test]
    fn generated_pem_tails_and_cr_names_preserve_batch_spans_and_read_schedules(
        input in prop_oneof![generated_pem_tail(), generated_cr_name()],
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let expected = filter(input.as_bytes()).must();
        prop_assert!(!expected.contains(CANARY), "generated sensitive continuation was not batch-hidden");
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
        prop_assert!(whole.error.is_none() && whole.output == expected.as_bytes(), "generated sensitive continuation differs from batch");
        for result in [streamed(input.as_bytes(), Vec::new(), 1), streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX), streamed(input.as_bytes(), schedule(input.as_bytes(), &cuts), size)] {
            prop_assert!(result == whole, "generated sensitive continuation changed with read schedules");
        }
    }

    #[test]
    fn generated_fourth_review_grammar_pins_removed_bytes_and_chunk_schedules(
        fixture in fourth_review_grammar(),
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let (input, expected) = fixture;
        prop_assert!(filter(input.as_bytes()).must() == expected, "generated expected spans differ from actual batch grammar");
        prop_assert!(!expected.contains(CANARY), "generated expected output still contains a protected canary");
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
        prop_assert!(whole.error.is_none() && whole.output == expected.as_bytes(), "generated contextual record differs from pinned batch spans");
        for result in [streamed(input.as_bytes(), Vec::new(), 1), streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX), streamed(input.as_bytes(), schedule(input.as_bytes(), &cuts), size)] {
            prop_assert!(result == whole, "generated contextual record changed output, evidence, or status with read schedules");
        }
    }

    #[test]
    fn pinned_fourth_review_records_preserve_random_read_schedules(
        index in 0usize..43,
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let case = fourth_review_records().into_iter().nth(index).must();
        let whole = streamed(case.input.as_bytes(), Vec::new(), usize::MAX);
        prop_assert!(whole.error.is_none() && whole.output == case.expected.as_bytes(), "pinned review record differs from actual batch spans");
        prop_assert!(streamed(case.input.as_bytes(), schedule(case.input.as_bytes(), &cuts), size) == whole, "pinned review record changed under generated read schedules");
    }

#[test]
    fn generated_fifth_review_poison_mixtures_match_actual_batch_and_schedules(
        fixture in fifth_review_grammar(),
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let (input, canary) = fixture;
        let whole = assert_batch_outcome(&input, &[&canary]);
        for result in [streamed(input.as_bytes(), Vec::new(), 1), streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX), streamed(input.as_bytes(), schedule(input.as_bytes(), &cuts), size)] {
            prop_assert!(result == whole, "generated fifth-review mixture changed output, report, or safe error with reads");
        }
    }

    #[test]
    fn pinned_fifth_review_successes_and_failures_preserve_random_read_schedules(
        index in 0usize..34,
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let input = if index < 30 {
            fifth_review_records().into_iter().nth(index).must().record.input
        } else {
            fifth_review_failures().into_iter().nth(index - 30).must().input
        };
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX);
        prop_assert!(streamed(input.as_bytes(), schedule(input.as_bytes(), &cuts), size) == whole, "pinned fifth-review record changed under generated read schedules");
    }

    #[test]
    fn private_marker_tail_records_preserve_random_read_schedules(
        index in 0usize..72,
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let input = private_marker_tail_records().into_iter().nth(index).must();
        let whole = assert_batch_outcome(&input, &[CANARY]);
        prop_assert!(streamed(input.as_bytes(), schedule(input.as_bytes(), &cuts), size) == whole, "private marker tail changed under generated read schedules");
    }
}

#[test]
fn live_staged_pipes_never_release_a_prefix_inconsistent_with_batch() {
    let cases: Vec<_> = review_cases()
        .into_iter()
        .chain(forward_quoted_assignment_cases())
        .map(|input| {
            let expected = filter(input.as_bytes()).must();
            serde_json::json!({"input": input, "expected": expected})
        })
        .chain(fourth_review_records().into_iter().map(|case| serde_json::json!({"input": case.input, "expected": case.expected, "protected": case.protected})))
        .chain(fifth_review_records().into_iter().map(|case| serde_json::json!({"input": case.record.input, "expected": case.record.expected, "protected": case.record.protected})))
        .chain(sixth_review_records().into_iter().map(|case| serde_json::json!({"input": case.input, "expected": case.expected, "protected": case.protected})))
        .collect();
    let output = Command::new("python3").env_clear().env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, os, select, subprocess, sys
for case in json.loads(sys.argv[2]):
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    emitted = b''
    expected = case['expected'].encode()
    try:
        for line in case['input'].splitlines(keepends=True):
            p.stdin.write(line.encode()); p.stdin.flush()
            while select.select([p.stdout], [], [], .02)[0]:
                part = os.read(p.stdout.fileno(), 8192)
                assert part, 'filter exited before EOF'
                emitted += part
                assert expected.startswith(emitted), 'live stream released inconsistent bytes'
        p.stdin.close(); p.stdin = None
        out, err = p.communicate(timeout=5)
        assert p.returncode == 0, 'live stream failed'
        assert emitted + out == expected, 'live final output differed from batch'
        assert b'SYNTHETIC_REVIEW_CANARY_0123456789' not in err, 'diagnostics disclosed a canary'
        for canary in case.get('protected', []):
            assert canary.encode() not in err, 'review diagnostics disclosed a protected canary'
    finally:
        if p.poll() is None: p.kill(); p.wait()
"#, env!("CARGO_BIN_EXE_rstr"), &serde_json::to_string(&cases).must()]).output().must();
    assert!(
        output.status.success(),
        "staged streaming subprocess failed"
    );
}

#[test]
fn fifth_review_ambiguous_records_withhold_every_staged_line_until_eof() {
    let cases: Vec<_> = fifth_review_records()
        .into_iter()
        .filter(|case| case.withhold)
        .map(|case| {
            let whole = streamed(case.record.input.as_bytes(), Vec::new(), usize::MAX);
            assert!(whole.error.is_none());
            serde_json::json!({
                "name": case.record.name,
                "input": case.record.input,
                "expected": case.record.expected,
                "report": String::from_utf8(whole.report).must(),
                "protected": case.record.protected
            })
        })
        .collect();
    assert_eq!(cases.len(), 19);
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, select, subprocess, sys
for case in json.loads(sys.argv[2]):
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    try:
        for line in case['input'].splitlines(keepends=True):
            p.stdin.write(line.encode()); p.stdin.flush()
            assert not select.select([p.stdout], [], [], .02)[0], 'ambiguous record emitted before EOF: ' + case['name']
            assert p.poll() is None, 'ambiguous record exited before EOF'
        p.stdin.close(); p.stdin = None
        out, err = p.communicate(timeout=5)
        assert p.returncode == 0, 'ambiguous record failed'
        assert out == case['expected'].encode(), 'held output differed from batch'
        assert err == case['report'].encode(), 'held report differed from library'
        for canary in case['protected']:
            assert canary.encode() not in out + err, 'held record disclosed a protected canary'
    finally:
        if p.poll() is None: p.kill(); p.wait()
"#, env!("CARGO_BIN_EXE_rstr"), &serde_json::to_string(&cases).must()])
        .output()
        .must();
    assert!(
        output.status.success(),
        "fifth-review withholding subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fifth_review_batch_failures_exit_two_with_exact_safe_library_output() {
    let cases: Vec<_> = fifth_review_failures()
        .into_iter()
        .map(|case| {
            let canaries: Vec<_> = case.canaries.iter().map(String::as_str).collect();
            let whole = assert_batch_outcome(&case.input, &canaries);
            let error = whole.error.must();
            serde_json::json!({
                "input": case.input,
                "stdout": String::from_utf8(whole.output).must(),
                "stderr": format!("rstr: {error}\n"),
                "canaries": case.canaries
            })
        })
        .collect();
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, subprocess, sys
for case in json.loads(sys.argv[2]):
    p = subprocess.run([sys.argv[1]], input=case['input'].encode(), capture_output=True, env={}, timeout=5)
    assert p.returncode == 2, 'batch failure did not exit with code 2'
    assert p.stdout == case['stdout'].encode(), 'failed stdout differed from library'
    assert p.stderr == case['stderr'].encode(), 'safe error differed from library'
    assert b'synthetic reproduction' in p.stderr or b'retry' in p.stderr, 'failure omitted recovery guidance'
    for canary in case['canaries']:
        assert canary.encode() not in p.stdout + p.stderr, 'batch failure disclosed a canary'
"#, env!("CARGO_BIN_EXE_rstr"), &serde_json::to_string(&cases).must()])
        .output()
        .must();
    assert!(
        output.status.success(),
        "fifth-review failure subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn completed_opaque_wire_values_with_unmatched_braces_stream_before_eof() {
    let cases: Vec<_> = ['{', '[']
        .into_iter()
        .map(|opening| {
            let value = format!("{CANARY} {opening}");
            let input = format!("password=\\\"{value}\\\"\n");
            let expected = format!(
                "password=\\\"[REDACTED sha256={}]\\\"\n",
                fingerprint(&value)
            );
            assert!(filter(input.as_bytes()).must() == expected);
            serde_json::json!({"input": input, "expected": expected})
        })
        .collect();
    let output = Command::new("python3").env_clear().env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, os, select, subprocess, sys, time
for case in json.loads(sys.argv[2]):
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    try:
        p.stdin.write(case['input'].encode()); p.stdin.flush()
        expected = case['expected'].encode()
        emitted = b''
        deadline = time.monotonic() + 5
        while len(emitted) < len(expected):
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([p.stdout], [], [], remaining)[0], 'completed opaque wire value waited for EOF'
            part = os.read(p.stdout.fileno(), len(expected) - len(emitted))
            assert part, 'filter exited before completed wire output'
            emitted += part
        assert emitted == expected and p.poll() is None, 'completed opaque wire value changed'
        p.stdin.close(); p.stdin = None
        out, err = p.communicate(timeout=5)
        assert p.returncode == 0 and out == b'', 'completed wire stream failed'
        assert b'SYNTHETIC_REVIEW_CANARY_0123456789' not in err, 'wire diagnostics disclosed a canary'
    finally:
        if p.poll() is None: p.kill(); p.wait()
"#, env!("CARGO_BIN_EXE_rstr"), &serde_json::to_string(&cases).must()]).output().must();
    assert!(
        output.status.success(),
        "completed wire liveness subprocess failed"
    );
}

#[test]
fn live_pretty_json_with_sensitive_quoted_keys_emits_when_the_object_closes() {
    let cases: Vec<_> = [
        format!("{{\n  \"password\": \"{CANARY}\"\n}}\n"),
        format!("{{\n  \"password\": \"{CANARY}\",\n  \"status\": 401\n}}\n"),
        format!("{{\"password\":\"{CANARY}\",\"token\":\"{CANARY}\"}}\n"),
        format!("{{\n  \"password\": \"{CANARY}\",\n  \"token\": \"{CANARY}\"\n}}\n"),
        format!("{{\n  \"token\": {{\n    \"value\": \"{CANARY}\"\n  }},\n  \"status\": 401\n}}\n"),
        format!("INFO {{\"password\":\"{CANARY}\",\"token\":\"{CANARY}\"}}\n"),
    ]
    .into_iter()
    .map(|input| {
        let expected = filter(input.as_bytes()).must();
        serde_json::json!({"input": input, "expected": expected})
    })
    .collect();
    let output = Command::new("python3").env_clear().env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, os, select, subprocess, sys, time
for case in json.loads(sys.argv[2]):
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    try:
        lines = case['input'].splitlines(keepends=True)
        for line in lines[:-1]:
            p.stdin.write(line.encode()); p.stdin.flush()
            assert not select.select([p.stdout], [], [], .02)[0], 'unfinished JSON object was released'
        p.stdin.write(lines[-1].encode()); p.stdin.flush()
        expected = case['expected'].encode()
        emitted = b''
        deadline = time.monotonic() + 5
        while len(emitted) < len(expected):
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([p.stdout], [], [], remaining)[0], 'closed JSON object waited for EOF'
            part = os.read(p.stdout.fileno(), len(expected) - len(emitted))
            assert part, 'filter exited before its completed JSON object'
            emitted += part
        assert emitted == expected, 'completed JSON differed from batch'
        assert p.poll() is None, 'filter exited before EOF'
        p.stdin.close(); p.stdin = None
        out, err = p.communicate(timeout=5)
        assert p.returncode == 0 and out == b'', 'completed JSON stream failed'
        assert b'SYNTHETIC_REVIEW_CANARY_0123456789' not in err, 'JSON diagnostics disclosed a canary'
    finally:
        if p.poll() is None: p.kill(); p.wait()
"#, env!("CARGO_BIN_EXE_rstr"), &serde_json::to_string(&cases).must()]).output().must();
    assert!(
        output.status.success(),
        "live pretty JSON subprocess failed"
    );
}

#[test]
fn live_common_log_colons_stream_while_real_mapping_indicators_stay_held() {
    let cases = serde_json::json!([
        [
            "url",
            [
                "Server listening on http://localhost:3000\n",
                "GET / 200\n",
                "GET /a 200\n"
            ]
        ],
        [
            "iso",
            [
                "2026-10-07T12:00:00Z INFO started\n",
                "2026-10-07T12:00:01Z INFO ready\n",
                "2026-10-07T12:00:02Z INFO done\n"
            ]
        ],
        [
            "clock",
            [
                "12:00:01 INFO started\n",
                "12:00:02 INFO ready\n",
                "12:00:03 INFO done\n"
            ]
        ],
        [
            "go",
            [
                "2026/10/07 12:00:00 started\n",
                "2026/10/07 12:00:01 ready\n",
                "2026/10/07 12:00:02 done\n"
            ]
        ],
        [
            "python",
            [
                "INFO:root:started\n",
                "INFO:root:ready\n",
                "INFO:root:done\n"
            ]
        ],
        [
            "pytest",
            [
                "tests/test_a.py::test_one PASSED\n",
                "tests/test_a.py::test_two PASSED\n",
                "tests/test_b.py::test_three PASSED\n"
            ]
        ],
        [
            "file",
            [
                "thread 'main' panicked at src/main.rs:3:5:\n",
                "synthetic diagnostic\n",
                "src/main.rs:4:6: synthetic diagnostic\n"
            ]
        ],
        [
            "compose",
            [
                "web-1  | 2026-10-07 12:00:00 started\n",
                "web-1  | GET / 200\n",
                "db-1   | ready\n"
            ]
        ],
    ]);
    let output = Command::new("python3").env_clear().env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, os, select, subprocess, sys, time
for name, lines in json.loads(sys.argv[2]):
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    try:
        for line in lines:
            expected = line.encode()
            p.stdin.write(expected); p.stdin.flush()
            emitted = b''
            deadline = time.monotonic() + 5
            while len(emitted) < len(expected):
                remaining = deadline - time.monotonic()
                assert remaining > 0 and select.select([p.stdout], [], [], remaining)[0], 'ordinary log waited for EOF: ' + name
                part = os.read(p.stdout.fileno(), len(expected) - len(emitted))
                assert part, 'filter exited before an ordinary log record: ' + name
                emitted += part
            assert emitted == expected, 'ordinary log bytes changed: ' + name
            assert p.poll() is None, 'filter exited while stdin remained open: ' + name
        p.stdin.close(); p.stdin = None
        out, err = p.communicate(timeout=5)
        assert p.returncode == 0 and out == b'' and err == b'', 'ordinary log stream failed: ' + name
    finally:
        if p.poll() is None: p.kill(); p.wait()
for raw in ['ERROR: retry later\nstatus=200\n', 'message: transient\nINFO recovered\n']:
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    try:
        p.stdin.write(raw.encode()); p.stdin.flush()
        assert not select.select([p.stdout], [], [], .05)[0], 'mapping indicator released an unfinished document'
        p.stdin.close(); p.stdin = None
        out, err = p.communicate(timeout=5)
        assert p.returncode == 0 and out == raw.encode() and err == b'', 'held mapping document changed'
    finally:
        if p.poll() is None: p.kill(); p.wait()
"#, env!("CARGO_BIN_EXE_rstr"), &cases.to_string()]).output().must();
    assert!(
        output.status.success(),
        "ordinary-colon liveness subprocess failed"
    );
}

#[test]
fn invalid_held_continuation_keeps_the_same_safe_prefix_for_all_chunkings() {
    for invalid in [0, 0xff] {
        let mut input = format!("status=401\n{{\npassword: A}}\n  {CANARY}").into_bytes();
        input.extend_from_slice(&[invalid, b'\n']);
        for (ends, size) in [
            (Vec::new(), usize::MAX),
            (Vec::new(), 1),
            (line_ends(&input), usize::MAX),
        ] {
            let result = streamed(&input, ends, size);
            let error = result.error.must();
            assert!(result.output == b"status=401\n" && result.report.is_empty());
            assert_eq!(error.line, Some(4));
            assert!(error.earlier_output_emitted);
            assert!(!format!("{error:?} {error}").contains(CANARY));
        }
    }
}

#[test]
fn subprocess_invalid_continuation_withholds_the_record_and_exits_two() {
    let prefix = format!("status=401\n{{\npassword: A}}\n  {CANARY}");
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import subprocess, sys
for invalid in [b'\0', b'\xff']:
    p = subprocess.run([sys.argv[1]], input=sys.argv[2].encode() + invalid + b'\n', capture_output=True, env={}, timeout=5)
    assert p.returncode == 2, 'invalid continuation did not fail with exit 2'
    assert p.stdout == b'status=401\n', 'invalid record emitted bytes'
    assert b'line 4' in p.stderr and b'withheld' in p.stderr, 'failure lacks recovery context'
    assert b'SYNTHETIC_REVIEW_CANARY_0123456789' not in p.stderr, 'failure disclosed a canary'
"#, env!("CARGO_BIN_EXE_rstr"), &prefix])
        .output()
        .must();
    assert!(
        output.status.success(),
        "invalid continuation subprocess failed"
    );
}
