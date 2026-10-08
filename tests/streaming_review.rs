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
