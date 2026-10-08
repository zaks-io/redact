#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use proptest::prelude::*;
use redact::{MAX_INPUT_BYTES, error::ErrorKind, filter, fingerprint, rstr::filter_to_writer};
use std::{
    io::{self, Read, Write},
    process::Command,
};

const CANARY: &str = "SYNTHETIC_STREAMING_CANARY_0123456789";

struct Chunks<'a> {
    input: &'a [u8],
    position: usize,
    first_split: usize,
    size: usize,
}

impl Read for Chunks<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let end = if self.position < self.first_split {
            self.first_split
        } else {
            self.input.len()
        };
        let count = (end - self.position).min(buffer.len()).min(self.size);
        buffer[..count].copy_from_slice(&self.input[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

fn streamed(input: &[u8], split: usize, size: usize) -> Result<Vec<u8>, redact::error::SafeError> {
    let mut output = Vec::new();
    filter_to_writer(
        Chunks {
            input,
            position: 0,
            first_split: split,
            size,
        },
        &mut output,
    )?;
    Ok(output)
}

#[test]
fn every_split_preserves_multiline_structures_unicode_and_exact_hashes() {
    let key = format!(
        "-----BEGIN FUTURE2 PRIVATE KEY-----\n{{'{CANARY}秘密\n-----END FUTURE2 PRIVATE KEY-----\r\n"
    );
    let cases = [
        format!("status=401\npassword=\"{CANARY}秘密\né\" host=example.test\r\n"),
        key.clone(),
        format!("{{\n\"d\":\"{CANARY}\",\n\"kty\":\"RSA\"\n}}\r\n"),
        format!(
            "{{\"servers\":\"public\",\n\"auths\":{{\"host\":{{\"auth\":\"{CANARY}\"}}}}\n}}\n"
        ),
        format!(
            "# synthetic document\ndata:\n  opaque: {CANARY}\nmetadata:\n  name: public\nkind: Secret\n"
        ),
        format!("password: synthetic-head\n  {CANARY}秘密\nstatus: 401\n"),
        format!("message=\"password='{CANARY}\n秘密'\" status=401\n"),
        format!("message='Authorization: Bearer {CANARY}' status=401\n"),
        format!("\"password\"\n= \"{CANARY}\"\n"),
        format!("metadata/labels: public\ndata:\n  opaque: {CANARY}\nkind: Secret\n"),
        format!("\"metadata/labels\":public\ndata:\n  opaque: {CANARY}\nkind: Secret\n"),
        format!("? [synthetic, key]\n: public\ndata:\n  opaque: {CANARY}\nkind: Secret\n"),
    ];
    for input in cases {
        let expected = filter(input.as_bytes()).must();
        assert!(!expected.contains(CANARY));
        for split in 0..=input.len() {
            assert_eq!(
                streamed(input.as_bytes(), split, usize::MAX).must(),
                expected.as_bytes()
            );
        }
    }
    let output = String::from_utf8(streamed(key.as_bytes(), 1, 1).must()).must();
    assert!(output.contains(&format!(
        "sha256={}",
        fingerprint(key.trim_end_matches(['\r', '\n']))
    )));
}

#[test]
fn reviewed_colon_escaped_quote_and_overlapping_marker_boundaries_preserve_detection() {
    let a = format!("{CANARY}_A");
    let b = format!("{CANARY}_B");
    let cases = [
        format!("password:{a}\n  {b}\n"),
        format!("password :{a}\n  {b}\n"),
        format!("password:|\n  {a}\n  {b}\n"),
        format!("password:>\n  {a}\n  {b}\n"),
        format!("\"password\"\n:{a}\n  {b}\n"),
        format!("kind:Secret\ndata:\n  payload:{a}\n"),
        format!("data:\n  payload:{a}\nkind:Secret\n"),
        format!("metadata/labels: public\ndata:\n  payload:{a}\nkind:Secret\n"),
        format!("ключ: public\ndata:\n  payload:{a}\nkind:Secret\n"),
        format!("service[debug], region: public\ndata:\n  payload:{a}\nkind:Secret\n"),
        format!("service=debug[local], region: public\ndata:\n  payload:{a}\nkind:Secret\n"),
        format!("status=401 apiToken:{a}\n  {b}\nkind:Secret\ndata:\n  payload:{a}\n"),
        format!("password=\\\"{a}\n{b}\\\" status=401\n"),
        format!("password=\\\"{a}\\\\\\\"embedded\n{b}\\\" status=401\n"),
        format!(
            "-----END RSA PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\n{a}\n-----END RSA PRIVATE KEY-----\n"
        ),
        format!(
            "key:public\n--- # -----BEGIN RSA PRIVATE KEY-----\n{a}\n---\n-----END RSA PRIVATE KEY-----\n"
        ),
    ];
    for input in cases {
        let expected = filter(input.as_bytes()).must();
        assert!(!expected.contains(CANARY));
        for split in 0..=input.len() {
            assert_eq!(
                streamed(input.as_bytes(), split, usize::MAX).must(),
                expected.as_bytes()
            );
        }
        assert_eq!(streamed(input.as_bytes(), 0, 1).must(), expected.as_bytes());
    }
    let input = format!("password:{a}\n  {b}\n");
    assert!(
        String::from_utf8(streamed(input.as_bytes(), 0, 1).must())
            .must()
            .contains(&format!("sha256={}", fingerprint(format!("{a}\n  {b}"))))
    );
    let input = format!("kind:Secret\ndata:\n  payload:{a}\n");
    assert!(
        String::from_utf8(streamed(input.as_bytes(), 0, 1).must())
            .must()
            .contains(&format!("sha256={}", fingerprint(&input)))
    );
}

#[test]
fn ordinary_colon_prefixes_keep_separate_context_without_releasing_later_yaml() {
    let tail = format!("data:\n  payload:{CANARY}\nkind:Secret\n");
    for prefix in ["metadata/labels:public\n", "ключ:public\n", "key:public\n"] {
        let input = format!("{prefix}{tail}");
        assert!(!filter(input.as_bytes()).must().contains(CANARY));
        let expected = format!("{prefix}{}", filter(tail.as_bytes()).must());
        assert!(!expected.contains(CANARY));
        for split in 0..=input.len() {
            assert_eq!(
                streamed(input.as_bytes(), split, usize::MAX).must(),
                expected.as_bytes()
            );
        }
        assert_eq!(streamed(input.as_bytes(), 0, 1).must(), expected.as_bytes());
    }
}

#[test]
fn complete_format_inventory_is_independent_of_read_boundaries() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/secret-formats.json")).must();
    assert_eq!(fixtures["synthetic_only"], true);
    for case in fixtures["cases"].as_array().must() {
        let input = case["input"].as_str().must().as_bytes();
        let expected = filter(input);
        for size in [1, 4096] {
            match (&expected, streamed(input, 0, size)) {
                (Ok(expected), Ok(output)) => {
                    assert_eq!(output, expected.as_bytes(), "{}", case["id"])
                }
                (Err(_), Err(_)) => {}
                _ => panic!("streaming changed a synthetic format fixture result"),
            }
        }
    }
}

#[test]
fn subprocess_emits_settled_records_before_eof_and_withholds_uncertain_input() {
    let quote = format!("password=\"{CANARY}\n秘密\" status=401\n");
    let key = format!("-----BEGIN PRIVATE KEY-----\n{{'{CANARY}\n-----END PRIVATE KEY-----\n");
    let nested_key = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\n{CANARY}\n-----END RSA PRIVATE KEY-----\n-----END EC PRIVATE KEY-----\n"
    );
    let jwk = format!("{{\n\"d\":\"{CANARY}\",\n\"kty\":\"RSA\"\n}}\n");
    let docker = format!(
        "{{\n\"servers\":\"public\",\n\"auths\":{{\"host\":{{\"auth\":\"{CANARY}\"}}}}\n}}\n"
    );
    let yaml = format!(
        "# synthetic metadata\nmetadata:\n  name: public\ndata:\n  opaque: {CANARY}\nkind: Secret\n"
    );
    let colon = format!("password:{CANARY}_A\n  {CANARY}_B\n");
    let colon_name = format!("\"password\"\n:{CANARY}_A\n  {CANARY}_B\n");
    let inline_colon = format!(
        "status=401 apiToken:{CANARY}_A\n  {CANARY}_B\nkind:Secret\ndata:\n  payload:{CANARY}_A\n"
    );
    let wire = format!("password=\\\"{CANARY}_A\n{CANARY}_B\\\" status=401\n");
    let shared_key = format!(
        "-----END RSA PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\n{CANARY}\n-----END RSA PRIVATE KEY-----\n"
    );
    let separator_key = format!(
        "--- # -----BEGIN RSA PRIVATE KEY-----\n{CANARY}\n---\n-----END RSA PRIVATE KEY-----\n"
    );
    let sensitive_json = format!("{{\"password\":\"{CANARY}\",\"status\":401}}\n");
    let inline_json = format!("level=info payload={{\"password\": \"{CANARY}\",\"status\":401}}\n");
    let kind_first = format!("kind:Secret\ndata:\n  payload:{CANARY}\n");
    let kind_late = format!("metadata/labels: public\ndata:\n  payload:{CANARY}\nkind:Secret\n");
    let block = format!("password:|\n  {CANARY}_A\n  {CANARY}_B\n");
    let folded = format!("password:>\n  {CANARY}_A\n  {CANARY}_B\n");
    let steps = serde_json::json!([
        {"steps": [["status=401\n", "status=401\n"], [&quote[..quote.find('秘').must()], ""], [&quote[quote.find('秘').must()..], filter(quote.as_bytes()).must()]], "tail": ""},
        {"steps": [[&key[..key.find("-----END").must()], ""], [&key[key.find("-----END").must()..], filter(key.as_bytes()).must()]], "tail": ""},
        {"steps": [[&nested_key[..nested_key.find("-----END EC").must()], ""], [&nested_key[nested_key.find("-----END EC").must()..], filter(nested_key.as_bytes()).must()]], "tail": ""},
        {"steps": [[&jwk[..jwk.find("\"kty\"").must()], ""], [&jwk[jwk.find("\"kty\"").must()..], filter(jwk.as_bytes()).must()]], "tail": ""},
        {"steps": [[&docker[..docker.find("\"auths\"").must()], ""], [&docker[docker.find("\"auths\"").must()..], filter(docker.as_bytes()).must()]], "tail": ""},
        {"steps": [[yaml, ""], ["---\n", filter(yaml.as_bytes()).must()]], "tail": "---\n"},
        {"steps": [[format!("Authorization: Bearer {CANARY}\n"), ""]], "tail": filter(format!("Authorization: Bearer {CANARY}\n").as_bytes()).must()},
        {"steps": [[format!("step can't authenticate password='{CANARY}' status=401\n"), filter(format!("step can't authenticate password='{CANARY}' status=401\n").as_bytes()).must()]], "tail": ""},
        {"steps": [["\"password\"\n", ""], [format!("= \"{CANARY}\"\n"), ""], ["status=401\n", filter(format!("\"password\"\n= \"{CANARY}\"\nstatus=401\n").as_bytes()).must()]], "tail": ""}
        ,{"steps": [["message=\"synthetic ordinary\"\n", ""], ["message=\"synthetic ordinary\"\n", "message=\"synthetic ordinary\"\n"], ["status=401\n", "message=\"synthetic ordinary\"\nstatus=401\n"]], "tail": ""}
        ,{"steps": [[&colon[..colon.find('\n').must()+1], ""], [&colon[colon.find('\n').must()+1..], ""]], "tail": filter(colon.as_bytes()).must()}
        ,{"steps": [["\"password\"\n", ""], [format!(":{CANARY}_A\n"), ""], [format!("  {CANARY}_B\n"), ""]], "tail": filter(colon_name.as_bytes()).must()}
        ,{"steps": [[&inline_colon[..inline_colon.find('\n').must()+1], ""], [&inline_colon[inline_colon.find('\n').must()+1..], ""]], "tail": filter(inline_colon.as_bytes()).must()}
        ,{"steps": [[&wire[..wire.find('\n').must()+1], ""], [&wire[wire.find('\n').must()+1..], filter(wire.as_bytes()).must()]], "tail": ""}
        ,{"steps": [[&shared_key[..shared_key.rfind("-----END").must()], ""], [&shared_key[shared_key.rfind("-----END").must()..], filter(shared_key.as_bytes()).must()]], "tail": ""}
        ,{"steps": [["key:public\n", "key:public\n"], [&separator_key[..separator_key.find('\n').must()+1], ""], [&separator_key[separator_key.find('\n').must()+1..], ""], ["---\n", filter(separator_key.as_bytes()).must()]], "tail": "---\n"}
        ,{"steps": [[sensitive_json, filter(sensitive_json.as_bytes()).must()]], "tail": ""}
        ,{"steps": [[inline_json, filter(inline_json.as_bytes()).must()]], "tail": ""}
        ,{"steps": [["kind:Secret\n", ""], [format!("data:\n  payload:{CANARY}\n"), ""]], "tail": filter(kind_first.as_bytes()).must()}
        ,{"steps": [["metadata/labels: public\n", ""], [format!("data:\n  payload:{CANARY}\n"), ""], ["kind:Secret\n", ""]], "tail": filter(kind_late.as_bytes()).must()}
        ,{"steps": [["timestamp=2026-10-07T20:00:00Z status=200\n", "timestamp=2026-10-07T20:00:00Z status=200\n"]], "tail": ""}
        ,{"steps": [["[2026-10-07T20:00:00Z] status=200\n", "[2026-10-07T20:00:00Z] status=200\n"]], "tail": ""}
        ,{"steps": [["password:|\n", ""], [format!("  {CANARY}_A\n  {CANARY}_B\n"), ""]], "tail": filter(block.as_bytes()).must()}
        ,{"steps": [["password:>\n", ""], [format!("  {CANARY}_A\n  {CANARY}_B\n"), ""]], "tail": filter(folded.as_bytes()).must()}
    ]);
    python(
        r#"
import json, os, select, subprocess, sys, time
def read_exact(pipe, expected):
    result = b''
    deadline = time.monotonic() + 5
    while len(result) < len(expected):
        remaining = deadline - time.monotonic()
        assert remaining > 0, 'completed record waited for EOF'
        assert select.select([pipe], [], [], remaining)[0], 'completed record waited for EOF'
        part = os.read(pipe.fileno(), len(expected) - len(result))
        assert part, 'filter exited before a completed record'
        result += part
    assert result == expected, 'filtered output differed'
for case in json.loads(sys.argv[2]):
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    try:
        for raw, expected in case['steps']:
            p.stdin.write(raw.encode()); p.stdin.flush()
            read_exact(p.stdout, expected.encode())
            assert not select.select([p.stdout], [], [], .05)[0], 'unfinished record was released'
            assert p.poll() is None, 'filter exited before EOF'
        p.stdin.close(); p.stdin = None
        output, error = p.communicate(timeout=5)
        assert p.returncode == 0, 'streaming subprocess failed'
        assert output == case['tail'].encode(), 'final filtered output differed'
        assert b'SYNTHETIC_STREAMING_CANARY_0123456789' not in error, 'diagnostics exposed a secret'
    finally:
        if p.poll() is None: p.kill(); p.wait()
"#,
        &steps.to_string(),
    );
}

fn python(script: &str, argument: &str) {
    let output = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", script, env!("CARGO_BIN_EXE_rstr"), argument])
        .output()
        .must();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn subprocess_late_failure_keeps_filtered_prefix_and_reports_global_location() {
    python(
        r#"
import os, select, subprocess, sys, threading, time
p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
try:
    prefix = b'status=401\n' * 1000
    writer = threading.Thread(target=lambda: (p.stdin.write(prefix), p.stdin.flush()))
    writer.start()
    emitted = b''
    deadline = time.monotonic() + 5
    while len(emitted) < len(prefix):
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([p.stdout], [], [], remaining)[0], 'completed record waited for EOF'
        part = os.read(p.stdout.fileno(), len(prefix) - len(emitted))
        assert part, 'filter exited before all completed records'
        emitted += part
    writer.join(timeout=5)
    assert not writer.is_alive() and emitted == prefix
    p.stdin.write(b'password="SYNTHETIC_STREAMING_CANARY_0123456789\n'); p.stdin.close(); p.stdin = None
    output, error = p.communicate(timeout=5)
    assert p.returncode == 2
    assert output == b''
    assert b'line 1001' in error and b'withheld' in error
    assert b'SYNTHETIC_STREAMING_CANARY_0123456789' not in error
finally:
    if p.poll() is None: p.kill(); p.wait()
"#,
        "",
    );
}

struct Repeated {
    record: Vec<u8>,
    remaining: usize,
    position: usize,
}

impl Read for Repeated {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = bytes.len().min(self.remaining);
        for byte in &mut bytes[..count] {
            *byte = self.record[self.position % self.record.len()];
            self.position += 1;
        }
        self.remaining -= count;
        Ok(count)
    }
}

#[derive(Default)]
struct CountedOutput {
    bytes: usize,
    flushes: usize,
}
impl Write for CountedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

#[test]
fn lifetime_exceeding_limit_succeeds_but_an_undecided_record_fails() {
    let record = format!("status=200 {}\n", "x".repeat(1012)).into_bytes();
    let size = record.len() * (MAX_INPUT_BYTES / record.len() + 2);
    let mut writer = CountedOutput::default();
    filter_to_writer(
        Repeated {
            record,
            remaining: size,
            position: 0,
        },
        &mut writer,
    )
    .must();
    assert_eq!(writer.bytes, size);
    assert!(writer.flushes > 1 && writer.flushes < size / 1000);
    let mut output = Vec::new();
    let error = filter_to_writer(
        io::repeat(b'x').take((MAX_INPUT_BYTES + 1) as u64),
        &mut output,
    )
    .must_err();
    assert!(output.is_empty());
    assert!(
        error
            .to_string()
            .contains("unfinished record exceeds 16 MiB")
    );
    python(
        r#"
import subprocess, sys
record = b'status=200 message="' + b'x' * 1002 + b'"\n'
raw = record * (16777216 // len(record) + 2)
output = subprocess.run([sys.argv[1]], input=raw, capture_output=True, env={}, timeout=15)
assert output.returncode == 0, 'long stream hit a lifetime size limit'
assert output.stdout == raw and output.stderr == b''
"#,
        "",
    );
}

struct FailedAfterPrefix {
    delivered: bool,
}
impl Read for FailedAfterPrefix {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.delivered {
            return Err(io::Error::other(CANARY));
        }
        self.delivered = true;
        let prefix = b"status=401\n";
        bytes[..prefix.len()].copy_from_slice(prefix);
        Ok(prefix.len())
    }
}

struct PartialWrite {
    bytes: Vec<u8>,
}
impl Write for PartialWrite {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.bytes.is_empty() {
            return Err(io::Error::other(CANARY));
        }
        let count = bytes.len().min(25);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn read_encoding_nul_and_partial_write_failures_are_safe() {
    let mut output = Vec::new();
    let error = filter_to_writer(FailedAfterPrefix { delivered: false }, &mut output).must_err();
    assert_eq!(output, b"status=401\n");
    assert_eq!(error.line, Some(2));
    assert!(!format!("{error:?} {error}").contains(CANARY));
    for suffix in [vec![0xff, b'\n'], vec![0, b'\n']] {
        let input = [b"status=401\n".as_slice(), suffix.as_slice()].concat();
        let mut output = Vec::new();
        let error = filter_to_writer(input.as_slice(), &mut output).must_err();
        assert_eq!(output, b"status=401\n");
        assert_eq!(error.line, Some(2));
    }
    let mut writer = PartialWrite { bytes: Vec::new() };
    let error = filter_to_writer(format!("password={CANARY}\n").as_bytes(), &mut writer).must_err();
    assert_eq!(error.kind, ErrorKind::Output);
    assert!(!String::from_utf8(writer.bytes).must().contains(CANARY));
    assert!(!format!("{error:?} {error}").contains(CANARY));
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn chunk_sizes_do_not_change_recognizable_log_fields(value in "[a-zA-Z0-9秘密é _-]{1,80}", size in 1usize..128) {
        let input = format!("status=401\r\npassword=\"{value}\" host=example.test\n");
        let expected = filter(input.as_bytes()).must();
        prop_assert_eq!(streamed(input.as_bytes(), 0, size).must(), expected.as_bytes());
    }
}
