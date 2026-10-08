use std::io::{self, Read};

use redact::{filter, rstr::filter_to_writer};

use crate::{CANARY, check_error};

struct InterruptedPrefix<'a>(&'a [u8]);

impl Read for InterruptedPrefix<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::Error::other("synthetic boundary input failure"));
        }
        let count = output.len().min(self.0.len());
        output[..count].copy_from_slice(&self.0[..count]);
        self.0 = &self.0[count..];
        Ok(count)
    }
}

fn probes() -> [String; 4] {
    [
        format!("\"token\":\n\"{CANARY}\"\n"),
        format!("x \"token\":\n  \"{CANARY}\"\n"),
        format!(" {CANARY}\nx\n"),
        format!("\"password\": {{\n\"inner\": \"{CANARY}\"\n}}\n"),
    ]
}

fn neutral_with_probe(prefix: &[u8], expected: &str, probe: &str) -> bool {
    let mut joined = prefix.to_vec();
    joined.extend_from_slice(probe.as_bytes());
    let Ok(separate) = filter(probe.as_bytes()) else {
        return false;
    };
    filter(&joined).is_ok_and(|output| output == format!("{expected}{separate}"))
}

fn check_boundary(prefix: &[u8], probes: &[String]) {
    let mut emitted = Vec::new();
    let result = filter_to_writer(InterruptedPrefix(prefix), &mut emitted);
    assert!(result.is_err(), "input failure did not reach the stream");
    if let Err(error) = result {
        check_error(&error);
    }
    let Ok(expected) = filter(prefix) else {
        return;
    };
    // Only a fully emitted prefix certifies a boundary. EOF must not force a hold.
    if emitted != expected.as_bytes() {
        return;
    }
    for probe in probes {
        assert!(
            neutral_with_probe(prefix, &expected, probe),
            "emitted boundary changed detection of later synthetic input"
        );
    }
}

pub fn exercise(data: &[u8]) {
    // Token composition varies syntax rather than selecting known failing layouts.
    // Authentication quote pairing and Kubernetes scope are record-local contracts.
    const TOKENS: &[&str] = &[
        "[",
        "]",
        "{",
        "}",
        "'",
        "\"",
        "\\\"",
        "\\'",
        ":",
        "=",
        ",",
        " ",
        "\t",
        "\n",
        "\n ",
        "\n\t",
        "token",
        "password",
        "api_key",
        "secret",
        "token'",
        "token\"",
        "\"token\"",
        "'password'",
        "ordinary",
        "x",
        "a",
        "é",
        "|",
        ">",
        "# n",
        "http://h/x]",
        "http://h/y[",
        "p://]a",
        "http://a/x",
        "http://b/y]",
        "host=h dbname=d",
        "AccountName=n;",
        "AccountKey=",
        "MII",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
    ];
    let selector = usize::from(data.first().copied().unwrap_or_default());
    let mut input = String::new();
    for byte in data.iter().skip(1).take(48) {
        input.push_str(TOKENS[usize::from(*byte) % TOKENS.len()]);
    }
    input.push('\n');
    if selector % 2 == 1 {
        input = input.replace('\n', "\r\n");
    }
    let ends: Vec<usize> = input
        .bytes()
        .enumerate()
        .filter_map(|(at, byte)| (byte == b'\n').then_some(at + 1))
        .collect();
    let probes = probes();
    // Bound per-iteration cost while sampling all ends across generated mutations.
    for sample in 0..ends.len().min(8) {
        let at = ends[(sample + selector) % ends.len()];
        check_boundary(&input.as_bytes()[..at], &probes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_oracle_rejects_a_disclosure_from_a_pretend_early_emission() {
        let prefix = b"[ http://h/x]\n";
        let expected = filter(prefix);
        assert!(expected.is_ok(), "synthetic fixture failed");
        if let Ok(expected) = expected {
            assert!(
                !neutral_with_probe(prefix, &expected, &probes()[0]),
                "boundary oracle missed a deliberately unsafe emission"
            );
        }
    }

    #[test]
    fn boundary_oracle_accepts_complete_ordinary_and_quoted_json_records() {
        for prefix in [
            b"ordinary log\n".as_slice(),
            b"{\"password\":\"synthetic\"}\n",
        ] {
            check_boundary(prefix, &probes());
        }
    }

    #[test]
    fn token_composition_covers_every_fragment_and_line_ending() {
        for selector in 0..=1 {
            for byte in 0..42 {
                exercise(&[selector, byte, 13, 22, 8, 13, 4, 25, 13]);
            }
        }
    }
}
