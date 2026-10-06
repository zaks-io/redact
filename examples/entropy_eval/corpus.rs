use base64::{Engine, engine::general_purpose::STANDARD};
use redact::{Span, secret::SecretString};
use sha2::{Digest, Sha256};

pub const LENGTHS: [usize; 12] = [8, 15, 16, 24, 31, 32, 40, 64, 128, 129, 256, 512];
pub const SAMPLES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    OpaqueSecret,
    PublicControl,
    StructuredSecret,
    OtherSecret,
    IndependentBenign,
}

pub struct Case {
    pub id: String,
    pub family: &'static str,
    pub kind: Kind,
    pub length: usize,
    pub text: SecretString,
    pub secrets: Vec<Span>,
}

impl Case {
    fn new(
        id: String,
        family: &'static str,
        kind: Kind,
        length: usize,
        text: String,
        secrets: Vec<Span>,
    ) -> Self {
        Self {
            id,
            family,
            kind,
            length,
            text: SecretString::new(text),
            secrets,
        }
    }
}

pub fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    for (alphabet, secret_family, public_family) in [
        (b"0123456789abcdef".as_slice(), "opaque-hex", "public-hash"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "opaque-base62",
            "public-base62-id",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "opaque-base64",
            "public-base64-id",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            "opaque-base64url",
            "public-base64url-id",
        ),
    ] {
        for length in LENGTHS {
            for sample in 0..SAMPLES {
                let value = generated(alphabet, length, sample);
                // Identical bytes deliberately expose the absence of semantic evidence.
                for (family, kind, secrets) in [
                    (
                        secret_family,
                        Kind::OpaqueSecret,
                        std::iter::once(0..length).collect(),
                    ),
                    (public_family, Kind::PublicControl, vec![]),
                ] {
                    cases.push(Case::new(
                        format!("{family}-{length}-{sample}"),
                        family,
                        kind,
                        length,
                        value.clone(),
                        secrets,
                    ));
                }
            }
        }
    }
    for sample in 0..SAMPLES {
        for length in [32, 512] {
            let value = generated(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                length,
                sample,
            );
            surround(
                &mut cases,
                "assignment",
                Kind::StructuredSecret,
                sample,
                "{\"password\":\"",
                &value,
                "\",\"status\":401}",
            );
            surround(
                &mut cases,
                "bearer",
                Kind::StructuredSecret,
                sample,
                "Authorization: Bearer ",
                &value,
                "\nHTTP 401\n",
            );
            surround(
                &mut cases,
                "url-credentials",
                Kind::StructuredSecret,
                sample,
                "postgres://",
                &format!("demo:{value}"),
                "@db.example.test/app",
            );
            let body = generated(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                length,
                sample,
            );
            let wrapped = body
                .as_bytes()
                .chunks(64)
                .map(|line| String::from_utf8_lossy(line))
                .collect::<Vec<_>>()
                .join("\n");
            let private =
                format!("-----BEGIN PRIVATE KEY-----\n{wrapped}\n-----END PRIVATE KEY-----");
            surround(
                &mut cases,
                "private-key",
                Kind::StructuredSecret,
                sample,
                "diagnostic before\n",
                &private,
                "\ndiagnostic after\n",
            );
            for label in ["PUBLIC KEY", "CERTIFICATE"] {
                benign(
                    &mut cases,
                    "public-pem",
                    sample,
                    format!("-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----"),
                );
            }
            benign(
                &mut cases,
                "public-ssh",
                sample,
                format!("ssh-ed25519 {body} demo@example.test"),
            );
        }
        let value = generated(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            32,
            sample,
        );
        surround(
            &mut cases,
            "punctuated-standalone",
            Kind::OtherSecret,
            sample,
            "",
            &format!("{}.{}", &value[..16], &value[16..]),
            "",
        );
        surround(
            &mut cases,
            "embedded-standalone",
            Kind::OtherSecret,
            sample,
            "prefix",
            &value,
            "suffix",
        );
        surround(
            &mut cases,
            "provider",
            Kind::StructuredSecret,
            sample,
            "value: ",
            &format!("ghp_{value}"),
            "\nrequest completed\n",
        );
        let jwt = format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.{value}");
        surround(
            &mut cases,
            "jwt",
            Kind::StructuredSecret,
            sample,
            "value: ",
            &jwt,
            "\nrequest completed\n",
        );
        let hex = generated(b"0123456789abcdef", 32, sample);
        benign(
            &mut cases,
            "uuid",
            sample,
            format!(
                "request_id=\"{}-{}-4{}-8{}-{}\"",
                &hex[..8],
                &hex[8..12],
                &hex[13..16],
                &hex[17..20],
                &hex[20..]
            ),
        );
        benign(
            &mut cases,
            "encoded-text",
            sample,
            STANDARD.encode(format!(
                "Synthetic public diagnostic {sample}: request completed successfully"
            )),
        );
        benign(
            &mut cases,
            "url-path",
            sample,
            format!("https://cdn.example.test/assets/{hex}.js"),
        );
    }
    for (sample, value) in [
        "synthetic-password",
        "aaaaaaaabbbbbbbbccccccccdddddddd",
        "0123456789abcdef0123456789abcdef",
        "password123",
        "correct horse battery staple",
        "雪synthetic秘密",
    ]
    .into_iter()
    .enumerate()
    {
        surround(
            &mut cases,
            "weak-standalone",
            Kind::OtherSecret,
            sample,
            "",
            value,
            "",
        );
        surround(
            &mut cases,
            "weak-assignment",
            Kind::StructuredSecret,
            sample,
            "password=\"",
            value,
            "\"\n",
        );
    }
    for (sample, value) in [
        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz".repeat(5).as_str(),
        "status=200 service=synthetic-api request completed in 123 milliseconds",
        "LongOrdinaryCamelCaseDiagnosticIdentifierWithoutCredentialContext",
        "ordinary Unicode prose: 雪の診断結果は正常です café résumé",
        "1234567890123456789012345678901234567890",
        "abcdabcdabcdabcdabcdabcdabcdabcd",
        "",
    ]
    .into_iter()
    .enumerate()
    {
        benign(&mut cases, "ordinary-text", sample, value.to_owned());
    }
    cases
}

fn surround(
    cases: &mut Vec<Case>,
    family: &'static str,
    kind: Kind,
    sample: usize,
    before: &str,
    value: &str,
    after: &str,
) {
    cases.push(Case::new(
        format!("{family}-{}-{sample}", value.len()),
        family,
        kind,
        value.len(),
        format!("{before}{value}{after}"),
        std::iter::once(before.len()..before.len() + value.len()).collect(),
    ));
}

fn benign(cases: &mut Vec<Case>, family: &'static str, sample: usize, text: String) {
    cases.push(Case::new(
        format!("{family}-{}-{sample}", text.len()),
        family,
        Kind::IndependentBenign,
        text.len(),
        text,
        vec![],
    ));
}

fn generated(alphabet: &[u8], length: usize, sample: usize) -> String {
    let mut output = String::with_capacity(length);
    let mut block = 0_u64;
    while output.len() < length {
        let mut hash = Sha256::new();
        hash.update(b"redact-entropy-eval-synthetic-v1");
        hash.update(alphabet);
        hash.update((length as u64).to_le_bytes());
        hash.update((sample as u64).to_le_bytes());
        hash.update(block.to_le_bytes());
        for byte in hash.finalize() {
            // Rejection sampling avoids modulo bias for Base62.
            if usize::from(byte) < 256 / alphabet.len() * alphabet.len() {
                output.push(char::from(alphabet[usize::from(byte) % alphabet.len()]));
                if output.len() == length {
                    break;
                }
            }
        }
        block += 1;
    }
    output
}
