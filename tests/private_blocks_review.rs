use redact::fingerprint;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn escaped_certificate_and_private_key_have_separate_boundaries() {
    let public =
        r"-----BEGIN CERTIFICATE-----\nSYNTHETIC_PUBLIC_CERTIFICATE\n-----END CERTIFICATE-----\n";
    for label in ["PRIVATE KEY", "ANY PRIVATE KEY", "FUTURE2 PRIVATE KEY"] {
        let key = format!(
            r"-----BEGIN {label}-----\nSYNTHETIC_PRIVATE_KEY_CANARY_0123456789\n-----END {label}-----"
        );
        let input = format!(r#"{{"certificate":"{public}","private_key":"{key}"}}"#);
        let expected = format!(
            r#"{{"certificate":"{public}","private_key":"[REDACTED sha256={}]"}}"#,
            fingerprint(&key)
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_rstr"))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty());
    }
}
