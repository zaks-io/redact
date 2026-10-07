use redact::{Evidence, Redaction, RedactionReport, error::ErrorKind};
use std::io::{self, Write};

fn redaction(hash: &str, line: usize, labels: Vec<Evidence>) -> Redaction {
    Redaction {
        fingerprint: hash.into(),
        line,
        labels,
    }
}

fn render(report: &RedactionReport) -> Vec<u8> {
    let mut bytes = Vec::new();
    assert!(report.write(&mut bytes).is_ok());
    bytes
}

#[test]
fn reports_rebase_lines_and_group_matching_evidence() {
    let mut report = RedactionReport::default();
    let rows = [redaction(
        "1d5a8919184510ff",
        2,
        vec![Evidence::SensitiveFieldOrQuotedCredential],
    )];
    assert!(report.observe(&rows, 40).is_ok());
    assert!(report.observe(&rows, 80).is_ok());
    assert_eq!(render(&report), b"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 41: sha256=1d5a8919184510ff; sensitive field or quoted credential (2 occurrences)\n");
}

#[test]
fn report_storage_and_rendering_are_bounded() {
    let mut report = RedactionReport::default();
    let rows: Vec<_> = (0..1000)
        .map(|index| {
            redaction(
                &format!("{index:016x}"),
                1,
                vec![
                    Evidence::AuthHeader,
                    Evidence::PrivateKey,
                    Evidence::UrlCredentials,
                    Evidence::ConnectionString,
                ],
            )
        })
        .collect();
    assert!(report.observe(&rows, 1).is_ok());
    let bytes = render(&report);
    let text = String::from_utf8(bytes).unwrap_or_else(|_| panic!("approved report must be UTF-8"));
    assert_eq!(text.lines().count(), 10);
    assert!(text.contains(" + other evidence"));
    assert!(text.ends_with("rstr: 992 more redactions; fingerprints remain in output markers.\n"));
    assert!(text.len() < 2000);
    assert!(format!("{report:?}").len() < 3000);
}

#[test]
fn invalid_metadata_is_never_echoed() {
    for row in [
        redaction("synthetic-secret-canary", 1, vec![Evidence::AuthHeader]),
        redaction("1d5a8919184510ff", 0, vec![Evidence::AuthHeader]),
        redaction("1d5a8919184510ff", 1, vec![]),
        redaction(
            "1d5a8919184510ff",
            1,
            vec![Evidence::AuthHeader, Evidence::AuthHeader],
        ),
    ] {
        let mut report = RedactionReport::default();
        let error = report
            .observe(&[row], 1)
            .err()
            .unwrap_or_else(|| panic!("invalid metadata accepted"));
        assert!(!format!("{error:?} {error} {report:?}").contains("synthetic-secret-canary"));
        assert!(render(&report).is_empty());
    }
    let mut report = RedactionReport::default();
    assert!(
        report
            .observe(
                &[redaction("1d5a8919184510ff", 2, vec![Evidence::AuthHeader])],
                usize::MAX
            )
            .is_err()
    );
}

struct FailedWriter;
impl Write for FailedWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("synthetic-secret-writer-canary"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn no_matches_are_quiet_and_writer_errors_are_safe() {
    let mut report = RedactionReport::default();
    assert!(report.write(&mut FailedWriter).is_ok());
    assert!(
        report
            .observe(
                &[redaction("1d5a8919184510ff", 1, vec![Evidence::AuthHeader])],
                1
            )
            .is_ok()
    );
    let error = report
        .write(&mut FailedWriter)
        .err()
        .unwrap_or_else(|| panic!("write failure accepted"));
    assert_eq!(error.kind, ErrorKind::Output);
    assert!(!format!("{error:?} {error}").contains("synthetic-secret-writer-canary"));
}
