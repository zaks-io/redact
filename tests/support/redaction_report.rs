pub fn assert_report(stdout: &[u8], stderr: &[u8]) {
    let output = String::from_utf8_lossy(stdout);
    if !output.contains("[REDACTED sha256=") {
        assert!(stderr.is_empty(), "zero-match output must stay quiet");
        return;
    }
    let report = std::str::from_utf8(stderr).unwrap_or_else(|_| panic!("report is not UTF-8"));
    let mut lines = report.lines();
    let summary = lines
        .next()
        .unwrap_or_else(|| panic!("missing redaction report"));
    let count = summary
        .strip_prefix("rstr: ")
        .and_then(|line| {
            line.strip_suffix(
                " redactions; labels describe local syntax evidence, not credential validity.",
            )
            .or_else(|| {
                line.strip_suffix(
                    " redaction; labels describe local syntax evidence, not credential validity.",
                )
            })
        })
        .and_then(|number| number.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("invalid report summary"));
    assert!(count > 0);
    assert_eq!(summary.contains(" redaction;"), count == 1);
    let mut entries = 0;
    for line in lines {
        if line.ends_with(" more redactions; fingerprints remain in output markers.")
            || line.ends_with(" more redaction; fingerprints remain in output markers.")
        {
            assert!(line.starts_with("rstr: "));
            continue;
        }
        entries += 1;
        let (position, detail) = line
            .split_once(": sha256=")
            .unwrap_or_else(|| panic!("invalid report entry"));
        assert!(
            position
                .strip_prefix("rstr: line ")
                .and_then(|number| number.parse::<usize>().ok())
                .is_some_and(|line| line > 0)
        );
        let (hash, labels) = detail
            .split_once("; ")
            .unwrap_or_else(|| panic!("missing evidence label"));
        assert_eq!(hash.len(), 16);
        assert!(
            hash.bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
        assert!(output.contains(&format!("[REDACTED sha256={hash}]")));
        assert!(!labels.is_empty());
    }
    assert!((1..=8).contains(&entries));
    assert!(report.len() < 3000, "report must remain bounded");
}
