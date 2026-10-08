use super::{MAX_INPUT_BYTES, filter_candidate, filter_with_evidence};
use crate::{context::RecordEnd, error::ErrorKind, synthetic::*};

#[test]
fn top_level_semantic_unfinished_failures_defer_candidate_detection() {
    let cases = [
        ("password=\"SYNTHETIC\n", ErrorKind::UnterminatedQuote),
        (
            "password=\\\"SYNTHETIC\n",
            ErrorKind::UnterminatedEscapedQuote,
        ),
        (
            "{\"password\":[\"SYNTHETIC\"\n",
            ErrorKind::UnterminatedSensitiveContainer,
        ),
        (
            "{\"kty\":\"oct\",\"k\":\"SYNTHETIC\"\n",
            ErrorKind::UnterminatedCredentialContainer,
        ),
        (
            "-----BEGIN A PRIVATE KEY-----\nSYNTHETIC\n",
            ErrorKind::UnterminatedPrivateKey,
        ),
    ];
    for (input, kind) in cases {
        let error = filter_with_evidence(input.as_bytes()).must_err();
        assert_eq!(error.kind, kind);
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
        for boundary in [
            RecordEnd::Newline,
            RecordEnd::NonDelimiter,
            RecordEnd::Document,
        ] {
            assert!(
                filter_candidate(input.as_bytes(), boundary)
                    .must()
                    .is_none()
            );
        }
    }
    assert!(!ErrorKind::Category("unterminated quoted value").can_complete());
    assert!(!ErrorKind::Detector.can_complete());
    assert!(!ErrorKind::InvalidEscape.can_complete());
    assert!(!ErrorKind::TooLarge.can_complete());
}

#[test]
fn errors_after_actual_provisional_quotes_wait_for_complete_detection() {
    let json_prefix = format!(
        "{{\"a\":'\\-----END A PRIVATE KEY-----\"'{}{}}}\n",
        "{".repeat(64),
        "}".repeat(64)
    );
    let context_prefix = "{'-----BEGIN A PRIVATE KEY-----':\nM\n-----END A PRIVATE KEY-----' ";
    let inputs = [
        (json_prefix, "x\"\n"),
        (
            format!("{context_prefix}\"password\": {{\"a\": ]}}}}\n"),
            "'\n",
        ),
        (format!("{context_prefix}\"password\": \"a\tb\"}}\n"), "'\n"),
        (
            format!(
                "{context_prefix}\"password\": {}{}}}\n",
                "[".repeat(65),
                "]".repeat(65)
            ),
            "'\n",
        ),
    ];
    for (prefix, suffix) in inputs {
        let error = filter_with_evidence(prefix.as_bytes()).must_err();
        assert!(!error.kind.can_complete());
        for boundary in [
            RecordEnd::Newline,
            RecordEnd::NonDelimiter,
            RecordEnd::Document,
        ] {
            assert!(
                filter_candidate(prefix.as_bytes(), boundary)
                    .must()
                    .is_none()
            );
        }
        filter_with_evidence(format!("{prefix}{suffix}").as_bytes()).must();
    }

    let no_quote_after_begin = "{'-----BEGIN A PRIVATE KEY-----:\nM\n-----END A PRIVATE KEY-----' \"password\": {\"a\": ]}}\n";
    let batch = filter_with_evidence(no_quote_after_begin.as_bytes()).must_err();
    let candidate =
        filter_candidate(no_quote_after_begin.as_bytes(), RecordEnd::Newline).must_err();
    assert_eq!(candidate, batch);
}

#[test]
fn json_quote_uncertainty_survives_a_later_contextual_failure() {
    let input = "'\\-----END A PRIVATE KEY-----\"'\npassword=\"\\qSYNTHETIC\"\n";
    let structured = crate::structured::detect_with_contexts(input).must();
    assert!(structured.json_end.provisional_quote());
    let failure = crate::context::detect_with_state(input, &structured.contexts, 0).must_err();
    assert!(!failure.can_complete());
    assert!(
        filter_candidate(input.as_bytes(), RecordEnd::Newline)
            .must()
            .is_none()
    );
    let batch = filter_with_evidence(input.as_bytes()).must_err();
    assert!(!batch.kind.can_complete());
    assert!(!format!("{batch:?} {batch}").contains("SYNTHETIC"));
}

#[test]
fn unfinished_errors_inside_closed_quoted_text_are_final() {
    for nested in [
        "bad line: password=\"SYNTHETIC",
        "bad line: password=\\\"SYNTHETIC",
        "{\"password\":[\"SYNTHETIC\"",
        "{\"kty\":\"oct\",\"k\":\"SYNTHETIC\"",
    ] {
        let quoted = serde_json::to_string(nested).must();
        let input = format!("level=error msg={quoted} code=1\n");
        let batch = filter_with_evidence(input.as_bytes()).must_err();
        assert!(batch.kind.can_complete());
        let candidate = filter_candidate(input.as_bytes(), RecordEnd::Newline).must_err();
        assert_eq!(candidate, batch);
        assert!(!format!("{candidate:?} {candidate}").contains("SYNTHETIC"));
    }
}

#[test]
fn invalid_encoding_escapes_structure_and_limits_fail_at_the_candidate() {
    let mut inputs = vec![
        b"password=\"\\qSYNTHETIC\"\n".to_vec(),
        b"{\"password\":[}\n".to_vec(),
        b"{\"kty\":\"oct\",\"k\":?}\n".to_vec(),
        b"SYNTHETIC\0\n".to_vec(),
        vec![0xff, b'\n'],
        vec![b'x'; MAX_INPUT_BYTES + 1],
    ];
    inputs.push(format!("{}SYNTHETIC\n", "{\"x\":".repeat(65)).into_bytes());
    for input in inputs {
        let batch = filter_with_evidence(&input).must_err();
        let candidate = filter_candidate(&input, RecordEnd::Newline).must_err();
        assert!(!candidate.kind.can_complete());
        assert_eq!(candidate, batch);
        assert!(!format!("{candidate:?} {candidate}").contains("SYNTHETIC"));
    }
}

#[test]
fn json_detector_quote_state_cannot_be_waived_by_context_certificates() {
    let input = "'\\-----END A PRIVATE KEY-----\"'\n";
    let structured = crate::structured::detect_with_contexts(input).must();
    let context = crate::context::detect_with_state(input, &structured.contexts, 0).must();
    assert!(context.end.settled(RecordEnd::NonDelimiter));
    assert!(!structured.json_end.settled());
    for boundary in [
        RecordEnd::Newline,
        RecordEnd::NonDelimiter,
        RecordEnd::Document,
    ] {
        assert!(
            filter_candidate(input.as_bytes(), boundary)
                .must()
                .is_none()
        );
    }
}

#[test]
fn certified_candidates_keep_batch_output_spans_fingerprints_and_evidence() {
    for input in [
        "status=401 password=\"SYNTHETIC_VALUE\" host=example.test\n",
        "token=\\\"SYNTHETIC_VALUE\\\"\n",
        "{\"kty\":\"oct\",\"k\":\"SYNTHETIC_VALUE\"}\n",
        "-----BEGIN A PRIVATE KEY-----\nSYNTHETIC\n-----END A PRIVATE KEY-----\n",
    ] {
        let batch = filter_with_evidence(input.as_bytes()).must();
        let candidate = filter_candidate(input.as_bytes(), RecordEnd::Newline)
            .must()
            .must();
        assert_eq!(candidate.output, batch.output);
        assert_eq!(candidate.redactions, batch.redactions);
    }
}
