use super::{
    combined,
    corpus::{Case, Kind, corpus},
    evaluate,
    metrics::measure,
    run,
    scoring::{Policy, Threshold, candidates, entropy, policies},
};
use proptest::prelude::*;
use redact::{
    rstr::{detect, merge_spans},
    secret::SecretString,
};
use std::io::{self, Write};

fn case(text: &str, secrets: Vec<std::ops::Range<usize>>) -> Case {
    Case {
        id: "synthetic-test".into(),
        family: "test",
        kind: Kind::OtherSecret,
        length: text.len(),
        text: SecretString::new(text.into()),
        secrets,
    }
}

#[test]
fn known_entropy_vectors_and_order_independence() {
    for (value, expected) in [
        ("", 0.0),
        ("aaaaaaaa", 0.0),
        ("abababab", 1.0),
        ("abcdefgh", 3.0),
        ("0123456789abcdef", 4.0),
    ] {
        assert!((entropy(value.as_bytes()) - expected).abs() < 1e-12);
    }
    assert!((entropy(b"abcdefgh") - entropy(b"hgfedcba")).abs() < 1e-12);
}

#[test]
fn tokens_preserve_utf8_boundaries_assignments_and_base64_padding() {
    let text = "雪 value=YWJjZA== other:YWJjZGU=\nabc_def-12+/";
    let tokens: Vec<_> = candidates(text)
        .into_iter()
        .map(|span| &text[span])
        .collect();
    assert_eq!(
        tokens,
        ["value", "YWJjZA==", "other", "YWJjZGU=", "abc_def-12+/"]
    );
}

#[test]
fn length_bounds_are_inclusive_and_do_not_clip_long_tokens() {
    let policy = Policy {
        min: 16,
        max: 32,
        threshold: Threshold::Bits(0.0),
    };
    for length in [15, 16, 32, 33, 512] {
        let text = "a".repeat(length);
        let spans = policy.detect(&text);
        assert_eq!(!spans.is_empty(), (16..=32).contains(&length));
        assert!(spans.iter().all(|span| span.len() == length));
    }
}

#[test]
fn relative_entropy_uses_the_hex_ceiling() {
    let text = "0123456789abcdef0123456789abcdef";
    let relative = Policy {
        min: 16,
        max: 128,
        threshold: Threshold::Relative(0.95),
    };
    let absolute = Policy {
        threshold: Threshold::Bits(4.5),
        ..relative
    };
    assert_eq!(
        relative.detect(text),
        std::iter::once(0..text.len()).collect::<Vec<_>>()
    );
    assert!(absolute.detect(text).is_empty());
    let short = Policy {
        min: 8,
        max: 16,
        threshold: Threshold::Relative(1.0),
    };
    assert_eq!(
        short.detect("abcdefgh"),
        std::iter::once(0..8).collect::<Vec<_>>()
    );
}

#[test]
fn partial_matches_remain_misses_and_collateral_is_separate() {
    let case = case("useful SECRET context", std::iter::once(7..13).collect());
    let partial = measure(&case, std::iter::once(0..10).collect())
        .unwrap_or_else(|_| panic!("synthetic metrics failed"));
    assert_eq!(partial.caught, 0);
    assert_eq!(partial.partial, 1);
    assert_eq!(partial.removed_useful_bytes, 7);
    let full =
        measure(&case, vec![7..10, 10..13]).unwrap_or_else(|_| panic!("synthetic metrics failed"));
    assert_eq!(full.caught, 1);
    assert_eq!(full.partial, 0);
    assert_eq!(full.removed_useful_bytes, 0);
    assert_eq!(full.useful_bytes, 15);
    assert_eq!(full.false_positives, 0);
    let benign = measure(
        &self::case("public", vec![]),
        std::iter::once(0..6).collect(),
    )
    .unwrap_or_else(|_| panic!("synthetic metrics failed"));
    assert_eq!(benign.false_positives, 1);
    assert_eq!(benign.other_false_positives, 1);
    assert_eq!(benign.control_false_positives, 0);
    assert_eq!(benign.removed_useful_bytes, 6);
    assert!(benign.row().contains("0/0 (n/a)"));
    let mut control = self::case("public", vec![]);
    control.kind = Kind::PublicControl;
    let measured = measure(&control, std::iter::once(0..6).collect())
        .unwrap_or_else(|_| panic!("synthetic metrics failed"));
    assert_eq!(measured.control_false_positives, 1);
    assert_eq!(measured.other_false_positives, 0);
}

#[test]
fn invalid_annotations_fail_without_echoing_input() {
    let case = case("synthetic-error-canary", std::iter::once(0..999).collect());
    let error = match measure(&case, vec![]) {
        Err(error) => error,
        Ok(_) => panic!("invalid synthetic annotation was accepted"),
    };
    assert!(!format!("{error:?} {error}").contains("synthetic-error-canary"));
}

#[test]
fn corpus_is_reproducible_and_opaque_pairs_are_indistinguishable() {
    let first = corpus();
    let second = corpus();
    assert_eq!(first.len(), second.len());
    let mut ids = std::collections::BTreeSet::new();
    for (left, right) in first.iter().zip(&second) {
        assert!(ids.insert(left.id.as_str()));
        assert_eq!(left.id, right.id);
        assert!(left.text.as_str() == right.text.as_str());
        assert_eq!(left.secrets, right.secrets);
    }
    for pair in first
        .as_chunks::<2>()
        .0
        .iter()
        .take(4 * super::corpus::LENGTHS.len() * super::corpus::SAMPLES)
    {
        assert!(pair[0].text.as_str() == pair[1].text.as_str());
        for policy in policies() {
            assert_eq!(
                policy.detect(pair[0].text.as_str()),
                policy.detect(pair[1].text.as_str())
            );
        }
    }
}

#[test]
fn additive_policies_preserve_baseline_and_all_structured_coverage() {
    let cases = corpus();
    let baseline = cases
        .iter()
        .map(|case| detect(case.text.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|_| panic!("synthetic detector failed"));
    let structured: Vec<_> = cases
        .iter()
        .zip(&baseline)
        .filter(|(case, _)| case.kind == Kind::StructuredSecret)
        .collect();
    assert_eq!(structured.len(), 166);
    for (case, spans) in structured {
        let metric =
            measure(case, spans.clone()).unwrap_or_else(|_| panic!("synthetic metrics failed"));
        assert_eq!(
            metric.caught, metric.secrets,
            "structured synthetic category lost coverage"
        );
    }
    assert!(evaluate(&cases, &baseline[..baseline.len() - 1], None).is_err());
}

#[test]
fn report_contains_metadata_and_metrics_without_fixture_values() {
    let mut output = Vec::new();
    assert!(run(&mut output).is_ok());
    let text = String::from_utf8(output).unwrap_or_else(|_| panic!("report was not UTF-8"));
    assert!(text.contains("| Baseline |"));
    assert!(text.contains("## Category breakdown:"));
    for case in corpus().iter().filter(|case| case.text.as_str().len() >= 8) {
        assert!(
            !text.contains(case.text.as_str()),
            "synthetic fixture leaked into report"
        );
        for span in case.secrets.iter().filter(|span| span.len() >= 8) {
            assert!(
                !text.contains(&case.text.as_str()[span.clone()]),
                "synthetic secret span leaked into report"
            );
        }
    }
}

struct BrokenWriter;
impl Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("synthetic-write-error-canary"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_failure_discards_source_diagnostics() {
    let error = match run(BrokenWriter) {
        Err(error) => error,
        Ok(()) => panic!("synthetic write failure was ignored"),
    };
    assert!(!format!("{error:?} {error}").contains("synthetic-write-error-canary"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn entropy_is_bounded_and_permutation_invariant(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let score = entropy(&bytes);
        let ceiling = if bytes.is_empty() { 0.0 } else { (bytes.len().min(256) as f64).log2() };
        prop_assert!(score >= 0.0 && score <= ceiling + 1e-12);
        let reverse: Vec<_> = bytes.iter().copied().rev().collect();
        prop_assert!((score - entropy(&reverse)).abs() < 1e-12);
    }

    #[test]
    fn candidates_are_valid_spans_and_combination_never_loses_coverage(tokens in prop::collection::vec("[A-Za-z0-9_+/=-]{0,300}", 0..6)) {
        let text = format!("雪 result=\"{}\" password=\"synthetic-low-entropy\"", tokens.join(" "));
        let case = case(&text, vec![]);
        let baseline = detect(&text).unwrap_or_else(|_| panic!("synthetic detector failed"));
        let policy = Policy { min: 16, max: 128, threshold: Threshold::Bits(3.5) };
        for span in policy.detect(&text) {
            prop_assert!((policy.min..=policy.max).contains(&span.len()));
            prop_assert!(candidates(&text).contains(&span));
        }
        let combined = combined(&case, &baseline, Some(policy));
        let merged = merge_spans(&text, combined);
        prop_assert!(merged.is_ok());
        if let Ok(spans) = merged {
            for baseline in baseline {
                prop_assert!(spans.iter().any(|span| span.start <= baseline.start && span.end >= baseline.end));
            }
        }
    }
}
