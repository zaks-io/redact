use crate::{CANARY, check_error, hash};
use arbitrary::{Arbitrary, Unstructured};
use redact::rstr::{Span, detect, filter, merge_spans, render_spans, validate_input};

pub fn check_spans(text: &str, spans: &[Span]) {
    let mut end = 0;
    for span in spans {
        assert!(
            span.start < span.end && span.end <= text.len(),
            "invalid detector bounds"
        );
        assert!(
            text.is_char_boundary(span.start) && text.is_char_boundary(span.end),
            "invalid Unicode boundary"
        );
        assert!(span.start >= end, "unmerged detector overlap");
        end = span.end;
    }
}

// Connected overlap components provide an independent union oracle.
pub fn union_oracle(text: &str, spans: &[Span]) -> Option<Vec<Span>> {
    if spans.iter().any(|span| {
        span.start > span.end
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
    }) {
        return None;
    }
    let mut remaining: Vec<_> = spans
        .iter()
        .filter(|span| !span.is_empty())
        .cloned()
        .collect();
    let mut result = Vec::new();
    while let Some(mut component) = remaining.pop() {
        while let Some(index) = remaining
            .iter()
            .position(|span| span.start < component.end && component.start < span.end)
        {
            let joined = remaining.swap_remove(index);
            component = component.start.min(joined.start)..component.end.max(joined.end);
        }
        result.push(component);
    }
    result.sort_by_key(|span| span.start);
    Some(result)
}

pub fn replacement_oracle(text: &str, spans: &[Span]) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    for span in spans {
        output.push_str(&text[cursor..span.start]);
        output.push_str(&format!(
            "[REDACTED sha256={}]",
            hash(text[span.clone()].as_bytes())
        ));
        cursor = span.end;
    }
    output.push_str(&text[cursor..]);
    output
}

pub fn generated_credentials(data: &[u8]) {
    crate::jwt::check_seed(data);
    let body: String = data
        .iter()
        .take(128)
        .map(|byte| char::from(b'A' + byte % 26))
        .collect();
    let value = format!("syntheticFuzz{body}0123456789");
    let mode = data.first().copied().unwrap_or_default() % 9;
    let (before, secret, after) = match mode {
        0 => (
            "status=401 λ ghp_".to_owned(),
            value,
            " context preserved\n".to_owned(),
        ),
        1 => (
            "status=401 λ password=\"".to_owned(),
            value,
            "\" context preserved\n".to_owned(),
        ),
        2 => (
            "status=401\nAuthorization: Bearer ".to_owned(),
            value,
            "\r\ncontext preserved\n".to_owned(),
        ),
        3 => (
            "status=401 λ https://".to_owned(),
            format!("syntheticUser:{value}"),
            "@example.test/path\n".to_owned(),
        ),
        4 => (
            "status=401 λ https://example.test/?password=".to_owned(),
            value,
            "&status=401\n".to_owned(),
        ),
        5 => (
            "status=401\n".to_owned(),
            format!("-----BEGIN PRIVATE KEY-----\n{value}\n-----END PRIVATE KEY-----"),
            "\ncontext preserved\n".to_owned(),
        ),
        6 => (
            "status=401 λ https://public.test/redirect=https://".to_owned(),
            format!("syntheticUser:{value}"),
            "@private.test/path?status=401\n".to_owned(),
        ),
        7 => (
            "status=401 λ https://outer.test/?password=".to_owned(),
            format!("https://syntheticUser:{value}@inner.test/path"),
            "&status=401\n".to_owned(),
        ),
        _ => (
            "status=401 λ ".to_owned(),
            format!("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzeW50aGV0aWMifQ.{body}A"),
            " context preserved\n".to_owned(),
        ),
    };
    let (before, secret) = if mode == 0 {
        (
            before.trim_end_matches("ghp_").to_owned(),
            format!("ghp_{secret}"),
        )
    } else {
        (before, secret)
    };
    let text = format!("{before}{secret}{after}");
    let expected: Vec<_> = std::iter::once(before.len()..before.len() + secret.len()).collect();
    let actual = detect(&text);
    assert!(actual.is_ok(), "generated recognizable credential rejected");
    if let Ok(actual) = actual {
        assert!(actual == expected, "structured detector span oracle failed");
        let output = filter(text.as_bytes());
        assert!(
            output.is_ok(),
            "generated recognizable credential filter failed"
        );
        if let Ok(output) = output {
            assert!(
                output == replacement_oracle(&text, &expected),
                "structured replacement oracle failed"
            );
        }
    }
    let malformed = format!("password=\"{CANARY}");
    let result = filter(malformed.as_bytes());
    assert!(result.is_err(), "unterminated sensitive field accepted");
    if let Err(error) = result {
        check_error(&error);
    }
    json_context_oracles(&value_for_json(data));
}

fn value_for_json(data: &[u8]) -> String {
    let body: String = data
        .iter()
        .take(64)
        .map(|byte| char::from(b'A' + byte % 26))
        .collect();
    format!("syntheticJson{body}0123456789")
}

fn json_context_oracles(value: &str) {
    let prefix = "{\"a\":\"Authorization: Bearer ";
    let middle = "\",\"b\":\"Authorization: Bearer ";
    let suffix = "\",\"status\":401}";
    let second = format!("{value}Changed");
    let text = format!("{prefix}{value}{middle}{second}{suffix}");
    let start = prefix.len();
    let second_start = start + value.len() + middle.len();
    let spans = vec![
        start..start + value.len(),
        second_start..second_start + second.len(),
    ];
    let actual = detect(&text);
    assert!(actual.is_ok(), "JSON embedded headers rejected");
    if let Ok(actual) = actual {
        assert!(actual == spans, "JSON embedded header span oracle failed");
    }
    let output = filter(text.as_bytes());
    assert!(output.is_ok(), "JSON embedded header filter failed");
    if let Ok(output) = output {
        assert!(
            output == replacement_oracle(&text, &spans),
            "JSON header scheme preservation oracle failed"
        );
    }
    for empty in [
        r#"{"message":"password=","status":401}"#,
        r#"{"message":"Authorization: Bearer ","status":401}"#,
    ] {
        let output = filter(empty.as_bytes());
        assert!(output.is_ok(), "empty JSON context rejected");
        if let Ok(output) = output {
            assert!(
                output == empty,
                "empty JSON context changed neighboring fields"
            );
        }
    }
    let malformed = format!("{{\"message\":\"password='{CANARY}\",\"status\":\"later'\"}}");
    let mut output = Vec::new();
    let result = redact::rstr::filter_to_writer(malformed.as_bytes(), &mut output);
    assert!(
        result.is_err() && output.is_empty(),
        "quoted context crossed enclosing JSON boundary"
    );
    if let Err(error) = result {
        check_error(&error);
    }
}

pub fn exercise_filter(data: &[u8]) {
    match validate_input(data) {
        Err(error) => {
            check_error(&error);
            assert!(filter(data).is_err(), "invalid input passed filter");
        }
        Ok(text) => match detect(text) {
            Err(error) => {
                check_error(&error);
                assert!(filter(data).is_err(), "detector failure passed filter");
            }
            Ok(spans) => {
                check_spans(text, &spans);
                let expected = replacement_oracle(text, &spans);
                let result = filter(data);
                assert!(result.is_ok(), "valid detected input failed filter");
                if let Ok(output) = result {
                    assert!(
                        output == expected,
                        "filter changed unmatched bytes or marker"
                    );
                }
            }
        },
    }
    let text = "synthetic λ unicode text αβγ with overlapping span fixtures";
    let mut decoder = Unstructured::new(data);
    let mut spans = Vec::new();
    while spans.len() < 32 {
        let Ok((start, end)) = <(u16, u16)>::arbitrary(&mut decoder) else {
            break;
        };
        spans.push(usize::from(start) % (text.len() + 3)..usize::from(end) % (text.len() + 3));
    }
    let expected = union_oracle(text, &spans);
    let actual = merge_spans(text, spans.clone());
    match expected {
        None => assert!(
            actual.is_err() && render_spans(text, spans).is_err(),
            "invalid span accepted"
        ),
        Some(expected) => {
            assert!(actual.is_ok(), "valid span set rejected");
            if let Ok(actual) = actual {
                assert!(actual == expected, "span union oracle failed");
            }
            let output = render_spans(text, spans);
            assert!(output.is_ok(), "valid span rendering failed");
            if let Ok(output) = output {
                assert!(
                    output == replacement_oracle(text, &expected),
                    "span replacement oracle failed"
                );
            }
        }
    }
    generated_credentials(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_structure_oracles_cover_each_context() {
        crate::jwt::validate_oracle_seeds();
        for mode in 0..9 {
            generated_credentials(&[mode]);
        }
    }

    #[test]
    fn union_oracle_preserves_adjacent_spans() {
        let oracle = union_oracle("0123456789", &[0..2, 2..4, 3..6, 8..10]);
        assert!(
            oracle == Some(vec![0..2, 2..6, 8..10]),
            "union oracle contract failed"
        );
    }
}
