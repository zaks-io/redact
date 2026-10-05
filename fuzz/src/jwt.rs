use crate::{check_error, hash};
use redact::error::ErrorKind;
use redact::rstr::{detect, filter, filter_to_writer};

const NUMERIC_PAYLOAD: &[u8] = include_bytes!("../corpus/detectors/jwt-large-number");
const NUMERIC_HEADER: &[u8] = include_bytes!("../corpus/detectors/jwt-large-header-number");
const DEEP_PAYLOAD: &[u8] = include_bytes!("../corpus/detectors/jwt-deep-payload");
const DEEP_HEADER: &[u8] = include_bytes!("../corpus/detectors/jwt-deep-header");
const BRACKETS_IN_STRING: &[u8] = include_bytes!("../corpus/detectors/jwt-brackets-in-string");

pub fn check_seed(data: &[u8]) {
    for seed in [NUMERIC_PAYLOAD, NUMERIC_HEADER, BRACKETS_IN_STRING] {
        if data != seed {
            continue;
        }
        let Ok(text) = std::str::from_utf8(data) else {
            panic!("invalid synthetic JWT fixture");
        };
        let expected: Vec<_> = std::iter::once(0..text.len()).collect();
        let spans = detect(text);
        assert!(spans.is_ok(), "representable JWT rejected");
        if let Ok(spans) = spans {
            assert!(spans == expected, "JWT representation span oracle failed");
        }
        let output = filter(data);
        assert!(output.is_ok(), "representable JWT filter failed");
        if let Ok(output) = output {
            assert!(
                output == format!("[REDACTED sha256={}]", hash(data)),
                "JWT representation disclosure oracle failed"
            );
        }
    }
    for seed in [DEEP_PAYLOAD, DEEP_HEADER] {
        if data != seed {
            continue;
        }
        let mut output = Vec::new();
        let result = filter_to_writer(data, &mut output);
        assert!(
            result.is_err() && output.is_empty(),
            "JWT depth failure passed unchecked output"
        );
        if let Err(error) = result {
            assert!(
                matches!(error.kind, ErrorKind::Detector),
                "JWT depth error category changed"
            );
            check_error(&error);
        }
    }
}

pub fn validate_oracle_seeds() {
    for seed in [
        NUMERIC_PAYLOAD,
        NUMERIC_HEADER,
        BRACKETS_IN_STRING,
        DEEP_PAYLOAD,
        DEEP_HEADER,
    ] {
        check_seed(seed);
    }
}
