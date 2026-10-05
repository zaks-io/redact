#![no_main]
use libfuzzer_sys::fuzz_target;
use redact::rstr::detect;
use redact_fuzz::{
    check_error,
    text::{check_spans, generated_credentials},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        match detect(text) {
            Ok(spans) => check_spans(text, &spans),
            Err(error) => check_error(&error),
        }
    }
    generated_credentials(data);
    redact_fuzz::providers::generated_credentials(data);
    redact_fuzz::inventory::check_fixture_oracles(data);
});
