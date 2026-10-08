#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    redact_fuzz::streaming::exercise(data);
    redact_fuzz::text::exercise_filter(data);
    redact_fuzz::providers::generated_credentials(data);
    redact_fuzz::inventory::check_fixture_oracles(data);
});
