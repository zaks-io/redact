#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    redact_fuzz::text::exercise_filter(data);
});
