#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(case) = redact_fuzz::policy::decode(data) {
        redact_fuzz::policy::exercise(&case, true);
    }
});
