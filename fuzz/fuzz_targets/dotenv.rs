#![no_main]
use libfuzzer_sys::fuzz_target;
use redact::rprintenv::parser::parse_dotenv;
use redact_fuzz::{CANARY, check_error, valid_name};

fuzz_target!(|data: &[u8]| {
    match parse_dotenv(data) {
        Ok(entries) => {
            assert!(
                entries.keys().all(|name| valid_name(name)),
                "invalid successful assignment name"
            );
            assert!(
                entries.len()
                    == entries
                        .keys()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len(),
                "duplicate assignment"
            );
        }
        Err(error) => check_error(&error),
    }
    let malformed = format!("VALUE='{CANARY}");
    let result = parse_dotenv(malformed.as_bytes());
    assert!(result.is_err(), "unterminated quote accepted");
    assert!(
        !format!("{result:?}").contains(CANARY),
        "parser formatting disclosed synthetic input"
    );
});
