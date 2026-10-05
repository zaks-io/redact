#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    match redact::dotenv::parse(bytes, "synthetic.env") {
        Ok(values) => {
            let mut names = BTreeSet::new();
            for (name, _) in values.iter() {
                assert!(names.insert(name));
                assert!(name.bytes().enumerate().all(|(i, c)| c == b'_'
                    || c.is_ascii_alphabetic()
                    || i > 0 && c.is_ascii_digit()));
            }
            assert!(!format!("{values:?}").contains("SYNTHETIC_FUZZ_CANARY_"));
        }
        Err(error) => {
            assert!(!format!("{error:?} {error}").contains("SYNTHETIC_FUZZ_CANARY_"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }
});
