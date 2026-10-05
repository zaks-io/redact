pub mod inventory;
pub mod jwt;
pub mod policy;
pub mod providers;
pub mod text;

use redact::error::SafeError;
use sha2::{Digest, Sha256};

pub const CANARY: &str = "synthetic-fuzz-canary-lilac-cobalt-0123456789";

pub fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn check_error(error: &SafeError) {
    let diagnostic = format!("{error} {error:?}");
    assert!(
        !diagnostic.contains(CANARY)
            && !diagnostic.contains("SYNTHETIC_FUZZ_CANARY_")
            && !diagnostic.contains("CREDENTIAL_CANARY_"),
        "error exposed synthetic value"
    );
    assert!(error.line.is_none_or(|line| line > 0), "invalid error line");
    assert!(
        std::error::Error::source(error).is_none(),
        "raw error source retained"
    );
}

pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}
