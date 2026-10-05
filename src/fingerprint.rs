use sha2::{Digest, Sha256};

pub fn fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn marker(bytes: &[u8]) -> String {
    format!("[REDACTED sha256={}]", fingerprint(bytes))
}
