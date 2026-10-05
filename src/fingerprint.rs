use sha2::{Digest, Sha256};

pub fn fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex = b"0123456789abcdef";
    let mut fingerprint = String::with_capacity(16);
    for byte in &digest[..8] {
        fingerprint.push(char::from(hex[usize::from(byte >> 4)]));
        fingerprint.push(char::from(hex[usize::from(byte & 0x0f)]));
    }
    fingerprint
}

pub fn marker(bytes: &[u8]) -> String {
    format!("[REDACTED sha256={}]", fingerprint(bytes))
}
