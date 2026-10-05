pub mod context;
pub mod dotenv;
pub mod environment;
pub mod error;
mod providers;
pub mod structured;
mod text;

pub use text::{MAX_INPUT_BYTES, Span, detect, filter, merge_spans, render_spans};

pub fn fingerprint(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
