pub mod context;
pub mod dotenv;
pub mod environment;
pub mod error;
pub mod fingerprint;
mod providers;
pub mod rprintenv;
pub mod rstr;
pub mod secret;
pub mod structured;
mod text;

pub use text::{MAX_INPUT_BYTES, Span, detect, filter, merge_spans, render_spans};

pub fn fingerprint(value: &str) -> String {
    fingerprint::fingerprint(value.as_bytes())
}

#[cfg(test)]
#[path = "../tests/support/synthetic.rs"]
mod synthetic;
