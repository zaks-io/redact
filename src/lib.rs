mod cli;
mod context;
pub mod error;
pub mod fingerprint;
mod providers;
pub mod rprintenv;
pub mod rstr;
pub mod secret;
mod structured;
mod text;

pub use cli::parse_arguments;
pub use fingerprint::fingerprint;
pub use text::{MAX_INPUT_BYTES, Span, detect, filter, merge_spans, render_spans, validate_input};

#[cfg(test)]
#[path = "../tests/support/synthetic.rs"]
mod synthetic;
