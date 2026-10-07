mod cli;
mod context;
pub mod error;
pub mod evidence;
pub mod fingerprint;
mod providers;
mod redaction_report;
pub mod rprintenv;
pub mod rstr;
pub mod secret;
mod structured;
mod text;

pub use cli::{CommandKind, parse_arguments, parse_arguments_for};
pub use evidence::{Evidence, Filtered, Redaction};
pub use fingerprint::fingerprint;
pub use redaction_report::RedactionReport;
pub use text::{
    MAX_INPUT_BYTES, Span, detect, filter, filter_with_evidence, merge_spans, render_spans,
    validate_input,
};

#[cfg(test)]
#[path = "../tests/support/synthetic.rs"]
mod synthetic;
