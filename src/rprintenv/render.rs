use super::policy::{Record, State};
use crate::error::{ErrorKind, SafeError};
use serde_json::{Value, json};
use std::io::Write;

pub fn render(
    records: &[Record],
    json_output: bool,
    output: &mut impl Write,
) -> Result<(), SafeError> {
    if json_output {
        let records: Vec<Value> = records.iter().map(json_record).collect();
        serde_json::to_writer(
            &mut *output,
            &json!({ "schema_version": 1, "records": records }),
        )
        .map_err(|_| SafeError::new(ErrorKind::Output))?;
        writeln!(output).map_err(|_| SafeError::new(ErrorKind::Output))?;
    } else {
        for record in records {
            let source = encoded(&record.source.label())?;
            let name = encoded(&record.name)?;
            let value = match &record.state {
                State::Visible(value) => encoded(value.as_str())?,
                State::Redacted(hash) => format!("[REDACTED sha256={hash}]"),
                State::Empty => "[EMPTY]".to_owned(),
                State::Missing => "[UNSET]".to_owned(),
            };
            writeln!(output, "{source}\t{name}\t{value}")
                .map_err(|_| SafeError::new(ErrorKind::Output))?;
        }
    }
    output
        .flush()
        .map_err(|_| SafeError::new(ErrorKind::Output))
}

fn encoded(text: &str) -> Result<String, SafeError> {
    serde_json::to_string(text).map_err(|_| SafeError::new(ErrorKind::Output))
}

fn json_record(record: &Record) -> Value {
    let (state, value, fingerprint) = match &record.state {
        State::Visible(value) => ("visible", Some(value.as_str()), None),
        State::Redacted(hash) => ("redacted", None, Some(hash.as_str())),
        State::Empty => ("empty", Some(""), None),
        State::Missing => ("missing", None, None),
    };
    json!({
        "source": record.source,
        "name": record.name,
        "state": state,
        "value": value,
        "fingerprint": fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rprintenv::policy::{Policy, Source, disclose};
    use crate::secret::SecretString;

    struct BrokenOutput;

    impl Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic-output-canary"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_failures_and_nested_records_are_safe() {
        let value = SecretString::new("synthetic-output-canary".to_owned());
        let mut policy = Policy::default();
        policy.allow.insert("KEY".to_owned());
        let records = [disclose(
            Source::Environment,
            "KEY".to_owned(),
            Some(&value),
            &policy,
        )];
        assert!(!format!("{records:?}").contains("synthetic-output-canary"));
        for json in [true, false] {
            let Err(error) = render(&records, json, &mut BrokenOutput) else {
                panic!("output failure accepted")
            };
            assert!(!format!("{error:?} {error}").contains("synthetic-output-canary"));
        }
    }
}
