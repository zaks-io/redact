#![no_main]
use libfuzzer_sys::fuzz_target;
use redact::environment::{self, Options, Snapshot, Source};
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    match redact::dotenv::parse(bytes, "synthetic.env") {
        Ok(values) => {
            let selected = values.iter().next().map(|(name, _)| name.to_owned());
            let mut options = Options::default();
            if bytes.first().is_some_and(|b| b & 1 != 0)
                && let Some(name) = selected
            {
                options.names.insert(name);
            }
            for (name, value) in values.iter() {
                redact_fuzz::check_render(name, value, 0);
            }
            let records = environment::sanitize(
                &[Snapshot {
                    source: Source::File {
                        path: "synthetic.env".to_owned(),
                    },
                    values,
                }],
                &options,
            );
            let _text = environment::render_text(&records).unwrap();
            let json = environment::render_json(&records).unwrap();
            let _: serde_json::Value = serde_json::from_str(&json).unwrap();
            for record in &records {
                if record.state == environment::State::Redacted {
                    assert!(record.value.is_none());
                    assert!(
                        record
                            .fingerprint
                            .as_ref()
                            .is_some_and(|value| value.len() == 16)
                    );
                }
            }
        }
        Err(error) => {
            assert!(!format!("{error} {error:?}").contains("SYNTHETIC_FUZZ_CANARY_"));
        }
    }
});
