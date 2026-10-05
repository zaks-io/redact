#![no_main]
use libfuzzer_sys::fuzz_target;
use redact::rprintenv::{
    parser::parse_dotenv,
    policy::{Policy, Source, disclose},
    render::render,
};
use redact_fuzz::{
    CANARY, check_error,
    policy::{check_record, outputs_match},
};

fuzz_target!(|data: &[u8]| {
    let parsed = parse_dotenv(data);
    match parsed {
        Err(error) => check_error(&error),
        Ok(entries) => {
            let mut policy = Policy::default();
            let flags = data.first().copied().unwrap_or_default();
            if let Some(name) = entries.keys().next() {
                if flags & 1 != 0 {
                    policy.allow.insert(name.clone());
                }
                if flags & 2 != 0 {
                    policy.redact.insert(name.clone());
                }
            }
            for name in entries
                .keys()
                .chain(std::iter::once(&"SYNTHETIC_MISSING".to_owned()))
            {
                let value = entries.get(name);
                let record = disclose(
                    Source::File {
                        path: "synthetic.env".to_owned(),
                    },
                    name.clone(),
                    value,
                    &policy,
                );
                check_record(&record, value.map(|value| value.as_str()), &policy);
                assert!(
                    outputs_match(&record, value.map(|value| value.as_str()), &policy),
                    "pipeline rendering failed"
                );
            }
        }
    }
    let malformed = format!("FIRST={CANARY}\nBROKEN='{CANARY}");
    let mut output = Vec::new();
    let result = parse_dotenv(malformed.as_bytes());
    if let Ok(entries) = result {
        let records: Vec<_> = entries
            .iter()
            .map(|(name, value)| {
                disclose(
                    Source::Environment,
                    name.clone(),
                    Some(value),
                    &Policy::default(),
                )
            })
            .collect();
        let _ = render(&records, false, &mut output);
        panic!("malformed input unexpectedly accepted");
    }
    assert!(output.is_empty(), "input failure produced records");
    let literal = b"VALUE=\"$NAME ${NAME} `synthetic-command` $(synthetic-command)\"\n";
    let parsed = parse_dotenv(literal);
    assert!(parsed.is_ok(), "literal shell syntax rejected");
    if let Ok(parsed) = parsed {
        let value = parsed.get("VALUE");
        assert!(
            value
                .is_some_and(|value| value.as_str()
                    == "$NAME ${NAME} `synthetic-command` $(synthetic-command)"),
            "literal syntax transformed"
        );
    }
});
