#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4096 {
        return;
    }
    let bits = bytes.first().copied().unwrap_or(0);
    if let Ok(value) = std::str::from_utf8(bytes.get(1..).unwrap_or_default()) {
        let name =
            ["SECRET", "NODE_ENV", "CI", "escaped\nname", "NAME\"\\"][(bits as usize >> 2) % 5];
        redact_fuzz::check_render(name, value, bits);
        redact_fuzz::check_render("SECRET", &format!("SYNTHETIC_FUZZ_CANARY_{value}"), bits);
        let first = format!("SYNTHETIC_FUZZ_CANARY_first_{value}");
        let second = format!("SYNTHETIC_FUZZ_CANARY_second_{value}");
        let render = |secret: &str| {
            let snapshot = redact::environment::Snapshot {
                source: redact::environment::Source::Environment,
                values: redact::environment::RawVariables::from_pairs([(
                    "SECRET".to_owned(),
                    secret.to_owned(),
                )]),
            };
            let records = redact::environment::sanitize(&[snapshot], &Default::default());
            (
                redact::environment::render_text(&records)
                    .unwrap()
                    .replace(&redact_fuzz::hash(secret), "HASH"),
                redact::environment::render_json(&records)
                    .unwrap()
                    .replace(&redact_fuzz::hash(secret), "HASH"),
            )
        };
        assert_eq!(render(&first), render(&second));
    }
});
