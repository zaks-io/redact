#![no_main]
use libfuzzer_sys::fuzz_target;
use redact::environment;
use redact_fuzz::{flags, policy};
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4096 {
        return;
    }
    let bits = bytes.first().copied().unwrap_or(0);
    let names = [
        "SECRET",
        "NODE_ENV",
        "node_env",
        "RUST_BACKTRACE",
        "CI",
        "NO_COLOR",
        "FORCE_COLOR",
        "CLICOLOR_FORCE",
        "NODE_ENV_EXTRA",
    ];
    let name = names[(bits as usize >> 2) % names.len()];
    let value = std::str::from_utf8(bytes.get(1..).unwrap_or_default()).ok();
    let options = flags(bits, name);
    assert_eq!(
        environment::decision(name, value, &options.allow, &options.redact),
        policy(name, value, bits & 1 != 0, bits & 2 != 0)
    );
    let wrong_case = name.to_lowercase();
    let options = flags(bits, &wrong_case);
    assert_eq!(
        environment::decision(name, value, &options.allow, &options.redact),
        policy(
            name,
            value,
            bits & 1 != 0 && name == wrong_case,
            bits & 2 != 0 && name == wrong_case
        )
    );
    if let Some(value) = value {
        assert_eq!(redact::fingerprint(value), redact_fuzz::hash(value));
    }
});
