#![no_main]
use libfuzzer_sys::fuzz_target;
use redact::Span;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    redact_fuzz::check_fixture_oracles(bytes);
    match redact::filter(bytes) {
        Ok(output) => {
            let input = std::str::from_utf8(bytes).unwrap();
            assert!(!input.contains('\0'));
            let spans = redact::detect(input).unwrap();
            assert_eq!(output, redact_fuzz::reference_render(input, &spans));
        }
        Err(error) => assert!(!format!("{error} {error:?}").contains("SYNTHETIC_FUZZ_CANARY_")),
    }
    let input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".repeat(2);
    let spans: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .take(32)
        .map(|pair| {
            let a = pair[0] as usize % input.len();
            let b = pair[1] as usize % input.len();
            Span {
                start: a.min(b),
                end: a.max(b),
            }
        })
        .collect();
    assert_eq!(
        redact::merge_spans(&input, &spans).unwrap(),
        redact_fuzz::reference_union(&input, &spans)
    );
    assert_eq!(
        redact::render_spans(&input, &spans).unwrap(),
        redact_fuzz::reference_render(&input, &spans)
    );
    let secret = "SYNTHETIC_FUZZ_CANARY_secret_0123456789";
    let input = format!("password=\"{secret}\" status=failed\n");
    let expected = format!(
        "password=\"[REDACTED sha256={}]\" status=failed\n",
        redact_fuzz::hash(secret)
    );
    assert_eq!(redact::filter(input.as_bytes()).unwrap(), expected);
});
