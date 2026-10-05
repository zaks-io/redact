use proptest::prelude::*;
use redact::error::{ErrorKind, SafeError};
use redact::fingerprint::fingerprint;
use redact::secret::SecretString;

#[test]
fn known_sha256_vectors() {
    assert_eq!(fingerprint(b"abc"), "ba7816bf8f01cfea");
    assert_eq!(
        fingerprint(b"synthetic-secret-lilac-48"),
        "1d5a8919184510ff"
    );
}

#[test]
fn nested_formatting_is_opaque() {
    let secret = SecretString::new("synthetic-secret-lilac-48".into());
    assert_eq!(format!("{secret:?}"), "SecretString([opaque])");
    let nested = Some(vec![secret]);
    assert!(!format!("{nested:?}").contains("synthetic-secret-lilac-48"));
    let error = SafeError::at(ErrorKind::UnterminatedQuote, 2);
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(
        error.to_string(),
        "line 2: unterminated quoted value. Close the quoted value and retry."
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0x5eed),
        ..ProptestConfig::default()
    })]
    #[test]
    fn fingerprints_use_only_fixed_hex_output(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let first = fingerprint(&bytes);
        prop_assert_eq!(first.len(), 16);
        prop_assert!(first.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        prop_assert_eq!(first, fingerprint(&bytes));
    }
}
