use crate::{environment::RawVariables, error::SafeError, rprintenv::parser::parse_dotenv};

/// Compatibility entry point delegates to the command's sole literal parser.
pub fn parse(bytes: &[u8], path: &str) -> Result<RawVariables, SafeError> {
    parse_dotenv(bytes)
        .map(RawVariables::from_secrets)
        .map_err(|error| error.with_source(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthetic::*;
    use proptest::prelude::*;

    #[test]
    fn literal_dialect_and_line_endings() {
        let values = parse(b"\xef\xbb\xbf # comment\r\nexport A = a#b # comment\r\nB=' $A\\n\r\nx'\r\nC=\"a\\n\\r\\t\\\\\\\"${A}$(literal)\"\r\nD= #empty\r\n", "synthetic.env").must();
        assert_eq!(values.get("A"), Some("a#b"));
        assert_eq!(values.get("B"), Some(" $A\\n\nx"));
        assert_eq!(values.get("C"), Some("a\n\r\t\\\"${A}$(literal)"));
        assert_eq!(values.get("D"), Some(""));
    }

    #[test]
    fn malformed_values_are_not_diagnostics() {
        for input in [
            "A='synthetic-secret-canary",
            "A=\"synthetic-secret-canary\\q\"",
            "A=synthetic-secret-canary\nA=other",
            "A='synthetic-secret-canary' junk",
            "1A=synthetic-secret-canary",
            "synthetic-secret-canary",
        ] {
            let error = parse(input.as_bytes(), "synthetic.env").must_err();
            assert!(!format!("{error:?} {error}").contains("synthetic-secret-canary"));
        }
        assert!(parse(b"A=bad\0value", "synthetic.env").is_err());
        assert!(parse(b"A=\xff", "synthetic.env").is_err());
    }

    #[test]
    fn diagnostics_keep_line_numbers_and_escape_metadata() {
        let duplicate = parse(b"A=one\n#comment\nA=two\n", "synthetic\n.env").must_err();
        let message = duplicate.to_string();
        assert!(message.contains("line 3"));
        assert!(message.contains("line 1"));
        assert!(message.contains("synthetic\\n.env"));
        assert_eq!(message.lines().count(), 1);
        for bytes in [b"A=one\nB=bad\0".as_slice(), b"A=one\nB=\xff".as_slice()] {
            assert!(
                parse(bytes, "synthetic.env")
                    .must_err()
                    .to_string()
                    .contains("line 2")
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        #[test]
        fn arbitrary_bytes_do_not_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            if let Ok(values) = parse(&bytes, "synthetic.env") {
                for (name, _) in values.iter() {
                    prop_assert!(!name.is_empty());
                    prop_assert!(name.as_bytes()[0].is_ascii_alphabetic() || name.starts_with('_'));
                }
            }
        }

        #[test]
        fn double_quoted_values_decode_without_normalizing(value in "[^\\x00]*") {
            let encoded = value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t");
            let fixture = format!("VALUE=\"{encoded}\"\n");
            let variables = parse(fixture.as_bytes(), "synthetic.env").must();
            prop_assert_eq!(variables.get("VALUE"), Some(value.as_str()));
        }
    }
}
