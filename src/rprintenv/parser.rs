use crate::error::{ErrorKind, SafeError};
use crate::secret::SecretString;
use std::collections::BTreeMap;

/// Parse only the documented literal dotenv dialect, without interpolation.
pub fn parse_dotenv(bytes: &[u8]) -> Result<BTreeMap<String, SecretString>, SafeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SafeError::new(ErrorKind::Encoding))?;
    if text.contains('\0') {
        return Err(SafeError::new(ErrorKind::Nul));
    }
    let text = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    let mut values = BTreeMap::new();
    let mut definitions = BTreeMap::new();
    let mut cursor = 0;
    let mut line = 1;
    while cursor < text.len() {
        let start_line = line;
        let line_end = text[cursor..].find('\n').map_or(text.len(), |i| cursor + i);
        let content = text[cursor..line_end].trim_start_matches([' ', '\t']);
        if content.is_empty() || content.starts_with('#') {
            cursor = (line_end + 1).min(text.len());
            line += 1;
            continue;
        }
        let content = match content.strip_prefix("export") {
            Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start_matches([' ', '\t']),
            _ => content,
        };
        let Some(equal) = content.find('=') else {
            return Err(SafeError::at(ErrorKind::InvalidAssignment, start_line));
        };
        let name = content[..equal].trim_end_matches([' ', '\t']);
        if !valid_name(name) {
            return Err(SafeError::at(ErrorKind::InvalidAssignment, start_line));
        }
        let raw_value = content[equal + 1..].trim_start_matches([' ', '\t']);
        cursor = line_end - raw_value.len();
        let value = if raw_value.starts_with(['\'', '"']) {
            let quote = text.as_bytes()[cursor];
            cursor += 1;
            let mut decoded = String::new();
            let mut closed = false;
            while cursor < text.len() {
                let Some(ch) = text[cursor..].chars().next() else {
                    break;
                };
                cursor += ch.len_utf8();
                if ch as u32 == u32::from(quote) {
                    closed = true;
                    break;
                }
                if ch == '\\' && quote == b'"' {
                    let Some(escape) = text[cursor..].chars().next() else {
                        return Err(SafeError::at(ErrorKind::UnterminatedQuote, start_line));
                    };
                    cursor += escape.len_utf8();
                    decoded.push(match escape {
                        '\\' => '\\',
                        '"' => '"',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        _ => return Err(SafeError::at(ErrorKind::InvalidEscape, line)),
                    });
                } else {
                    if ch == '\n' {
                        line += 1;
                    }
                    decoded.push(ch);
                }
            }
            if !closed {
                return Err(SafeError::at(ErrorKind::UnterminatedQuote, start_line));
            }
            let end = text[cursor..].find('\n').map_or(text.len(), |i| cursor + i);
            let remainder = text[cursor..end].trim_start_matches([' ', '\t']);
            if !remainder.is_empty() && !remainder.starts_with('#') {
                return Err(SafeError::at(ErrorKind::TrailingText, line));
            }
            cursor = (end + 1).min(text.len());
            line += 1;
            decoded
        } else {
            let comment = raw_value.char_indices().find_map(|(index, ch)| {
                (ch == '#'
                    && (index == 0 || matches!(raw_value.as_bytes()[index - 1], b' ' | b'\t')))
                .then_some(index)
            });
            let value = raw_value[..comment.unwrap_or(raw_value.len())]
                .trim_end_matches([' ', '\t'])
                .to_owned();
            cursor = (line_end + 1).min(text.len());
            line += 1;
            value
        };
        if let Some(previous) = definitions.insert(name.to_owned(), start_line) {
            let mut error = SafeError::at(ErrorKind::DuplicateName, start_line);
            error.previous_line = Some(previous);
            return Err(error);
        }
        values.insert(name.to_owned(), SecretString::new(value));
    }
    Ok(values)
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn literal_dialect() -> Result<(), SafeError> {
        let input = b"\xef\xbb\xbf # ignored\r\nexport A = a#b # comment\r\nB=' x\r\ny $A \\n'\r\nC=\"a\\n\\r\\t\\\\\\\"\" # comment\r\nD=\r\nE=$(touch synthetic-sentinel)\r\n";
        let values = parse_dotenv(input)?;
        assert_eq!(values["A"].as_str(), "a#b");
        assert_eq!(values["B"].as_str(), " x\ny $A \\n");
        assert_eq!(values["C"].as_str(), "a\n\r\t\\\"");
        assert_eq!(values["D"].as_str(), "");
        assert_eq!(values["E"].as_str(), "$(touch synthetic-sentinel)");
        Ok(())
    }

    #[test]
    fn rejects_safely_and_reports_duplicates() {
        for input in [
            "BAD NAME=synthetic-canary",
            "BARE",
            "A=\"synthetic-canary\\q\"",
            "A='synthetic-canary' junk",
            "A='synthetic-canary",
            "A=synthetic-canary\0",
        ] {
            let result = parse_dotenv(input.as_bytes());
            assert!(result.is_err());
            assert!(!format!("{result:?}").contains("synthetic-canary"));
        }
        let Err(error) = parse_dotenv(b"A=x\nA=x\n") else {
            panic!("duplicate accepted")
        };
        assert_eq!(error.line, Some(2));
        assert_eq!(error.previous_line, Some(1));
    }

    #[test]
    fn framing_comments_quotes_and_substitutions() -> Result<(), SafeError> {
        let values = parse_dotenv(b"# comment\n\t\nA = \t a  b \t # comment\nB=# ignored\nC=a#b\nD=' # literal \\t'\nE=\"# literal\"\nF=$NAME ${NAME} `command` $(command) \\\nG='$NAME ${NAME} `command` $(command)'\nH=\"$NAME ${NAME} `command` $(command)\"\n")?;
        assert_eq!(values["A"].as_str(), "a  b");
        assert_eq!(values["B"].as_str(), "");
        assert_eq!(values["C"].as_str(), "a#b");
        assert_eq!(values["D"].as_str(), " # literal \\t");
        assert_eq!(values["E"].as_str(), "# literal");
        assert_eq!(
            values["F"].as_str(),
            "$NAME ${NAME} `command` $(command) \\"
        );
        assert_eq!(values["G"].as_str(), "$NAME ${NAME} `command` $(command)");
        assert_eq!(values["G"].as_str(), values["H"].as_str());
        Ok(())
    }

    #[test]
    fn invalid_name_and_quote_forms_fail() {
        for input in [
            "=value",
            "1NAME=value",
            "NAME-X=value",
            "export NAME",
            "A='a'='b'",
            "A=\"a\\x\"",
            "A=\"a\\",
            "A=a\\\nb",
        ] {
            assert!(parse_dotenv(input.as_bytes()).is_err());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x5eed),
            ..ProptestConfig::default()
        })]
        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_dotenv(&bytes);
        }
        #[test]
        fn single_quotes_preserve_unicode(value in "[^'\\x00\\r]{0,128}") {
            let input = format!("VALUE='{value}'\n");
            let result = parse_dotenv(input.as_bytes());
            prop_assert!(result.is_ok());
            if let Ok(values) = result {
                prop_assert_eq!(values["VALUE"].as_str(), value.as_str());
            }
        }
    }
}
