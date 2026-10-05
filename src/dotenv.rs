use crate::environment::RawVariables;
use crate::error::SafeError;
use std::collections::BTreeMap;

/// Parse the documented literal dotenv dialect without changing the environment.
pub fn parse(bytes: &[u8], path: &str) -> Result<RawVariables, SafeError> {
    let text = std::str::from_utf8(bytes).map_err(|failure| {
        error(
            path,
            line_at(bytes, failure.valid_up_to()),
            "invalid UTF-8. Save the file as UTF-8 and retry.",
        )
    })?;
    if let Some(offset) = text.find('\0') {
        return Err(error(
            path,
            line_at(bytes, offset),
            "NUL byte. Remove NUL bytes and retry.",
        ));
    }
    let normalized = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    let mut parser = Parser {
        text: &normalized,
        offset: 0,
        line: 1,
        path,
    };
    let mut values = BTreeMap::new();
    let mut lines = BTreeMap::new();
    while parser.offset < parser.text.len() {
        parser.horizontal();
        if matches!(parser.peek(), Some('\n' | '#')) {
            parser.skip_line();
            continue;
        }
        if parser.peek().is_none() {
            break;
        }
        let start_line = parser.line;
        if parser.remaining().starts_with("export")
            && parser
                .remaining()
                .as_bytes()
                .get(6)
                .is_some_and(|c| matches!(c, b' ' | b'\t'))
        {
            parser.offset += 6;
            parser.horizontal();
        }
        let start = parser.offset;
        while parser
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            parser.advance();
        }
        let name = &parser.text[start..parser.offset];
        if name.is_empty()
            || !name.as_bytes()[0].is_ascii_alphabetic() && name.as_bytes()[0] != b'_'
        {
            return Err(error(
                path,
                start_line,
                "invalid variable name. Use a letter or underscore followed by letters, digits, or underscores.",
            ));
        }
        parser.horizontal();
        if parser.peek() != Some('=') {
            return Err(error(
                path,
                start_line,
                "invalid assignment. Use NAME=VALUE and retry.",
            ));
        }
        parser.advance();
        parser.horizontal();
        let value = match parser.peek() {
            Some('\'' | '"') => parser.quoted(start_line)?,
            _ => parser.unquoted(),
        };
        if let Some(previous) = lines.insert(name.to_owned(), start_line) {
            return Err(error(
                path,
                start_line,
                "duplicate variable. Keep one definition and retry.",
            )
            .with_related_line(previous));
        }
        values.insert(name.to_owned(), value);
    }
    Ok(RawVariables::from_pairs(values))
}

fn error(path: &str, line: usize, category: &'static str) -> SafeError {
    SafeError::at_line(category, line).with_source(path)
}

fn line_at(bytes: &[u8], offset: usize) -> usize {
    bytes[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

struct Parser<'a> {
    text: &'a str,
    offset: usize,
    line: usize,
    path: &'a str,
}

impl Parser<'_> {
    fn remaining(&self) -> &str {
        &self.text[self.offset..]
    }
    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }
    fn advance(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.offset += character.len_utf8();
        if character == '\n' {
            self.line += 1;
        }
        Some(character)
    }
    fn horizontal(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.advance();
        }
    }
    fn skip_line(&mut self) {
        while let Some(character) = self.advance() {
            if character == '\n' {
                break;
            }
        }
    }
    fn unquoted(&mut self) -> String {
        let start = self.offset;
        let mut previous_space = true;
        let mut end = start;
        while let Some(character) = self.peek() {
            if character == '\n' {
                break;
            }
            if character == '#' && previous_space {
                break;
            }
            previous_space = matches!(character, ' ' | '\t');
            self.advance();
            end = self.offset;
        }
        let value = self.text[start..end].trim_matches([' ', '\t']).to_owned();
        self.skip_line();
        value
    }
    fn quoted(&mut self, start_line: usize) -> Result<String, SafeError> {
        let quote = match self.advance() {
            Some(quote) => quote,
            None => {
                return Err(error(
                    self.path,
                    start_line,
                    "unterminated quoted value. Close the quoted value and retry.",
                ));
            }
        };
        let mut value = String::new();
        loop {
            match self.advance() {
                Some(character) if character == quote => break,
                Some('\\') if quote == '"' => {
                    let escaped = match self.advance() {
                        Some('\\') => '\\',
                        Some('"') => '"',
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some('t') => '\t',
                        None => {
                            return Err(error(
                                self.path,
                                start_line,
                                "unterminated quoted value. Close the quoted value and retry.",
                            ));
                        }
                        _ => {
                            return Err(error(
                                self.path,
                                self.line,
                                "unsupported escape. Use only the documented double-quote escapes and retry.",
                            ));
                        }
                    };
                    value.push(escaped);
                }
                Some(character) => value.push(character),
                None => {
                    return Err(error(
                        self.path,
                        start_line,
                        "unterminated quoted value. Close the quoted value and retry.",
                    ));
                }
            }
        }
        self.horizontal();
        match self.peek() {
            Some('#' | '\n') | None => self.skip_line(),
            _ => {
                return Err(error(
                    self.path,
                    self.line,
                    "trailing text after quoted value. Remove text after the closing quote or begin a comment and retry.",
                ));
            }
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn literal_dialect_and_line_endings() {
        let values = parse(b"\xef\xbb\xbf # comment\r\nexport A = a#b # comment\r\nB=' $A\\n\r\nx'\r\nC=\"a\\n\\r\\t\\\\\\\"${A}$(literal)\"\r\nD= #empty\r\n", "synthetic.env").unwrap();
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
            let error = parse(input.as_bytes(), "synthetic.env").unwrap_err();
            assert!(!format!("{error:?} {error}").contains("synthetic-secret-canary"));
        }
        assert!(parse(b"A=bad\0value", "synthetic.env").is_err());
        assert!(parse(b"A=\xff", "synthetic.env").is_err());
    }

    #[test]
    fn diagnostics_keep_line_numbers_and_escape_metadata() {
        let duplicate = parse(b"A=one\n#comment\nA=two\n", "synthetic\n.env").unwrap_err();
        let message = duplicate.to_string();
        assert!(message.contains("line 3"));
        assert!(message.contains("line 1"));
        assert!(message.contains("synthetic\\n.env"));
        assert_eq!(message.lines().count(), 1);
        for bytes in [b"A=one\nB=bad\0".as_slice(), b"A=one\nB=\xff".as_slice()] {
            assert!(
                parse(bytes, "synthetic.env")
                    .unwrap_err()
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
            let variables = parse(fixture.as_bytes(), "synthetic.env").unwrap();
            prop_assert_eq!(variables.get("VALUE"), Some(value.as_str()));
        }
    }
}
