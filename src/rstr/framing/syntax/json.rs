// The JSON detector skips double-quoted regions, but single quotes are log text.
// Keep that grammar independent of assignment quoting so wrappers cannot hide objects.
#[derive(Default)]
pub(super) struct JsonSyntax {
    pub(super) quote: bool,
    escaped: bool,
    escaped_outside: bool,
    pub(super) depth: usize,
    first_member: bool,
}

impl JsonSyntax {
    pub(super) fn byte(&mut self, byte: u8) {
        let quote_starts = crate::structured::json_quote_starts_string(byte, self.escaped_outside);
        self.escaped_outside = byte == b'\\' && !self.escaped_outside;
        if self.first_member && !byte.is_ascii_whitespace() {
            self.first_member = false;
            if !matches!(byte, b'"' | b'}') {
                self.depth = 0;
            }
        }
        if self.quote {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.quote = false;
            }
        } else {
            match byte {
                b'"' if quote_starts => self.quote = true,
                b'{' => {
                    self.first_member = self.depth == 0;
                    self.depth += 1;
                }
                b'}' => self.depth = self.depth.saturating_sub(1),
                _ => {}
            }
        }
    }
}
