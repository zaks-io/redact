use std::fmt;

/// Diagnostics retain only fixed categories and escaped, approved metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeError {
    category: &'static str,
    line: Option<usize>,
    source: Option<String>,
    related_line: Option<usize>,
}

impl SafeError {
    pub fn new(category: &'static str) -> Self {
        Self {
            category,
            line: None,
            source: None,
            related_line: None,
        }
    }
    pub fn at_line(category: &'static str, line: usize) -> Self {
        Self {
            category,
            line: Some(line),
            source: None,
            related_line: None,
        }
    }
    pub fn with_source(mut self, source: &str) -> Self {
        self.source = Some(source.to_owned());
        self
    }
    pub fn with_related_line(mut self, line: usize) -> Self {
        self.related_line = Some(line);
        self
    }
}

impl fmt::Display for SafeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(source) = &self.source {
            let escaped = serde_json::to_string(source).map_err(|_| fmt::Error)?;
            write!(f, "{escaped}, ")?;
        }
        if let Some(line) = self.line {
            write!(f, "line {line}: ")?;
        }
        f.write_str(self.category)?;
        if let Some(line) = self.related_line {
            write!(f, " First definition on line {line}.")?;
        }
        Ok(())
    }
}

impl std::error::Error for SafeError {}
