use redact::Span;

#[derive(Clone, Copy)]
pub enum Threshold {
    Bits(f64),
    Relative(f64),
}

#[derive(Clone, Copy)]
pub struct Policy {
    pub min: usize,
    pub max: usize,
    pub threshold: Threshold,
}

impl Policy {
    pub fn label(self) -> String {
        let threshold = match self.threshold {
            Threshold::Bits(value) => format!("bits={value:.1}"),
            Threshold::Relative(value) => format!("relative={value:.2}"),
        };
        format!("{}..{} {threshold}", self.min, self.max)
    }

    pub fn detect(self, text: &str) -> Vec<Span> {
        candidates(text)
            .into_iter()
            .filter(|span| {
                let token = &text.as_bytes()[span.clone()];
                if !(self.min..=self.max).contains(&token.len()) {
                    return false;
                }
                let entropy = entropy(token);
                match self.threshold {
                    Threshold::Bits(threshold) => entropy >= threshold,
                    Threshold::Relative(threshold) => {
                        let ceiling = (alphabet_size(token).min(token.len()) as f64).log2();
                        ceiling > 0.0 && entropy / ceiling >= threshold
                    }
                }
            })
            .collect()
    }
}

pub fn policies() -> Vec<Policy> {
    let mut policies = Vec::new();
    for min in [16, 24, 32] {
        for max in [64, 128, 256] {
            for threshold in [3.0, 3.5, 4.0, 4.5, 5.0]
                .map(Threshold::Bits)
                .into_iter()
                .chain([0.75, 0.85, 0.95].map(Threshold::Relative))
            {
                policies.push(Policy {
                    min,
                    max,
                    threshold,
                });
            }
        }
    }
    policies
}

pub fn entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0_usize; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn alphabet_size(token: &[u8]) -> usize {
    if token.iter().all(u8::is_ascii_digit) {
        10
    } else if token.iter().all(u8::is_ascii_hexdigit) {
        16
    } else if token.iter().all(u8::is_ascii_alphanumeric) {
        62
    } else if token
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(byte))
        || token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_=".contains(byte))
    {
        64
    } else {
        66
    }
}

/// Equals separates assignments; trailing Base64 padding belongs to a candidate.
pub fn candidates(text: &str) -> Vec<Span> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        if !candidate_byte(bytes[position]) {
            position += 1;
            continue;
        }
        let start = position;
        while position < bytes.len() && candidate_byte(bytes[position]) {
            position += 1;
        }
        let mut end = position;
        while end < bytes.len() && bytes[end] == b'=' && end - position < 2 {
            end += 1;
        }
        if end > position && (end == bytes.len() || !candidate_byte(bytes[end])) {
            position = end;
        }
        spans.push(start..position);
    }
    spans
}

fn candidate_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"_-+/".contains(&byte)
}
