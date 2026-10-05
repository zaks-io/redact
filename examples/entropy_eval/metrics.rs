use super::corpus::{Case, Kind};
use redact::{
    error::SafeError,
    rstr::{Span, merge_spans},
};

#[derive(Clone, Copy, Default)]
pub struct Metrics {
    pub secrets: usize,
    pub caught: usize,
    pub partial: usize,
    pub benign_cases: usize,
    pub false_positives: usize,
    pub control_cases: usize,
    pub control_false_positives: usize,
    pub other_benign_cases: usize,
    pub other_false_positives: usize,
    pub useful_bytes: usize,
    pub removed_useful_bytes: usize,
}

impl Metrics {
    pub fn add(&mut self, other: Self) {
        self.secrets += other.secrets;
        self.caught += other.caught;
        self.partial += other.partial;
        self.benign_cases += other.benign_cases;
        self.false_positives += other.false_positives;
        self.control_cases += other.control_cases;
        self.control_false_positives += other.control_false_positives;
        self.other_benign_cases += other.other_benign_cases;
        self.other_false_positives += other.other_false_positives;
        self.useful_bytes += other.useful_bytes;
        self.removed_useful_bytes += other.removed_useful_bytes;
    }

    pub fn row(self) -> String {
        format!(
            "{}/{} ({}) | {} | {}/{} ({}) | {}/{} ({}) | {}/{} ({}) | {}/{} ({})",
            self.caught,
            self.secrets,
            percent(self.caught, self.secrets),
            self.partial,
            self.false_positives,
            self.benign_cases,
            percent(self.false_positives, self.benign_cases),
            self.control_false_positives,
            self.control_cases,
            percent(self.control_false_positives, self.control_cases),
            self.other_false_positives,
            self.other_benign_cases,
            percent(self.other_false_positives, self.other_benign_cases),
            self.removed_useful_bytes,
            self.useful_bytes,
            percent(self.removed_useful_bytes, self.useful_bytes)
        )
    }
}

pub fn measure(case: &Case, detections: Vec<Span>) -> Result<Metrics, SafeError> {
    let text = case.text.as_str();
    let detected = merge_spans(text, detections)?;
    let secrets = merge_spans(text, case.secrets.clone())?;
    let mut metrics = Metrics {
        secrets: secrets.len(),
        benign_cases: usize::from(secrets.is_empty()),
        ..Metrics::default()
    };
    for secret in &secrets {
        let covered: usize = detected.iter().map(|span| overlap(span, secret)).sum();
        if covered == secret.len() {
            metrics.caught += 1;
        } else if covered > 0 {
            metrics.partial += 1;
        }
    }
    metrics.false_positives = usize::from(secrets.is_empty() && !detected.is_empty());
    if case.kind == Kind::PublicControl {
        metrics.control_cases = metrics.benign_cases;
        metrics.control_false_positives = metrics.false_positives;
    } else {
        metrics.other_benign_cases = metrics.benign_cases;
        metrics.other_false_positives = metrics.false_positives;
    }
    metrics.useful_bytes = text.len() - secrets.iter().map(Span::len).sum::<usize>();
    metrics.removed_useful_bytes = detected
        .iter()
        .map(|span| {
            span.len()
                - secrets
                    .iter()
                    .map(|secret| overlap(span, secret))
                    .sum::<usize>()
        })
        .sum();
    Ok(metrics)
}

pub fn overlap(left: &Span, right: &Span) -> usize {
    left.end
        .min(right.end)
        .saturating_sub(left.start.max(right.start))
}

fn percent(numerator: usize, denominator: usize) -> String {
    if denominator == 0 {
        "n/a".into()
    } else {
        format!("{:.1}%", 100.0 * numerator as f64 / denominator as f64)
    }
}
