//! Synthetic-only experiment. This code is never called by either shipped CLI.
mod corpus;
mod metrics;
mod scoring;
#[cfg(test)]
mod tests;

use corpus::{Case, Kind, corpus};
use metrics::{Metrics, measure};
use redact::{
    Span, detect,
    error::{ErrorKind, SafeError},
};
use scoring::{Policy, Threshold, policies};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    process::ExitCode,
    time::Instant,
};

fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        eprintln!("entropy evaluation takes no arguments; run its built-in synthetic corpus");
        return ExitCode::from(2);
    }
    match run(io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!(
                "entropy evaluation failed; check output access and rerun the synthetic harness"
            );
            ExitCode::from(2)
        }
    }
}

fn run(mut writer: impl Write) -> Result<(), SafeError> {
    let cases = corpus();
    let start = Instant::now();
    let baseline: Vec<Vec<Span>> = cases
        .iter()
        .map(|case| detect(case.text.as_str()))
        .collect::<Result<_, _>>()?;
    let baseline_time = start.elapsed();
    let (base, _) = evaluate(&cases, &baseline, None)?;
    let start = Instant::now();
    let mut report = String::from(
        "# Synthetic entropy evaluation\n\nCorpus v1. No external input, environment values, model calls, or live credentials.\n\n",
    );
    report.push_str(&format!("{} cases; {} annotated secrets; {} wholly benign cases. Baseline is the current production detector.\n\n", cases.len(), base.secrets, base.benign_cases));
    report.push_str("Every added policy unions entropy spans with baseline spans. Full recall requires removal of every annotated secret byte; partial removal remains a miss. False positives count wholly benign cases with any removal. Useful-byte loss also measures collateral removal in secret-bearing cases.\n\n");
    report.push_str("Opaque public controls and other benign cases are reported separately. The controls intentionally have identical bytes to opaque secrets. Other benign cases cover public containers, UUIDs, encoded text, URLs, and ordinary text.\n\n");
    report.push_str("An absolute threshold of H bits implies a candidate length of at least ceil(2^H): 3.0 needs 8 characters, 3.5 needs 12, 4.0 needs 16, 4.5 needs 23, and 5.0 needs 32. Hex cannot exceed 4 bits. These ceilings assume optimal character diversity, not typical random samples.\n\n");
    report.push_str("| Added policy | Opaque in bounds caught | Full secrets caught | Partial secrets | All benign removed | Paired controls removed | Other benign removed | Useful bytes removed |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    report.push_str(&format!("| Baseline | n/a | {} |\n", base.row()));
    for policy in policies() {
        let (metrics, in_bounds) = evaluate(&cases, &baseline, Some(policy))?;
        report.push_str(&format!(
            "| {} | {}/{} | {} |\n",
            policy.label(),
            in_bounds.caught,
            in_bounds.secrets,
            metrics.row()
        ));
    }
    let selected = [
        Policy {
            min: 16,
            max: 128,
            threshold: Threshold::Bits(3.5),
        },
        Policy {
            min: 32,
            max: 128,
            threshold: Threshold::Bits(4.5),
        },
        Policy {
            min: 16,
            max: 128,
            threshold: Threshold::Relative(0.85),
        },
    ];
    for policy in selected {
        report.push_str(&format!("\n## Category breakdown: {}\n\n", policy.label()));
        report.push_str("| Category | Baseline full | Added full | Partial secrets | All benign removed | Paired controls removed | Other benign removed | Useful bytes removed |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n");
        let mut families: BTreeMap<&str, (Metrics, Metrics)> = BTreeMap::new();
        for (case, spans) in cases.iter().zip(&baseline) {
            let row = families.entry(case.family).or_default();
            row.0.add(measure(case, spans.clone())?);
            row.1
                .add(measure(case, combined(case, spans, Some(policy)))?);
        }
        for (family, (base, added)) in families {
            report.push_str(&format!(
                "| {family} | {}/{} | {} |\n",
                base.caught,
                base.secrets,
                added.row()
            ));
        }
        report.push_str("\n| Opaque secret length | Baseline full | Added full | Paired public cases removed |\n| --- | --- | --- | --- |\n");
        for length in corpus::LENGTHS {
            let mut base = Metrics::default();
            let mut added = Metrics::default();
            for (case, spans) in cases.iter().zip(&baseline).filter(|(case, _)| {
                case.length == length
                    && matches!(case.kind, Kind::OpaqueSecret | Kind::PublicControl)
            }) {
                base.add(measure(case, spans.clone())?);
                added.add(measure(case, combined(case, spans, Some(policy)))?);
            }
            report.push_str(&format!(
                "| {length} | {}/{} | {}/{} | {}/{} |\n",
                base.caught,
                base.secrets,
                added.caught,
                added.secrets,
                added.false_positives,
                added.benign_cases
            ));
        }
        let missed = cases
            .iter()
            .zip(&baseline)
            .filter_map(
                |(case, spans)| match measure(case, combined(case, spans, Some(policy))) {
                    Ok(_) if !(policy.min..=policy.max).contains(&case.length) => None,
                    Ok(metric) if metric.caught < metric.secrets => Some(Ok(case.id.as_str())),
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                },
            )
            .take(5)
            .collect::<Result<Vec<_>, _>>()?;
        report.push_str(&format!(
            "\nFirst missed case IDs within the policy's length bounds: {}. Only safe synthetic metadata is reported.\n",
            missed.join(", ")
        ));
    }
    report.push_str(&format!("\nBaseline detector time: {:.3} ms including first initialization. Sweep and report time: {:.3} ms. Timing excludes corpus generation and output writes; it is not a performance gate.\n", baseline_time.as_secs_f64() * 1000.0, start.elapsed().as_secs_f64() * 1000.0));
    report.push_str("\nThis intentionally constructed corpus is not a production prevalence estimate. Public and secret opaque pairs have identical bytes. No string-only policy can distinguish their role. See docs/entropy-evaluation.md for boundaries and interpretation.\n");
    writer
        .write_all(report.as_bytes())
        .and_then(|()| writer.flush())
        .map_err(|_| SafeError::new(ErrorKind::Output))
}

fn combined(case: &Case, baseline: &[Span], policy: Option<Policy>) -> Vec<Span> {
    let mut spans = baseline.to_vec();
    if let Some(policy) = policy {
        spans.extend(policy.detect(case.text.as_str()));
    }
    spans
}

fn evaluate(
    cases: &[Case],
    baseline: &[Vec<Span>],
    policy: Option<Policy>,
) -> Result<(Metrics, Metrics), SafeError> {
    if cases.len() != baseline.len() {
        return Err(SafeError::new(ErrorKind::Detector));
    }
    let mut metrics = Metrics::default();
    let mut in_bounds = Metrics::default();
    for (case, spans) in cases.iter().zip(baseline) {
        let measured = measure(case, combined(case, spans, policy))?;
        metrics.add(measured);
        if case.kind == Kind::OpaqueSecret
            && let Some(policy) = policy
            && (policy.min..=policy.max).contains(&case.length)
        {
            in_bounds.add(measured);
        }
    }
    Ok((metrics, in_bounds))
}
