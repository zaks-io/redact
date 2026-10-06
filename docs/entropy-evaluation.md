# Entropy detection experiment

Status: research only. Neither CLI uses entropy detection, and no production
policy, threshold, length bound, or acceptable false-positive rate is selected.

The harness in [`examples/entropy_eval`](../examples/entropy_eval) measures what
length-bounded Shannon-entropy matching would add on top of the shipped
detectors. It always unions entropy spans with the production spans, so existing
detection is never weakened.

```sh
cargo run --locked --release --example entropy_eval > report.md
cargo test --locked --example entropy_eval -- --test-threads=2
```

The run takes no arguments, reads no stdin, files, or environment values, and
prints a Markdown report of metrics and synthetic case IDs, never fixture values.
Reports are run output; do not check them in.

## What it measures

- **Corpus:** a reproducible synthetic generator in `corpus.rs`. Opaque hex,
  Base62, Base64, and Base64url values across many lengths each appear twice
  with identical bytes, once labeled secret and once public. Structured secrets,
  weak passwords, PEM/SSH framing, UUIDs, URLs, and ordinary text fill out the rest.
- **Policies:** 72 combinations of minimum length (16/24/32), maximum length
  (64/128/256), and absolute (3.0 to 5.0 bits) or alphabet-relative
  (0.75/0.85/0.95) thresholds over maximal ASCII tokens.
- **Metrics:** full-secret recall (partial removal is a miss), wholly benign
  cases with any removal, paired public controls separately, and removed bytes
  outside annotated secrets.

## Limits

The corpus is deliberately adversarial, not a prevalence sample, so it cannot
support precision or production false-positive claims. Identical public and
secret pairs show that no string-only score can tell their roles apart. A
policy chosen from this corpus is not validated by it.

## Before any production decision

- Decide how much harmless-value removal (request IDs, hashes, encoded text) is
  acceptable, and whether entropy should apply everywhere or only in contexts
  existing rules miss.
- Never let entropy veto or gate an existing provider, assignment, header, URL,
  private-key, or JWT match.
- Evaluate on a separate, representative, held-out corpus with independent labels.
- Any evaluation on real logs must have an explicit, authorized scope, run
  locally, and report only aggregate counts. Raw text must never reach tool
  results, model context, fixtures, commits, or reports.
- Keep detection local to `rstr` stdin with no new modes or configuration.
