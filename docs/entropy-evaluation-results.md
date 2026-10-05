# Initial entropy evaluation results

Run on 2026-10-05 in the assigned T3 worktree on Linux x86-64, sandbox `sbx-2`,
Rust/Cargo 1.99.0, release profile, two Cargo build jobs. Baseline production
detector code is commit `72491cf`; the experiment does not change that code.
[The complete report](entropy-evaluation-report.md) records all 72 policies.
[The harness contract](entropy-evaluation.md) explains generation and metrics.

## Observations

The final corpus has 1,892 synthetic cases, with 972 annotated secrets and 920
wholly benign cases. The baseline catches all 166 structured/contextual secret
fixtures and none of the intentionally unrecognized opaque/standalone fixtures.
It removes no harmless text in this corpus. That aggregate recall is a property
of this deliberately difficult corpus, not an estimate of production coverage.

All entropy policies run on top of the baseline. Three fixed comparisons show
the tradeoff:

| Added policy | Full secrets caught | Additional full secrets | Partial secrets | Paired public controls affected | Other harmless cases affected | Useful bytes removed |
| --- | --- | --- | --- | --- | --- | --- |
| Baseline | 166/972 | 0 | 0 | 0/768 | 0/152 | 0/119,839 |
| Length 16 to 128, entropy at least 3.5 bits | 598/972 | 432 | 16 | 414/768, 53.9% | 128/152, 84.2% | 41,512/119,839, 34.6% |
| Length 32 to 128, entropy at least 4.5 bits | 358/972 | 192 | 0 | 176/768, 22.9% | 79/152, 52.0% | 31,094/119,839, 25.9% |
| Length 16 to 128, relative entropy at least 0.85 | 596/972 | 430 | 16 | 413/768, 53.8% | 82/152, 53.9% | 34,564/119,839, 28.8% |

Length bounds successfully reject short and oversized candidates. Within the
commonly discussed 32, 64, and 128 character sizes, the 3.5-bit policy catches
188/192 opaque secrets. It also removes all 188 identical public controls.
Thus high coverage of random strings is achievable, while role identification
remains unresolved. Those public-control pairs are intentionally identical,
so no threshold can separate them.

The stricter 4.5-bit policy catches zero opaque hex secrets, because hex entropy
cannot exceed 4 bits per character. It preserves the UUID and asset-URL fixtures
that the 3.5-bit policy damages. However, it still removes 52/64 public PEM
fixtures and all 16 Base64 ordinary-text fixtures. Raising the minimum to 32
does not protect long public PEM material wrapped into 64-character lines.

Relative entropy preserves all 16 UUIDs, all 16 asset URLs, and all 16 encoded
ordinary-text fixtures in this corpus. It catches more hex values than the
3.5-bit policy, while missing some Base64 samples. Short-sample character
frequencies and alphabet inference affect the score. This is a useful comparison,
not evidence that relative entropy generalizes to arbitrary encoded text.

The first run lacked punctuated opaque secrets and embedded secrets, so a second
iteration added 16 of each. Both 16-to-128 comparison policies partially remove
all punctuated secrets, leaving some of their annotated span visible.
Those remain misses. The absolute policies remove all embedded secrets but also
all 192 bytes of their ordinary prefixes/suffixes. Token boundaries matter even
when the entropy calculation is correct.

Long private keys and low-entropy sensitive assignments retain full baseline
coverage under every policy. Entropy neither needs to recognize nor gets to
exclude those existing matches.

## Performance and validation

The recorded release run took 5.517 ms for baseline detection across the whole
corpus, including first initialization, and 44.040 ms for the 72-policy sweep
and report construction. These exclude fixture generation and output writes.
This is one local observation, not a cross-platform benchmark or a timing gate.

The harness includes known entropy vectors, inclusive length boundaries, ASCII
token boundaries in Unicode text, Base64 padding, hex normalization, full versus
partial removal, collateral accounting, invalid annotation rejection,
deterministic corpus generation, preserved baseline coverage, report disclosure,
output-write failure, and bounded property tests. Example tests run in normal
Cargo validation. Local validation does not establish hosted macOS coverage.

Local checks passed: `cargo fmt --check`, Clippy with all targets/features and
warnings denied, `cargo deny --locked check`, and all 176 normal tests. Release
builds and all 57 release workflow/redaction/regression tests passed. The release
evaluation executable was also launched with a cleared environment: report
generation succeeded without reading synthetic stdin, unexpected arguments
returned exit 2 without echoing the argument, and a forced output-write failure
returned exit 2 with a sanitized diagnostic. The dependency checker reported
the existing unmatched fuzz-library license exception warning; the separate
fuzz policy check reported an existing duplicate `syn` version warning. Both
checks passed. All non-timing evaluation results are identical to the original
run against `996325a` after rebasing onto `72491cf`.

## Next experiment

The [future options record](entropy-options.md) captures alternatives and the
evidence required before choosing a production policy. Chat-history evaluation
is deferred, and no real logs have been evaluated.

The measured tradeoff supports keeping this as an experiment. A next iteration
should add a larger independently labeled synthetic log corpus with ordinary
public identifiers at realistic frequencies, keeping it separate from this
paired stress corpus. Compare context-aware candidate selection and public
container handling against the same baseline. Preserve weak-secret coverage
and full-span accounting; an entropy threshold should never veto a contextual
secret. No production entropy default has been selected.

A local read-only review by Claude Opus 5.5 covered the initial harness. Its
material findings prompted separate control/other-benign metrics, in-bound opaque
recall, threshold length-floor documentation, typed case categories, and stronger
secret-span disclosure/property tests. The meaningful delta was reviewed locally
by Codex. Hosted review was unnecessary for this isolated synthetic experiment.
