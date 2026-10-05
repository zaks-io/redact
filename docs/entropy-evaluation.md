# Entropy detection experiment

This is a synthetic evaluation of an additional entropy detector, not a change
to `rstr`. Production detection and the v1 entropy-only exclusion remain intact.
The experiment measures coverage gained and useful text lost when entropy spans
are added to every existing detector's spans.
The [future options record](entropy-options.md) captures proposed strategies and
open decisions, including a possible chat-history evaluation that is deferred.

## Run

```sh
cargo run --locked --release --example entropy_eval
cargo test --locked --example entropy_eval -- --test-threads=2
```

The first command prints a Markdown report with the full threshold sweep and
three fixed policy breakdowns. It takes no arguments, reads no stdin or files,
and never inspects environment values. Output contains metrics and synthetic
case IDs, not fixture values. Save the report with shell redirection if desired.
No model calls, paid services, scheduled evaluation, or new dependencies are
needed. Example tests also run in the normal `cargo test --locked` suite.

## Corpus and annotations

The versioned corpus generator is in
[`examples/entropy_eval/corpus.rs`](../examples/entropy_eval/corpus.rs).
SHA-256 counter blocks with a fixed synthetic domain generate reproducible
characters. Rejection sampling avoids alphabet modulo bias. These are synthetic
examples, not issued credentials or a cryptographic random generator API.

Opaque values cover lowercase hex, Base62, Base64, and Base64url at lengths
8, 15, 16, 24, 31, 32, 40, 64, 128, 129, 256, and 512. Each combination has 16
samples. Every opaque value appears twice with identical text, once annotated
as a secret and once as public data. Public cases represent hashes and opaque
identifiers. These pairs isolate the information missing from string-only
detection, rather than estimate their relative frequency in real logs.

Other examples include sensitive JSON assignments, Bearer headers, URL
credentials, provider-prefixed tokens, JWTs, short and weak passwords, wrapped
private-key blocks, public PEM blocks, SSH public-key framing, UUIDs, Base64
ordinary text, asset URLs, ordered alphabets, repeated patterns, identifiers,
prose, and Unicode. Key bodies are synthetic framing fixtures, not validated
DER or SSH objects. JWTs and provider tokens exercise local recognition, not
issuer validity. Secret annotations specify complete byte spans independently
of the detector. All surrounding bytes are useful text that should survive.
Some structured and public-container fixtures deliberately reuse generated
values to compare framing. These are not independent statistical samples;
the corpus carries no confidence-interval or prevalence claim.
Punctuated opaque secrets and secrets joined to ordinary prefixes/suffixes
exercise partial removal and collateral loss in otherwise unrecognized text.

## Policies

Each policy uses inclusive minimum and maximum candidate lengths. Minimums are
16, 24, and 32; maximums are 64, 128, and 256. There are 72 combinations with:

- Absolute Shannon entropy thresholds of 3.0, 3.5, 4.0, 4.5, or 5.0 bits per
  character.
- Relative thresholds of 0.75, 0.85, or 0.95, dividing Shannon entropy by
  `log2(min(inferred alphabet size, candidate length))`.

Absolute thresholds also impose a length floor of `ceil(2^H)`: 3.0 bits needs
at least 8 characters, 3.5 needs 12, 4.0 needs 16, 4.5 needs 23, and 5.0 needs
32. The effective floor is the greater of that floor and the policy minimum.
Actual random samples often score below their ceiling. Relative normalization
only caps the ceiling by length; it does not correct finite-sample estimation
bias, and scores need not increase monotonically with length.

Alphabet inference checks digits, hexadecimal characters, Base62, Base64,
Base64url, then the full allowed alphabet. It is itself a heuristic. A short
Base64 string containing only hexadecimal characters will be classified as hex.
Padding counts in observed entropy, while the relative alphabet ceiling treats
it as Base64 framing. The score measures character diversity, not the entropy
of the unknown process that generated the string. Ordered alphabets can score
as highly as random samples.

Candidates are maximal contiguous ASCII letters, digits, `_`, `-`, `+`, or `/`,
with up to two trailing `=` padding characters. An assignment's `=` is a
separator when followed by another candidate character. Length is measured in
ASCII bytes, which equal characters here. Quotes, dots, spaces, and non-ASCII
characters split candidates. Candidates longer than the maximum are rejected
whole; the experiment does not slide windows, trim, decode, or reassemble wrapped
text. This can miss secrets joined to prefixes or suffixes, or remove only part
of a punctuated secret. Partial detection is explicitly a miss.

The experiment always unions entropy matches with the baseline matches and uses
the production span-merging function. Entropy never vetoes existing detection.
The production detector runs once per corpus case, and every policy reuses its
spans. Three fixed policies get category and length breakdowns; they are selected
for comparison, not fitted or recommended defaults.

## Metrics and limits

- Full secret recall requires coverage of every byte of each annotated secret.
  Partial coverage is counted separately and never counted as success.
- False-positive rate is wholly benign cases with any removed text divided by
  all wholly benign cases. Reports additionally separate byte-identical public
  controls from other benign examples, so those controls cannot obscure damage
  to public containers or ordinary text.
- Useful-byte loss counts removed bytes outside all annotated secret spans,
  including surrounding diagnostics in cases containing secrets.

Denominators appear in every report. Aggregate recall includes opaque secrets
outside each policy's bounds, so in-bound opaque recall and the length breakdown
are also reported. The corpus is intentionally constructed and not a production
prevalence sample. Precision,
accuracy, and production false-positive rates cannot be inferred from its label
balance. There is no held-out dataset or claim of generalization. Add independently
labeled, explicitly synthetic examples before selecting a policy.

Timings use a monotonic clock. Baseline time includes its first detector
initialization. Sweep time includes scoring, metrics, and report construction.
Both exclude corpus generation and writing the report. Fixture values and
counts reproduce exactly; timing lines vary by run. Compare release builds
on the same runner; there is no invented performance threshold.

## Iteration and done

Change the corpus and annotations to represent the next question, then rerun
the same command. Change policy arrays to compare new length bounds or scores.
Keep paired public controls, low-entropy secrets, and context preservation in
the suite. A new strategy belongs in this experiment until its tradeoffs justify
a separate production decision.

Done means a reproducible synthetic report, comparison with existing detectors,
full and partial secret coverage, harmless-text loss, length/category breakdowns,
and passing entropy, token-boundary, annotation, property, and safe-output tests.
Actual observations are recorded in [the results](entropy-evaluation-results.md).
