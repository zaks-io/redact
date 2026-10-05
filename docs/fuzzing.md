# Fuzzing specification

Status: planned follow-up to v1 tests. This document defines the harnesses;
no fuzzing has been run and no harness exists yet.

## Objective

Find crashes, hangs, incorrect parsing, and accidental disclosure, especially
through malformed input and errors. A parser that never crashes but prints a
secret still fails. Coverage-guided fuzzing supplements the deterministic and
property tests in [acceptance.md](acceptance.md).

## Prepare during v1 implementation

Keep the core operations callable with explicit in-memory inputs: parse bytes,
apply disclosure policy, fingerprint a value, and render sanitized records or
errors. Keep process environment reads, filesystem reads, and stdout/stderr
writes at the CLI boundary. No new adapter abstraction is needed.

The core must not read the developer's environment, execute commands, perform
network I/O, or load unrelated files. Test fixtures and corpus entries must
contain only synthetic data. Share production logic with the harness; do not
reimplement the parser or disclosure pipeline just for fuzzing.

## Harness tooling

Use [cargo-fuzz and libFuzzer](https://rust-fuzz.github.io/book/cargo-fuzz.html)
for coverage-guided fuzzing and its documented Rust toolchain requirements.
Use [arbitrary](https://docs.rs/arbitrary/latest/arbitrary/) for structured
fuzz inputs where necessary. Keep fuzz-only dependencies out of the runtime
binary. Pin the harness toolchain in the implementation so runs are reproducible.

## Targets

The first four targets cover `rprintenv`; the last two cover `rstr`.

| Target | Inputs | Required checks |
| --- | --- | --- |
| `dotenv` | Arbitrary file bytes | Valid parsed result or sanitized error; no panic; bounded progress; valid names and unique assignments in successful results |
| `disclosure` | Structured names, values, allow/redact flags | Default hiding, exact name matching, redact precedence, correct empty state, deterministic fingerprints |
| `rendering` | Structured synthetic source records and policy options | Text/JSON policy parity, valid JSON, escaping, no hidden raw values in either output format |
| `pipeline` | File bytes, selected names, policy options | Parse through production rendering; safe error output; no records on input failure; no interpolation or execution |
| `detectors` | Arbitrary UTF-8 and structured synthetic credentials | Correct detector spans, malformed-input behavior, no panic or unbounded work |
| `text_filter` | Arbitrary stdin bytes and generated span fixtures | Detection through production replacement, union of overlapping spans, unchanged unmatched bytes, safe failures |

Inputs that fail to form a valid structured test case may be rejected by the
harness. Invalid dotenv bytes are expected test cases and must reach the parser.
Seed structured targets with valid examples so coverage is not dominated by
input rejection and shallow parse failures.

## Detecting disclosure

Use multiple complementary checks:

1. **Exact policy oracle.** A small test-only decision table independently
   computes allowed disclosure from name, value state, and flags. Compare its
   result with production decisions. Do not call the implementation under test
   to calculate the expected policy.
2. **Structured output checks.** Parse JSON back into records and verify that
   redacted records have a null value and only the expected fingerprint.
   Text records must match the specified escaped representation, without extra
   fields, lines, prefixes, suffixes, or diagnostics.
3. **Synthetic canaries.** Inject long unique secret values with fixed safe
   metadata. Exercise malformed lines and error paths as well as successful
   parsing. Look for the raw canary and its JSON-escaped form in rendered output
   and diagnostics. A whole-value search alone cannot detect partial leaks.
4. **Mutation relationships.** Change only a hidden value, holding its name,
   source, and policy fixed. For nonempty values that remain hidden, only its
   fingerprint may change. The state, metadata, output shape, and diagnostics
   must not acquire value-derived information. Changing source or name while
   preserving a hidden value must preserve its fingerprint.

Do not assert that arbitrary short secrets can never occur as substrings of
metadata or fixed text. Do not treat intentional `--allow` disclosure as a leak.
Keep the oracle simple and review it separately from production decisions.

For `rstr`, generate recognizable synthetic credentials in random surrounding
text and compare output against independent expected spans. Separately exercise
span union and rendering with generated span sets and a simple reference oracle.
Mutations must preserve the detector's required syntax when testing that a
changed secret remains hidden. Do not apply the `rprintenv` invariant that every
unknown nonempty value must be hidden to arbitrary `rstr` text.

## Seed corpus

Include minimal valid assignments, all quote forms, multiline values, CRLF,
BOM, Unicode, escape sequences, comments, duplicate names, literal shell syntax,
invalid UTF-8, NUL bytes, truncated quotes, long lines, and empty input.

Include regressions for unusual variable names in the environment-oriented
structured targets, malformed CLI arguments in subprocess tests, and conflicting
allow/redact flags. Store minimal synthetic reproductions, not host environment
snapshots or real `.env` files. Include synthetic headers, token formats, URLs,
private keys, JWTs, quoted fields, malformed boundaries, and overlapping matches
for `rstr`.

Seed suitable targets from the [agent workflow fixtures](../tests/README.md).
Preserve deterministic tests for context retention and recovery; successful
fuzzing does not replace those assertions.

Add versioned provider shapes and malformed variants from the
[format inventory](secret-formats/README.md) and its
[acceptance requirements](secret-formats/acceptance.md) to detector seeds. Never
contact a provider to verify a generated credential. Distinguish classification
failures from disclosure failures; a supported sensitive context must stay hidden
when a mutated value no longer matches its expected provider format.

## Running and triaging

When the harness exists, its documented commands will be:

```sh
cargo fuzz run dotenv
cargo fuzz run disclosure
cargo fuzz run rendering
cargo fuzz run pipeline
cargo fuzz run detectors
cargo fuzz run text_filter
```

Define explicit input-size, memory, and time budgets for each actual campaign.
Report the toolchain, commit, target, seed corpus, duration, executions, coverage
when available, and findings. Input-size and resource caps in the harness are
campaign controls, not undocumented product parsing limits.

A finite campaign with no findings is evidence for that campaign, not proof that
all inputs are safe. Distinguish sanitizer crashes, assertion failures,
resource exhaustion, and harness defects when triaging.

For every valid finding, minimize the input, add a deterministic regression test,
fix the production issue, replay the regression corpus, then rerun the affected
fuzz target. Never weaken the disclosure oracle or skip the input to turn green.

## Done

- All six targets build and execute against production core logic.
- Synthetic seed corpora exercise both successful and failure paths.
- Oracles detect a deliberately introduced disclosure defect during harness
  validation; remove that defect before committing production code.
- Campaigns have recorded budgets and results, and no unresolved reproducible
  disclosure failures, crashes, or hangs remain within the exercised cases.
- Every confirmed finding has a minimal normal-test regression.
- Replay commands and harness prerequisites are documented and reproducible.
