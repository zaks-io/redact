# rprintenv acceptance and validation

This document covers `rprintenv`. The companion `rstr` has its own
[CLI acceptance requirements](text-redaction.md#required-tests-and-future-fuzzing)
and [detector tests](detection.md#acceptance-and-fuzzing). Both commands share
the [fuzzing plan](fuzzing.md) and must pass their own real-binary checks.

The named scenarios and fixture inputs in [agent usability acceptance](agent-usability.md)
are required executable tests, including presence versus configuration state,
focused output, cross-run fingerprints, and safe recovery.

## Disclosure invariant

A populated value may enter stdout in full only if an explicit `--allow` or
validated built-in allowlist rule permits it and no `--redact` overrides it.
Otherwise, value-derived output is limited to the documented stable fingerprint.
Error paths must not disclose raw values or source text.

Test this as a data-flow rule, not a naive substring prohibition for every
possible short value: a hidden value such as `env` may coincidentally occur in
fixed metadata. Use long unique synthetic canaries for end-to-end leak tests,
and assert exact record structures and policy outcomes for arbitrary values.
Never use real credentials or the developer's inherited environment in fixtures.

## Policy and fingerprint tests

- Every allowlisted name and each accepted value is visible by default.
- Unexpected values under every allowlisted name remain hidden.
- Unknown names default to redacted, even when their values look ordinary.
- Exact `--allow` reveals the value; `--redact` wins in every argument order.
- Case variations and partial name matches do not grant disclosure.
- Missing and empty values follow their own states and have no fingerprint.
- Validate the `abc` known SHA-256 vector and independent longer vectors.
- Across separate subprocesses, the same bytes have the same fingerprint.
- Different names and source kinds do not change a value's fingerprint.
- Leading/trailing value whitespace, Unicode normalization differences, and
  embedded newlines are not silently normalized after decoding.
- The display contains exactly 16 lowercase hex characters and no fragments.
- Distinct known fixtures have different fingerprints. Do not assert that
  truncated hashes can never collide.

## Parser tests

Cover every syntax rule in [disclosure.md](disclosure.md), including:

- LF, CRLF, BOM, blank lines, comments, `export`, and empty assignments.
- Quoted whitespace versus trimmed unquoted framing whitespace.
- Literal single quotes, supported double-quote escapes, and multiline values.
- Comment markers inside quotes, adjacent to text, and following whitespace.
- Literal interpolation and command substitution strings in each quoting mode.
- Duplicate definitions with equal and unequal values, with both line numbers.
- Invalid names, bare names, invalid UTF-8, NUL bytes, malformed quotes,
  unsupported escapes, and trailing junk after a closing quote.
- Parse failures in variables excluded by the requested name filter.

Compare decoded values with separately constructed environment fixtures to
verify cross-source fingerprint equality. Run command-substitution fixtures
with a sentinel path and assert that no command executed or file was created.
Verify parsing never changes the test process environment.

## CLI integration tests

Spawn the real compiled binary with a cleared, explicitly populated environment
and temporary synthetic `.env` files. Exercise stdout, stderr, and exit status.

- Default environment listing and explicit `--env`.
- File-only listing, multiple files, and mixed environment/file inspection.
- No implicit `.env` reads or source merging.
- Filtering, deduplication of requested names, deterministic record ordering.
- Missing records in some or all sources, including visible JSON null fields.
- Presence mode for populated, empty, missing, and multiple requested names.
- Rejection of incompatible presence flags and presence with no names.
- File access failures, invalid options, repeated identical file arguments,
  unsupported stdin, and invalid input after an otherwise valid source.
- Text escaping of tabs, newlines, terminal escapes, and unusual metadata.
- Valid parseable JSON with exactly the documented fields and states.
- Equivalent disclosure decisions in text and JSON.
- Output write failure, including a closed output pipe, returns `2` without
  dumping raw buffers or a panic payload.
- Platform-supported tests for non-Unicode environment entries fail safely.
- Help and version work without reading any environment values or files.

For representative listing and input-failure cases, place unique canaries in
multiple secret variables and malformed lines. Assert that neither stdout nor
stderr contains those canaries. Include a canary in an unexpected CLI argument
to catch default argument-parser error echoing.

Verify that an invalid input produces no stdout even when an earlier source was
valid. Ensure diagnostic snapshots contain no source lines or decoded values.

Exercise `Debug`/`Display` and serialization boundaries for secret-bearing types
and nested errors using synthetic canaries. Fault tests must cover third-party
parser errors, argument rejection, and I/O failures.
Run representative subprocess failures with backtraces enabled to check that
error handling does not panic and echo values. Verify diagnostics explain the
problem and safe recovery without quoting input. Do not rely on terminal output
masking or CI secret masking to make these tests pass.

## Property testing and robustness

Use bounded property tests for Unicode values, escaping, policy precedence, and
fingerprint determinism. Feed arbitrary byte sequences to the file parser and
assert successful parsing or a sanitized structured failure, never a panic.
For accepted generated fixtures, assert that rendering hidden records uses only
metadata, markers, and fingerprints. Include multiline and control-character
canaries in both text and JSON integration tests.

Keep test seeds reproducible. A failing case must become a minimal regression
fixture. Bounded parser and disclosure property suites are part of v1
acceptance. Use [proptest](https://docs.rs/proptest/latest/proptest/) for
structured generation and shrinking rather than hand-rolling a generator.

Prepare for the [fuzzing milestone](fuzzing.md) from the first implementation:
parsing, policy decisions, fingerprinting, and rendering must be callable with
explicit inputs. This requires ordinary functions, not speculative adapter
interfaces or a generic framework. CLI tests separately verify OS interactions.
Long-running coverage-guided fuzz campaigns are a later milestone, not a claim
that unit tests or property tests have already fuzzed the executable.

## Verification commands

Once implementation exists, run:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked --release
```

Also run the release executable against temporary files and a controlled
subprocess environment, covering listing, JSON, stable cross-run fingerprints,
mixed-source comparison, empty/missing presence checks, and malformed input.
Capture only synthetic output. Unit tests alone do not satisfy CLI acceptance.

Run the platform and agent workflow checks from [CI](ci.md) on Blacksmith
Linux and macOS runners. Windows is outside current acceptance.

## Done

- All documented behavior has passing focused and CLI integration coverage.
- Both output formats and all error paths satisfy the disclosure contract.
- Property tests run in normal validation and retain reproducible failures.
- Core logic accepts explicit inputs suitable for the documented fuzz targets.
- Release-binary smoke checks confirm the complete agent workflow.
- Help and docs explain accepted hash-guessing and collision limitations.
- No actual credentials, host environment snapshots, or personal configuration
  appear in test fixtures, logs, or documentation.
- No production deployment or hosted service is required for this local tool.
