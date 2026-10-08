# Performance specification

This contract defines release-build, resource-use, and validation requirements
for `rprintenv` and `rstr`. Optimize command startup and filtering throughput
while preserving the CLI and disclosure contracts. Executable size is secondary:
a larger binary is acceptable when it buys measurable speed or simpler code.
Correctness and secret-safe failure handling take precedence over speed.

## Release builds and portability

Both binaries must use the pinned stable Rust toolchain and checked-in lockfile.
The canonical release profile is:

| Setting | Required value |
| --- | --- |
| Optimization level | `3`, Cargo's release default |
| Symbol stripping | Enabled |
| Link-time optimization | `fat` |
| Codegen units | `1` |

`cargo build --locked --release` and `cargo install --locked --path .` must use
the same release profile. Development and test profiles may retain debug
information; they do not establish shipped binary size or performance.

The test profile uses optimization level `1` with debug assertions and overflow
checks enabled. This keeps large synthetic subprocess watchdog cases within
their existing deadlines on the two-vCPU CI runners. Test inputs, output
assertions, and process deadlines remain the same.

Release executables must run on supported Linux and macOS targets without
depending on the build machine's CPU features. Do not use host-specific CPU
flags for distributed builds. Keep target and architecture selection explicit
when comparing artifacts. Platform acceptance requires execution on the
[Blacksmith platform matrix](ci.md#platforms-and-runners).

Alternative compiler settings must satisfy the comparison and acceptance
requirements below before replacing the canonical profile. A smaller executable
alone does not establish a better release profile. Cargo's
[profile documentation](https://doc.rust-lang.org/cargo/reference/profiles.html)
defines the settings and their defaults.

## Dependency features

Runtime dependencies must enable only features needed by shipped behavior and
measured performance. Test, fuzz, and evaluation dependencies must not become
runtime requirements. Keep root and fuzz lockfiles consistent with selected
features without unrelated dependency upgrades.

Clap must retain argument parsing, derive support, help, usage, typed error
context, and standard-library support. Help and version output remain plain
text. Error context identifies missing values for a closed set of known flags;
only approved static syntax is rendered. Rejected values, spelling suggestions,
raw parser diagnostics, and color rendering are never forwarded. See the
[clap feature documentation](https://docs.rs/crate/clap/4.6.7/features).

Regex must retain its performance engines and every Unicode capability used by
bundled detectors. The required Unicode features cover boolean properties,
general categories, case folding, and Perl classes and boundaries. Unused age,
script, and segmentation tables are outside the required feature set. A new
rule requiring additional Unicode data must update the dependency features and
standalone release acceptance coverage together. See the
[regex feature documentation](https://docs.rs/crate/regex/1.13.1/features).

Validate the shipped feature set with binaries built without test dependencies.
Cargo feature unification can enable extra Unicode tables during `cargo test`,
including release tests. Those tests alone cannot establish that bundled
detectors initialize with the shipped feature set.

## Behavior and allocation requirements

Optimization must preserve exact stdout, stderr, exit statuses, input limits,
and detection boundaries for the documented inputs. Preserve unmatched text,
diagnostic context, source distinctions, and the separate input models of the
two commands. Do not weaken validation, skip a detector, or release unchecked
output to improve a measurement.

Fingerprints must remain the first 16 lowercase hexadecimal characters of
SHA-256 over the exact protected bytes. Equivalent inputs must produce the same
markers across names, sources, builds, and platforms. Fingerprint encoding must
use one output buffer without allocating a temporary string for each digest
byte. It must not expose raw input through formatting, errors, or panic paths.

Detection setup must not repeat invariant parser or regex initialization for
each candidate within one invocation. Any retained initialization failure must
remain a safe operational error. Do not add persistent caches, background
processes, environment lookup, or configuration layers for performance.

Memory use must remain bounded by the documented pending-input and file limits
and the records or spans needed to produce output. Completed stream records can
exceed 16 MiB in total; undecided input cannot. Changes to input buffering, retained state,
or detection passes must include peak-memory measurements at the input limits
and on adversarial synthetic fixtures. Do not introduce an undocumented input
limit to reduce memory or runtime.

## Measurement contract

Compare the current accepted implementation with the candidate using standalone
release binaries saved in separate directories. Use the same machine, target,
toolchain, capture method, and fixed synthetic inputs for both builds. Record
the source revisions or reproducible source digests, dependency selections,
compiler settings, OS, architecture, repetition count, and resource settings.

The fixed comparison set must include:

| Scenario | Required observation |
| --- | --- |
| `rprintenv` presence check | Startup and end-to-end latency; empty output and correct exit status |
| One sensitive JSON field | `rstr` startup and detector initialization; exact replacement |
| Approximately 4 MiB secret-heavy JSON log | Filtering and repeated fingerprint throughput; neighboring fields preserved |
| 16 MiB ordinary diagnostic log | Behavior at the input limit; byte-identical output |
| Approximately 4 MiB rejected provider prefixes | Bounded scanning; byte-identical unmatched output |

Report the byte size of each executable and minimum, median, and maximum
end-to-end duration for each scenario. Timings must include process startup,
stdin transfer, and stdout capture. Discard one warmup per build and case, use
at least 21 measured invocations for an acceptance comparison, and rotate build
order between repetitions. Run builds and other task checks outside measurement
windows. State shared-host load and capture overhead as limits on the evidence.

Use synthetic inputs and cleared child environments. Compute expected hashes
independently of production code. Verify complete stdout, stderr, and exit
status on every invocation, including warmups. A timeout, output mismatch, or
failed process invalidates the comparison; it must not be counted as a sample
or retried with unchecked output. Failure diagnostics must not echo input.

The executable comparison command is:

```sh
python3 scripts/benchmark.py target/optimization/baseline target/optimization/candidate --repeats 21
```

When comparing with v0.1.0's quiet stderr contract, add
`--legacy-bin-dir target/optimization/baseline`. This applies only to the saved
baseline; the candidate's bounded redaction report is verified byte for byte.

## Acceptance criteria

An optimization must improve at least one measured objective: startup latency,
bulk filtering time, or allocation overhead. A size reduction alone does not
justify slower runs. Assess both
binaries and every fixed scenario. Investigate regressions beyond ordinary
run-to-run variation with repeated comparisons on the same runner. Any retained
regression must have an explicit product tradeoff and supporting measurements.
Do not claim a universal speedup from a single favorable scenario.

There are no fixed executable-size or latency budgets in this contract.
Shared-sandbox timings must not become CI pass/fail thresholds. A future numeric
budget or regression threshold requires a reproducible baseline on a named
runner and a documented rationale before enforcement.

All [normal validation](../README.md#validate), [CLI acceptance](acceptance.md),
[agent workflows](agent-usability.md), and applicable [fuzz checks](fuzzing.md)
must pass. Run every checked-in workflow fixture against standalone release
executables, including successful redaction, malformed-input recovery, Unicode
boundaries, general categories, and case folding:

```sh
cargo build --locked --release --bins --jobs 2
python3 scripts/acceptance.py --bin-dir target/release --repeats 10
```

Verify byte-identical help, version, and rejected-argument diagnostics against
the accepted build. Include piped output, real terminals, and forced-color and
no-color settings when changing argument-parser features. Known-vector and
property tests must establish fingerprint compatibility. Real subprocess tests
must cover safe read/write failures and producer pipeline exit statuses.

Validate supported platforms independently. A Linux result cannot establish
macOS size, timing, or CLI acceptance. Record measured outcomes and validation
limitations in the pull request or handoff; do not check results into the
repository. This specification defines requirements.

## Done

- Both release binaries use the canonical profile and required runtime features.
- Standalone release acceptance verifies detector initialization and behavior
  without test dependency features.
- Fingerprints, CLI output, failure diagnostics, and input boundaries satisfy
  the existing contracts.
- Reproducible comparisons cover both executable sizes and every fixed scenario;
  improvements and any retained regressions have supporting measurements.
- Required checks pass on supported platforms, with unverified platform claims
  explicitly excluded from the validation evidence.
