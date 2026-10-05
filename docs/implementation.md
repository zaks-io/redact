# Implementation and validation

The Rust package builds both CLIs and exposes in-memory parser, policy,
fingerprint, rendering, detection, and replacement functions for tests and fuzzing.
Runtime dependencies are local libraries. Neither binary calls a provider,
launches a scanner, downloads rules, or records telemetry.

`rprintenv` implements explicit source selection, full-source validation, the
literal dotenv dialect, exact-name disclosure overrides, the narrow built-in
allowlist, presence checks, sorted text records, and schema-version-1 JSON.
Renderers receive policy-approved records. Raw values have opaque Debug output.
Errors retain fixed categories and approved source/line metadata.

`rstr` implements all v1 detector categories, validates bounded UTF-8 stdin, and
renders the union of original secret spans. See the [rule ledger](rules.md) and
[machine-readable coverage](../rules/coverage.json) for exact provider and
container coverage. Researched formats beyond those rules remain explicitly
deferred or context-only. Standalone arbitrary passwords and recursive encoded
containers are outside the claimed coverage.

## Local evidence

Validation on 2026-10-05 used Linux x86-64, pinned Rust 1.99.0, two Cargo build
jobs, and two test threads. The first pass is commit `497fb7f`; review fixes
follow it on the `feat/v1-implementation` branch.

- Formatting and Clippy pass with warnings denied across all targets/features.
- All 84 unit, fixed-seed property, subprocess, workflow, and regression tests pass.
- Both optimized binaries build, and 57 detector/workflow/regression tests pass
  against them.
- A 2026-10-05 review replayed six confirmed `rstr` disclosure shapes as
  deterministic subprocess regressions (`tests/rstr_regressions.rs`): log fields
  after labels or flag dashes, JWTs inside dotted runs, rejected provider
  prefixes hiding later candidates, camelCase field names, and unencoded URI
  password delimiters, plus a linear-time guard. Five of the six fail against
  `497fb7f` and pass after the fixes.
- Cross-family review of those fixes used Codex (session
  `01a10d15-fd6f-7ff0-ac01-eca9c98cd695`) on code and synthetic reproductions only.
  It found mixed-case names such as `PassWord` broken by camelCase splitting,
  IPv6 hosts mistaken for user information, and a pre-existing JWT payload shape
  hidden by serde_json's arbitrary-precision number marker. All three are fixed
  and replayed in the regression suite.
- The first hosted CI run failed to compile the pseudo-terminal test on macOS
  because `openpty` takes mutable pointers there; it now passes `null_mut` on
  both platforms.
- All 17 named fixtures run against real binaries with cleared environments.
- Failure checks cover arguments, input encoding, NUL, parser and detector
  errors, read/write errors, the exact 16 MiB boundary, and interactive stdin.
- Pipeline checks filter producer stdout/stderr directly and preserve producer
  failures with `pipefail`. Recovery pairs use two tool commands.
- Independent local review found and fixed overlapping URI detection, JWT
  signature overvalidation, JSON context boundaries, JWT JSON representation
  limits, and repeated-assignment performance issues.
  Review used an available Codex agent from the same model family.
- cargo-deny advisory, license, dependency-source, and version-policy checks pass
  for the application and fuzz harness. LLVM's permissive
  [NCSA license](https://spdx.org/licenses/NCSA.html) is allowed
  only for pinned libfuzzer-sys 0.4.10; the remaining dependency licenses follow
  the shared policy.
- Actionlint passes with the documented Blacksmith runner labels configured.
- Six ASan fuzz targets build and complete short budgeted smoke runs. Their
  independent oracles reject deliberate synthetic disclosure defects.
  [Fuzz evidence](fuzzing-results.md) records actual execution and coverage counts.

Scoped gitleaks checks passed for production source, rules, workflow, and fuzz
harness source. Test and seed scans flag deliberately synthetic canaries and
fake credential containers. Those fixtures are retained without blanket scanner
exclusions. No host environment snapshots or real credentials were used.

Release workflow timings include process startup and capture overhead and vary
with shared sandbox load. The measured small fixed fixtures took approximately
0.3 to 0.5 ms for `rprintenv` and 0.8 to 1.4 ms for `rstr` in one local run.
The workflow runner records each case's actual duration and output byte count.
These measurements are a local baseline, not a performance promise or CI gate.

Release builds strip symbols and use fat LTO with one codegen unit. On Linux
x86-64 this reduced `rprintenv` from 1.31 MiB to 777 KiB and `rstr` from 3.45 MiB
to 2.15 MiB. With those builds, `rstr` filtered a 12 MiB synthetic mixed log in
about 0.5 s; the slowest adversarial 16 MiB shapes took about 2.3 s. Peak
resident memory stayed below 100 MiB at the input limit. macOS is unmeasured.

The [binary optimization specification](binary-optimization.md) defines release
settings, required dependency features, behavior compatibility, measurement
procedures, and acceptance criteria for binary size and performance work.

## Remaining platform evidence

The [workflow](../.github/workflows/ci.yml) defines Blacksmith Linux and Apple
Silicon macOS test/release jobs and a separate Linux nightly fuzz-harness job.
No hosted run, GitHub App access check, or macOS execution has been performed
locally. A hosted run is required before claiming that platform acceptance.

## Done

- The documented CLIs run against synthetic environments, files, and pipelines.
- Named workflow expectations and safe error paths pass on actual binaries.
- Disclosure and span-union oracles run in normal tests and the fuzz harness.
- Core logic is callable without process input for future regression campaigns.
- Reproduction commands, dependency policy, rule provenance, and deferred
  detection coverage are checked in.
