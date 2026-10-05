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
jobs, and two test threads. The implementation remains an uncommitted change
based on `b74d71d37a60a8073b59ed4cb0f26c1aad3cf41a`.

- Formatting and Clippy pass with warnings denied across all targets/features.
- All 78 unit, fixed-seed property, subprocess, and workflow tests pass.
- Both optimized binaries build, and 51 detector/workflow tests pass against them.
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
