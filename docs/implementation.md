# Implementation

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

Release builds strip symbols and use fat LTO with one codegen unit. The
[performance specification](performance.md) defines release settings, required
dependency features, behavior compatibility, and measurement procedures.

## Platform evidence

The [workflow](../.github/workflows/ci.yml) runs tests, acceptance, and native
packaging on Blacksmith Ubuntu 24.04 x86-64 and macOS 26 Apple Silicon, plus a
separate Linux nightly fuzz-harness job. Hosted runs pass on both platforms, and
v0.1.0 was published from a successful Release workflow run. Older operating
system versions remain unverified.

## Done

- The documented CLIs run against synthetic environments, files, and pipelines.
- Named workflow expectations and safe error paths pass on actual binaries.
- Disclosure and span-union oracles run in normal tests and the fuzz harness.
- Core logic is callable without process input for future regression campaigns.
- Reproduction commands, dependency policy, rule provenance, and deferred
  detection coverage are checked in.
