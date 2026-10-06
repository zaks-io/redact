# CI specification

Status: implemented in [the workflow](../.github/workflows/ci.yml). These
requirements do not claim a passing hosted run or verified Blacksmith App access.

## Platforms and runners

Use GitHub Actions with Blacksmith runners for both supported platforms.
Initial coverage is Linux x86-64 and macOS Apple Silicon. Windows is out of scope.

| Job | Runner |
| --- | --- |
| Formatting, linting, dependency checks | `blacksmith-2vcpu-ubuntu-2404` |
| Linux tests and release smoke checks | `blacksmith-2vcpu-ubuntu-2404` |
| macOS tests and release smoke checks | `blacksmith-6vcpu-macos-26` |

These runner labels are published in the current
[Blacksmith instance documentation](https://docs.blacksmith.sh/blacksmith-runners/overview),
checked when this spec was written. Pin OS versions instead of a moving `latest`
label. Verify runner availability and GitHub App access in this repository when
connecting hosted CI; do not silently substitute another runner provider.

The Linux and macOS verification jobs can be one matrix. Keep formatting,
dependency checks, and other platform-independent work on Linux to avoid repeating
it on the larger macOS runner. Increase runner size only when measurements warrant.
Linux ARM and Intel macOS can be added when those architectures are required;
this initial matrix does not certify them.

## Required checks

- Use the checked-in stable toolchain and `Cargo.lock`. Pin external actions to
  immutable revisions and update them deliberately.
- Run `cargo fmt --check` and
  `cargo clippy --locked --all-targets --all-features -- -D warnings`.
- Run `cargo test --locked` on both platforms, including unit, property, real
  executable integration, and documentation tests where present.
- Run `cargo build --locked --release` and smoke-test both release executables
  on both platforms with controlled synthetic inputs.
- Check dependencies for advisories and license compatibility using a reviewed
  `cargo-deny` policy. Adopted detector rule data needs provenance/license checks
  as well as Rust dependencies.
- Cache dependencies/build outputs with OS, architecture, toolchain, and lockfile
  boundaries. Never cache real environment snapshots or sensitive test inputs.
- Run on pull requests and the default branch. Cancel superseded PR runs, set
  timeouts, and restrict workflow token permissions to what the checks need.
- Run ordinary validation with synthetic inputs and no application credentials.
  Never execute untrusted PR code in a privileged workflow context.

Fuzz regression tests are normal CI tests. Coverage-guided campaigns use the
separate nightly harness and explicit time/resource budgets from [fuzzing.md](fuzzing.md).
They must not make the stable application build depend on nightly.
The Linux fuzz-harness job independently validates its oracles and builds all six
sanitizer-enabled targets with the pinned nightly toolchain. It also runs ten-second synthetic campaigns per target with a 1 GiB RSS limit
and five-second per-input timeout. cargo-fuzz lacks a locked build flag, so CI validates the
lockfile before the build and rejects any resulting lockfile change.

## Agent workflow smoke checks

Run every named case and additional integration scenario in
[agent usability acceptance](agent-usability.md), consuming the
[checked-in fixtures](../tests/README.md). Fixture validation alone does not
satisfy this gate. Exercise the following with real release executables:

| Task | Expected agent workflow |
| --- | --- |
| Check whether a variable exists | One `rprintenv --exists NAME` command; exit status is sufficient |
| Distinguish missing, empty, and populated | One filtered `rprintenv --json NAME` invocation |
| Compare environment and explicit file values | One mixed-source `rprintenv` invocation; stable fingerprints |
| Filter recognizable secrets from output | Producer pipes directly to `rstr`; only its filtered output is captured |
| Recover from malformed input | Safe category and location; no raw-input retry is needed to understand the failure |

Record correctness and command count. Measure startup/end-to-end duration over a
fixed synthetic fixture set on a named runner before setting a performance
threshold; do not invent a speed claim or a flaky timing gate. No model calls or
scheduled token spending are required for these deterministic checks.

Performance and binary size work must also satisfy the
[performance specification](performance.md), including
standalone release feature validation and reproducible comparisons.

## Done

Both Blacksmith platform jobs pass against the current commit; both release
binaries pass workflow smoke checks; logs contain only synthetic fixtures; and
runner access, cache behavior, and required checks have been verified live.
