# Fuzz campaign results

Run date: 2026-10-05. Platform: Linux x86-64, kernel 7.0.0-38-generic.
Tooling: cargo-fuzz 0.13.2, nightly-2026-10-04, AddressSanitizer enabled.

Base commit: `b74d71d37a60a8073b59ed4cb0f26c1aad3cf41a`. Runs exercised the
uncommitted implementation in the dedicated T3 worktree. Production source,
lockfiles, toolchain manifests, embedded fixture data, harness source, and
checked-in synthetic corpus SHA-256:

`b14689ce68f1407ddd14f08bbea4c7a9f8e9cbbd4ad762ad025cbc089421b17b`

The digest covers 1,071 files: `src/**/*.rs`, `fuzz/**/*.rs` excluding build
output, `tests/fixtures/*.json`, all files under `fuzz/corpus`, and both Cargo
manifest/lockfile and Rust toolchain pairs. Hash relative paths in lexical order,
appending each UTF-8 path, a NUL byte, and its complete file bytes.

Each campaign ran serially with a 20-second libFuzzer budget, 1 GiB RSS limit,
five-second per-input timeout, seed `20261005`, and Cargo build jobs limited to
two. The maximum mutation size was 4 KiB for disclosure/rendering and 64 KiB
for the other targets. These are campaign controls, not product input limits.
Synthetic checked-in corpora were copied to temporary campaign directories so
generated mutations did not replace reviewed seeds.

| Target | Executions | Actual seconds | Coverage counters | Features | Peak reported RSS | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `dotenv` | 2,479,326 | 21 | 806 | 2,980 | 522 MiB | Passed |
| `disclosure` | 4,028,730 | 21 | 252 | 385 | 545 MiB | Passed |
| `rendering` | 274,584 | 21 | 1,122 | 2,413 | 498 MiB | Passed |
| `pipeline` | 723,637 | 21 | 1,727 | 7,508 | 502 MiB | Passed |
| `detectors` | 85,711 | 21 | 5,433 | 23,636 | 517 MiB | Passed |
| `text_filter` | 110,617 | 21 | 5,535 | 26,942 | 525 MiB | Passed |

Total: 7,702,605 executions in the final recorded campaigns. All six targets
were rerun after the final review fixes and independent fixture-oracle changes.
Both detector corpora replay all 389 inventory cases across 61 entries and all
26 context workflows. Coverage counters are libFuzzer counters, not percentages
of secret families or credential safety.

The initial pipeline campaign found a harness false positive when a synthetic
canary appeared in both approved variable-name metadata and a hidden value.
The fix compares complete independent text and JSON records, preserving strict
checks for extra raw data while permitting documented metadata. A normal test
and minimal checked-in pipeline seed reproduce the case; the original synthetic
artifact replay passed after the fix. No production disclosure occurred in that
finding. The final campaigns had no crashes, hangs, assertion failures, or
disclosure findings.

All 61 inventory entries have executable evidence. Review findings on quoted
fields, malformed containers, URL framing, provider overlaps, and resource
progress also have deterministic CLI/property regressions and detector seeds.
The local Claude review and follow-up review findings were assessed against the
current code, fixed where reproduced, and reviewed locally after the fixes.
Optional hosted review was omitted because local review and deterministic
regression coverage addressed the concrete risks.
A finite campaign is limited evidence, not a guarantee that every secret in
arbitrary text will be detected.

Replay instructions and prerequisites are in [fuzz/README.md](../fuzz/README.md).
Local final validation passed 80 Rust tests, including properties and format
subprocess cases, all formatting and strict Clippy checks, both dependency
policies, and actionlint. Release acceptance passed 43 scenarios with three
repeats each and one command per scenario. Median command latency was 2.227 ms
and maximum latency was 3.730 ms on this sandbox; these are observations, not
a performance guarantee.

Blacksmith CI runs a shorter ten-second campaign for each target. Hosted Linux
and macOS checks were configured but not run in this task.
