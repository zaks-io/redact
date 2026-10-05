# Fuzz campaign results

Run date: 2026-10-05. Platform: Linux x86-64, kernel 7.0.0-38-generic.
Tooling: cargo-fuzz 0.13.2, nightly-2026-10-05, AddressSanitizer enabled.

Integration base: `996325a29cebe0fc13df8e926d38b713650a40f0`, combined with
implementation snapshot `bd6a669`. Runs exercised the integrated source in the
dedicated T3 worktree. Source and corpus SHA-256:

`1f2cab0b89c100d821dd26bb936db811ee895e475cb79265b8be72065129b2e6`

The digest covers 1,487 files: `src/**/*.rs`, `fuzz/**/*.rs` excluding build
output, `tests/fixtures/*.json`, `rules/*.json`, all files under `fuzz/corpus`,
and both Cargo manifest/lockfile and Rust toolchain pairs. Hash relative paths
in lexical order, appending each UTF-8 path, a NUL byte, and complete file bytes.

Each campaign ran serially with a 20-second libFuzzer budget, 1 GiB RSS limit,
five-second per-input timeout, seed `20261005`, and Cargo build jobs limited to
two. The maximum mutation size was 4 KiB for disclosure/rendering and 64 KiB
for the other targets. These are campaign controls, not product input limits.
Synthetic checked-in corpora were copied to temporary campaign directories so
generated mutations did not replace reviewed seeds.

| Target | Executions | Actual seconds | Coverage counters | Features | Peak reported RSS | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `dotenv` | 1,523,121 | 21 | 802 | 2,799 | 524 MiB | Passed |
| `disclosure` | 411,802 | 21 | 856 | 969 | 464 MiB | Passed |
| `rendering` | 273,456 | 21 | 1,083 | 2,325 | 472 MiB | Passed |
| `pipeline` | 517,040 | 21 | 1,541 | 6,364 | 473 MiB | Passed |
| `detectors` | 23,590 | 21 | 5,927 | 20,936 | 530 MiB | Passed |
| `text_filter` | 23,862 | 21 | 5,887 | 21,909 | 530 MiB | Passed |

Total: 2,772,871 executions in the final integration campaigns. All six targets
were rerun after reconciling remote main's canonical environment implementation,
existing CLI regressions, JSON safeguards, and unified provider registry.
The previous standalone implementation passed 7,702,605 executions on the
2026-10-04 nightly; those counts are not included in this integration total.
Both detector corpora include all 389 inventory cases across 61 entries and all
26 context workflows. Six normal fuzz-library tests validate independent
oracles, generated prefix parity, and every literal fixture. Coverage counters
are libFuzzer counters, not percentages of credential safety.

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
Local integration validation passed 164 Rust tests, including properties and
format subprocess cases, all formatting and strict Clippy checks, both dependency
policies, and actionlint. All six fuzz-library oracle tests passed. Release
acceptance passed 43 scenarios with three repeats and one command per scenario;
main's release workflow/rstr/regression suites also passed. Median acceptance
command latency was 2.353 ms and maximum was 3.713 ms on this sandbox; these are
observations, not a performance guarantee.

Blacksmith CI runs a shorter ten-second campaign for each target. Hosted Linux
and macOS checks were configured but not run in this task.
