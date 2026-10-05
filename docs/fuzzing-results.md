# Fuzz smoke results

On 2026-10-05, all six targets built with AddressSanitizer and completed bounded
coverage-guided smoke runs against the uncommitted implementation based on
`b74d71d37a60a8073b59ed4cb0f26c1aad3cf41a`. These are short smoke runs, not release
campaigns or proof of disclosure safety.

The pinned toolchain was `nightly-2026-10-05`, rustc
`1.101.0-nightly (282215592 2026-10-04)`. Tooling was cargo-fuzz 0.13.2,
libfuzzer-sys 0.4.10, and arbitrary 1.4.2. Builds used two Cargo workers.
Targets ran sequentially with libFuzzer seed 20261005, a 10-second requested
budget, maximum input length 4096, RSS limit 2048 MiB, and timeout 2 seconds
per input. The engine checks its time limit with one-second granularity and
reported 11 seconds for each run. Wall time includes cargo-fuzz build checks.

Corpora are checked-in synthetic seeds, including agent workflow fixtures,
documented dotenv syntax and failures, provider prefix variants, context
containers, malformed boundaries, and overlapping spans. The runs used copied
corpora under ignored `fuzz/coverage/smoke/`; generated discoveries and logs
remain outside the checked-in seed directories.

| Target | Initial seed files | Executions | Coverage counters | Features | Engine seconds | Wall seconds | Outcome |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| dotenv | 17 | 1,009,425 | 735 | 2494 | 11 | 11.18 | Passed |
| disclosure | 18 | 230,823 | 797 | 910 | 11 | 11.16 | Passed |
| rendering | 18 | 153,398 | 1022 | 2171 | 11 | 15.21 | Passed |
| pipeline | 17 | 303,321 | 1371 | 5238 | 11 | 11.51 | Passed |
| detectors | 99 | 420 | 7882 | 15439 | 11 | 11.27 | Passed |
| text_filter | 100 | 377 | 7924 | 15699 | 11 | 11.25 | Passed |

No sanitizer crashes, failed oracle assertions, timeouts, or resource-limit
failures occurred in these runs. Coverage counters are libFuzzer feedback,
not source line or branch coverage percentages.

Three normal library tests passed. One test deliberately changes a policy-hidden
synthetic record into a visible record and confirms that the independent
text/JSON oracle rejects it. The injected defective record exists only inside
that test; production code is unchanged. The other verifies that the independent
span-union oracle merges overlaps while retaining adjacent spans. A third exercises
every generated credential context against the exact-span oracle.

Replay prerequisites and all target commands are in [fuzz/README.md](../fuzz/README.md).
Use `cargo test --locked --lib` from the fuzz directory for oracle validation.
For a deterministic seed replay, use `cargo fuzz run TARGET corpus/TARGET -- -runs=0`.
Normal CLI, property, failure-path, and usability tests remain required.

After local review fixes for nested URI candidates, contextual assignments in
JSON diagnostic strings, and JWT lexical signatures, the affected two targets
were rebuilt and rerun with the same budgets and seed. New minimized synthetic
seeds and generated exact-span cases cover the corrected behavior.

| Target | Initial seed files | Executions | Coverage counters | Features | Engine seconds | Wall seconds | Outcome |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| detectors | 104 | 415 | 8180 | 17018 | 11 | 15.28 | Passed |
| text_filter | 105 | 341 | 8256 | 16839 | 11 | 11.25 | Passed |

No findings occurred in the final replay. Fuzz package formatting and
`cargo clippy --locked --all-targets -- -D warnings` also passed.

A further local review corrected quote boundaries inside JSON strings, empty
assignment/header handling, and scheme preservation for separate JSON-contained
Authorization headers. The generated independent oracles now assert these
relationships, and four additional synthetic regression seeds cover them.
The affected targets replayed their complete seed corpora with `-runs=0`, then
ran another smoke campaign using the same explicit budgets.

| Target | Stage | Seed files | Executions | Coverage counters | Features | Engine seconds | Wall seconds | Outcome |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| detectors | seed-replay | 108 | 108 | 8052 | 13368 | 8 | 14.12 | Passed |
| detectors | json-final-smoke | 108 | 172 | 8083 | 13617 | 11 | 11.21 | Passed |
| text_filter | seed-replay | 109 | 109 | 8116 | 13994 | 7 | 7.73 | Passed |
| text_filter | json-final-smoke | 109 | 166 | 8172 | 14157 | 11 | 11.39 | Passed |

The final seed replays and smoke campaigns passed with no findings. The
three library oracle tests and strict all-target Clippy checks passed again
after the added JSON oracles. No unrelated campaigns were repeated.

The final production delta enabled arbitrary-precision JSON numbers and safely
rejected decoded JWT header/payload nesting beyond the documented detector
budget. Five synthetic JWT seeds and independent fixed-seed oracles cover
large numbers in either object, deep objects/arrays, and escaped quote/bracket
characters inside strings. Representable cases require exact whole-token
redaction; depth failures require a detector error and no output.
The existing third library test validates these cases.

| Target | Stage | Seed files | Executions | Coverage counters | Features | Engine seconds | Wall seconds | Outcome |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| detectors | jwt-seed-replay | 113 | 113 | 8386 | 17174 | 7 | 13.17 | Passed |
| detectors | jwt-final-smoke | 113 | 178 | 8418 | 17428 | 11 | 11.28 | Passed |
| text_filter | jwt-seed-replay | 114 | 114 | 8446 | 17298 | 8 | 8.22 | Passed |
| text_filter | jwt-final-smoke | 114 | 159 | 8451 | 17375 | 11 | 11.18 | Passed |

No final replay or smoke findings remained. All six targets rebuilt after
this delta. The three oracle tests, formatting, strict all-target Clippy, and
fuzz dependency policy checks passed. The policy check reports an informational
`syn` version duplication from the upstream derive dependencies.

The 2026-10-05 review found that every detector call re-parsed the bundled
inventory and recompiled its regular expressions, which limited the two
detector targets to a few hundred executions per budget. Patterns now compile
once per process. The same review fixed log fields after labels or flag dashes,
JWTs inside dotted runs, rejected provider prefixes hiding later candidates,
camelCase sensitive names, and unencoded URI password delimiters. The generated
exact-span oracle gained four contexts for those shapes (13 in total).

| Target | Stage | Seed files | Executions | Coverage counters | Features | Engine seconds | Wall seconds | Outcome |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| detectors | review-seed-replay | 113 | 156 | 2999 | 6763 | 0 | n/a | Passed |
| detectors | review-smoke | 113 | 20,685 | 3793 | 11509 | 11 | 11.32 | Passed |
| text_filter | review-seed-replay | 114 | 158 | 3056 | 6881 | 0 | n/a | Passed |
| text_filter | review-smoke | 114 | 21,506 | 3837 | 11391 | 11 | 11.36 | Passed |

Throughput rose roughly 50 to 130 times over the earlier smoke rows. Counters
fell because regex compilation no longer executes for each input; they are
libFuzzer feedback, not a measure of detector coverage. The three library
oracle tests passed. These remain smoke runs, not release campaigns.
