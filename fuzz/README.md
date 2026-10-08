# Coverage-guided fuzzing

The six cargo-fuzz targets call the production dotenv parser, disclosure policy,
renderers, detectors, and stdin filter. They do not read process environment,
open unrelated files, or contact credential issuers. Both implementations' seed
sets remain synthetic and checked in.

Install the pinned tools, then run commands from this directory:

```sh
rustup toolchain install nightly-2026-10-05 --profile minimal --component rust-src,llvm-tools-preview
cargo install cargo-fuzz --version 0.13.2 --locked
CARGO_BUILD_JOBS=2 cargo fuzz build
cargo test --locked --lib
cargo fuzz run dotenv -- -runs=0 -max_len=65536 -rss_limit_mb=1024 -timeout=10
cargo fuzz run disclosure -- -runs=0 -max_len=4096 -rss_limit_mb=1024 -timeout=10
cargo fuzz run rendering -- -runs=0 -max_len=4096 -rss_limit_mb=1024 -timeout=10
cargo fuzz run pipeline -- -runs=0 -max_len=65536 -rss_limit_mb=1024 -timeout=10
cargo fuzz run detectors -- -runs=0 -max_len=65536 -rss_limit_mb=1024 -timeout=10
cargo fuzz run text_filter -- -runs=0 -max_len=65536 -rss_limit_mb=1024 -timeout=10
```

For a bounded campaign, replace `-runs=0` with `-max_total_time=20`.
Run targets sequentially and limit Cargo builds to two jobs. Copy each corpus
to a temporary directory before a mutation campaign so generated inputs do not
replace reviewed seeds. These caps control campaigns, not application limits.
The stable binaries accept the documented bounded input independently of nightly.

`disclosure` and `rendering` decode one flags byte followed by UTF-8 name,
value, and file path separated by NUL. Flags 1 and 2 set exact allow/redact;
4 selects missing; 8 and 16 add deliberately different allow/redact names;
32 selects a file source. Metadata can include Unicode or control characters.
Invalid structured UTF-8 may be rejected, while arbitrary dotenv and stdin bytes
reach production input validation.

The independent policy table and complete text/JSON oracle check missing and
empty states, exact matching, redact precedence, escaping, and fingerprints.
Hidden-value mutation and source/name changes preserve the specified output
relationships. Library tests inject a deliberately visible synthetic value into
a record that policy requires hidden and verify that the oracle rejects it.
Normal regression tests also reject raw, escaped, partial, and extra-field
leaks, while permitting synthetic canaries in approved metadata.

Both text targets check the 61-row inventory and contextual workflow fixtures
against independent literal output/status expectations. Every iteration samples
both fixture sets, and an exact corpus input checks its own oracle. Generated
provider shapes cover every supported prefix; context mutations retain hiding
when provider grammar changes. Structured generated cases cover Unicode,
nested URLs, separate JSON auth schemes, empty fields, private armor, and JSON
quote boundaries. Fixed JOSE seeds exercise large JSON numbers, escaped brackets,
and safe errors beyond the documented nesting budget.

The text filter also uses arbitrary structured spans and an independent
endpoint-count union oracle. It checks Unicode boundaries, overlapping unions,
separate adjacency, exact original-byte hashing, and preserved unmatched bytes.
It compares streaming output, evidence and errors across read sizes on up to
4 KiB of arbitrary input per iteration. Generated complete records compare
streaming with batch filtering for connection-string escaped values, sensitive
continuations, differing container syntax and assignments beside private-key
blocks. These records use synthetic canaries and retain their whole detection
context. Arbitrary mixed streams have record-local context, so the harness does
not require their output to equal whole-input batch filtering.
All corpus fixtures contain synthetic data; never add host environment snapshots
or real credential material.

Keep artifacts local. Minimize a confirmed finding, add a normal regression,
fix production, replay seeds, and rerun the affected target. Do not weaken an
oracle or bypass the redactor. Report the toolchain, tested revision or tree
digest, seed set, budgets, executions, coverage counters where available, and
findings in the pull request or handoff; do not check results in. Rerun after
meaningful changes. A finite clean campaign is limited evidence, not exhaustive
secret detection.
