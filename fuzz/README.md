# Coverage-guided fuzzing

Install the pinned prerequisites once:

```sh
rustup toolchain install nightly-2026-10-04 --profile minimal --component rust-src,llvm-tools-preview
cargo install cargo-fuzz --version 0.13.2 --locked
```

From this directory, build all six targets and replay the synthetic corpus:

```sh
CARGO_BUILD_JOBS=2 cargo fuzz build
cargo fuzz run dotenv -- -runs=0 -max_len=65536 -rss_limit_mb=1024 -timeout=10
cargo fuzz run disclosure -- -runs=0 -max_len=4096 -rss_limit_mb=1024 -timeout=10
cargo fuzz run rendering -- -runs=0 -max_len=4096 -rss_limit_mb=1024 -timeout=10
cargo fuzz run pipeline -- -runs=0 -max_len=65536 -rss_limit_mb=1024 -timeout=10
cargo fuzz run detectors -- -runs=0 -max_len=65536 -rss_limit_mb=1024 -timeout=10
cargo fuzz run text_filter -- -runs=0 -max_len=65536 -rss_limit_mb=1024 -timeout=10
```

For a bounded campaign, replace `-runs=0` with `-max_total_time=30`.
Run one campaign at a time on the shared sandbox. Set `CARGO_BUILD_JOBS=2`
for builds. To keep generated mutations separate from the reviewed seeds, copy
a target corpus to a temporary directory and pass its absolute path after the
target name. These caps control campaigns,
not production input acceptance. The application retains its documented
16 MiB stdin limit and stable toolchain.

The corpora contain locally constructed synthetic inventory shapes, versioned
provider prefixes, malformed private blocks, public forms, workflow fixtures,
dotenv dialect failures, and allow/redact conflicts. No provider verification,
network call, process environment read, or external command runs in a target.
`detectors` mutates supported prefix families and tests format drift under
sensitive provider fields. Both `detectors` and `text_filter` sample independent
inventory and context-workflow output/status oracles on every iteration and
check exact known corpus seeds against their own fixture oracles. `text_filter`
uses an independent endpoint-count span-union oracle, exact original-byte
hashing, and context preservation. The first four targets call production
dotenv parsing, policy decisions, and both renderers.

The policy oracle is a separate decision table. Canary checks account for
escaped output and recognizable partial leaks. A normal regression test proves
that the shared canary oracle rejects deliberate raw, escaped, and partial
output defects without modifying production code.

Keep crash artifacts local. Diagnose with synthetic reproductions, minimize a
confirmed finding, add a normal regression, fix production, replay all seeds,
and rerun the affected target. Never send raw artifacts to a service or agent.
Report target, pinned toolchain, commit/tree, seed set, budgets, elapsed time,
executions, coverage where available, and results. A short clean campaign is
limited evidence and does not certify every possible input.
