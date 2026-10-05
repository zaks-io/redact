# Fuzzing

These six cargo-fuzz targets call the production parser, disclosure policy,
renderers, detectors, and stdin filter. They do not read the environment or
open input files. Seed corpora contain synthetic inputs only, including the
checked-in agent workflow fixtures and versioned provider prefixes.

Install the pinned cargo-fuzz release, then run commands from this directory.
The local toolchain file pins nightly and rust-src. AddressSanitizer,
libFuzzer coverage, debug assertions, and overflow checks are enabled by
cargo-fuzz.

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cd fuzz
CARGO_BUILD_JOBS=2 cargo fuzz build
cargo test --lib
cargo fuzz run dotenv -- -max_total_time=10 -max_len=4096 -rss_limit_mb=2048 -timeout=2
cargo fuzz run disclosure -- -max_total_time=10 -max_len=4096 -rss_limit_mb=2048 -timeout=2
cargo fuzz run rendering -- -max_total_time=10 -max_len=4096 -rss_limit_mb=2048 -timeout=2
cargo fuzz run pipeline -- -max_total_time=10 -max_len=4096 -rss_limit_mb=2048 -timeout=2
cargo fuzz run detectors -- -max_total_time=10 -max_len=4096 -rss_limit_mb=2048 -timeout=2
cargo fuzz run text_filter -- -max_total_time=10 -max_len=4096 -rss_limit_mb=2048 -timeout=2
```

If shared rustup storage is read-only, install the pinned nightly into
project-owned storage and select it with `RUSTUP_HOME` and `RUSTUP_TOOLCHAIN`.
Keep inherited environment variables; no credential lookup or environment
dump is needed.

The budgets above are smoke-test controls, not parsing limits. Run targets
sequentially to respect shared resources. See
[the recorded smoke results](../docs/fuzzing-results.md) for the actual evidence.
A finite campaign cannot prove that arbitrary input is safe.

`disclosure` and `rendering` use a compact structured format. The first byte
contains flags, followed by UTF-8 name, value, and file path separated by NUL.
Flags 1 and 2 set exact allow/redact rules; 4 selects an absent value; 8 and 16
add deliberately different allow/redact names; 32 selects a file source.
Metadata can contain Unicode and control characters to exercise escaping.
Malformed UTF-8 structured cases are rejected. Arbitrary dotenv and stdin
bytes always reach their production input validation.

The independent policy decision table and exact text/JSON oracle check
default hiding, empty/missing states, flag precedence, escaping, fingerprints,
and complete output shape. Fixed synthetic canaries check error and nested
debug formatting. Hidden-value mutations may change only the fingerprint.
Changing name or source preserves the fingerprint. The library tests
deliberately put a visible synthetic value into a record that policy requires
to be hidden and verify that the output oracle rejects the defect.

The detector oracle generates credentials inside stable surrounding context
and checks exact removed spans. The text-filter target also builds arbitrary
span fixtures using `arbitrary`; an independent connected-components union
oracle checks overlap handling, adjacency, Unicode boundaries, and preserved
bytes. All assertion messages are fixed strings and do not format inputs.

JSON context oracles check separate Authorization schemes, empty assignments,
and quote boundaries. Fixed JWT seed oracles require full-token redaction for
large JSON numbers and escaped bracket strings. Header/payload nesting over
the documented detector budget must fail with a safe error and no output.

Builds, coverage data, and crash artifacts are ignored. Keep only minimized
synthetic regressions in the seed corpus. Confirm any finding with a normal
deterministic regression, fix production code, then replay and rerun the
affected target. Do not inspect or pass real sensitive input to fuzzing.
