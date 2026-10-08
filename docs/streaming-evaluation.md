# Streaming evaluation

`rstr` filters each completed logical record independently. Producer read sizes
cannot change detector context. Only already-filtered bytes are batched for
writing, while unfinished records remain bounded by the pending-input limit.
See the [stdin contract](text-redaction.md) for conservative boundaries and
the distinction from whole-input batch filtering.

## Behavior checks

Run the ordinary and release test suites, including [streaming](../tests/streaming.rs)
and [review regressions](../tests/streaming_review.rs). They verify exact removed
bytes, read-boundary invariance, live output before EOF, late failures, and
bounded evidence reports. Use cleared subprocess environments and synthetic
fixtures. Standalone release acceptance must run after the production binary
build so test dependencies cannot supply missing runtime features.
The boundary regressions interrupt input without EOF and test emitted prefixes
with additional detector-sensitive lines. This verifies that a boundary cannot
discard quote, container or continuation context needed by later input. The fuzz
oracle composes syntax fragments independently of the fixed review reproductions.

```sh
cargo test --locked --jobs 2 -- --test-threads=2
cargo test --locked --release --test workflows --test rstr --test rstr_regressions \
  --test streaming --test streaming_review --test streaming_detector_state \
  --jobs 2 -- --test-threads=2
cargo build --locked --release --bins --jobs 2
python3 scripts/acceptance.py --bin-dir target/release --repeats 10
```

## Performance comparison

Save the accepted baseline's standalone release binaries before rebuilding the
candidate. Both builds must use the pinned toolchain, locked dependencies,
canonical release profile, and the same target. Do not run builds or other heavy
checks during measurement. The benchmark rotates build order, discards a warmup,
and verifies exit status and complete output on every run.

```sh
python3 scripts/benchmark.py target/streaming-baseline/release target/release \
  --legacy-bin-dir target/streaming-baseline/release --repeats 21
```

Measure time to the first ordinary record while stdin remains open separately
from total filtering time. Record executable sizes and process peak memory on
completed logs, secret-heavy JSON, a single unfinished line, possible YAML,
rejected provider prefixes, and an unfinished quoted record over the limit.
On Linux, sample the child's `VmHWM`; parent memory retained across `fork` can
contaminate `wait4` resource measurements. Sampling may miss a final peak.

Per-record detection adds CPU work. Earlier output and reduced retained input
are the product tradeoff; no bulk throughput improvement is promised. Pending
records still require the batch detector's allocations, so the pending byte
limit does not cap total process memory at that value.

Keep measured results, fuzz campaign budgets and results, review evidence, and
platform limitations in the PR or handoff, as required by [performance](performance.md)
and [fuzzing](fuzzing.md). Shared-host measurements are observations, not CI
thresholds. Linux results do not establish macOS performance.

To identify an uncommitted runtime candidate, hash each filename, a NUL, its
bytes, and another NUL, in this order: `Cargo.toml`, `Cargo.lock`,
`rust-toolchain.toml`, then `src/**/*.rs` and `rules/*.json`, sorting each glob
by its path components. Documentation changes do not alter that runtime digest.
