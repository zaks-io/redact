# redact

Two local Rust CLIs for inspecting configuration and filtering command output.

- `rprintenv` reads the environment and explicitly selected `.env` files. It hides
  populated values by default and shows stable fingerprints. Missing and empty
  values have separate states.
- `rstr` reads stdin only and replaces recognizable secrets. Arbitrary standalone
  passwords can pass through unchanged. Exit `0` does not certify safe text.

## Build and use

The pinned Rust toolchain installs through rustup. macOS and Linux are supported.

```sh
cargo build --locked --release
target/release/rprintenv --help
target/release/rstr --help
```

To install both binaries locally, run `cargo install --locked --path .`.

Inspect only the configuration you need. `--exists` includes empty values;
`--json` distinguishes missing, empty, and populated. Neither establishes that a
credential works with a provider.

```sh
target/release/rprintenv --exists API_KEY
target/release/rprintenv --json API_KEY
target/release/rprintenv --env --file .env --file .env.local API_KEY
```

Pipe the original producer output so field names and authentication context reach
the filter. Include stderr when it can contain secrets. Enable shell `pipefail`
when the producer's failure must remain visible in the pipeline status.

```sh
set -o pipefail
command 2>&1 | target/release/rstr
```

Both tools use SHA-256 fingerprints of the exact protected bytes, truncated to 16
lowercase hex characters. Fingerprints permit correlation and guessing of weak
values. They are not encryption or proof of equality. `--allow` intentionally
prints full values; use it only when disclosure is appropriate.

## Validate

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked -- --test-threads=2
cargo build --locked --release
python3 scripts/acceptance.py
cargo test --locked --release --test workflows --test rstr --test rstr_regressions -- --test-threads=2 --nocapture
cargo install cargo-deny --version 0.18.9 --locked --jobs 2
cargo deny --locked check
cargo deny --manifest-path fuzz/Cargo.toml --locked check --config ../deny.toml
```

The workflow suite executes every checked-in synthetic fixture against real
binaries in isolated temporary directories with cleared child environments. It
records per-invocation duration and output size without a performance threshold.
The release command repeats the suite against optimized binaries. CI runs on
Blacksmith Linux and Apple Silicon macOS with immutable action revisions.

See the [specifications](docs/README.md),
[agent guide](docs/agent-usage.md), and [rule coverage](docs/rules.md). The research
inventory now has executable coverage for all 61 entries in the
[format coverage ledger](docs/secret-formats/coverage.md). Context-only families
still require recognizable fields or structures. Property
tests run in normal validation; six coverage-guided fuzz targets have a separate
pinned nightly toolchain and explicit campaign budgets.
Hosted CI and macOS results require an
actual GitHub Actions run.
The [implementation summary](docs/implementation.md) describes what is built and
which platform checks remain.

The `.env` parser implements the [documented literal dialect](docs/disclosure.md).
It never expands variables or executes shell syntax. Core functions take explicit
inputs for tests and fuzz targets.

Argument parsing uses [clap](https://docs.rs/clap/4.6.7/clap/), but failures map to
fixed diagnostics instead of echoing rejected arguments. SHA-256 uses
[sha2](https://docs.rs/sha2/0.10.9/sha2/), and JSON escaping uses
[serde_json](https://docs.rs/serde_json/1.0.151/serde_json/). Environment reads use
[vars_os](https://doc.rust-lang.org/std/env/fn.vars_os.html) to handle encoding
errors explicitly. The parser implements the specified dotenv subset because
its no-interpolation and duplicate-error rules are part of the product contract.
