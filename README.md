# redact

Two small command line tools that let agents and people inspect configuration
and command output without copying secrets into transcripts, logs, or chat.

- `rprintenv` reads environment variables and explicitly named `.env` files. It
  hides populated values by default, shows a stable fingerprint instead, and
  tells missing, empty, and populated values apart.
- `rstr` reads stdin and replaces recognizable secrets with fingerprints. It
  never looks at the environment or opens files.

Both run locally on macOS and Linux. They make no network requests, keep no
configuration, and record no telemetry.

## Install

Prebuilt binaries for Linux x86-64 and Apple Silicon macOS are attached to each
[GitHub Release](https://github.com/zaks-io/redact/releases). Each archive
contains both commands and does not require Rust. The
[installation guide](docs/releases.md#download-and-install) has a copy-paste
script that downloads, verifies the checksum, and installs into
`~/.local/bin`. The macOS binaries are not notarized, so browser downloads may
trigger a security prompt.

To build from source with the pinned Rust toolchain (installed through rustup):

```sh
cargo install --locked --path .
```

## rprintenv

```sh
rprintenv --json OPENAI_API_KEY DATABASE_URL   # state of specific variables
rprintenv --exists OPENAI_API_KEY              # presence only; exit 0 or 1
rprintenv --env --file .env --file .env.local OPENAI_API_KEY   # compare sources
```

Text output has one tab-separated record per line: source, name, and value.
With synthetic values:

```text
"env"        "API_TOKEN"     [REDACTED sha256=abe6c8011330fbd6]
"file:.env"  "API_TOKEN"     [REDACTED sha256=abe6c8011330fbd6]
"file:.env"  "EMPTY_TOKEN"   [EMPTY]
"file:.env"  "MISSING_TOKEN" [UNSET]
"file:.env"  "NODE_ENV"      "production"
```

Matching fingerprints show the two sources likely hold the same value. A small
built-in set of ordinary variables such as `NODE_ENV` is shown; everything else
is hidden unless you pass `--allow NAME`, which prints the full value. `--redact
NAME` always wins.

Without `--file`, the current environment is read. With `--file`, only those
files are read unless `--env` is also given. Files use a literal dotenv dialect:
no variable expansion and no shell execution.

Exit status is `0` on success, `1` when a requested variable is missing from a
selected source, and `2` for usage, input, or parse errors. `--exists` counts
empty values as present; use `--json` to see whether a value is empty. A
populated value does not prove a provider will accept it.

## rstr

Pipe the original command output, including stderr, so field names and headers
reach the filter:

```sh
set -o pipefail
command 2>&1 | rstr
```

```text
connecting as admin
password=[REDACTED sha256=c558f136da60f3aa]
Authorization: Bearer [REDACTED sha256=b52e2fa25863e5e8]
done
```

`rstr` recognizes provider token formats, authentication headers, sensitive
assignments, URL credentials, private key blocks, and JWTs. Unmatched text
passes through byte for byte. Input is limited to 16 MiB of UTF-8.

Detection needs recognizable structure or context. An arbitrary standalone
password can pass through unchanged, so exit `0` or zero replacements does not
prove the text is safe. `pipefail` keeps the producer's failure visible in the
pipeline status.

## Fingerprints and limits

Both tools print `[REDACTED sha256=<16 hex>]`: the first 16 lowercase hex
characters of the SHA-256 of the exact hidden bytes. Fingerprints are stable
across runs, names, sources, and machines, so they work for correlation. They
are not encryption, allow guessing of weak values, and are too short to prove
two values are equal.

These tools prevent accidental disclosure by cooperative agents. They are not
an access control boundary: anything that can read the environment or file
directly can read the secret.

## Documentation

- [Agent usage guide](docs/agent-usage.md): preferred commands and safe recovery.
- [Specifications](docs/README.md): CLI contracts, disclosure rules, detection,
  acceptance, performance, and fuzzing.
- [Rule coverage](docs/rules.md) and the
  [format coverage ledger](docs/secret-formats/coverage.md): which credential
  formats are detected and their limits.
- [Binary releases](docs/releases.md): installation, package contents,
  compatibility, and the release process.

## Development

Run the same checks as CI:

```sh
cargo fmt --check
cargo fmt --manifest-path fuzz/Cargo.toml --check
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked -- --test-threads=2
cargo build --locked --release --bins
python3 scripts/acceptance.py
cargo test --locked --release --test workflows --test rstr --test rstr_regressions -- --test-threads=2
cargo install cargo-deny --version 0.18.9 --locked
cargo deny --locked check
cargo deny --manifest-path fuzz/Cargo.toml --locked check --config ../deny.toml
```

Tests run real binaries against checked-in synthetic fixtures with cleared child
environments; never use real secrets in tests, fixtures, or output. Property
tests run with `cargo test`. The six coverage-guided fuzz targets use a separate
pinned nightly toolchain; see [fuzz/README.md](fuzz/README.md).

CI runs on Blacksmith Ubuntu 24.04 x86-64 and macOS 26 Apple Silicon, packages
both platforms on every run, and runs short fuzz campaigns. Releases are
prepared as drafts by the manual `Release` workflow and published by hand.

Contributors and agents should read [AGENTS.md](AGENTS.md) first.

## License

[MIT](LICENSE)
