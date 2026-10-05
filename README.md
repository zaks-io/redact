# redact

Local Rust tools for inspecting configuration and filtering recognizable secrets.

```sh
cargo install --locked --path .
rprintenv --json OPENAI_API_KEY
rprintenv --env --file .env API_KEY
command 2>&1 | rstr
```

`rprintenv` hides populated values by default. It distinguishes missing and empty
values and supports explicit file sources and narrowly controlled disclosure.
`rstr` reads stdin only and recognizes the documented provider prefixes,
authentication schemes, sensitive fields, URLs and private credential containers.
Both replace hidden values with stable SHA-256 fingerprints truncated to 16 hex
characters. Fingerprints support comparison and permit guessing weak values.

A successful filter run is not proof that arbitrary text contains no secrets.
Unknown standalone passwords and unsupported encodings can pass through. Format
recognition does not validate a credential or identify its owner. Public keys and
resource IDs stay distinct from private material. See the
[coverage ledger](docs/secret-formats/coverage.md) for exact rules and limitations.

The [specifications](docs/README.md) define the CLI and disclosure contracts.

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked --release
python3 scripts/acceptance.py
```

See [fuzzing](docs/fuzzing.md) for all six coverage-guided harnesses and reproducible
campaign commands. CI uses Blacksmith Linux and macOS runners.
