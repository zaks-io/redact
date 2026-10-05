# rstr: stdin text redaction

Status: implemented as the `rstr` binary in the local `redact` package. Registry
publication is disabled; package-name availability has not been checked. The
[rule ledger](rules.md) distinguishes shipped coverage from deferred research.

## Purpose

`rstr` reads text from stdin, detects secrets within that text, and writes the
redacted result to stdout. `rprintenv` separately inspects environment variables
and `.env` files. Each command has one input model and one purpose.

`rstr` does not enumerate environment variables, read `.env` files, or build a
known-secret dictionary. Its redaction behavior depends only on stdin and the
bundled detector rules. A file can supply stdin through shell redirection; the
command does not open input file paths itself.

Both commands use `[REDACTED sha256=<fingerprint>]`, with the first 16 lowercase
hex characters of SHA-256. Shared fingerprint behavior does not couple their
input sources or disclosure policies.

## CLI

```text
rstr
rstr -h | --help
rstr -V | --version
```

```sh
# Redact stdout before the agent sees it.
command | rstr

# Include producer stderr in the filtered stream.
command 2>&1 | rstr

# Supply saved text through standard input.
rstr < application.log

# Synthetic example only.
printf '%s\n' 'password=example-password' | rstr
```

No positional text argument, `--file`, `--env`, `--allow`, `--redact`, JSON mode,
or configuration file in v1. Never require a literal secret in a CLI argument.
Help and version return `0` without reading stdin. If stdin is an interactive
terminal, return `2` with a hint to pipe text or redirect a file rather than
waiting indefinitely for interactive input. Invalid arguments return `2`
with a sanitized error that does not echo the arguments.

Agents should pipe producer output directly without first reading it into their
chat. Shell tracing and producer output outside the pipe are outside the
filter's control. Use shell `pipefail` when the caller also needs producer
failures reflected in the pipeline status.

## Detection

Run the bundled [secret detectors](detection.md) over stdin. Recognize provider
token formats, authentication headers, sensitive assignments, URL credentials,
private-key blocks, and JWTs. Ordinary unmatched text passes through unchanged.
No runtime rule downloads, provider calls, or external scanner process.

Detection requires recognizable structure or context. An arbitrary standalone
password may not be recognizable. A successful exit means the configured rules
ran, not proof that every secret was removed. Do not silently fall back to fewer
rules or unchecked passthrough if detector initialization or execution fails.

## Replacements

Compute all detector match spans over the original input. If several rules
match overlapping text, merge those spans into their full union so no secret
prefix or suffix is left behind. Adjacent, non-overlapping spans remain separate.
This is internal matching behavior; there is no cross-tool lookup or comparison.

Replace each resulting span with `[REDACTED sha256=<fingerprint>]`, hashing the
exact original bytes removed. Preserve unmatched bytes and newline framing
exactly, without appending a newline. Render once from the original spans;
never repeatedly scan newly generated markers for more replacements.

For a span equal to a decoded environment value, the fingerprint agrees with
`rprintenv`. Encoded values, compound credentials, and merged spans can have
different fingerprints because the actual removed bytes differ. No decoding or
normalization is applied solely for hashing.

## Input, output, and failures

Buffer stdin and finish input validation and detection before writing output.
V1 accepts bounded text, not an unbounded live log stream. Limit input to 16 MiB
(16,777,216 bytes). Detect overflow with a bounded read and fail with no stdout;
never truncate input, spill raw text to temporary files, or pass it through.

Require UTF-8 input and reject NUL bytes. Preserve valid unmatched line endings,
whitespace, and other characters. This filter removes matched secrets; it does
not neutralize terminal escape sequences or embedded instructions.

- Exit `0`: filtering completed, including empty input or input with no matches.
- Exit `2`: usage, input, encoding, size-limit, detector, or output failure.
- No stdout on failures discovered before writing. An output I/O failure may
  leave a partial redacted result; never retry with raw input.
- Use sanitized stderr with no input snippets, raw values, or parser dumps.
  Report a fixed problem category and a safe recovery step. Never suggest
  rerunning the producer without the filter or printing the input for diagnosis.
- Secret-bearing types, nested errors, and panic paths follow the shared
  [formatting contract](disclosure.md#formatting-and-recovery-contract).
- A run with zero matches outputs the original text unchanged.

## Required tests and future fuzzing

- Cover each detector category with positive, negative, and malformed fixtures.
- Assert output does not depend on inherited environment values, the current
  directory, or nearby `.env` files, including malformed files.
- Reject the source and disclosure flags belonging to `rprintenv`.
- Verify matching fingerprints across commands for identical removed bytes.
- Test embedded, adjacent, repeated, nested, and partially overlapping matches.
- Split input at every byte offset for representative Unicode and multiline
  secrets to catch accidental dependence on I/O boundaries.
- Verify interactive stdin fails promptly with a safe usage hint on both platforms.
- Cover invalid UTF-8, NUL bytes, empty input, input-size limits, failed reads,
  detector failures, and failed output writes.
- Verify unmatched bytes are preserved and replacements are never reprocessed.
- Test both detected and undetected transformed copies against documented rules.
- Fuzz detectors and complete text processing as defined in [fuzzing.md](fuzzing.md).
- Check failures for leaks using synthetic canaries and exact output assertions.
- Run the [usability fixtures](agent-usability.md) for detection context,
  preservation of surrounding diagnostics, and safe failure recovery.

## Done

- `rstr` filters stdin using bundled detectors with no environment/file lookup.
- The documented 16 MiB limit fails safely, with no unchecked passthrough.
- Fingerprints agree with `rprintenv` when the hashed bytes are identical.
- Detector, I/O-boundary, replacement, and error-path tests pass on the binary.
- Required detector categories have pinned rules and positive/negative fixtures.
- Future fuzz targets exercise production detection and rendering functions.
- Help explains detection limits and the stable fingerprint representation.
