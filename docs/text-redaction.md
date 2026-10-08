# rstr: stdin text redaction

Status: implemented as the `rstr` binary in the local `redact` package. Registry
publication is disabled; package-name availability has not been checked. The
[rule ledger](rules.md) records shipped rules; the [format ledger](secret-formats/coverage.md) records
contextual limits for the complete inventory.

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
The error explains that input belongs on stdin and gives the file-redirection
and producer-pipeline syntax.

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

Compute all detector match spans over each completed input record. If several rules
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

Stream completed ordinary log records before EOF. Validate and detect the entire
record before writing any of it. Keep undecided input in memory, limited to
16 MiB (16,777,216 bytes); completed streams can exceed that total. Never truncate
input, spill raw text to temporary files, or release it on a timeout.

Ordinary non-YAML log lines and `NAME=value` assignments settle at a newline.
Multiline quoted values, JSON containers, and private-key blocks wait for closing
delimiters. Potential YAML mappings, sequences, comments/directives, and document
starts remain buffered through the next document separator or EOF. This protects
credential data even when the identifying `kind: Secret` occurs later. Colon-based
headers can conservatively wait too. `ERROR: retry later` can resemble a YAML
key and hold the remaining stream through `---` or EOF. A plain mapping's first
colon must be followed by whitespace or the end of the line; URLs, clock times,
and file locations with non-space colon suffixes remain ordinary log records.
Common held log prefixes include cargo `warning:`, rustc `error[E...]:`, Node
`Error:`, uvicorn `INFO:`, BuildKit `#1` comments, and `- ` list items. These
can resemble valid YAML, so the filter cannot release their earlier text before
the document boundary. A held log can reach the pending limit even when each
individual line is short.
Sensitive names, quoted names, and Kubernetes `kind`, `data`, and `stringData`
retain their detector context even without whitespace after the colon.
A newline does not settle every format.
Input without a final newline settles at EOF.

An unmatched double quote anywhere can also hold a record because the JSON
detector pairs quotes across lines. Sensitive line-start colon assignments retain
more deeply indented continuations. A `kind: Secret` discriminator within a held
record makes it a possible YAML document, including ambiguous JSON-shaped lines.
Wire-escaped quotes outside JSON strings do not open a JSON string. Inside
strings, the scanner retains JSON escape handling. Completed wire assignments
can settle without changing how later credential objects are detected.
The document separator is `---` at column zero, optional spaces or tabs, an
optional comment, and at most one carriage return before the newline.

Streaming records establish detection context. A later YAML document cannot
retroactively absorb clearly separate log records already emitted. Within a
buffered document, the detectors retain their original full-document behavior.
The standalone batch operation retains its full-input contract; compare it with
streamed output on complete supported records rather than arbitrary mixed logs.

Each completed logical record is detected separately. Only already-filtered
output is batched for writing; producer read sizes cannot change detection
context. Framing uses the detector's assignment and YAML separator grammar, and
tracks JSON containers independently of single-quoted log wrappers.

Changing read chunk sizes must not change stream redactions or fingerprints.
Complete supported-record fixtures retain the same removed bytes as the batch
detector. Boundaries must never split overlapping matches or a construct that
later bytes can identify as credentials. A record ending with a quoted name can
wait for the next non-whitespace character, because a later colon or equals sign
may turn it into a sensitive assignment.

Ambiguous assignment quoting can require EOF. Quote or bracket syntax in a plain
sensitive value or its indented continuation can change how later lines are
parsed. Plain sensitive JSON values followed by more quote or bracket syntax on
the same line also require EOF. Escaped quoted values can overlap URL or
connection-string context, including a connection string that starts at column
zero. Retain ambiguous records through EOF instead of guessing which context owns
their delimiters. Standalone completed escaped quoted assignments without that
overlap still stream. Multiline quoted mapping names retain the document from
the name's opening line.

The context and JSON credential-container detectors certify each candidate
boundary using their own remaining container depth, quote state, pending
sensitive values and continuation extent.
Only certified candidates reach rendering and reporting. A non-neutral candidate
retains the remaining stream through EOF without repeating detection over growing
prefixes. An observed non-delimiter lookahead can close quoted-name lookahead;
a verified document separator can close YAML continuation state. Neither clears
container depth, unmatched quotes or a pending sensitive value.
This check can also hold Go-style URL lists such as
`targets=[http://a/x http://b/y]`, whose closing bracket belongs to URL context.
An incomplete quoted value, private-key block or credential container found at a
candidate boundary waits through EOF so later input can complete it. EOF applies
the normal detector and reports any remaining error. Invalid escapes, input
encoding errors and limits still fail without releasing unchecked text.

Require UTF-8 input and reject NUL bytes. Preserve valid unmatched line endings,
whitespace, and other characters. This filter removes matched secrets; it does
not neutralize terminal escape sequences or embedded instructions.

- Exit `0`: filtering completed, including empty input or input with no matches.
- Exit `2`: usage, input, encoding, size-limit, detector, or output failure.
- Input/detector failures withhold the unfinished record. Earlier completed,
  filtered output may already exist; stderr identifies its presence and the
  global input location. An output I/O failure may leave a partial redacted
  record; never retry with raw input.
- Use sanitized stderr with no input snippets, raw values, or parser dumps.
  Report a fixed problem category and a safe recovery step. Never suggest
  rerunning the producer without the filter or printing the input for diagnosis.
- Secret-bearing types, nested errors, and panic paths follow the shared
  [formatting contract](disclosure.md#formatting-and-recovery-contract).
- A run with zero matches outputs the original text unchanged.

## Redaction evidence on stderr

Stdout markers and their fingerprints remain unchanged. When filtering succeeds
with matches, stderr supplies a bounded report with the number of redactions and
up to eight distinct fingerprint/evidence entries. Repeated entries report their
occurrence count. Each entry gives its first global input line and fixed labels
from the actual detector matches. Overlapping matches retain the union of their
evidence; at most three labels are printed per entry, followed by an indication
that other evidence exists. Additional entries are counted without retaining
unbounded metadata. Zero matches, empty input, and help/version emit no report.

Reports describe recognizable syntax, not credential validity, activity,
ownership, or permission to reveal values. Shared prefixes remain ambiguous.
No value fragments, secret lengths, line ranges, decoded claims, or raw field
content enter evidence labels. The report uses only approved metadata and never
retains removed input. See the [classification contract](secret-formats/classification.md).

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
- Cover invalid UTF-8, NUL bytes, empty input, undecided-input limits, failed reads,
  detector failures, and failed output writes.
- Verify unmatched bytes are preserved and replacements are never reprocessed.
- Test both detected and undetected transformed copies against documented rules.
- Fuzz detectors and complete text processing as defined in [fuzzing.md](fuzzing.md).
- Check failures for leaks using synthetic canaries and exact output assertions.
- Exercise output before producer exit, data-before-discriminator JSON/YAML,
  streams longer than 16 MiB, bounded evidence reporting, and global failure lines.
- Run the [usability fixtures](agent-usability.md) for detection context,
  preservation of surrounding diagnostics, and safe failure recovery.

## Done

- `rstr` filters stdin using bundled detectors with no environment/file lookup.
- The documented 16 MiB pending-input limit fails safely, with no unchecked passthrough.
- Fingerprints agree with `rprintenv` when the hashed bytes are identical.
- Detector, I/O-boundary, replacement, and error-path tests pass on the binary.
- Required detector categories have pinned rules and positive/negative fixtures.
- Future fuzz targets exercise production detection and rendering functions.
- Help explains pending structures, partial-output failures, evidence limits,
  detection limits, and the stable fingerprint representation.
