# Disclosure and input rules

## Decision order

Apply these rules independently to each selected variable:

1. Absent: report `missing`.
2. Present with a zero-length value: report `empty`.
3. Name explicitly supplied with `--redact`: hide the value.
4. Name explicitly supplied with `--allow`: reveal the value.
5. Name and value match the built-in allowlist: reveal the value.
6. Otherwise: hide the value and show its fingerprint.

Name matching is exact and case-sensitive. `--redact` always wins. No wildcard,
substring, suffix, or prefix allow rules. There is no `--allow-all` option.

## Built-in allowlist

Keep v1 deliberately small. Both name and value must match this table exactly.
Empty values are handled separately before allowlist matching.

| Name | Permitted nonempty values |
| --- | --- |
| `NODE_ENV` | `development`, `test`, `production` |
| `RUST_BACKTRACE` | `0`, `1`, `full` |
| `RUST_LIB_BACKTRACE` | `0`, `1`, `full` |
| `CI` | `true`, `false`, `0`, `1` |
| `NO_COLOR` | `1` |
| `FORCE_COLOR` | `0`, `1`, `2`, `3` |
| `CLICOLOR` | `0`, `1` |
| `CLICOLOR_FORCE` | `0`, `1` |

Do not automatically reveal URLs, paths, usernames, hostnames, arbitrary log
configuration, or variables simply because their names look harmless. Those
values can contain credentials or private information. An unexpected value
under an allowlisted name must be fingerprinted, not printed or rejected.

## Fingerprints

Compute SHA-256 over the exact UTF-8 bytes of the decoded nonempty value, then
encode the first 8 digest bytes as 16 lowercase hexadecimal characters.

Do not include the name, source, salt, newline, or any other data. Do not trim,
case-fold, normalize Unicode, or remove prefixes. Do not report secret length,
character classes, guessed provider, prefixes, or suffixes.

Known vector: the synthetic value `abc` produces `ba7816bf8f01cfea`.

The same bytes always produce the same fingerprint. Different values may
collide in the truncated 64-bit display. Never use the displayed fingerprint
as authentication, authorization, or a unique storage key. There is no separate
"equal" verdict in v1; agents compare displayed fingerprints.

Fingerprints expose correlation and permit offline dictionary guesses. This
accepted limitation supports stable identification for cooperative agents.
The original values remain accessible to a process with the same read access.

## Environment input

Read the current process environment without changing it. Avoid convenience
APIs that panic on non-Unicode input. V1 requires lossless UTF-8 representation
of environment names and values; fail with a sanitized encoding error if any
entry in the selected environment cannot be represented. Never use lossy
replacement characters, since they can change values or create false matches.

Metadata such as variable names and supplied file paths is visible. The value
redaction guarantee does not attempt to hide a secret embedded in metadata by
the caller. Escape metadata to prevent control-character and multiline output
injection.

## .env input

Files are UTF-8 text. Accept an optional leading UTF-8 BOM and LF or CRLF record
endings. Strip the BOM as file framing; never trim decoded values for hashing.
All selected files are fully validated, including unselected variables.

The supported v1 dialect is intentionally explicit:

- Blank lines and lines whose first non-space character is `#` are ignored.
- Assignments use `NAME=VALUE`, optionally preceded by `export` and whitespace.
- Names use `[A-Za-z_][A-Za-z0-9_]*`. Spaces and tabs around the name and `=`
  are syntax, not part of the decoded value.
- `NAME=` defines an empty value. A bare `NAME` is a parse error.
- Unquoted values have outer spaces and tabs removed. A `#` starts an inline
  comment only at the start of the value or when preceded by a space or tab.
  Thus `VALUE=a#b` preserves `a#b`. Interior whitespace is preserved.
- Single-quoted values preserve their contents literally. There are no escapes.
- Double-quoted values support only `\\`, `\"`, `\n`, `\r`, and `\t` escapes.
  Unknown escape sequences are errors, not silently transformed text.
- Quoted values may span physical lines. Line endings inside multiline quoted
  values are decoded as LF, whether the file uses LF or CRLF.
- After a closing quote, allow only spaces, tabs, and an optional `#` comment.
- In unquoted values, backslashes are literal and do not continue lines.
- `$NAME`, `${NAME}`, backticks, and `$(...)` are literal text. Never interpolate
  variables, invoke a shell, or execute commands, including in double quotes.
- Duplicate names in one file are errors, even when their values are equal.
  Report line numbers without quoting the assignments.
- Invalid UTF-8, NUL bytes, invalid assignments, and unterminated quotes fail.

This is not a shell parser. Document this dialect rather than claiming universal
compatibility with every dotenv implementation. Compare fingerprints over the
decoded value; quotes, comments, and assignment syntax are not hashed.

## Output and errors

Use a shared disclosure decision for text and JSON. Renderers receive only
sanitized records, with raw values absent from redacted records. Avoid Debug
output, panic messages, logs, or tracing that could include source contents.

Read and validate all input before rendering records. Input failures produce
no stdout. An output I/O failure may leave a partial sanitized listing; return
`2` without retrying with raw input or another format.

Errors identify the source, line number where available, and a fixed error
category. Never quote a raw assignment, value, parser remainder, or rejected
argument. CLI errors use generic descriptions and help hints rather than
reflecting arbitrary supplied arguments. Usage examples contain placeholders.

Do not forward third-party parser or I/O diagnostics wholesale. Map failures to
safe messages. Only deliberately visible metadata may appear, and it must be
escaped. No network or telemetry path may receive input or output.

## Formatting and recovery contract

Secret-bearing types must not expose raw contents through derived `Debug`,
`Display`, or `Serialize`, including when nested in another value or error.
Use opaque debug output or omit formatting implementations. Safe output records
are the serialization boundary, and intentional allowed-value output stays in
the renderer. Errors must not retain raw input for later formatting.

Map third-party failures into fixed categories and approved metadata. Avoid
`unwrap`/`expect` on input-derived errors. A caught panic can still leak through
the panic hook, so catching a panic is not a replacement for safe error paths.
No verbose setting, environment flag, or debug build enables raw input logging.

A useful diagnostic identifies the problem and safe next step, for example:

```text
rprintenv: ".env", line 12: unterminated quoted value. Close the quoted value and retry.
```

Do not append the source line, a matching substring, or a raw nested error.
Agents must reproduce with synthetic input when more diagnosis is needed, never
retry by bypassing redaction. Successful commands should have no diagnostic
banner or repetitive warning that adds noise to agent context.

## Library guidance

Prefer maintained libraries for established primitives:

- [clap](https://docs.rs/clap/latest/clap/) for argument parsing, with sanitized
  error rendering instead of default argument echoing.
- [sha2](https://docs.rs/sha2/latest/sha2/) for SHA-256.
- [serde_json](https://docs.rs/serde_json/latest/serde_json/) for JSON encoding
  and text-field escaping.
- [std::env::vars_os](https://doc.rust-lang.org/std/env/fn.vars_os.html) for
  environment enumeration without implicit Unicode panics.

Before choosing a dotenv library, verify its literal parsing, duplicate handling,
multiline behavior, and diagnostic controls against this contract. Do not use
an API that mutates the process environment or performs interpolation. If no
maintained parser supports the specified subset, implement only that documented
subset and cover it directly with parser tests. Do not build custom crypto or
JSON escaping.
