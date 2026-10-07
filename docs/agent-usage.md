# Agent usage guide

These are the preferred commands for agents using `rprintenv` and `rstr`. Use
synthetic fixtures during development; never test a redactor by printing real
secrets into a transcript.

## Choose the command

Use `rprintenv` for environment variables and `.env` files. It hides populated
values by default even when they have no recognizable secret format. Use `rstr`
for recognizable credentials inside piped logs, messages, and command output.

## Inspect configuration in one command

```sh
rprintenv --json OPENAI_API_KEY DATABASE_URL
```

Read `state`: `missing` means absent, `empty` means present but zero-length, and
`redacted` means populated and hidden. `visible` is deliberate allowed output.
Missing requested variables produce exit `1` with valid JSON; consume that
output rather than rerun a raw command. A populated value does not prove that
a service will accept it.

Use literal presence checking only when emptiness does not matter:

```sh
rprintenv --exists OPENAI_API_KEY
```

Exit `0` includes empty values; `1` means missing; `2` means an operation failed.

## Compare sources without exposing values

```sh
rprintenv --env --file .env --file .env.local --json OPENAI_API_KEY
```

Compare the stable fingerprints on each source's record. They identify likely
equal values across runs and names. The fingerprint is truncated, so it is not
proof of equality or credential validity. Request names to keep output focused.

## Pipe text with its context intact

```sh
set -o pipefail
command 2>&1 | rstr
```

Pipe the producer directly. Keep field names, headers, and structured messages;
a password field can be detected when the bare password alone cannot. Avoid
capturing the raw output into a tool result before passing it through `rstr`.
`pipefail` preserves producer failure in the pipeline's exit status.

Complete ordinary log records can appear before the producer exits. Unfinished
quoted values, JSON containers, private keys, and YAML documents wait for a safe
boundary. Colon-style messages such as `ERROR: retry later` can resemble YAML
keys. URLs, clock times, and file locations normally remain ordinary records.
YAML-like documents may wait until the next document
separator or EOF because a later field can identify earlier data as credentials. No timeout
releases unchecked input. The 16 MiB limit applies to pending input, so longer
streams of completed records are supported.
Cargo warnings, Node errors, uvicorn `INFO:` lines, BuildKit `#1` comments and
`- ` lists can resemble YAML and hold later output too. A short first line can
therefore make a long log reach the pending limit. Keep any retry inside the
filter; do not inspect the raw log to identify the hold.
Unquoted sensitive values containing quotes or brackets and some inline escaped
quoted values also retain their record through EOF. Their delimiters can change
the interpretation of later lines.

`rstr` reads no environment values or `.env` files. No matches means unchanged
output, not proof that no secret was present. Use `rprintenv` directly for
variable inspection instead of piping an environment dump through a detector.

## Recover safely

A failure should name a safe category and location, for example an unterminated
quote on line 12. Follow that diagnosis using an appropriate safe editing path;
never dump the source line into chat. If a tool defect needs investigation,
reproduce its structure with synthetic input and report the version and safe
error message. Never bypass redaction or write an ad hoc regex against real
secrets to get the command through.

`--allow NAME` on `rprintenv` deliberately prints the complete value. It is not
an error-recovery technique and should not be used just to inspect a credential.

Streaming errors identify the global line and say when earlier filtered output
was emitted. Treat that output as incomplete. The unfinished input record stays
withheld when input validation or detection fails. Output-write failures can
leave a partial filtered record; never retry with raw input.

## Future format hints

The [format inventory](secret-formats/README.md) records recognizable types for
future detection and classification. A hint such as "Stripe publishable-key
format" can help identify the wrong kind of credential, but is not a validity or
account check. An unknown format may be a new or custom version. Keep it hidden
and avoid raw inspection or rotation solely on the basis of a pattern mismatch.
