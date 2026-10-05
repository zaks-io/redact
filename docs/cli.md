# CLI contract

## Usage

```text
rprintenv [OPTIONS] [NAME...]

--env            Include the current process environment
--file PATH      Include a .env file; repeatable
--allow NAME     Reveal this variable's value; repeatable, exact name only
--redact NAME    Force this variable's value to remain hidden; repeatable
--exists         Check presence without printing values or records
--json           Emit the versioned JSON format
-h, --help       Show help
-V, --version    Show version
```

No names means list all variables in the selected sources. Names select exact,
case-sensitive variable names. Repeated requested names are deduplicated.
`--` ends option parsing. No glob or regular expression matching.

## Sources

- Without `--file`, inspect the current environment. `--env` is redundant.
- With any `--file`, inspect only those files unless `--env` is also present.
- `--file` is explicit: never search parent directories or load another file.
- Each source remains separate. Do not merge, override, or backfill its values.
- Output environment records first, followed by files in argument order.
- Read each source once per invocation, retaining its snapshot for processing.
  Multiple sources are not an atomic snapshot of the whole system.
- Passing the identical file path argument twice is a usage error. Do not
  resolve different aliases solely to deduplicate sources.
- A file argument of `-` is a usage error in v1, not stdin.
- Any unreadable or invalid source fails the whole invocation before records
  are written to stdout.

For each source, sort records by variable name using UTF-8 byte ordering.
When names are requested, emit a record for each name in each source, including
missing names. Without a name filter, emit only variables actually present.
Allow/redact flags change disclosure, not which names are selected.

## Examples

```sh
rprintenv
rprintenv OPENAI_API_KEY DATABASE_URL
rprintenv --exists OPENAI_API_KEY
rprintenv --file .env
rprintenv --env --file .env --file .env.local OPENAI_API_KEY
rprintenv --allow API_BASE_URL API_BASE_URL
rprintenv --redact NODE_ENV NODE_ENV
rprintenv --file .env --json
```

## Text output

One record per physical line, with three tab-separated fields: source, variable
name, and display value. No header, alignment padding, colors, or terminal
control sequences. Source and name are JSON string literals so unusual names
and paths remain unambiguous. Source labels are `env` and `file:<argument>`.
Visible values are also JSON string literals. Markers are unquoted.

In this example, column gaps represent tabs; the fingerprint is SHA-256 of the
synthetic value `abc`:

```text
"env"        "API_TOKEN"       [REDACTED sha256=ba7816bf8f01cfea]
"env"        "EMPTY_TOKEN"     [EMPTY]
"env"        "MISSING_TOKEN"   [UNSET]
"env"        "NODE_ENV"        "production"
"file:.env"  "API_TOKEN"       [REDACTED sha256=ba7816bf8f01cfea]
```

`[EMPTY]` denotes a present zero-length value, regardless of disclosure policy.
`[UNSET]` denotes absence. Empty and missing values have no fingerprint.

## JSON output

Emit one JSON object followed by a newline. `schema_version` starts at `1`.
Records follow the same ordering as text output. Each record has exactly
`source`, `name`, `state`, `value`, and `fingerprint`.

```json
{
  "schema_version": 1,
  "records": [
    {
      "source": { "kind": "environment" },
      "name": "API_TOKEN",
      "state": "redacted",
      "value": null,
      "fingerprint": "ba7816bf8f01cfea"
    },
    {
      "source": { "kind": "file", "path": ".env" },
      "name": "EMPTY_TOKEN",
      "state": "empty",
      "value": "",
      "fingerprint": null
    }
  ]
}
```

| State | Value | Fingerprint |
| --- | --- | --- |
| `visible` | Exact decoded nonempty string | `null` |
| `redacted` | `null` | 16 lowercase hex characters |
| `empty` | Empty string | `null` |
| `missing` | `null` | `null` |

The format itself identifies the algorithm through this versioned contract.
Never include a second raw or debug value field. Do not emit error objects on
stdout; failures use sanitized stderr and exit status `2`.

## Presence and exit statuses

`--exists` requires at least one name. It produces no stdout. A variable exists
when the source defines it, including an empty value. With multiple sources,
every requested name must exist in every selected source for success.
All files are still fully parsed and validated.

Reject `--exists` combined with `--json`, `--allow`, or `--redact` as usage
errors, since those output options have no effect in presence mode.

| Exit | Meaning |
| --- | --- |
| `0` | Successful listing; all explicitly requested variables exist |
| `1` | At least one requested variable is missing from a selected source |
| `2` | Usage, input, encoding, parsing, or output error |

Listing with missing requested names still prints their missing records and
returns `1`. An unfiltered empty source returns `0`. Invalid input takes
precedence over missing variables. Help and version return `0`.

## Agent guidance

Help and documentation must say:

- Fingerprints are stable across runs, files, names, and machines.
- Compare fingerprints to identify likely equal values. They are truncated.
- Missing and empty are different; either can explain configuration failures.
- `--exists` includes empty values. Use `--json NAME` to inspect configuration
  state; populated does not establish provider authentication success.
- Use explicit sources to inspect the actual configuration being compared.
- `--allow` prints full values that may then enter logs and chat history.
- Fingerprints permit guessing weak values; they are not encryption.

Preferred agent commands and recovery are specified in [agent usage](agent-usage.md),
with required [usability tests](agent-usability.md).
