# rprintenv and rstr specifications

Status: proposed implementation contract. No implementation exists yet.

`rprintenv` is a Rust command line tool that lets agents inspect environment
variables and `.env` files without accidentally copying full secrets into logs
or chat history. It shows ordinary values under narrow disclosure rules and
replaces other values with stable fingerprints.

`rstr` is a separate Rust command line tool that detects and redacts secrets in
piped text. It reads stdin only and preserves ordinary unmatched text.

## Product success

The tools succeed when an agent can finish ordinary secret-handling tasks with
fewer commands and without hand-written redaction regexes or raw-data debugging.
Concise output, stable fingerprints, presence checks, and safe actionable errors
are product requirements. Both normal and failure workflows must be tested.
See [project instructions](../AGENTS.md) for the development rules.

## Agreed rprintenv decisions

- Read the current process environment and explicitly selected `.env` files.
- Hide values by default; recognize a small set of common ordinary variables.
- Allow explicit command line overrides for disclosure.
- Distinguish missing variables, empty values, and populated values.
- Help agents identify equal values across variable names, sources, and runs.
- Fingerprint the exact value with SHA-256, showing the first 16 lowercase hex
  characters. Do not use per-invocation randomness or a stored hashing key.
- Do not reveal secret prefixes or suffixes.
- Target accidental disclosure by cooperative agents. This is not an access
  control boundary against an agent that can read the original environment or
  file.

Stable unkeyed fingerprints allow offline guessing of low-entropy values. This
is an accepted tradeoff. A truncated fingerprint is an identification aid, not
cryptographic proof that two values are equal.

## Documents

- [rprintenv CLI contract](cli.md): commands, sources, output, and exit statuses.
- [Disclosure and input rules](disclosure.md): allowlist, fingerprints, parsing,
  and safe errors.
- [Acceptance and validation](acceptance.md): tests and release criteria.
- [Fuzzing](fuzzing.md): future harnesses, leak oracles, and corpus handling.
- [rstr CLI contract](text-redaction.md): stdin filtering, replacements, and limits.
- [rstr detection](detection.md): detector categories and rule gates.
- [CI](ci.md): Blacksmith on macOS and Linux, plus agent workflow checks.
- [Agent usage](agent-usage.md): preferred commands and safe recovery.
- [Agent usability acceptance](agent-usability.md): required workflows and
  [synthetic test fixtures](../tests/README.md).

Defaults and edge cases below are proposed v1 decisions that make the agreed
behavior implementable. Changes to these contracts should update the specs and
acceptance coverage together.

## Scope

| Command | Input | Behavior |
| --- | --- | --- |
| `rprintenv` | Environment variables and explicit `.env` files | Hide values by default, allow approved ordinary values, and report presence/fingerprints |
| `rstr` | Stdin | Detect recognizable secrets and redact matching text |

The tools share the fingerprint format. Their input sources and disclosure rules
remain separate. `rstr` has no environment/file-source flags or allowlist.

Support macOS and Linux. Use Blacksmith runners for both; Windows is outside
the current scope.

Both tools are local. No network requests, telemetry, background processes,
configuration file, secret storage, environment mutation, or shell execution.
No recursive file discovery, automatic `.env` loading, file editing, or
repository scanning in v1. `rprintenv` has no stdin mode or secret-pattern
detector. `rstr` has no environment or `.env` lookup.

## Done

- The documented commands work against real subprocess environments and files.
- `rprintenv` text and JSON follow the same disclosure policy.
- `rstr` filters stdin independently of environment values and nearby files.
- Stable fingerprints match the documented SHA-256 representation.
- Missing, empty, malformed, and duplicate input cases have verified behavior.
- Tests verify disclosure rules across success and failure paths, including
  debug formatting, nested errors, and synthetic recovery scenarios.
- Parsing and disclosure logic can be exercised directly by future fuzz targets
  without reading the host environment or accessing real files.
- Formatting, linting, unit tests, and CLI integration tests pass.
- Help explains stable fingerprints, each command's input model, and `rstr`
  detection limits.
