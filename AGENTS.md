# Project instructions

## Purpose and product decisions

These tools should save agents time while preventing accidental secret disclosure
into transcripts, logs, and artifacts. A workflow that requires agents to write
one-off redaction regexes or inspect raw input after failure has not succeeded.
Keep ordinary tasks to one predictable command and safe, actionable output.

- `rprintenv` inspects the environment and explicit `.env` files. Hide populated
  values by default, with narrowly validated ordinary-value exceptions.
- `rstr` detects secrets in stdin only. It never looks up environment values or
  loads `.env` files. Keep its pipe-based interface simple.
- Both use stable SHA-256 fingerprints, truncated to 16 lowercase hex characters.
  Do not expose prefixes or suffixes of a secret.
- Preserve the separate input models. Do not add modes or configuration layers
  to solve a problem already handled by one of the existing commands.
- macOS and Linux are the supported platforms. Use Blacksmith for CI on both.
  Windows is outside the current scope.

Read [the specs](docs/README.md) before implementation. Treat detection limits
honestly: `rstr` cannot recognize every arbitrary standalone password.

## Secret-safe development and failure handling

- Never print real raw environment values, `.env` contents, sensitive stdin, or
  secret-bearing command output into tool results or the conversation. Use
  controlled synthetic fixtures while building and validating these tools.
- Never retry a failed redaction operation by printing the unredacted input,
  showing a matching snippet, invoking a verbose raw dump, or bypassing a rule.
  Reproduce the failure with synthetic data and fix the supported path.
- Treat `Debug`, `Display`, `Serialize`, error sources/chains, panic payloads,
  assertions, tracing fields, and snapshots as potential disclosure paths.
- Types holding raw input or secret values must not derive formatting or
  serialization that exposes their contents. Omit those implementations or make
  debug output explicitly opaque. Nested formatting must remain safe too.
- Rendering code should receive policy-approved output, not raw secret-bearing
  records. Explicit allowed-value output belongs only in the intended renderer.
- Error types must carry safe categories and deliberately approved metadata,
  not raw values, rejected arguments, parser remainders, or source lines.
  Do not forward third-party diagnostics wholesale.
- Report what failed, a source/line when appropriate, and a safe recovery step.
  Never include "the exact input that failed". Do not fingerprint incomplete
  error fragments as a workaround for showing them.
- Handle fallible input with explicit errors. Never use `unwrap`, `expect`, or
  panic formatting on input-derived errors or values in production paths.
  `catch_unwind` alone is not a disclosure boundary: a panic hook may print first.
- No flag, environment setting, or debug build may turn on raw secret logging.
  If a detector or parser fails, fail without unchecked output; never silently
  skip that rule, substitute data, or weaken a test to turn green.
- Do not place real secrets in arguments, fixtures, snapshots, fuzz corpora,
  crash artifacts, commits, or CI logs. Synthetic data should be clearly marked.
- Escape approved metadata in diagnostics. Variable names and caller-supplied
  paths are visible metadata, not a loophole for echoing sensitive input.

## Tests and verification

- Cover failures as deliberately as successful redaction. Assert stdout, stderr,
  and exit status using real subprocesses and synthetic secret canaries.
- Test formatting of secret-bearing types and nested errors. Force parser,
  detector, argument, input-read, and output-write failures and check for leaks.
- Include property tests in normal validation. Keep production parsing,
  detection, and rendering callable with explicit inputs for future fuzzing.
- Build subprocess environments with `Command::env_clear` and `Command::env`.
  Do not mutate the test runner's global environment.
- Use the [acceptance](docs/acceptance.md), [fuzzing](docs/fuzzing.md), and
  [CI](docs/ci.md) contracts. Unit tests alone do not establish CLI acceptance.
- Do not send raw input to another process, service, or agent for debugging.
  Cross-review uses code and synthetic reproductions only.

## Agent workflow acceptance

An agent must be able to check presence, identify matching fingerprints, compare
explicit variable sources, and filter recognizable secrets in command output
without writing custom regexes or reading raw sensitive data into its context.
Successful output stays concise; failures tell the agent how to recover safely.
Use synthetic end-to-end scenarios to verify those tasks. Measure command count,
correctness, and reproducible latency before adding convenience abstractions.
Do not add scheduled model-driven evaluations without an agreed budget and stop
threshold. Deterministic CLI scenarios are the initial acceptance harness.

The [agent usage guide](docs/agent-usage.md) and
[usability acceptance cases](docs/agent-usability.md) are required product
contracts. Wire the checked-in synthetic fixtures into executable tests during
implementation. Assert preserved diagnostic context as well as removed secrets.
Never conflate presence with a nonempty or valid credential, or a zero-match
filter result with proof that text is safe. Keep original context when piping.
