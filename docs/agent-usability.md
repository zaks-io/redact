# Agent usability acceptance

Status: required behavior, with [synthetic executable test fixtures](../tests/README.md)
prepared before implementation. No CLI acceptance tests have run yet.

The goal is to answer routine configuration questions and filter recognizable
secrets without custom redaction regexes, raw-input debugging, or unnecessary
commands. The [agent usage guide](agent-usage.md) defines the preferred workflows.

## Presence and configuration state

`--exists` answers literal presence, including an empty value. It must not be
presented as proof that a credential is nonempty, valid, or accepted by a provider.
For configuration diagnosis, use `rprintenv --json NAME` and inspect the state.
Even a populated value does not establish provider authentication success.

Tests must prove:

- `presence_empty_is_present`: empty value, exit `0`, no stdout/stderr.
- `presence_missing`: absent value, exit `1`, no stdout/stderr.
- `configuration_states`: one invocation distinguishes missing, empty, and
  populated records. Missing records cause exit `1` but the JSON remains usable.
- Help describes empty-as-present and points configuration checks to JSON.

Do not add a new flag to compensate for unclear presence documentation.

## Targeted inspection and comparisons

`targeted_inspection` must output exactly the requested record, with no unrelated
variables, raw values, banners, or diagnostic chatter. The result must not need
`grep`, `sed`, or a custom parser to extract the answer.

`compare_explicit_sources` must retain each selected source and its fingerprint,
so one invocation reveals which sources agree and which differ. Do not silently
merge sources. `stable_text_fingerprint` must produce byte-identical output in
separate processes. For identical removed bytes, the `rstr` JSON/password fixture
must contain that same fingerprint.

JSON consumers must get the documented stable schema without extra prose. Text
consumers must get deterministic records. Successful commands have empty stderr.

## Preserve detection context

`rstr` uses patterns and context, without environment or file lookup. Teach agents
to pipe the original structured producer output directly. Extracting a bare value
first can discard the field name that makes it recognizable.

Paired cases must prove the limit:

- `bare_value_has_no_context`: the synthetic standalone value is unchanged.
- `json_preserves_diagnostic_context`: the same value in a password field is
  replaced while the neighboring status, hostname, and explanation survive.
- `environment_and_files_do_not_affect_filter`: adding the same value to the
  environment and a malformed nearby `.env` cannot change the bare-value result.

These are coverage statements, not permission to expose real secrets while
experimenting. Test only synthetic values. Help must explain that no matches
and exit `0` do not certify an absence of secrets.

## Preserve useful surrounding text

Secret removal and preservation of ordinary diagnostic context are separate
assertions. A detector that redacts an entire clearly structured message when
only one field is sensitive fails usability acceptance.

Required exact-output cases:

- `json_preserves_diagnostic_context`: retain JSON framing, other fields,
  status `401`, `api.example.test`, and `authentication failed`.
- `quoted_log_preserves_following_fields`: retain fields after the proven closing
  quote of a password value as well as fields before it.
- `header_preserves_scheme_and_other_lines`: retain the Bearer scheme, HTTP
  status, and unrelated request-ID header.
- `ordinary_output_has_no_banner`: preserve ordinary text byte for byte.
- `ambiguous_unquoted_value_is_conservative`: retain text before the sensitive
  assignment, but redact the whole ambiguous remainder of its line.

The last case documents an intentional limit: guessing where an unquoted secret
ends can leak its suffix. Preserve context when boundaries are known; prioritize
complete removal when they are ambiguous. Generic fallback rules must not erase
context already understood by a structured detector.

## Safe and useful recovery

For each tool, pair `malformed_*_recovery` with `malformed_*_corrected`:

1. The first command fails with exit `2`, empty stdout, and safe stderr naming
   the unterminated quote, its line, and the recovery instruction.
2. The synthetic fixture is corrected by closing the quote.
3. The second command succeeds and redacts the synthetic secret.

That is two tool invocations including the failed attempt, with no help lookup,
raw dump, custom regex, or unfiltered retry. The harness supplies the fixture
correction; this is not a claim that an agent can repair every secret-bearing
file without inspecting or editing it through an appropriate safe mechanism.

Separate fault tests must cover detector initialization errors and safe formatting
of nested errors. A detector failure must produce no stdout and must not print
its input, raw regex diagnostic, or a third-party error chain. Give a safe next
step, such as reporting the version and a synthetic reproduction. Test this via
internal fallible operations; do not add a public bypass or debug flag for tests.

Debug/backtrace settings must not change the disclosure policy. Neither runtime
errors nor agent guidance may recommend exposing the input to diagnose a failure.

## End-to-end workflow and timing

Run these scenarios with real binaries on Blacksmith Linux and macOS:

- One invocation each for presence, state inspection, and source comparison.
- One shell pipeline for filtering producer stdout and stderr. The producer's
  synthetic raw output flows only to `rstr`, not an intermediate transcript.
- A failing producer retains its failure in the shell pipeline status when
  `pipefail` is enabled, even when `rstr` itself succeeds.
- Both malformed/corrected pairs complete with the two invocations above.
- `rstr` rejects interactive stdin promptly instead of waiting for input.

Count user-facing commands, not harness setup or Rust test-process launches.
Record fixed-fixture latency and output size for regression investigation, with
runner and build information. Set performance thresholds only after measuring a
baseline. A timeout is a failure, never a reason to retry without redaction.
No scheduled model evaluation is needed for this deterministic suite.

Automated command counts demonstrate that a short workflow is possible; they do
not prove how a particular model will behave. Any later agent-driven evaluation
must separately report its actual commands, recovery, and transcript disclosure.

## Test integration requirements

The fixture contract in [tests/README.md](../tests/README.md) must become real
binary tests as part of implementation. Named cases must not be dropped, marked
ignored, or treated as passing when the executable is absent. Preserve expected
outputs independently of production functions and review intentional changes to
these contracts against the product requirements.

Add passing fixtures to future fuzz seed coverage where their representation
fits the target. Fuzzing supplements these deterministic usability assertions;
it does not replace context-preservation and recovery scenarios.

## Done

- Every named fixture is exercised by real executable tests on both platforms.
- Help and the agent guide teach presence/state distinctions and context retention.
- Context-preservation assertions pass alongside secret-removal assertions.
- Safe failure recovery, formatting, pipeline, and interactive-input tests pass.
- The workflow uses the expected command count with no raw-data diagnostic step.
- CI records actual evidence; fixture validation alone is not product acceptance.
