# Safe credential classification

Status: design requirements for future format-aware annotations or checks.
No new CLI flag or output field is introduced by this document. Before shipping
such an interface, update the versioned output contract and executable fixtures.

## What the agent should learn

Useful claims describe recognized syntax and purpose:

- "Matches Stripe live secret-key format."
- "Matches Stripe publishable-key format; this is not a server secret."
- "Matches an AWS access key ID; a secret access key is a separate value."
- "Matches a private-key container."
- "Bearer credential; provider unknown."
- "No recognized format; value remains hidden."

Never say "valid key", "active token", "correct account", or "safe to expose"
from a local pattern match. Even a checksum can be reproduced by someone
constructing a synthetic token. JSON claims and prefixes are attacker-controlled
bytes until authenticated by an issuer, which these tools do not contact.

## Evidence and ambiguity

Classification carries a fixed approved family/purpose label and evidence class
from the inventory. Use the narrowest supported label. Shared `glpat-` cannot
distinguish GitLab personal/project/group access. Generic `sk-` cannot confidently
attribute OpenAI rather than another provider. A JWT is not automatically an
OpenAI, Google, Supabase, or any other specific provider credential.

For multiple plausible families, use a generic label or an explicit ambiguous
result. Do not silently choose whichever regex ran first. Specific documented
prefixes may refine broad family candidates; this must have tests. No numeric
confidence percentages without a measured calibration method.

No private fragments or decoded claims may be added to explain a label. Approved
static words such as provider, family, and documented test/live purpose may be
reported; arbitrary account IDs, subjects, tenant IDs, or scopes from a token
must not flow into user-facing output.

## Expected-type comparisons

A future expected-type check needs an explicit expectation, not a guess from a
variable's name. `API_KEY` gives little information, and `OPENAI_API_KEY` can be
misnamed. Name-based hints may be advisory but are not proof of a mismatch.

Distinguish three outcomes:

1. Recognized matching format within the supported version.
2. Recognized conflicting format, such as a Stripe publishable-key format when
   a Stripe server-secret format was explicitly expected.
3. Unknown/unrecognized format, including possible new or custom variants.

The third outcome is not "invalid". Do not fail normal inspection, reveal a
value, or propose rotating a working credential solely because a scanner lacks
its format. A strict syntax rejection is justified only for a documented exact
version and an explicitly requested syntax check. It still says nothing about
whether a matching value is accepted by the provider.

## Relationship to redaction

Recognition and disclosure are separate decisions. `rprintenv` hides a value
unless its established explicit or narrow built-in allow rule permits output.
Adding format labels later must not make hiding dependent on a detector match.
Recognizing a publishable key does not silently allow it through.

`rstr` uses format and context to find spans in stdin. A recognized sensitive
field with an unknown or malformed value remains protected. Bad checksum,
length, or alphabet must not turn a sensitive field into ordinary output.
For a bare incomplete prefix without context, document actual detection coverage
and limits; do not claim every malformed credential can be located in prose.

A detector failure is an operational error with no unchecked output. An unknown
format is a normal classification outcome. Keep those cases distinct so agents
can act without raw retries or unnecessary debugging.

## Fingerprints

Keep hashing the exact protected bytes, independently of classification. Changing
an issuer label or upgrading a detector does not change the fingerprint for an
unchanged redaction span. Encoded values and combined spans retain their existing
byte-based fingerprint semantics. Do not decode a JWT or normalize a provider
key to make it fit a classifier before hashing.

## Done

A future classification interface must preserve the redaction contract, represent
unknown/ambiguous outcomes, and pass the [format acceptance suite](acceptance.md).
Until that interface is specified and implemented, this inventory guides detector
coverage and tests without changing v1 output.
