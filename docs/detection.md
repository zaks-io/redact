# rstr secret detection

## Contract

`rstr` runs these detectors over stdin only. It does not load environment values
or `.env` files. Detection is local and requires no provider requests. A
successful run means all configured rules ran; it does not certify that
arbitrary text is free of secrets.

Generic text cannot reveal whether every otherwise ordinary string is a
password. Detection therefore requires recognizable structure or context.
Do not promise perfect coverage, and do not treat absence of matches as evidence
that a value is harmless.

## Format evidence

Use the [researched format inventory](secret-formats/README.md) when selecting
rules and assigning future credential-family labels. It records official
prefixes, legacy variants, contextual secrets, public identifiers, source URLs,
and research gaps. Recognition is local format evidence, never validity proof.

The [format regression requirements](secret-formats/acceptance.md) apply to every
shipped family. Existing v1 categories below retain their scope; additional
catalogue entries are researched coverage candidates until explicitly implemented
and tested. Unknown formats in recognized sensitive fields remain redacted.

## Required v1 categories

| Category | Required behavior |
| --- | --- |
| Provider credentials | Recognize documented token formats for OpenAI, Anthropic, GitHub, GitLab, Slack, Stripe secret/restricted keys, and AWS access key IDs. Apply maintained format rules, not invented length assumptions. |
| Authentication headers | Detect case-insensitive `Authorization` and `Proxy-Authorization` headers with Bearer or Basic credentials. Remove the credential payload, retaining the header name and authentication scheme. |
| Sensitive assignments | Detect values assigned to sensitive names in dotenv-style lines, JSON string fields, and common `name=value` or `name: value` log fields. |
| URL credentials | Detect user information before `@` in a URI authority and sensitive query or fragment parameters, including explicit comma/semicolon fields. Remove the entire user-information span, including username and password when both are present. |
| Private keys | Detect PEM private-key blocks, including RSA, EC, encrypted, and OpenSSH variants. Remove the full block from its BEGIN marker through its END marker. Do not redact public certificates solely because they use PEM framing. |
| JWTs | Detect three-segment compact JWS with a bounded Base64url JSON header containing `alg`, and five-segment JWE with `alg` and `enc`. JWS payloads need not be JSON. Protect full candidates including unknown extension segments, without validating signatures, claims, or expiry. |

An AWS secret access key alone has no unique recognizable format. Contextual
assignment rules may detect it; the AWS access key ID rule must not claim to
cover every standalone AWS secret. Likewise, provider prefixes and formats can
change. The bundled rules have finite, versioned coverage.

## Sensitive names and contexts

For contextual detection only, match names case-insensitively, normalize dots,
hyphens, spaces, and tabs to underscores, and split CamelCase word boundaries.
Start with these complete names and underscore-delimited
suffixes: `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `apikey`,
`access_key`, `secret_key`, `private_key`, `client_secret`, `credential`,
`credentials`, and `authorization`.

Thus `DATABASE_PASSWORD` is sensitive while `tokenizer` is not. Contextual name
normalization belongs to `rstr` detection. `rprintenv` independently uses its
exact-name allowlist and does not run these detectors.

Quoted log messages and JSON strings are also checked for embedded recognizable
credentials and assignments. Decoded detections map back to their exact original
escape bytes for hashing. Nested quoting is bounded to 32 levels; nested sensitive
object/array values are bounded to 1 MiB and 64 levels. Proven indented sensitive
YAML blocks, sequence values, and plain-scalar continuations are removed as
complete spans; this is not a general YAML validator. Unquoted assignment values
that begin with brackets retain their full opaque value, including any suffix.

For JSON string fields, understand string escapes so an escaped quote cannot
terminate the match early. Redact the entire string contents while preserving
its framing quotes. For quoted assignments, handle the supported quoting rules.
For an unquoted dotenv assignment, redact its full value span. For generic log
fields, conservatively include ambiguous trailing text through the physical
line ending rather than guess a narrow boundary and expose a secret suffix.

Specific structured contexts define their own credential boundaries. Generic
sensitive-assignment fallbacks apply only when no supported structured context
establishes the boundary. In particular, they must not swallow neighboring JSON
fields, fields after a closed quoted log value, or an authentication scheme that
the header detector preserves. Apply overlap merging to the valid resulting
spans; do not manufacture a wider fallback match for an already parsed context.

For URI query parameters, use the same sensitive-name rules. Redact the complete
raw parameter value, including percent-encoded text, up to the query delimiter.
Encoded names must be recognized by one percent-decoding pass before comparison.
Do not recursively decode arbitrary input or execute interpolation.

A sensitive assignment with an opening quote but no provable closing boundary,
or a recognized PEM private-key BEGIN without its END, fails with a sanitized
error and no stdout. Detection must never silently abandon an already recognized
sensitive construct and pass its contents through.

## Rule sourcing and review

Prefer a pinned, license-compatible snapshot of maintained detection rules,
such as the [Gitleaks rule set](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml),
for provider signatures. This is a candidate upstream reference, not a claim
that its current contents have been inspected or selected. Verify compatibility
and licensing during implementation; record the immutable source revision and
licenses for any adopted rules. Do not execute an external scanner at runtime.

Keep the rule inventory in the repository and version it with the executable.
Each shipped rule requires:

- A stable internal identifier and a human-readable coverage description.
- Its precise pattern or structured parser and captured redaction span.
- Upstream revision/provenance, where applicable.
- Inventory evidence class, supported versions, and any unresolved grammar.
- Exact purpose of a future label: credential family, container, or public ID;
  never issuance, activity, account ownership, or authorization.
- Positive, negative, boundary, malformed, and near-match fixtures.
- A documented false-positive or false-negative limitation when known.

Do not silently skip unsupported expressions when adapting upstream rules.
If regexes are used, prefer the Rust [regex crate](https://docs.rs/regex/latest/regex/)
and its documented resource controls. A matcher must enumerate overlapping
candidate spans as required by the companion contract, not silently use a
non-overlapping iterator that leaves the tail of another match exposed.

Exact provider patterns and the complete machine-readable inventory are an
implementation deliverable. Categories alone do not constitute tested coverage.
Broad entropy-only detection is out of scope for v1: random-looking identifiers
are not sufficient evidence and ordinary passwords can have low entropy.

## Matching and fingerprint behavior

Run every detector over the original input. Merge overlapping detector spans
before replacing text. `rstr` has no environment lookup, known-value matcher,
allowlist, or detector bypass flags.

Hash the exact original bytes removed. Do not hash a decoded or normalized
replacement for those bytes. An encoded or escaped credential therefore may
have a different fingerprint from its decoded environment value. A compound
span, such as URL user information or an overlapping union, also has its own
fingerprint. Help must explain these exceptions to cross-source comparison.

Empty spans produce no replacement. If detector initialization or execution
fails, return `2` with no stdout; never downgrade to a subset of the promised
rules and claim successful filtering.

## Acceptance and fuzzing

- Required categories have real rule implementations and synthetic fixtures.
- False-positive fixtures include public keys/certificates, ordinary identifiers,
  innocent JSON fields, URLs without credentials, and near-matching prefixes.
- Test detection with a cleared environment and no files available.
- Verify changing environment values or nearby files cannot change the result.
- Test the same secret caught by several detector rules.
- Verify complete spans for quotes, escapes, query delimiters, multiline private
  keys, prefixes, adjacent matches, and partial overlaps.
- Test the documented encoded-value fingerprint differences explicitly.
- Fuzz detectors with arbitrary valid UTF-8, malformed structured fragments,
  long near-matches, and generated synthetic credentials in random surrounding
  text. Detection and span-merging assertions matter as much as crash detection.
- Require every span to be in bounds and on UTF-8 boundaries before rendering.
- Replay every confirmed detector finding as a deterministic regression test.
- Include researched legacy/current variants and format-mismatch regressions
  from the [inventory acceptance contract](secret-formats/acceptance.md).
- Enforce the exact context-preservation fixtures in
  [agent usability acceptance](agent-usability.md#preserve-useful-surrounding-text).

## Done

All required categories pass their fixtures, detector matching passes leak and
overlap tests, provenance is recorded, and help accurately states the limits of
detection. No unresolved reproducible disclosure bug in a supported format may
be dismissed as a generic limitation of heuristic detection.
