# Secret-format acceptance requirements

Status: detector requirements are exercised by `tests/format_regressions.rs`,
`tests/provider_evolution.rs`, and `tests/structured.rs`. Format classification
annotations remain a future interface decision. Use only synthetic credentials constructed locally for the documented
version. Never copy complete real keys or plausible live-looking examples from
provider documentation into fixtures.

## Per-family coverage ledger

Each inventory row ID must map to a rule/parser and tests, or an explicit
unsupported/deferred/context-only entry. A source URL or regex alone is not
coverage evidence. Record:

- Inventory ID, evidence class, source revision or retrieval date, and versions.
- Captured span boundaries and exact replacement behavior.
- What is classified: credential family, credential container, or public ID.
- Positive, negative, malformed, delimiter, encoding, and legacy fixtures.
- Known false positives/negatives and resource limits.
- Whether default v1 coverage requires the family or it is planned for later.

Use maintained upstream rules only with their provenance/license and a pinned
revision. All family labels come from fixed approved strings, never token data.

## Research-derived regression cases

| Case | Required assertion |
| --- | --- |
| GitHub token generations | Recognize documented classic and current families; variable-length installation tokens include their complete `ghs_` outer token and inner JWT |
| GitLab shared/custom prefix | `glpat-` does not imply personal rather than group/project; custom prefix remains unknown or contextually redacted, never deemed harmless |
| Slack rotating prefix | Redact the complete `xoxe.`-prefixed credential; legacy shorter components do not leak |
| Stripe roles | Distinguish secret, restricted, organization, webhook, and publishable formats; test-mode secrets are protected |
| Cloudflare generations | Current prefixes and contextual legacy values are covered; no invented checksum algorithm or body constraints |
| Supabase generations | Secret/publishable opaque formats differ from legacy JWTs; untrusted JWT roles cannot establish provider or permission |
| Gemini evolving format | Unsupported/new format in `GEMINI_API_KEY` or a supported sensitive field stays hidden; historical prefix mismatch is not invalidity |
| SendGrid length drift | Do not truncate at a historical 69-character boundary or expose a longer suffix |
| Azure DevOps offset ambiguity | No strict marker offset or old/new validity claim without resolving the source ambiguity and version contract |
| Shared or short prefixes | Generic `sk-`, `secret_`, or short example-backed prefixes do not acquire an unjustified provider/subtype |
| Resource IDs | Twilio `AC`/`SK` IDs and Anthropic `apikey_` IDs are not labeled complete secrets; paired secret fields are protected |
| Public key material | Publishable keys, certificates, and public JWKs are distinct from private keys; classification never expands environment allowlisting |
| Bearer grammar | Cover `+`, `/`, `.`, `~`, and padding as permitted, not only Base64url characters |
| JOSE variants | Three- and five-segment structures remain distinct; supported empty segments and non-provider-specific claims do not cause false provider attribution |
| Private containers | Whole private blocks are removed, including encrypted keys; public blocks are not mislabeled private; malformed recognized private constructs fail safely |
| Password verifiers | Recognized bcrypt/PHC values are labeled verifiers rather than raw passwords; hiding includes their salt/hash payload without diagnostic decoding |
| URI dialects | Percent encoding, reserved delimiters, multiple hosts, sensitive query values, and provider path credentials preserve complete secret spans |
| Provider field spelling | `AccountKey`, `SharedAccessSignature`, `privateKeyData`, `_authToken`, and session-token fields cannot be missed by naive suffix-only matching |
| Encoded containers | No claim of recursive coverage without a bounded parser; decoding never emits secret material or error dumps |
| Classifier failure | Unknown format differs from failed detector initialization; both respect disclosure, and operation failure has no unchecked output |
| Conflicting expectation | A future explicit expected-type check can report a recognized mismatch without showing any part of the value |

Add Notion current/legacy prefixes, Linear API/OAuth types, and other developer
service variants from the provider inventory as those rows become supported.

## Property tests and fuzzing

Generate valid synthetic shapes for each supported version, then mutate length,
alphabet, separators, checksums, framing, and surrounding context. A mutation may
change recognition, but must not cause disclosure when the sensitive field or
container is still recognized. Do not define safety as "regex returned a match".

Assert the full output, removed spans, and preserved context. Include adversarial
long near-matches and suffixes that resemble new token formats. Seed existing
detector/text-filter fuzz targets with these cases. Never use a provider API to
confirm a generated token, and never run a verifier borrowed from a scanner.

Classifier labels must not affect fingerprints for unchanged spans. Nested error
formatting, decoded JSON errors, failed checksum checks, and unsupported provider
variants all need synthetic leak assertions.

## Done

Every shipped family has executable evidence and a truthful coverage entry;
format mismatches do not weaken hiding; classification never claims validity;
and tests cover format evolution as well as ordinary positive examples.
