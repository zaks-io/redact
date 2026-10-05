# Secret format inventory

Research checked against online sources on 2026-10-04. This is a documented
coverage inventory for future implementation, not a claim that detectors exist
or that every possible secret format is known. Sources can change; preserve
version-specific evidence when turning an entry into a rule.

## Purpose

Use documented structure to redact recognizable credentials and, where supported,
identify a credential family without revealing its contents. A family match can
help distinguish a Stripe publishable key from a server secret or an AWS key ID
from its paired secret. It cannot establish validity, ownership, authorization,
expiry, or whether a credential is the right one for an account.

## Catalogue

- [Provider tokens](providers.md): source control, AI, payments, messaging,
  packages, and developer services.
- [Cloud credentials](cloud.md): AWS, Google, Azure, Cloudflare, and Supabase.
- [Structured credentials](structures.md): HTTP auth, signed tokens, private
  keys, connection strings, signed URLs, and encoded containers.
- [Classification contract](classification.md): evidence, confidence, and safe
  mismatch reporting.
- [Acceptance requirements](acceptance.md): regression cases derived from this
  research and coverage bookkeeping.

Each table entry has a stable test-facing ID. IDs are implementation metadata,
not labels to expose to CLI users. References cite primary documentation unless
explicitly identified as a research gap or an upstream scanner source.

## Evidence vocabulary

| Evidence | Meaning | Permitted inference |
| --- | --- | --- |
| Documented | Official prose, protocol grammar, or schema explicitly states the format feature | Recognized documented family/structure, within the stated version |
| Example-backed | Official examples show a prefix or shape without promising complete syntax | Candidate family; do not infer exact lengths, alphabet, checksum, or exhaustiveness |
| Context-only | Credential role is documented, but its value lacks a verified distinctive grammar | Sensitive because of its field, header, URL, or container; provider can remain unknown |

One entry can have different evidence levels for its prefix and its full body.
An official example is not a complete validator. Matching a distinctive prefix
is still not proof that the issuer generated the string. Checksums detect format
errors; they do not authenticate a token or prove it is active.

## How this changes the existing specs

The existing v1 categories remain the initial delivery requirement. This inventory
records additional families and variants that must be considered when implementing
or extending those categories. A researched row does not silently become a claim
of shipped support. Every row must eventually have a tested rule, a tested
contextual path, or an explicit deferred/unsupported status with its limitation.

Current CLI markers, JSON version, and exit statuses remain as specified. Type
annotations and expected-type checks are a future interface decision governed
by [classification](classification.md), not an undocumented extra field in v1.
`rprintenv` keeps hiding unknown values regardless of format. `rstr` continues
to inspect stdin only; this research adds no cross-tool source lookup.

## Non-negotiable detection rules

- Failure to recognize a format is never evidence that a value is safe to reveal.
- A malformed candidate under a sensitive field stays redacted. Format checks
  must never become a prerequisite for protecting a recognized sensitive field.
- Preserve legacy variants. Prefix, length, and token lifecycle changes can
  coexist with credentials that continue to work.
- Use token boundaries and whole-credential spans. Do not redact only the portion
  matching an outdated shorter regex, leaving a new suffix visible.
- Prefer documented specific prefixes over shared fragments such as `sk-`.
  Ambiguous matches stay generic rather than acquiring a guessed provider.
- Keep intentionally public keys and resource IDs distinct from authentication
  secrets. Recognizing them does not modify `rprintenv`'s disclosure allowlist.
- Never display decoded claims, key material, account IDs, or token fragments as
  an explanation of classification. Use a fixed approved family label.
- Never contact an issuer to validate credentials. Both tools remain local.

## Upstream scanner references

[GitHub's supported-pattern inventory](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)
is a useful breadth checklist, not a public specification of every regex.
Its [validity-check documentation](https://docs.github.com/en/code-security/concepts/secret-security/validity-checks)
explicitly distinguishes detecting a pattern from contacting its issuer to test
whether it is active. These tools perform only local recognition.

[Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
and [TruffleHog](https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors)
are potential secondary implementation references. Their rule implementations
and licenses were not comprehensively audited in this research. Before adopting
code or patterns, pin a revision, verify its license, distinguish verification
network calls from detection logic, and test it against the primary-source
contract. Do not treat a scanner's heuristic as an issuer guarantee.

## Done

The inventory is sourced, evidence levels are explicit, and format-derived
acceptance requirements are linked to implementation. Shipping a family requires
its own pinned rule or contextual parser and executable tests. Future changes
must update coverage status and regression fixtures together.
