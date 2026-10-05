# Bundled rstr rules

The [provider inventory](../rules/providers.json), [coverage ledger](../rules/coverage.json),
and [synthetic span fixtures](../tests/fixtures/secret-formats.json) describe all
61 researched entries. The ledger names each implementation path, evidence
class, source retrieval date, supported scope, exact fixture IDs, and limits.
[Detailed coverage](secret-formats/coverage.md) records contextual and public forms.
These records describe built-in rules, not runtime configuration.

The rules are original implementations of the inventory's primary sources,
retrieved 2026-10-04, and use the project MIT license. No Gitleaks or TruffleHog
code or rule data was copied. Recognition is local format evidence, never
validity, ownership, authorization, or a reason to reveal unknown data.
Current CLI output remains the specified fingerprint marker and JSON schema.

`src/providers.rs` compiles documented or example-backed prefixes for source
control, registries, AI, payments, messaging, secret managers, developer services,
and current cloud keys. The provider inventory gives every supported prefix and
complete pattern. Bodies have no inferred historical length or checksum gate.
The Unicode-aware preceding boundary rejects letters, numbers, underscore, dot,
plus, and hyphen before an ordinary prefix. URL path separators can establish a
boundary, and an invalid outer hint cannot conceal a later credential. Dollar
markers establish verifier boundaries independently, including immediately
adjacent provider credentials. Prefix and boundary checks precede open-ended
body scans, so large invalid near matches make bounded progress.

AWS recognition requires the common access-ID prefix and 16 following
alphanumeric characters, then conservatively protects the complete supported
suffix. It does not identify a standalone secret access key or authenticate a
key. SendGrid covers both components without the obsolete 69-character limit.
Generic `sk-` and `secret_` matches stay ambiguous. Short Resend `re_`, legacy
Vault markers, uncertain Grafana `glsa` grammar, custom instance prefixes, opaque
credentials, and uncertain Azure DevOps marker offsets need sensitive context.
No checksum algorithm or undocumented body grammar is invented.

Structured detectors operate on original input:

| Structure | Removed span and preserved context | Limits |
| --- | --- | --- |
| Sensitive fields | Supported assignments, JSON strings/objects/arrays, Python quoted names, dotted/CamelCase names, and YAML blocks remove complete raw value spans. JSON framing and provable neighboring diagnostic fields remain. | Unknown provider values remain hidden under recognized context. Unsupported ambiguous unquoted forms may conservatively hide the physical line. Recognized incomplete constructs fail safely. |
| Authentication | Basic, Bearer, and Bot credential payloads under case-insensitive Authorization/Proxy-Authorization retain scheme/header framing. Provider-specific credential headers have explicit mappings. | Scheme recognition does not identify or validate an issuer. Malformed sensitive header values stay protected. |
| URLs | Userinfo, sensitive query/fragment values, AWS signature/credential/session-token fields, contextual Azure SAS signatures, Telegram bot paths, and Slack capability URLs use structural raw-byte boundaries. | Parameter names decode once. Nested schemes scan original text. Unencoded `/`, `?`, and `#` password recovery preserves numeric-port/IPv6 safeguards. No recursive decoding or issuer requests. Generic userinfo handling conservatively hides public Sentry DSN userinfo. |
| Connection dialects | PostgreSQL, MongoDB, and Redis URI credentials retain host/status context; libpq password quoting and Azure semicolon fields have dialect-specific boundaries. | Bare hosts, public identifiers, and unrelated query fields remain visible. |
| JOSE | Valid compact JWS/JWT and JWE shapes remove complete credentials without signature verification. Empty standards-permitted segments and evolving outer suffixes are covered. | Untrusted claims do not establish provider or privilege. Supabase anon JWTs may conservatively redact. Decoded header/payload nesting above 64 fails safely; large JSON numbers do not gate recognition. |
| Private armor | Matching private PEM, traditional RSA/DSA/EC, OpenSSH, and OpenPGP blocks remove complete BEGIN/END framing. | Public keys and certificates remain distinct. Recognized missing END or mismatched framing fails with no unchecked output. |
| Private JSON and encoded configuration | Private RSA/EC/OKP/symmetric JWK objects, Docker auths objects, and Kubernetes Secret containers are hidden as whole recognized objects/documents. | Bounded structural parsing, no arbitrary recursive Base64 decoding. Duplicate discriminator fields and recognized malformed credential objects fail safely. |
| Password verifiers | Supported bcrypt `$2b$` and Argon2 PHC shapes remove salt/hash payload together. | Verifier evidence identifies a stored verifier, not plaintext or a provider. Unverified historical markers need context. |

Spans must be in bounds and on UTF-8 boundaries. Overlapping matches merge into
their full union; adjacent non-overlapping spans stay separate. Fingerprints
hash exact original removed bytes, including encoding and merged structures.
Render once from validated spans and never rescan generated markers.

`rprintenv` independently hides unknown values regardless of these patterns.
Public publishable keys and resource IDs do not expand its allowlist. Arbitrary
standalone passwords, unrecognized provider generations, binary containers, and
unsupported encodings remain outside `rstr` recognition unless sensitive context
establishes their role. A zero-match result does not prove that text is safe.
