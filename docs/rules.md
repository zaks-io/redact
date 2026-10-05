# Bundled rstr rules

Version 1 ships the machine-readable [provider inventory](../rules/providers.json)
and [catalogue coverage ledger](../rules/coverage.json).
Patterns are original conservative adaptations of the primary sources listed
there and the format research dated 2026-10-04. No Gitleaks or TruffleHog code
or patterns were copied. The rules use the project's MIT license. Provider
sources describe recognition evidence, not credential validation.

Provider candidates consume the complete supported lexical body, including
new longer GitHub installation tokens and Slack rotation prefixes. No historical
fixed token length or checksum gates disclosure. The generic `sk-` candidate
is deliberately ambiguous. Bodies use the precise pattern in the inventory;
punctuation in that alphabet can cause conservative false positives. A prefix
alone does not match. Every prefix occurrence at a token boundary is a candidate,
so a rejected occurrence inside another word cannot hide a later credential.
Tokens directly after `.`, `_`, or `-` remain outside the boundary rule. Unknown alphabets and customized GitLab prefixes need
sensitive context. The AWS rule covers alphanumeric access-ID candidates with at
least 16 characters overall. It does not identify standalone secret-access keys.
Public Stripe publishable prefixes do not match.

Structured rules run on the original input:

| Internal identifier | Parser and removed span | Evidence and limitation |
| --- | --- | --- |
| sensitive-assignment | Case-insensitive complete names and underscore suffixes from detection.md; hyphens and camelCase boundaries normalize to underscores. Names may follow labels, separators, or command-line dashes. Quoted contents exclude framing quotes. Unquoted values continue to the physical line ending. | Context-only. Single quotes are literal; double quotes validate the documented backslash, quote, n, r, and t escapes. Ambiguous unquoted log fields may hide following diagnostic fields. |
| json-string-field | Lexical JSON string boundaries plus serde_json string escape validation; remove sensitive field string contents. | Context-only. Preserves neighboring fields. Sensitive assignments within ordinary JSON diagnostic strings use the enclosing string boundary. Escaped contents are inspected as raw bytes rather than recursively decoded; non-string JSON values have no contextual rule in v1. |
| http-auth | Case-insensitive Authorization and Proxy-Authorization with Basic/Bearer; remove line payload excluding trailing framing spaces/tabs. | RFC 7617/6750. Preserves scheme. Opaque malformed payloads are still hidden. Other schemes need sensitive-assignment context. |
| uri-credentials | Scheme/authority parser removes all user information before the last authority @; when `user:` precedes an unencoded `/`, `?`, or `#` that is not a numeric port or bracketed IPv6 host, user information runs to the next @. Query parser removes complete raw sensitive parameter values. | URI container evidence. A digits-only password before a delimiter reads as a port, and a later @ inside such a password ends the span early. Parameter names undergo one percent-decoding pass. Invalid encodings and provider-specific parameter names outside the sensitive-name contract are deferred. |
| pem-private | Matching BEGIN/END label for PRIVATE KEY, ENCRYPTED PRIVATE KEY, RSA/DSA/EC/OPENSSH PRIVATE KEY, PGP PRIVATE KEY BLOCK; remove full armor. | RFC 7468, OpenSSL/OpenSSH/OpenPGP inventory references. Unclosed recognized armor fails safely; public containers remain unchanged. |
| jws-jwt | Any three consecutive segments of a dotted Base64url run; decoded header/payload must be JSON objects, with string alg in header. Remove that compact token and keep dotted labels or trailing segments around it. Empty signature supported. | RFC 7515/7519. No signature decoding, validation, or expiry check. Decoded header/payload JSON nesting above 64 fails with a fixed detector error and no output. JSON numeric magnitudes do not gate recognition. Arbitrary JWS payloads and five-segment JWE are deferred. |

A recognized sensitive opening quote without a close fails with no output.
Malformed JSON escapes in recognized sensitive string fields also fail safely.
All errors use fixed categories and line numbers without parser diagnostics.
Spans are checked for bounds and Unicode boundaries, and overlapping spans are
merged before hashing their full union. Adjacent spans remain separate.

Every additional catalogue entry is deferred as a standalone lexical rule:
Azure DevOps, npm, PyPI, Hugging Face, Docker, Gemini, Slack webhook URLs,
Resend, SendGrid, Twilio, Discord-specific Bot headers, Telegram URLs, Vault,
1Password, Vercel, Linear, Notion, DigitalOcean, Pulumi, Grafana, New Relic,
Datadog-specific headers, Sentry-specific formats, Shopify-specific headers,
Google service-account encoded containers, Azure connection strings and SAS,
AWS signed URLs with provider-specific names, Cloudflare, Supabase opaque keys,
JWE, JWK, encoded configuration, and password verifiers. Ordinary recognized
sensitive fields, Basic/Bearer headers, URI credentials, private armor, and JWTs
still protect those families where their required context is present. Supabase
legacy JWTs use generic JWT coverage without provider or privilege inference.
Standalone ordinary passwords and recursively encoded secrets remain outside
recognizable coverage. A zero-match result does not prove safety.
