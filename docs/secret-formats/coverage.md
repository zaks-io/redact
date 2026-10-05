# Implemented secret-format coverage

The complete executable ledger is [secret-formats.json](../../tests/fixtures/secret-formats.json). It covers every stable row in the provider, cloud, and structure inventories with literal original-byte spans and fingerprints. [format_regressions.rs](../../tests/format_regressions.rs) requires inventory parity and positive, negative, malformed, delimiter, and encoding cases for each row; legacy variants and public forms add specific cases.

Research retrieval date is 2026-10-04. Rules were written from the cited primary evidence, not copied from an upstream scanner; no scanner code or unverifiable issuer validation is bundled. Current CLI markers and JSON schema remain unchanged. Detection yields internal span evidence, never issuer validity, ownership, permission, or a provider label in output.

`rprintenv` hides unknown values regardless of family. Real subprocess regressions replay every distinct removed fixture value through its default policy, including contexts whose provider grammar is unknown. Property tests mutate all inventory fixture values under sensitive context so format drift cannot release a value.

| Inventory ID | Implemented recognition and removed span | Limits |
| --- | --- | --- |
| `github-access` | src/providers.rs::detect: ghp_, github_pat_, gho_, ghu_, ghs_, ghr_ | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `github-installation` | src/providers.rs::detect: ghs_ including variable-length APPID_JWT outer tokens | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `github-checksummed-legacy` | src/providers.rs::detect: ghp_/gho_/ghu_/ghs_/ghr_ without checksum validity gating | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `gitlab-access` | src/providers.rs::detect: glpat-; custom prefixes require sensitive context | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `gitlab-other` | src/providers.rs::detect: gloas-, gldt-, glrt-, glrtr-, glcbt-, glptt-, glft-, glimt-, glagent-, glwt-, glsoat-, glffct- | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `azure-devops-pat` | src/context/names.rs + src/context.rs: PAT / *_PAT fields; no standalone AZDO offset rule | Sensitive PAT context supported; AZDO placement ambiguity remains unresolved, so no standalone length or offset rule. |
| `npm-token` | src/providers.rs::detect: npm_; legacy UUIDs require registry auth context | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `pypi-token` | src/providers.rs::detect: pypi- | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `huggingface-token` | src/providers.rs::detect: hf_ | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `docker-token` | src/context/names.rs + src/context.rs: Docker credential fields, authentication headers, or auths containers | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `openai-key` | src/providers.rs::detect: sk-proj-, sk-admin-; shared sk- is generic | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `anthropic-key` | src/providers.rs::detect: sk-ant-admin, sk-ant-api03- | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `gemini-key` | src/context/names.rs + src/context.rs: GEMINI_API_KEY and auth headers; no unverified AQ./AIza exhaustiveness | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `stripe-key` | src/providers.rs::detect: sk_test_, sk_live_, sk_org_, rk_test_, rk_live_; pk_test_/pk_live_ stay public | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `stripe-webhook` | src/providers.rs::detect: whsec_ | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `slack-token` | src/providers.rs::detect: xoxb-, xoxp-, xwfp-, xapp-, xoxe.xapp- | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `slack-rotation` | src/providers.rs::detect: xoxe.xoxb-, xoxe.xoxp-, xoxe.xapp-, xoxe- | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `slack-webhook` | src/structured/urls.rs::urls: hooks.slack.com or hooks.slack-gov.com /services/ capability with three components | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `resend-key` | src/context/names.rs + src/context.rs: RESEND_API_KEY/auth headers; no standalone short re_ rule | Short re_ prefix alone is ambiguous; supported sensitive assignment context required. |
| `sendgrid-key` | src/providers.rs::detect: SG.<component>.<component>, without historical length truncation | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `twilio-credentials` | src/context/names.rs + src/context.rs: TWILIO_AUTH_TOKEN, API secret fields; AC/SK IDs stay public | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `discord-token` | src/context/names.rs + src/context.rs: Authorization: Bot/Bearer/Basic and sensitive token fields | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `telegram-token` | src/structured/urls.rs::urls: api.telegram.org /bot<id>:<token> or /file/bot<id>:<token> | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `vault-token` | src/providers.rs::detect: hvs., hvb., hvr.; s./b./r. require sensitive context | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `onepassword-service` | src/providers.rs::detect: ops_ | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `vercel-token` | src/providers.rs::detect: vcp_; legacy opaque values require context | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `linear-token` | src/providers.rs::detect: lin_api_, lin_oauth_ | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `notion-token` | src/providers.rs::detect: ntn_; shared secret_ stays generic | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `digitalocean-token` | src/providers.rs::detect: dop_v1_, doo_v1_, dor_v1_ | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `pulumi-token` | src/providers.rs::detect: pul- | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `grafana-token` | src/providers.rs::detect: glc_; glsa/legacy encoded values require sensitive context | glc_ supported lexically; glsa and legacy Base64 require credential context; no invented glsa_ grammar. |
| `newrelic-key` | src/providers.rs::detect: NRAK; 40-hex license keys require LICENSE_KEY context | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `datadog-key` | src/context/names.rs + src/context.rs: DD-API-KEY and DD-APPLICATION-KEY headers/fields | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `sentry-credentials` | src/context/names.rs + src/context.rs: SENTRY_AUTH_TOKEN; URI userinfo conservatively includes public DSNs | Auth tokens supported contextually; generic URI redaction conservatively hides public DSN userinfo without labeling it an auth token. |
| `shopify-token` | src/context/names.rs + src/context.rs: X-Shopify-Access-Token and sensitive fields; no unverified shpat_ grammar | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `aws-access-id` | src/providers.rs::detect: AKIA/ASIA plus at least 16 alphanumeric tail bytes; complete extended candidate | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `aws-secret-key` | src/context/names.rs + src/context.rs: AWS_SECRET_ACCESS_KEY / SecretAccessKey fields | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `aws-session-token` | src/context/names.rs + src/context.rs: AWS_SESSION_TOKEN / sessionToken fields | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `aws-signed-url` | src/structured/urls.rs::urls: X-Amz-Credential, X-Amz-Signature, X-Amz-Security-Token query fields | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `google-service-account` | src/context/names.rs + src/context.rs: private_key / privateKeyData fields; metadata is preserved | Private JWK whole JSON object and service-account private fields supported; structural JSON scanning bounded to 1 MiB; no decoded material emitted. |
| `azure-storage-key` | src/structured/urls.rs::connections + context: AccountKey / SharedAccessSignature semicolon connection fields | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `azure-sas` | src/structured/urls.rs::urls: sv plus authorization/expiry/resource fields and sig | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `cloudflare-current` | src/providers.rs::detect: cfk_, cfut_, cfat_; no invented checksum validation | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `cloudflare-legacy` | src/context/names.rs + src/context.rs: CLOUDFLARE_API_KEY / token fields; no bare 40-hex rule | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `supabase-current` | src/providers.rs::detect: sb_secret_; sb_publishable_ stays public | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `supabase-legacy` | src/structured/jose.rs::detect + context: JOSE syntax and *_SERVICE_ROLE_KEY fields; never trust decoded role | JWT container syntax is recognized without trusting roles; anon JWT may conservatively redact; opaque service-role context supported. |
| `http-bearer` | src/structured.rs::authentication: Case-insensitive Authorization/Proxy-Authorization Bearer | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `http-basic` | src/structured.rs::authentication: Case-insensitive Authorization/Proxy-Authorization Basic | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `jws-jwt` | src/structured/jose.rs::detect: Compact JWS with Base64url JSON alg header; includes empty signature | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `jwe` | src/structured/jose.rs::detect: Compact JWE with alg/enc header and five segments; empty encrypted-key allowed | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `pem-private` | src/structured.rs::private_blocks: BEGIN/END label ending PRIVATE KEY or PRIVATE KEY BLOCK | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `pem-traditional` | src/structured.rs::private_blocks: BEGIN/END label ending PRIVATE KEY or PRIVATE KEY BLOCK | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `openssh-private` | src/structured.rs::private_blocks: BEGIN/END label ending PRIVATE KEY or PRIVATE KEY BLOCK | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `openpgp-private` | src/structured.rs::private_blocks: BEGIN/END label ending PRIVATE KEY or PRIVATE KEY BLOCK | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `jwk-private` | src/structured/containers.rs::json_containers: kty with RSA/EC/OKP private members or oct k; malformed discriminator remains protected | Private JWK whole JSON object and service-account private fields supported; structural JSON scanning bounded to 1 MiB; no decoded material emitted. |
| `postgres-connection` | src/structured/urls.rs: postgres/postgresql URI authority, query, and libpq keyword dialect | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `mongodb-connection` | src/structured/urls.rs::urls: mongodb/mongodb+srv URI authority and sensitive query fields | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `redis-connection` | src/structured/urls.rs::urls: redis/rediss URI authority and sensitive query fields | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `encoded-config` | src/structured/containers.rs: Docker auths and Kubernetes Secret JSON/YAML containers | Whole recognized Docker auths or Kubernetes Secret JSON object hidden, bounded to 1 MiB; Kubernetes YAML Secret document hidden; arbitrary recursive Base64/binary containers unsupported. |
| `bcrypt-verifier` | src/providers.rs::detect + context: $2b$ verifier marker or password-hash field | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |
| `phc-verifier` | src/providers.rs::detect + context: $argon2id$ / $argon2i$ / $argon2d$ or password-hash field | Recognition is local evidence only; arbitrary standalone unknown passwords remain undetectable. |

Public publishable keys, certificates, public JWKs, SSH public keys, ordinary identifiers, resource IDs, and bare hosts have explicit passthrough cases. Generic URL userinfo and valid JWT syntax are conservatively redacted even when a Sentry DSN user or a Supabase anon token is intended public; this does not classify them as privileged secrets.

Private constructs with missing framing, invalid recognized credential JSON, or duplicate discriminator members fail with safe diagnostics and no stdout. Provider checksums and uncertain Azure DevOps marker offsets are not invented. Old/custom opaque credentials require sensitive context. A password outside recognizable structure remains outside detection coverage.

Kubernetes/Docker support protects recognized containers without recursively decoding arbitrary input. Structural credential-object scanning has a 1 MiB resource bound and fails safely beyond it. The text filter accepts at most 16 MiB of UTF-8 without NUL. Binary OpenPGP, arbitrary nested encodings, and unrecognized provider generations remain unsupported outside sensitive contexts.

All six [fuzz harnesses](../../fuzz/README.md) call production logic. Seeds include the full synthetic format corpus and agent workflows. Independent policy, original-byte fingerprint, span-union, and canary oracles supplement arbitrary-byte mutation. The normal suite tests that the canary oracle catches deliberately defective raw, escaped, and partial outputs. Campaign results belong in the fuzz run record; bounded clean campaigns are not proof of exhaustive detection.
