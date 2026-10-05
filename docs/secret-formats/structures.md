# Structured and contextual credential formats

Checked 2026-10-04. These structures often support confident identification of a
credential container without identifying a provider. Public structural markers
are listed here; no complete real credential is needed for a test fixture.

| ID | Structure and evidence | Redaction/classification requirements | Primary sources |
| --- | --- | --- | --- |
| http-bearer | RFC 6750 `Bearer` plus a nonempty token; grammar permits letters, digits, `- . _ ~ + /` and trailing `=` | Recognize a bearer credential, not necessarily a JWT or a particular issuer. Preserve scheme/header framing, redact complete payload. Do not assume Base64url-only characters. | [RFC 6750 section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1) |
| http-basic | RFC 7617 encodes `user-id:password` using Base64; first colon separates the two | Redact the entire encoded credential, not decoded fields. Base64 is reversible, not redaction. Scheme parsing is case-insensitive; provider remains unknown. | [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html) |
| jws-jwt | Compact JWS uses three Base64url segments separated by two dots. A JWT imposes claims structure beyond arbitrary JWS payload | Recognize signed-token structure locally without signature verification. Do not require the whole token to begin `eyJ`, fixed lengths, a known issuer, or nonempty signature in every standards-permitted case. JWT header/claims can reveal sensitive data; never print decoded content. | [RFC 7515 section 3.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-3.1), [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html) |
| jwe | Compact JWE has five segments separated by four dots | Recognize encrypted-token structure, not a provider. Some algorithm modes permit an empty encrypted-key segment. Do not apply a three-segment JWT-only detector as complete JOSE coverage. | [RFC 7516 section 3.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-3.1) |
| pem-private | RFC textual boundaries `-----BEGIN <LABEL>-----` / matching END; `PRIVATE KEY` and `ENCRYPTED PRIVATE KEY` identify private containers | Redact the complete block including boundaries. Encryption does not make private-key material safe to expose. `CERTIFICATE` and `PUBLIC KEY` are distinct public containers, not secrets solely by PEM framing. | [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html) |
| pem-traditional | OpenSSL defines traditional `RSA PRIVATE KEY`, `DSA PRIVATE KEY`, and `EC PRIVATE KEY` labels | Treat all as private containers; do not restrict detection to generic PKCS#8 `PRIVATE KEY`. Match complete BEGIN/END blocks and keep public variants distinct. | [OpenSSL PEM labels](https://github.com/openssl/openssl/blob/master/include/openssl/pem.h) |
| openssh-private | `OPENSSH PRIVATE KEY` armor; the decoded container has `openssh-key-v1` magic, public fields, and encrypted or unencrypted private payload | Classify a private-key container without extracting keys/comments. Public `ssh-ed25519` or `ssh-rsa` key lines must not be mistaken for private keys by shared algorithm names. OpenSSH framing is separate from PKCS#8. | [OpenSSH format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key), [armor constants](https://github.com/openssh/openssh-portable/blob/master/sshkey.c) |
| openpgp-private | OpenPGP distinguishes secret-key packets from public-key packets; ASCII-armored private exports are a separate private container | Redact private blocks regardless of passphrase protection. Public-key blocks and signatures alone are not private material. Binary OpenPGP is outside the UTF-8 text filter's input scope. | [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html) |
| jwk-private | JSON Web Keys use `kty` and algorithm-specific members. RSA private members include `d`, `p`, `q`, `dp`, `dq`, `qi`; EC private includes `d`; symmetric key uses `k` | Context determines secrecy: do not classify every JSON `k` or `d` field as a key. Remove private members or the full private object according to a specified parser contract; never emit decoded values. Public JWK `n`/`e` or `x`/`y` alone is different. | [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7518 section 6](https://www.rfc-editor.org/rfc/rfc7518.html#section-6) |
| postgres-connection | `postgresql://` or `postgres://` with optional `user[:password]@`; keyword/value form supports quoted values and backslash escaping | Parse credential spans and percent encoding. A database URI without credentials is not a secret merely because it names a database. Preserve host/status context where boundaries are known. | [libpq connections](https://www.postgresql.org/docs/current/libpq-connect.html) |
| mongodb-connection | `mongodb://` or `mongodb+srv://`, optional `username:password@`, host list and options | Redact user-information credentials and sensitive query parameters. No credentials should be invented from the scheme alone. Quoting/encoding must not expose a password suffix. | [Connection formats](https://www.mongodb.com/docs/manual/reference/connection-string-formats/) |
| redis-connection | `redis://` and TLS `rediss://`, optional username/password, host/port/database | Treat URI password/user-information as contextual credentials. Bare Redis hosts are not secrets. | [Redis CLI URI documentation](https://redis.io/docs/latest/develop/tools/cli/) |
| encoded-config | Kubernetes Secret `data` values and Docker-registry credential configuration use encoded containers; plaintext may also appear in `stringData` | Base64 does not grant safety or identify a provider. A future container parser needs bounded decoding and a whole-container protection rule. Do not claim the current text matcher recursively covers all encodings. | [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/), [registry credentials](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) |

## Password verifiers

| ID | Structure and evidence | Redaction/classification requirements | Primary sources |
| --- | --- | --- | --- |
| bcrypt-verifier | OpenBSD documents the `$2b$` bcrypt format marker; modular crypt strings encode cost/salt/hash components | This is a stored password verifier, not the plaintext password or an API token. It can support offline guessing and should be treated as sensitive in password-hash context. Other legacy markers need their own versioned evidence. | [OpenBSD crypt](https://man.openbsd.org/crypt) |
| phc-verifier | PHC strings have `$`-delimited algorithm/version/parameter/salt/hash fields. RustCrypto documents Argon2id v19 output beginning `$argon2id$v=19$` | Classify a verifier/algorithm, not a provider credential. Do not expose the salt/hash components in diagnostics. No arbitrary long Base64 string is automatically an Argon2 verifier. | [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md), [RustCrypto Argon2](https://docs.rs/argon2/latest/argon2/) |

## Contextual credentials with no universal lexical grammar

Passwords, OAuth client secrets, opaque access/refresh tokens, session cookies,
webhook shared secrets, database passwords, and private registry credentials can
all be ordinary strings. Identify their role from a trusted parser context,
field name, authentication scheme, or credential-bearing URL. That identifies
sensitivity, not provider validity. A long random string or UUID alone is not a
reliable provider classifier; a short weak password is still a secret.

Explicit contextual families need their own tested key-name mappings. Examples
include `client_secret`, `refresh_token`, `access_token`, `AWS_SESSION_TOKEN`,
`AccountKey`, `SharedAccessSignature`, `privateKeyData`, and registry `_authToken`.
CamelCase and provider-specific names must not be accidentally missed by an
underscore-suffix-only matcher. Do not blanket-redact every `key`, `id`, or
`signature` property without a credential context.

Provider webhook and bot URL paths can carry secrets without URI user information
or a sensitive query parameter. Slack and Telegram have separate entries in
[provider formats](providers.md#payments-messaging-and-email). A generic URI
password detector alone does not cover these capability URLs.
