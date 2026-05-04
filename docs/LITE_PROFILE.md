# Custodia Lite profile

Custodia Lite is a single-node deployment profile for the same Custodia source tree. It is not a fork, not a reduced security model, and not a second configuration vocabulary.

Lite is intended for a local machine, VM, or single container where the operator wants minimal external dependencies while preserving Custodia's core boundaries:

- API access to `/v1/*` remains mTLS-only.
- Secret plaintext, DEKs, private keys, ciphertext formats, and recipient envelopes remain client-side concerns.
- The server stores ciphertext, opaque envelopes, crypto metadata, access grants, revocation state, and audit records.
- Audit integrity remains enabled.
- The web UI keeps the same MFA model as the full profile.
- Upgrade to a full deployment is a configuration and migration path, not a source-code fork.

## Profile defaults

A typical Lite configuration uses:

```text
CUSTODIA_PROFILE=lite
CUSTODIA_STORE_BACKEND=sqlite
CUSTODIA_DATABASE_URL=file:/var/lib/custodia/custodia.db
CUSTODIA_RATE_LIMIT_BACKEND=memory
CUSTODIA_DEPLOYMENT_MODE=lite-single-node
CUSTODIA_DATABASE_HA_TARGET=none
CUSTODIA_WEB_MFA_REQUIRED=true
CUSTODIA_WEB_PASSKEY_ENABLED=false
CUSTODIA_SIGNER_KEY_PROVIDER=file
```

The packaged `custodia-server` build is Lite-capable by default and includes the SQLite build tag. Source builds can override this with `SERVER_BUILD_TAGS` when producing package artifacts.

## Components disabled by default

Lite removes mandatory runtime dependencies on external services:

| Component | Lite default | Notes |
| --- | --- | --- |
| PostgreSQL / CockroachDB | Off | SQLite is used for single-node storage. |
| Valkey / Redis | Off | Rate limiting uses in-memory state. |
| HSM / PKCS#11 / SoftHSM | Off | File-backed signing is used unless configured otherwise. |
| S3 Object Lock / WORM / SIEM shipment | Off | Local audit chain and export remain available. |
| k3s / HA rehearsal | Off | Full-profile and lab-only path. |
| External WebAuthn assertion verifier | Off | TOTP remains the minimum MFA path. |
| Production evidence gates | Off by default | Available as explicit checks, not runtime dependencies. |

## Components that remain active

Lite does not disable the security model:

- mTLS API authentication;
- client-side crypto boundary;
- access grants and revocation checks;
- audit chain generation and verification;
- local audit export;
- web MFA;
- `custodia-admin` operational tooling;
- certificate-based setup using the same signer model.

## YAML configuration

`custodia-server` supports a shared YAML configuration path for Lite and full deployments:

```bash
custodia-server --config /etc/custodia/config.yaml
```

Configuration precedence:

1. profile-derived defaults;
2. optional YAML file;
3. environment variable overrides;
4. final validation.

Example Lite YAML:

```yaml
profile: lite

api_addr: ":8443"
web_addr: ":9443"

store_backend: sqlite
database_url: file:/var/lib/custodia/custodia.db

rate_limit_backend: memory
web_mfa_required: true
web_passkey_enabled: false

deployment_mode: lite-single-node
database_ha_target: none

client_ca_file: /etc/custodia/client-ca.crt
client_crl_file: /etc/custodia/client.crl.pem
tls_cert_file: /etc/custodia/server.crt
tls_key_file: /etc/custodia/server.key

signer_key_provider: file
signer_ca_cert_file: /etc/custodia/custodia-ca.pem
signer_ca_key_file: /etc/custodia/custodia-ca-key.pem
```

## SQLite store

SQLite is supported only for the Lite single-node profile. It must not be treated as a full/HA production target.

Required behavior:

- same logical model as the full store;
- no reduced Lite schema;
- logical secret versioning remains active;
- foreign keys enabled;
- WAL mode enabled;
- busy timeout configured;
- backups performed with the SQLite backup API or `sqlite3 .backup`;
- migration to PostgreSQL/CockroachDB handled by a dedicated future migration tool, not by ad-hoc SQL dumps for production use.

## Local CA and signer

Lite uses a file-backed local CA by default:

```text
CUSTODIA_SIGNER_KEY_PROVIDER=file
CUSTODIA_SIGNER_CA_CERT_FILE=/etc/custodia/custodia-ca.pem
CUSTODIA_SIGNER_CA_KEY_FILE=/etc/custodia/custodia-ca-key.pem
```

Recommended hardening:

- keep the CA key offline when possible;
- use restrictive filesystem permissions;
- use a dedicated `custodia` system user;
- prefer a passphrase-protected CA key when the file provider supports it;
- rotate the initial admin certificate after bootstrap;
- back up CA material offline.

Full deployments should use a real HSM, PKCS#11 provider, or TPM-backed signing path with evidence captured by production checks.

## Web UI and MFA

Lite keeps MFA enabled:

```text
CUSTODIA_WEB_MFA_REQUIRED=true
CUSTODIA_WEB_PASSKEY_ENABLED=false
```

Passkeys can be enabled in custom/full deployments when the assertion verifier is configured. Lite must not introduce an unauthenticated or JWT-only administrative mode as its default.

## Audit

Lite keeps local audit integrity enabled. The default path is:

- append local audit records;
- preserve hash chaining;
- allow audit export and verification;
- keep WORM/SIEM shipment disabled unless explicitly configured.

## Upgrade path to full deployment

A Lite deployment can move toward full deployment by changing configuration and running explicit migration tooling:

1. `profile: lite` to `profile: custom` or `profile: full`;
2. SQLite to PostgreSQL/CockroachDB;
3. memory rate limiting to Valkey;
4. file signer to PKCS#11/HSM/TPM-backed signer;
5. local audit to S3 Object Lock or SIEM/WORM shipment;
6. passkeys enabled where appropriate;
7. production evidence gates enabled.

The SQLite-to-PostgreSQL migration tool is intentionally a future dedicated deliverable. Do not document raw `sqlite3 .dump` as the production migration procedure.

## Operational checklist

For Lite deployments:

- run under a dedicated `custodia` user;
- restrict `/etc/custodia` permissions;
- keep SQLite and audit data under `/var/lib/custodia` or another protected local path;
- schedule SQLite backups;
- verify audit exports periodically;
- avoid direct Internet exposure without firewalling and TLS hardening;
- store CA backups offline;
- document single-node disaster recovery.
