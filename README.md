# Custodia

[![CI](https://github.com/marcofortina/custodia/actions/workflows/ci.yml/badge.svg)](https://github.com/marcofortina/custodia/actions/workflows/ci.yml)
[![Release artifacts](https://github.com/marcofortina/custodia/actions/workflows/release.yml/badge.svg)](https://github.com/marcofortina/custodia/actions/workflows/release.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
[![Wiki](https://img.shields.io/badge/wiki-project%20portal-forestgreen.svg)](https://github.com/marcofortina/custodia/wiki)

Custodia is a REST vault for encrypted secrets. The server authenticates clients with mTLS, authorizes access, stores opaque encrypted blobs and returns only the caller's opaque envelope. Encryption, decryption, private-key handling, key rotation and key trust stay outside the server. Custodia may store authenticated client application public keys and fingerprints as metadata to simplify recipient discovery, but it is not a decryption service or a key-trust oracle.

## Start here

New to Custodia? Start with the step-by-step quickstart:

**[`docs/DEPLOYMENT_MATRIX.md` — choose bare metal vs Kubernetes and Lite vs Full](docs/DEPLOYMENT_MATRIX.md)**

**[`docs/QUICKSTART.md` — bare-metal install from packages or from source](docs/QUICKSTART.md)**

**[`docs/KUBERNETES_INSTALL.md` — Kubernetes install from a Git-built image](docs/KUBERNETES_INSTALL.md)**

**[`docs/KUBERNETES_RUNTIME_SMOKE.md` — read-only Kubernetes runtime smoke](docs/KUBERNETES_RUNTIME_SMOKE.md)**

**[`docs/LITE_BACKUP_RESTORE_SMOKE.md` — disposable Lite backup/restore smoke](docs/LITE_BACKUP_RESTORE_SMOKE.md)**

**[`docs/END_TO_END_OPERATOR_SMOKE.md` — release-candidate end-to-end operator smoke](docs/END_TO_END_OPERATOR_SMOKE.md)**

If you are not sure what to choose, use the package install path. It covers Debian/Ubuntu `.deb`, Fedora `.rpm`, the server/client/SDK package split, Lite bootstrap, admin certificate setup, Web TOTP, the first API check and the first encrypted client smoke test.

## What is implemented

- Go vault server with TLS 1.3 / mTLS support and optional client CRL rejection.
- Client identity extraction from certificate SAN/CN.
- REST API for encrypted secret create/read/delete/share/new-version plus metadata-only secret listing and authenticated client public-key metadata, with namespace/key lookup for normal user-facing workflows.
- Admin API/CLI and metadata-only Web Console workflows for client metadata create/list/revoke, enrollment tokens, secret version/access inspection and future access-grant revocation.
- Pending grant request/activation workflow: admins can request access, but a client with `share` must upload the target envelope.
- Per-version access grants with `read`, `write`, `share` bitmask and optional future `expires_at`.
- Configurable recipient-envelope cap for create/new-version requests, defaulting to 100.
- Future revocation semantics: revoked grants stop future reads; already downloaded material is not invalidated.
- PostgreSQL-compatible schema contract plus optional `pgx` store implementation behind the `postgres` build tag.
- In-memory store for local development and tests.
- Hash-chained audit event model with admin audit listing and verification API/CLI.
- Memory and Valkey-compatible rate limiter backends with readiness checks.
- Minimal admin CLI for metadata operations exposed by the API.
- Go, Python and Node.js / TypeScript client libraries with raw transport helpers; all three include high-level client-side crypto wrappers that keep plaintext, DEKs and private keys outside the server.
- Java, C++ and Rust client libraries with raw transport helpers plus high-level client-side crypto wrappers that use the shared AES-256-GCM/HPKE-v1 vectors.
- Go `custodia-client` CLI for encrypted namespace/key put/get/share/update, access revoke/delete workflows, server-published application public-key metadata, reusable JSON client profiles and one-shot enrollment for client-side mTLS CSR signing.
- Docker, Compose, Helm and Lite/Full deployment examples, with the install/profile split documented in [`docs/DEPLOYMENT_MATRIX.md`](docs/DEPLOYMENT_MATRIX.md), Kubernetes example values and render guardrails via `make helm-check`.
- Dedicated `custodia-signer` service for enrollment-backed client CSR signing.
- Custodia Lite profile with YAML config, SQLite build-tag artifact, local CA bootstrap, backup helper and Lite-to-Full readiness checks.

## What is deliberately not implemented server-side

- No plaintext handling.
- No DEK/wrapped-DEK handling.
- No private application-key custody.
- No server-side DEK unwrap, recipient-envelope generation or application decryption.
- No server-side public-key trust decision; published public-key metadata is discovery data, not proof that a key should be trusted.

## Community and security

- Contributions are welcome, but they must preserve Custodia's metadata-only security boundary. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- All participants are expected to follow the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- Do not open public issues for vulnerabilities or sensitive disclosures; follow [`SECURITY.md`](SECURITY.md).


## License

Copyright (c) 2026 Marco Fortina.

Custodia is licensed under the **GNU Affero General Public License v3.0 only** (`AGPL-3.0-only`). See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Custodia is open source, but the AGPL network-copyleft terms are intentional: if you modify Custodia and make that modified version available to users over a network, you must make the corresponding source code available under the AGPL.

Commercial licensing, enterprise support and integration work may be available separately from the maintainer.

## Support the project

Custodia is maintained as an open-source privacy-first secret-management project. If this repository helps your lab, research, compliance work, or integration testing, sponsorship helps keep development, testing, documentation, and security hardening moving.

Ways to support the project:

- GitHub Sponsors: use the repository **Sponsor** button or sponsor `@marcofortina`.
- PayPal: `https://paypal.me/marcofortina`.
- Bitcoin: `36jDV57roGb4o59TwK1CB7viPrXToQHGiP`.

Bitcoin URI:

```text
bitcoin:36jDV57roGb4o59TwK1CB7viPrXToQHGiP
```


## Client SDKs

The canonical repository-level SDK matrix is [`docs/CLIENT_LIBRARIES.md`](docs/CLIENT_LIBRARIES.md). Use that document as the source of truth for implemented client surfaces and verification status.

- Go: [`docs/GO_CLIENT_SDK.md`](docs/GO_CLIENT_SDK.md)
- Python: [`docs/PYTHON_CLIENT_SDK.md`](docs/PYTHON_CLIENT_SDK.md)
- Node.js / TypeScript transport and crypto: [`docs/NODE_CLIENT_SDK.md`](docs/NODE_CLIENT_SDK.md)
- Java transport and crypto: [`docs/JAVA_CLIENT_SDK.md`](docs/JAVA_CLIENT_SDK.md)
- C++ transport and crypto: [`docs/CPP_CLIENT_SDK.md`](docs/CPP_CLIENT_SDK.md)
- Rust transport and crypto: [`docs/RUST_CLIENT_SDK.md`](docs/RUST_CLIENT_SDK.md)
- Encrypted client CLI: [`docs/CUSTODIA_CLIENT_CLI.md`](docs/CUSTODIA_CLIENT_CLI.md)
- Alice/Bob first encrypted secret smoke test: [`docs/CUSTODIA_ALICE_BOB_SMOKE.md`](docs/CUSTODIA_ALICE_BOB_SMOKE.md)
- Kubernetes runtime smoke: [`docs/KUBERNETES_RUNTIME_SMOKE.md`](docs/KUBERNETES_RUNTIME_SMOKE.md)
- Lite backup/restore smoke: [`docs/LITE_BACKUP_RESTORE_SMOKE.md`](docs/LITE_BACKUP_RESTORE_SMOKE.md)
- End-to-end operator release-candidate smoke: [`docs/END_TO_END_OPERATOR_SMOKE.md`](docs/END_TO_END_OPERATOR_SMOKE.md)
- Bash SDK helper: [`docs/BASH_SDK.md`](docs/BASH_SDK.md)
- Shared crypto contract: [`docs/CLIENT_CRYPTO_SPEC.md`](docs/CLIENT_CRYPTO_SPEC.md)
- Client crypto threat model: [`docs/CLIENT_CRYPTO_THREAT_MODEL.md`](docs/CLIENT_CRYPTO_THREAT_MODEL.md)
- Namespace/key secret keyspace model: [`docs/SECRET_KEYSPACE_MODEL.md`](docs/SECRET_KEYSPACE_MODEL.md)
- SDK release policy: [`docs/SDK_RELEASE_POLICY.md`](docs/SDK_RELEASE_POLICY.md)
- Linux DEB/RPM packaging: [`docs/LINUX_PACKAGES.md`](docs/LINUX_PACKAGES.md)
- Start here / install quickstart: [`docs/QUICKSTART.md`](docs/QUICKSTART.md)
- Release notes for 0.1.0: [`docs/RELEASE_NOTES_0_1_0.md`](docs/RELEASE_NOTES_0_1_0.md)
- SBOM artifacts: [`docs/SBOM.md`](docs/SBOM.md)

## Linux packages

Build local DEB/RPM packages with:

```bash
VERSION=0.1.0 REVISION=1 make package-deb
VERSION=0.1.0 REVISION=1 make package-rpm
```

Generate release verification files:

```bash
VERSION=0.1.0 REVISION=1 make package-checksums
cd dist/packages && sha256sum -c SHA256SUMS
```

Smoke-test package contents without installing them into the host system:

```bash
make package-smoke
```

Validate package installation on a disposable clean VM/container before publishing:

```bash
make package-install-smoke
make lite-backup-restore-smoke
# On the clean test machine, after copying artifacts:
export CUSTODIA_PACKAGE_INSTALL_CONFIRM=YES
sudo -E ./scripts/package-install-smoke.sh install-verify
```

Generate a release SBOM:

```bash
VERSION=0.1.0 make sbom
```

For a clean machine first run, start with **[`docs/QUICKSTART.md`](docs/QUICKSTART.md)**. For the release scope and final pre-release guardrails, see **[`docs/RELEASE_NOTES_0_1_0.md`](docs/RELEASE_NOTES_0_1_0.md)**.

The package split is:

- `custodia-server`: server, admin CLI, signer, hardened systemd units, server docs, YAML examples and SQLite backup helper;
- `custodia-client`: encrypted `custodia-client` CLI.
- `custodia-sdk`: SDK source snapshots, shared vectors and SDK docs.

See [`docs/LINUX_PACKAGES.md`](docs/LINUX_PACKAGES.md).

## Local development

```bash
cp .env.example .env
make
make run-dev
```

The default `make` target runs `make all`, which executes the Go test suite, builds the main binaries and generates local manual pages. Use `make test` when you only want the Go tests, `make build` when you only want binaries, `make man` when you only want manual pages, and `make check` for the full multi-language/release-like verification pass. Install all locally built server, client and SDK artifacts plus manual pages with `sudo make install`; use `sudo make install-server`, `sudo make install-client` or `sudo make install-sdk` for partial installs. Override `PREFIX`, `BINDIR`, `MANDIR`, `SHAREDIR`, `DOCDIR`, `SYSTEMDUNITDIR` or `DESTDIR` for staged installs.

The development mode uses the in-memory store and insecure HTTP only when `CUSTODIA_DEV_INSECURE_HTTP=true` is set. Production must use `CUSTODIA_TLS_CERT_FILE`, `CUSTODIA_TLS_KEY_FILE` and `CUSTODIA_CLIENT_CA_FILE`. Set `CUSTODIA_CLIENT_CRL_FILE` to a PEM CRL signed by the configured client CA to fail closed on revoked client certificate serials.

## Build metadata

Release builds can stamp version, commit and date into every binary. Use `make release-metadata-check VERSION=0.1.0` before publishing artifacts, or `make release VERSION=0.1.0` to run the metadata guardrail plus the default build/test/manpage flow. The values are exposed through `GET /v1/status`, `/web/status`, `custodia-admin version`, `custodia-client version`, `custodia-server version` and `custodia-signer version`. Development builds print `dev unknown unknown` until release `-ldflags` are supplied. See `docs/BUILD_METADATA.md`.

## Audit export integrity

Audit JSONL exports include SHA-256 and event-count headers for offline verification. `custodia-admin audit verify-export` verifies exported body/digest/count artifacts. See `docs/AUDIT_EXPORT_INTEGRITY.md`.

## PostgreSQL store

The default `make build`/`make install` path builds a universal `custodia-server` with both `sqlite` and `postgres` store support. Select PostgreSQL at runtime with configuration, not by installing a different product:

```bash
make
```

Then configure:

```bash
CUSTODIA_STORE_BACKEND=postgres
CUSTODIA_DATABASE_URL=postgres://custodia:secret@127.0.0.1:5432/custodia?sslmode=require
```

Run `migrations/postgres/001_init.sql` before starting the server. Container builds can enable the optional store with `CUSTODIA_GO_BUILD_TAGS=postgres docker compose build custodia` after the `pgx/v5` dependency is present in `go.mod`. The store persists only opaque ciphertext/envelope bytes and metadata; it does not add any server-side cryptographic key handling.

## Custodia Lite / SQLite store

Lite is a single-node profile of the same codebase. The default build is universal and includes SQLite support, so Lite and Full use the same installed server binary. Select SQLite at runtime with configuration:

```bash
make
```

Then configure:

```bash
CUSTODIA_PROFILE=lite
CUSTODIA_STORE_BACKEND=sqlite
CUSTODIA_DATABASE_URL=file:/var/lib/custodia/custodia.db
```

Lite keeps mTLS, Web MFA, audit integrity and the opaque crypto boundary. It removes mandatory external runtime services; it does not create a weaker server-side crypto model.

## API permissions

```text
share = 1
write = 2
read  = 4
all   = 7
```

## Example encrypted secret payload

```json
{
  "namespace": "oracle-prod",
  "key": "user:sys",
  "ciphertext": "Y2lwaGVydGV4dA==",
  "crypto_metadata": { "format": "client-defined" },
  "envelopes": [
    { "client_id": "client_alice", "envelope": "ZW52ZWxvcGUtZm9yLWFsaWNl" }
  ],
  "permissions": 7
}
```

The server validates authorization, the configured envelope-count cap and base64 transport syntax, then stores opaque transport data. It does not interpret the cryptographic content. Permission bitmasks must be non-zero combinations of `share`, `write` and `read`; the PostgreSQL schema enforces the same non-zero range guardrail.

## Admin client metadata

```bash
custodia-admin client create --client-id client_bob --mtls-subject client_bob
custodia-admin client list
custodia-admin client revoke --client-id client_bob --reason compromised
custodia-admin audit list --limit 100
custodia-admin audit verify --limit 500
```

Client creation registers metadata only. Secret sharing is performed by the client workflow with `namespace/key`; the server stores only opaque ciphertext and recipient envelopes. Certificate issuance/signing remains outside the vault server and belongs to the dedicated `custodia-signer` service. Lite package installs include `custodia-signer.service`; source installs can copy `deploy/examples/custodia-signer.service`.

Development signer example:

```bash
make run-signer-dev
```

Production signer mode requires mTLS and a dedicated CA material backend. See `docs/CA_SIGNING_SERVICE.md`.

## Web metadata console

The admin web console is intentionally metadata-only. It requires an admin mTLS identity, uses a TOTP/passkey-capable web session, applies SameSite cookies plus same-origin browser mutation guards, and never renders ciphertext, envelopes, plaintext, or key material. Client drilldown pages show only metadata such as visible keyspace, owner/relationship and share permissions, and Kubernetes-safe operations such as one-shot client enrollment, future client revocation, client-CRL status, client CRL PEM download, CRL serial checks and browser-downloadable audit JSONL evidence. See `docs/WEB_CONSOLE.md` for the current page map and security boundary.

## HTTP timeout guardrails

The server has bounded HTTP timeouts by default: read/write 15s, idle 60s and graceful shutdown 10s. Override with `CUSTODIA_HTTP_READ_TIMEOUT_SECONDS`, `CUSTODIA_HTTP_WRITE_TIMEOUT_SECONDS`, `CUSTODIA_HTTP_IDLE_TIMEOUT_SECONDS` and `CUSTODIA_SHUTDOWN_TIMEOUT_SECONDS`.


### PostgreSQL integration tests

The default test suite does not require external services. To exercise the optional PostgreSQL store, install the `postgres` build-tag dependencies and provide a disposable database URL:

```bash
go get github.com/jackc/pgx/v5
TEST_CUSTODIA_POSTGRES_URL=postgres://user:pass@localhost:5432/custodia_test?sslmode=disable make test-postgres
```


### Optional PostgreSQL integration check

The default test target is dependency-free. To verify the optional PostgreSQL store, provide a live test database and run:

```bash
TEST_CUSTODIA_POSTGRES_URL=postgres://user:pass@localhost:5432/custodia_test?sslmode=disable make test-postgres
```


### Runtime diagnostics

Use `custodia-admin diagnostics read` or `GET /v1/diagnostics` with an admin mTLS client to inspect runtime metadata. On a standard local install, `custodia-admin diagnostics read` and `custodia-admin status read` derive the server URL and admin mTLS paths from `/etc/custodia/custodia-server.yaml`. The diagnostics output is metadata-only and never includes secret payloads or client-side cryptographic material.

For install diagnostics, use read-only doctor commands. See the dedicated
[doctor diagnostics runbook](docs/DOCTOR.md) for offline, systemd, network and
client-profile examples.


### Operational runbooks

The operational documentation is grouped by the workflow it supports, rather than by the order in which the documents were added.

**Release readiness and closure**

- [Production checklist](docs/PRODUCTION_CHECKLIST.md)
- [Production readiness gate](docs/PRODUCTION_READINESS_GATE.md)
- [Production external evidence gate](docs/PRODUCTION_EVIDENCE.md)
- [Release check](docs/RELEASE_CHECK.md)
- [Formal verification scope](docs/FORMAL_VERIFICATION.md)

**Project planning and history**

- [Project history index](docs/PROJECT_HISTORY.md)
- [Custodia Wiki](https://github.com/marcofortina/custodia/wiki)
- [GitHub Project roadmap](https://github.com/marcofortina/custodia/projects)

**Deployment model and install paths**

- [Deployment matrix](docs/DEPLOYMENT_MATRIX.md)
- [Custodia bare-metal install quickstart](docs/QUICKSTART.md)
- [Linux packages](docs/LINUX_PACKAGES.md)
- [Kubernetes install](docs/KUBERNETES_INSTALL.md)
- [Kubernetes Lite backup and restore](docs/KUBERNETES_LITE_BACKUP_RESTORE.md)
- [Kubernetes runtime smoke](docs/KUBERNETES_RUNTIME_SMOKE.md)
- [End-to-end operator release-candidate smoke](docs/END_TO_END_OPERATOR_SMOKE.md)
- [k3s CockroachDB HA profile](docs/K3S_COCKROACHDB_HA.md)

**Lite deployment and upgrade path**

- [Custodia bare-metal install quickstart](docs/QUICKSTART.md)
- [Custodia Lite profile](docs/LITE_PROFILE.md)
- [Custodia Lite configuration](docs/LITE_CONFIG.md)
- [Configuration reference](docs/CONFIG_REFERENCE.md)
- [Doctor diagnostics](docs/DOCTOR.md)
- [Lite installation guide](docs/LITE_INSTALL.md)
- [Lite SQLite store](docs/LITE_SQLITE_STORE.md)
- [Lite local CA bootstrap](docs/LITE_CA_BOOTSTRAP.md)
- [Lite backup and restore](docs/LITE_BACKUP_RESTORE.md)
- [Lite backup/restore smoke](docs/LITE_BACKUP_RESTORE_SMOKE.md)
- [Kubernetes Lite backup and restore](docs/KUBERNETES_LITE_BACKUP_RESTORE.md)
- [Lite migration readiness](docs/LITE_MIGRATION_READINESS.md)
- [Lite to Full upgrade path](docs/LITE_TO_FULL_UPGRADE.md)

**High availability, backup and disaster recovery**

- [Backup and restore runbook](docs/BACKUP_RESTORE_RUNBOOK.md)
- [Disaster recovery runbook](docs/DR_RUNBOOK.md)
- [Database HA runbook](docs/DATABASE_HA_RUNBOOK.md)
- [k3s CockroachDB HA profile](docs/K3S_COCKROACHDB_HA.md)

**Identity, certificates and web authentication**

- [CA signing service design](docs/CA_SIGNING_SERVICE.md)
- [Client certificate lifecycle](docs/CLIENT_CERTIFICATE_LIFECYCLE.md) — includes one-shot enrollment and client-side CSR signing
- [CRL and OCSP operations](docs/CRL_OCSP_RUNBOOK.md)
- [PKCS#11 and SoftHSM signer bridge](docs/PKCS11_SOFTHSM.md)
- [Web MFA](docs/WEB_MFA.md)
- [Web passkey support](docs/WEB_PASSKEY.md)

**Audit, evidence and shipment**

- [Audit archive runbook](docs/AUDIT_ARCHIVE_RUNBOOK.md)
- [Audit shipment runbook](docs/AUDIT_SHIPMENT_RUNBOOK.md)
- [S3 Object Lock audit shipment](docs/S3_OBJECT_LOCK_AUDIT_SHIPMENT.md)
- [SIEM and WORM audit export](docs/SIEM_WORM_EXPORT.md)

**Client SDKs and crypto contracts**

- [Custodia client libraries specification](docs/CLIENT_LIBRARIES.md)
- [Client crypto specification](docs/CLIENT_CRYPTO_SPEC.md)
- [Client crypto threat model](docs/CLIENT_CRYPTO_THREAT_MODEL.md)
- [Namespace/key secret keyspace model](docs/SECRET_KEYSPACE_MODEL.md)
- [Go client SDK](docs/GO_CLIENT_SDK.md)
- [Custodia client CLI](docs/CUSTODIA_CLIENT_CLI.md)
- [Python client SDK](docs/PYTHON_CLIENT_SDK.md)
- [Node.js / TypeScript client SDK](docs/NODE_CLIENT_SDK.md)
- [Java client SDK](docs/JAVA_CLIENT_SDK.md)
- [C++ client SDK](docs/CPP_CLIENT_SDK.md)
- [Rust client SDK](docs/RUST_CLIENT_SDK.md)
- [Bash SDK helper](docs/BASH_SDK.md)


### Formal verification

Server-side authorization invariants have executable Go model tests and a TLA+ model under `formal/`. Run `make formal-check` when TLC is installed.

### Production readiness gate

Validate offline production readiness/evidence environment files before promotion:

```bash
custodia-admin production check --env-file .env.production
```

The command fails on unsafe development defaults and missing external production dependencies.

### Revocation serial status

`custodia-signer` exposes a CRL-backed JSON revocation responder at `/v1/revocation/serial`. Use `custodia-admin revocation check-serial --serial-hex HEX` for operator drills. See `docs/CRL_OCSP_RUNBOOK.md`.


Source install smoke:

```bash
make install-smoke
```


Validate runtime configuration without starting daemons:

```bash
custodia-server config validate --config /etc/custodia/custodia-server.yaml
custodia-signer config validate --config /etc/custodia/custodia-signer.yaml
```


Render starter runtime configuration templates:

```bash
custodia-server config render --profile lite
custodia-server config render --profile full
custodia-signer config render
```


Audit log permission guardrail:

```bash
make audit-log-permissions-check
```

- Reproducible build notes: [`docs/REPRODUCIBLE_BUILDS.md`](docs/REPRODUCIBLE_BUILDS.md)
