# Custodia threat model

## Version and scope

This document is the versioned repository threat model for Custodia before the stable 1.0 security promise. It consolidates the security boundary already described across the server, client crypto, Web Console, signer, storage and release documentation.

Custodia is a privacy-first vault for encrypted secrets. The server authenticates clients, authorizes metadata operations, stores opaque encrypted payloads and returns caller-visible envelopes. Secret encryption, decryption, data encryption keys, private application keys and key trust decisions remain outside the server boundary.

## Primary assets

Custodia protects or deliberately avoids custody of these asset classes:

| Asset | Custodia server custody | Security expectation |
| --- | --- | --- |
| Plaintext secret values | Never | Must exist only on authorized clients or operator-controlled files before client encryption. |
| DEKs, wrapped DEKs and application private keys | Never | Must not be sent to the server, logged by the server or exposed through Web Console/API responses. |
| Ciphertext, envelopes and crypto metadata | Yes, opaque only | Stored and returned without server-side decryption or trust interpretation. |
| Namespace/key metadata and version/access metadata | Yes | Authorized by mTLS identity and ACLs; exposed only through metadata APIs. |
| Client certificate material | Public certificates and CSR metadata only | Private mTLS keys stay on the client; signer receives CSR and enrollment token, not private keys. |
| Audit chain and export metadata | Yes | Hash-chained, exportable and verifiable by operators. |
| Web operator/session metadata | Yes | Metadata-only admin control plane; no secret material exposure. |

## Trust boundaries

### Client and SDK boundary

Clients own plaintext handling, client-side encryption, envelope creation, private application-key custody and public-key trust decisions. SDKs may help implement these operations, but the server remains metadata-only even when SDKs provide high-level crypto helpers.

### Transport boundary

mTLS authenticates clients and admins. Enrollment is intentionally separated: the enrollment claim endpoint accepts an enrollment token and CSR without a client certificate, while normal client/admin operations require mTLS. TLS verification is normal by default; `--insecure` is for disposable lab first-run only and must not be treated as a production trust model.

### Server/API boundary

The server enforces authentication, authorization, namespace/key lookup, visibility, versioning, access grants, revocation metadata and audit recording. It must not decrypt, unwrap, derive, generate recipient envelopes or decide whether an application public key is trustworthy.

### Storage boundary

The database or Lite SQLite store contains metadata, ciphertext, opaque envelopes, public-key discovery metadata, audit data and configuration-derived state. A storage compromise can expose encrypted payloads and metadata. It must not expose plaintext, DEKs or private application keys because those are not stored server-side.

### Signer/CA boundary

The signer signs approved client CSRs and can be backed by file keys, PKCS#11/HSM or lab SoftHSM. Production claims require operator evidence for CA key custody, PIN delivery and signer host/device controls. The signer does not receive client private mTLS keys.

### Web Console boundary

The Web Console is an admin metadata surface protected by admin mTLS and optional Web MFA/passkey flows. It can inspect metadata and initiate metadata workflows. It must not expose plaintext, DEKs, application private keys or decryptable envelopes outside the same opaque transport semantics as the API.

### Release and package boundary

Release artifacts are validated by package smoke, checksums, artifact manifests, SBOM and release provenance metadata. These artifacts help verify what was published; they do not replace runtime production evidence such as HSM custody, WORM retention or penetration testing.

## In-scope threats and controls

| Threat | Control / expectation |
| --- | --- |
| Network attacker intercepts traffic | TLS/mTLS, normal certificate validation, no production `--insecure`. |
| Unauthorized client reads another client's secret | mTLS identity mapping, keyspace visibility, ACL checks and regression tests. |
| Server operator or Web admin attempts to decrypt | Server and Web Console never receive plaintext, DEKs or application private keys. |
| Database compromise | Attacker sees metadata and opaque encrypted payloads only; client-side crypto remains required for decryption. |
| Stale access after recipient revocation | Server revokes future reads; strong cryptographic revocation requires a new version encrypted for remaining recipients. |
| Malicious or stale public-key metadata | Server publishes public-key metadata for discovery only; clients that require stronger assurance must pin or compare fingerprints. |
| Enrollment token replay or misuse | Enrollment tokens are one-shot/TTL-bound; clients generate private mTLS keys locally. |
| CA/signer key compromise | Production requires external custody evidence, signer hardening and revocation lifecycle evidence. |
| Package/release substitution | Release flow publishes checksums, artifact manifest, SBOM and provenance metadata; operators verify before install. |
| Audit tampering | Audit records are hash-chained and exportable for verification and external retention. |

## Explicit server-side exclusions

The following are not allowed server-side and must be treated as security regressions if introduced:

- plaintext secret storage, logging, rendering or API/Web Console exposure;
- DEK or wrapped-DEK storage, unwrap or derivation;
- application private-key custody;
- recipient envelope generation by the server;
- public-key trust decisions by the server;
- server-side decryption for Web Console convenience;
- migration code that requires sending plaintext or private keys to the server.

## Residual risks and required operator evidence

Custodia cannot prove the following by repository tests alone:

- production HSM/PKCS#11/TPM custody and signer-device controls;
- WebAuthn/passkey external assertion-verifier deployment evidence;
- WORM/Object Lock/SIEM retention guarantees;
- database HA/failover and backup restore evidence;
- network policy enforcement in the target environment;
- penetration testing and disaster-recovery rehearsal.

These are production evidence items. They must not be closed by weakening the metadata-only server boundary.

## Threat model change control

Before the stable 1.0 promise, this document may change as implementation and evidence mature. After 1.0, changes that weaken the server metadata-only boundary, change cryptographic trust assumptions or change compatibility promises require an explicit release note and the compatibility process in `API_COMPATIBILITY_POLICY.md`.
