# Security model

## Cryptographic boundary

The server never receives plaintext, DEKs, private keys or interpretable cryptographic material. It stores and returns opaque transport fields plus optional application public-key metadata:

- `ciphertext`
- `crypto_metadata`
- `envelope`
- application public key metadata (`scheme`, public key bytes, fingerprint)

The server exposes application public-key metadata only for discovery. It does not mediate trust between clients; clients that require stronger assurance must compare fingerprints or pin keys. It validates base64 transport syntax and public-key shape only; this is not cryptographic interpretation of secret payloads.

## Authentication and authorization

- mTLS authenticates the caller.
- When `CUSTODIA_CLIENT_CRL_FILE` is configured, the TLS layer rejects revoked client certificate serials before request handling. The CRL must be signed by the configured client CA.
- The `clients` table maps certificate subject to `client_id`.
- `secret_visibility` resolves each caller-visible `(client_id, namespace, key)` tuple to the owned secret; `secret_access` authorizes the readable/updatable version for each client.
- Permissions use a bitmask: share=1, write=2, read=4.

## Revocation semantics

Server-side client certificate revocation prevents future TLS authentication when the configured CRL contains that certificate serial. Server-side access revocation prevents future reads. Strong revocation requires a new secret version with new client-side ciphertext and new envelopes for the remaining authorized clients. When a new version is created, older active versions are superseded for future server-side operations and pending grants on superseded versions are cancelled.

## Audit semantics

Successful and failed authentication, authorization and metadata operations are audit-recorded. Failure events include a machine-readable reason in audit metadata and remain hash-chained like successful events.

## Admin boundary

Admin metadata APIs are restricted to configured admin client IDs. This does not grant decryption capability.


## HTTP response hardening

Custodia emits conservative security headers by default, including `nosniff`, `DENY` framing, `no-referrer`, `no-store` and a restrictive Content Security Policy. The current web surface remains metadata-only and does not expose plaintext or client-side key material.


## Client certificate revocation

When `CUSTODIA_CLIENT_CRL_FILE` is configured, the mTLS verifier fails closed on certificates whose serial appears in a trusted client CRL. The verifier reloads the CRL when the file metadata changes, so revocations can be distributed operationally without restarting the API process. CRL signature validation still requires the configured client CA. OCSP stapling remains a production hardening gap.

## Web user metadata boundary

The HTTP `/web/` shell is protected by admin mTLS authorization and can require a TOTP-backed signed web session. Passkey/WebAuthn challenge, credential metadata and external assertion-verifier delegation are available for deployments that enable passkeys. The PostgreSQL schema includes `web_users` and `web_user_mappings` for the metadata-only admin console described by the design document. These tables store authentication and role metadata only. They do not store plaintext secrets, client private encryption keys or decryptable envelopes. Application public-key metadata is stored separately as discovery metadata, not as a trust decision. Web operators can only be mapped to existing `client_id` subjects; access activation still requires an opaque envelope produced outside the vault by a subject with `share` permission.


## Explicit remaining security gaps

The implemented server keeps the application cryptographic boundary intact, but the following Fort Knox items remain external or future work:

- Audited external WebAuthn assertion verifier deployment evidence when passkeys are enabled; the repository provides the fail-closed adapter and pre-signature validation boundary.
- Physical HSM/PKCS#11/TPM signing evidence for the CA key in the target environment.
- OCSP stapling or revocation distribution monitoring evidence in the target environment.
- External WORM/SIEM retention evidence.
- Formal verification execution evidence from CI or a dedicated verification pipeline.

These gaps must not be closed by moving client-side private encryption keys, public-key trust decisions or plaintext handling into the vault server.


## Web authentication boundary

The metadata-only web console can require admin mTLS plus a TOTP-backed signed web session. Passkey challenge/options, metadata validation and external assertion-verifier delegation are available for WebAuthn integration. TOTP should stay enabled until the configured external verifier is deployed, tested and independently reviewed. Web authentication never changes the vault cryptographic boundary: plaintext, ciphertext, envelopes and client-side key material are not rendered or processed by the web console.


## Production readiness boundary

The repository includes a production readiness gate and operational artifacts for Phase 3, but the following claims remain deliberately external:

- `pkcs11` signer provider is the production target and readiness requirement; actual HSM/PKCS#11 integration must be validated in the deployment environment.
- Audit archive shipment is verified before handoff; legal WORM immutability is provided by the external sink.
- Database HA metadata and runbooks describe the topology; quorum, failover and multi-region behavior must be proven by the selected database platform.
- Formal artifacts model server authorization invariants; they do not prove client-side encryption algorithms or external CA hardware.

These boundaries prevent the server from drifting into plaintext handling, private-key custody, public-key trust decisions or fake HSM claims.
