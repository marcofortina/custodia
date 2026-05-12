# Custodia production checklist

This checklist turns the Fort Knox analysis into deployable operator gates. It does not change the cryptographic boundary: Custodia stores and authorizes opaque ciphertext/envelope blobs only.

## Required before production

- API listener serves TLS 1.3 with `ClientAuth: RequireAndVerifyClientCert`.
- `CUSTODIA_STORE_BACKEND=postgres` or a CockroachDB-compatible PostgreSQL endpoint is configured.
- `CUSTODIA_DEPLOYMENT_MODE` and `CUSTODIA_DATABASE_HA_TARGET` reflect the real DB HA topology.
- `CUSTODIA_RATE_LIMIT_BACKEND=valkey` is configured for shared rate limits.
- `CUSTODIA_CLIENT_CRL_FILE` is mounted when local CRL enforcement is used.
- `custodia-admin revocation status` is monitored and alerts before CRL expiry.
- Web Console CRL download and serial-check drills are exercised for Kubernetes operations where pod shell access is not part of the normal workflow.
- `/ready` runs on a dedicated health listener that is not exposed outside the cluster.
- Admin client IDs are explicitly configured; no wildcard admin mode exists.
- Web console remains metadata-only and requires admin mTLS; enable TOTP MFA before production. Kubernetes operators can inspect secret version/access metadata and revoke future access grants without entering application pods.
- Passkey endpoints are available behind admin mTLS and Web MFA. Keep TOTP enabled unless an audited external assertion verifier is configured and evidenced.
- Audit export integrity headers are validated by downstream archival jobs with `custodia-admin audit verify-export`; Web Console JSONL downloads are acceptable evidence capture only when the SHA-256 and event-count headers are preserved with the body.
- Audit export artifacts are bundled with `custodia-admin audit archive-export` before WORM/SIEM ingestion.
- Verified audit archive bundles are shipped with `custodia-admin audit ship-archive` before SIEM/WORM ingestion.
- `CUSTODIA_SIGNER_KEY_PROVIDER` is explicitly set; production must not rely on file-backed CA keys unless this is an isolated bootstrap environment.
- Kubernetes values pass `make helm-check`; unsafe chart combinations fail before render.
- Kubernetes Lite, when used outside disposable labs, has `persistence.enabled=true`, one server replica and a documented PVC snapshot/off-cluster backup plan. See [`KUBERNETES_LITE_BACKUP_RESTORE.md`](KUBERNETES_LITE_BACKUP_RESTORE.md).
- Kubernetes Full uses external PostgreSQL/CockroachDB, Valkey, HSM/PKCS#11 or equivalent signer controls and WORM/SIEM/object-lock evidence; SoftHSM and MinIO remain development/smoke substitutes unless independently production-governed.
- The end-to-end operator smoke in [`END_TO_END_OPERATOR_SMOKE.md`](END_TO_END_OPERATOR_SMOKE.md) is rehearsed on disposable release-candidate hosts before promotion, including source install, Web Console checkpoints, Alice/Bob enrollment/share/revoke/delete and Lite backup.

## Must remain false

- Do not add a server-side private credential-key directory or any DEK unwrap path. Public-key metadata is discovery-only and must not become a trust decision.
- Do not add DEK, wrapped DEK or key unwrap logic to the server.
- Do not render ciphertext/envelopes in web pages.
- Do not use the memory store for production.
- Do not disable web MFA on externally reachable deployments.

## Formal verification gate

- Run `go test ./internal/formalmodel` after authorization model changes.
- Run `make formal-check` in release pipelines where TLC is installed.
- Treat new authorization transitions as requiring updates to both executable model tests and the TLA+ model.


## Final promotion gate

Before promoting a release, run:

```bash
custodia-admin production check --env-file .env.production
```

Promotion must stop on any `critical` finding. Warnings require an explicit operator decision and should be resolved before declaring a Fort Knox production deployment complete.

## External evidence gate

Before declaring a Fort Knox production release complete, run:

```bash
CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-evidence-check
```

The environment file must reference evidence for HSM/PKCS#11, WORM retention, database HA, Valkey cluster, zero-trust networking, air-gapped backup, penetration testing, formal verification, revocation drills and release checks.

## PKCS#11 signer gate

- `CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11` is set.
- `CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND` points to an audited HSM/PKCS#11 bridge.
- SoftHSM is not used for production signing.
- PKCS#11 token/key labels and PIN source are managed outside the repository.
- HSM/TPM attestation is attached to the production evidence gate.

- S3/Object Lock audit shipment is configured and verified with `custodia-admin audit ship-archive-s3` or an equivalent WORM sink adapter.
- `make minio-object-lock-smoke` passes in development if MinIO is used as the WORM-like test profile.

## k3s CockroachDB rehearsal gate

- Run `make k3s-cockroachdb-smoke` against the rehearsal cluster before relying on the CockroachDB HA profile.
- Replace the example insecure SQL endpoint with TLS-enabled CockroachDB credentials before production.
- Capture the smoke output as production evidence when `CUSTODIA_DATABASE_HA_TARGET=cockroachdb-k3s-3node` is used.

- Signer revocation serial status responder is exercised during certificate revocation drills.

## Passkey/WebAuthn verification gate

- Passkey challenges must be stored with TTL and consumed once.
- `POST /web/passkey/*/verify` must reject replayed, expired or wrong-origin `clientDataJSON`.
- Registration must store credential metadata and require supported `credential_key_cose` metadata.
- Authentication must validate authenticator data, RP ID hash, user-present/user-verified flags and non-increasing signature counters.
- `CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND` must point to an audited verifier before passkeys are promoted beyond pre-signature validation.
- The fail-closed template `scripts/passkey-assertion-verify-command.sh` must never be used as a production verifier.
- Capture verifier version, negative tests and audit evidence in the release evidence bundle.
