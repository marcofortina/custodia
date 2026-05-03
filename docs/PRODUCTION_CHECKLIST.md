# Custodia production checklist

This checklist turns the Fort Knox analysis into deployable operator gates. It does not change the cryptographic boundary: Custodia stores and authorizes opaque ciphertext/envelope blobs only.

## Required before production

- API listener serves TLS 1.3 with `ClientAuth: RequireAndVerifyClientCert`.
- `CUSTODIA_STORE_BACKEND=postgres` or a CockroachDB-compatible PostgreSQL endpoint is configured.
- `CUSTODIA_RATE_LIMIT_BACKEND=valkey` is configured for shared rate limits.
- `CUSTODIA_CLIENT_CRL_FILE` is mounted when local CRL enforcement is used.
- `vault-admin revocation status` is monitored and alerts before CRL expiry.
- `/ready` runs on a dedicated health listener that is not exposed outside the cluster.
- Admin client IDs are explicitly configured; no wildcard admin mode exists.
- Web console remains metadata-only and requires admin mTLS; enable TOTP MFA before production.
- Passkey challenge endpoints are available, but keep TOTP enabled until full assertion verification is completed and audited.
- Audit export integrity headers are validated by downstream archival jobs with `vault-admin audit verify-export`.
- Audit export artifacts are bundled with `vault-admin audit archive-export` before WORM/SIEM ingestion.
- Verified audit archive bundles are shipped with `vault-admin audit ship-archive` before SIEM/WORM ingestion.
- `CUSTODIA_SIGNER_KEY_PROVIDER` is explicitly set; production must not rely on file-backed CA keys unless this is an isolated bootstrap environment.

## Must remain false

- Do not add a server-side public-key directory.
- Do not add DEK, wrapped DEK or key unwrap logic to the server.
- Do not render ciphertext/envelopes in web pages.
- Do not use the memory store for production.
- Do not disable web MFA on externally reachable deployments.
