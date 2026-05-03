# Custodia Phase 2 closure

Phase 2 is closed as the repository hardening baseline for Custodia.

## Goal

Phase 2 hardened the secure vault baseline with stronger operational controls, client lifecycle behavior, MFA, revocation semantics, rate limiting, audit integrity and SDK/operator usability.

## Closed in the repository

- Strong revocation/version-aware access behavior.
- Client lifecycle and certificate/signing service boundary.
- CRL-backed revocation status and serial-status checks.
- Valkey-compatible rate limiting.
- TOTP-backed web MFA.
- Passkey/WebAuthn server-side hardening boundary:
  - challenge TTL;
  - consume-once anti-replay;
  - origin checks;
  - credential id metadata;
  - authenticatorData parsing;
  - RP ID hash validation;
  - user-present and user-verified flag checks;
  - sign counter handling;
  - COSE credential-key metadata parsing;
  - external assertion verifier adapter.
- Go/Python SDK helpers for operational APIs.
- Audit export integrity and verification helpers.
- Production/readiness guardrails for unsafe defaults.

## WebAuthn boundary

The repository is ready to delegate final WebAuthn assertion signature verification to an audited verifier command.

The repository does not claim to contain an in-process full WebAuthn implementation unless a dedicated audited WebAuthn library is integrated.

Acceptable production paths are:

1. keep the external verifier adapter and provide a real audited command, for example implemented with a mature WebAuthn library;
2. replace the adapter with an in-process verifier built on an audited library and update this closure document accordingly.

Do not hand-write complete CBOR/COSE/signature verification inside the vault code unless it receives the same audit/testing treatment as the rest of the security boundary.

## Verification gates

Run:

```bash
go test -p=1 -timeout 60s ./...
go build ./cmd/custodia-server ./cmd/vault-admin ./cmd/custodia-signer
python3 -m py_compile clients/python/custodia_client/__init__.py
bash -n scripts/release-check.sh scripts/check-formal.sh scripts/pkcs11-sign-command.sh scripts/softhsm-dev-token.sh scripts/minio-object-lock-smoke.sh scripts/k3s-cockroachdb-smoke.sh scripts/passkey-assertion-verify-command.sh
make passkey-assertion-verifier-template-check
```

Expected result: all checks pass.

## Required production evidence

Phase 2 repository closure does not itself prove the external WebAuthn verifier is production-grade. Production sign-off must include evidence for:

- the configured passkey assertion verifier command;
- its WebAuthn library/version;
- supported algorithms and attestation policy;
- negative tests for challenge replay, origin mismatch, RP ID mismatch, counter replay and signature failure.

## Closure statement

Phase 2 is closed at repository level when tests/builds pass, TOTP remains a real MFA path, and passkey assertion verification is either delegated to a configured audited verifier or explicitly held behind production evidence gates.
