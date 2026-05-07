# Custodia formal verification scope

Custodia ships both an executable Go invariant model and a TLA+ access-control model. These artifacts cover server-side authorization state transitions, not client-side cryptography.

## Implemented artifacts

- `internal/formalmodel`: executable state-machine model with Go tests.
- `formal/CustodiaAccess.tla`: TLA+ model for client activation, access grants, client revocation and strong secret-version revocation.
- `formal/CustodiaAccess.cfg`: bounded TLC configuration.
- `make formal-check`: wrapper for a local TLC installation.

## Model boundary

The server model includes:

- active/revoked client state;
- `secret_access` read authorization;
- version-aware strong revocation;
- pending grant activation as a server-side authorization transition.

The model excludes:

- plaintext secrets;
- DEK wrapping/unwrapping;
- encryption public-key discovery;
- browser/client cryptographic behavior;
- passkey/WebAuthn cryptographic verification.

## Invariants

- A revoked client cannot retain read access.
- Strong revocation removes old secret versions from readable access.
- Access entries must reference positive configured versions.
- The server never derives plaintext from stored blobs.

## Production use

Formal artifacts are useful as regression gates during design changes. They are not a replacement for integration tests, mTLS tests, external WORM storage validation or PKCS#11/HSM certification.
