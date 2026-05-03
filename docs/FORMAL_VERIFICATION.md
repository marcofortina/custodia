# Custodia formal verification scope

The Fort Knox analysis calls out formal verification for the protocol. This document scopes what should be modeled without inventing server-side cryptography.

## Model boundary

The server model includes:

- mTLS-authenticated client identity.
- active/revoked client state.
- `secret_access` authorization checks.
- permission bits: read, write, share.
- version superseding for strong revocation.
- pending grant activation requiring an authorized sharer.

The server model excludes:

- plaintext secrets.
- DEK wrapping/unwrapping.
- encryption public-key discovery.
- client-side key resolver behavior.

## Invariants

- A client without active read access cannot read a secret version.
- A revoked client cannot obtain new secret material from the vault.
- Share activation cannot complete without a client that currently has share permission.
- Creating a new strong-revocation version supersedes old active versions.
- The server never derives plaintext from stored blobs.

## Suggested next artifact

A TLA+ spec should model state transitions for clients, secret versions, access grants and revocations. ProVerif should be reserved for a separate client-side cryptographic protocol, not for server storage logic.
