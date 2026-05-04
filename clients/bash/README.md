# Custodia Bash transport helper

`clients/bash/custodia.sh` is a shell transport helper for CI, smoke tests and lightweight ops scripts.

It is **not** a high-level crypto SDK. It does not encrypt, decrypt, open envelopes, manage DEKs or resolve recipient public keys. Callers must provide already-opaque payloads produced by a real crypto client or application-side crypto code.

## Configuration

```bash
export CUSTODIA_BASE_URL=https://vault:8443
export CUSTODIA_CLIENT_CERT=client.crt
export CUSTODIA_CLIENT_KEY=client.key
export CUSTODIA_CA_CERT=ca.crt
```

Optional:

```bash
export CUSTODIA_USER_AGENT=custodia-bash-transport/0.0.0
```

## Usage

```bash
clients/bash/custodia.sh status
clients/bash/custodia.sh list-secrets
clients/bash/custodia.sh create-secret-raw payload.json
clients/bash/custodia.sh get-secret-raw 550e8400-e29b-41d4-a716-446655440000
clients/bash/custodia.sh share-secret-raw 550e8400-e29b-41d4-a716-446655440000 share.json
clients/bash/custodia.sh audit-export > audit.jsonl
```

## Security boundary

- Do not run with `set -x` around secret payloads.
- Do not put plaintext, DEKs, private keys or passphrases in shell history.
- Treat payload files as sensitive even when they contain only ciphertext/envelopes.
- Prefer Go/Python/Node/Java/C++/Rust high-level clients for local crypto flows.

## Test

```bash
make test-bash-client
```
