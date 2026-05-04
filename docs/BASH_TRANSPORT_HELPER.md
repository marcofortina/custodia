# Custodia Bash transport helper

The Bash helper is an ops/developer convenience wrapper around `curl` for raw Custodia REST/mTLS calls.

It is intentionally **transport-only** and is not part of the high-level crypto SDK set. It never encrypts, decrypts, opens envelopes, derives DEKs, manages private keys or resolves recipient public keys.

## Supported uses

- CI/CD smoke checks.
- Release and deployment scripts.
- Manual metadata/status diagnostics.
- Uploading/downloading already-opaque payloads.
- Demonstrating mTLS REST calls without writing application code.

## Unsupported uses

- Local plaintext encryption/decryption.
- HPKE envelope creation/opening.
- DEK management.
- Recipient public-key discovery.
- Long-running applications that need typed errors, retries or structured logging.

## Environment

```bash
export CUSTODIA_BASE_URL=https://vault:8443
export CUSTODIA_CLIENT_CERT=client.crt
export CUSTODIA_CLIENT_KEY=client.key
export CUSTODIA_CA_CERT=ca.crt
```

## Example

```bash
clients/bash/custodia.sh status
clients/bash/custodia.sh create-secret-raw payload.json
clients/bash/custodia.sh get-secret-raw 550e8400-e29b-41d4-a716-446655440000
```

## Verification

```bash
make test-bash-client
```
