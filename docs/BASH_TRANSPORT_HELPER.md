# Custodia Bash transport helper

The Bash helper is an ops/developer convenience wrapper around `curl` for Custodia REST/mTLS calls.

Native Bash code remains **transport-only**. It never implements encryption, decryption, HPKE envelope creation/opening, DEK management, private-key handling or recipient public-key resolution.

Patch 743 adds an optional external crypto-provider bridge. This makes Bash usable for encrypted workflows in CI/ops while keeping cryptography outside shell code.

## Supported uses

- CI/CD smoke checks.
- Release and deployment scripts.
- Manual metadata/status diagnostics.
- Uploading/downloading already-opaque payloads.
- Demonstrating mTLS REST calls without writing application code.
- Optional encrypted create/read/share/version flows through a provider executable.

## Unsupported native Bash uses

- Local plaintext encryption/decryption in shell code.
- HPKE envelope creation/opening in shell code.
- DEK management in shell code.
- Recipient public-key discovery in shell code.
- Long-running applications that need typed errors, retries or structured logging.

## Environment

```bash
export CUSTODIA_BASE_URL=https://vault:8443
export CUSTODIA_CLIENT_CERT=client.crt
export CUSTODIA_CLIENT_KEY=client.key
export CUSTODIA_CA_CERT=ca.crt
```

Optional external provider:

```bash
export CUSTODIA_CRYPTO_PROVIDER=/usr/local/bin/custodia-crypto-provider
```

`CUSTODIA_CRYPTO_PROVIDER` must point to an executable path or command name. It must not contain secret values or shell fragments.

## Raw transport example

```bash
clients/bash/custodia.sh status
clients/bash/custodia.sh create-secret-raw payload.json
clients/bash/custodia.sh get-secret-raw 550e8400-e29b-41d4-a716-446655440000
```

## External crypto-provider commands

```bash
clients/bash/custodia.sh create-secret-encrypted request.json
clients/bash/custodia.sh read-secret-decrypted 550e8400-e29b-41d4-a716-446655440000
clients/bash/custodia.sh share-secret-encrypted 550e8400-e29b-41d4-a716-446655440000 share-request.json
clients/bash/custodia.sh create-secret-version-encrypted 550e8400-e29b-41d4-a716-446655440000 version-request.json
```

Provider protocol:

```text
$CUSTODIA_CRYPTO_PROVIDER create-encrypted-secret < request.json > create-payload.json
$CUSTODIA_CRYPTO_PROVIDER read-decrypted-secret < raw-secret-response.json > plaintext-response.json
$CUSTODIA_CRYPTO_PROVIDER share-encrypted-secret < request.json > share-payload.json
$CUSTODIA_CRYPTO_PROVIDER create-encrypted-secret-version < request.json > version-payload.json
```

The provider must own all application-crypto responsibilities:

- canonical AAD construction;
- AES-256-GCM content encryption/decryption;
- HPKE-v1 recipient envelope creation/opening;
- local public-key resolution;
- local private-key handling;
- CSPRNG use;
- compatibility with `testdata/client-crypto/v1` vectors.

Bash only passes JSON through stdin/stdout and then calls raw REST/mTLS endpoints with opaque payloads.

## Security notes

- Do not run encrypted commands with shell tracing enabled.
- Do not pass plaintext, DEKs, private keys or passphrases as command-line arguments.
- Treat provider request/output files as sensitive.
- Prefer provider implementations in Go, Rust, Node, Python, Java or C++ that already pass the shared vectors.
- Use the full language SDKs for application code; use Bash only for ops/CI glue.

## Verification

```bash
make test-bash-client
```


## Safety notes

Path parameters are percent-encoded by the helper before invoking curl. External crypto-provider outputs must use server-compatible field names such as `envelope`; ad-hoc names such as `envelope_for_target` are rejected by the helper contract checks.
