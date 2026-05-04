# Custodia Bash transport helper

`clients/bash/custodia.sh` is a shell transport helper for CI, smoke tests and lightweight ops scripts.

Native Bash code is **not** a high-level crypto SDK. It does not encrypt, decrypt, open envelopes, manage DEKs or resolve recipient public keys.

For encrypted flows it can optionally delegate to an **external crypto provider** executable. In that mode Bash only orchestrates provider stdin/stdout JSON and then sends the opaque REST payload to Custodia.

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
export CUSTODIA_CRYPTO_PROVIDER=/usr/local/bin/custodia-crypto-provider
```

`CUSTODIA_CRYPTO_PROVIDER` must be an executable path or command name. Do not include plaintext, DEKs, private keys or passphrases in that value.

## Raw transport usage

```bash
clients/bash/custodia.sh status
clients/bash/custodia.sh list-secrets
clients/bash/custodia.sh create-secret-raw payload.json
clients/bash/custodia.sh get-secret-raw 550e8400-e29b-41d4-a716-446655440000
clients/bash/custodia.sh share-secret-raw 550e8400-e29b-41d4-a716-446655440000 share.json
clients/bash/custodia.sh audit-export > audit.jsonl
```

## External crypto-provider usage

```bash
clients/bash/custodia.sh create-secret-encrypted request.json
clients/bash/custodia.sh read-secret-decrypted 550e8400-e29b-41d4-a716-446655440000
clients/bash/custodia.sh share-secret-encrypted 550e8400-e29b-41d4-a716-446655440000 share-request.json
clients/bash/custodia.sh create-secret-version-encrypted 550e8400-e29b-41d4-a716-446655440000 version-request.json
```

Provider contract:

```text
$CUSTODIA_CRYPTO_PROVIDER create-encrypted-secret < request.json > create-payload.json
$CUSTODIA_CRYPTO_PROVIDER read-decrypted-secret < raw-secret-response.json > plaintext-response.json
$CUSTODIA_CRYPTO_PROVIDER share-encrypted-secret < request.json > share-payload.json
$CUSTODIA_CRYPTO_PROVIDER create-encrypted-secret-version < request.json > version-payload.json
```

The provider, not Bash, is responsible for canonical AAD, AES-256-GCM, HPKE-v1 envelopes, local key resolution, safe randomness and compatibility with the shared client crypto vectors.

## Security boundary

- Do not run with `set -x` around secret payloads.
- Do not put plaintext, DEKs, private keys or passphrases in shell history.
- Treat request, provider-output and raw response files as sensitive.
- Provider input/output must use stdin/stdout JSON, not secret-bearing command-line arguments.
- Prefer Go/Python/Node/Java/C++/Rust high-level clients for application crypto flows.

## Test

```bash
make test-bash-client
```


## Safety notes

Path parameters are percent-encoded by the helper before invoking curl. External crypto-provider outputs must use server-compatible field names such as `envelope`; ad-hoc names such as `envelope_for_target` are rejected by the helper contract checks.
