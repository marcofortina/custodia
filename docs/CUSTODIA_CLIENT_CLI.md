# Custodia client CLI

`custodia-client` is the end-user encrypted secrets CLI. It is separate from `custodia-admin`: the admin CLI manages server metadata, certificates and audit workflows, while `custodia-client` creates, reads, shares and rotates secrets with client-side encryption.

The CLI never sends plaintext, DEKs, private keys or recipient public keys to the server. It sends only ciphertext, versioned `crypto_metadata` and opaque recipient envelopes.

## Key files

Generate a local X25519 application key pair for each Custodia client identity:

```bash
custodia-client key generate \
  --client-id client_alice \
  --private-key-out client_alice.x25519.json \
  --public-key-out client_alice.x25519.pub.json
```

The private key file is local secret material and is written with mode `0600`. The public key file may be distributed through an application-controlled trust channel, for example configuration management, a pinned repository, an internal directory or offline provisioning.

The server is not a public-key directory. Recipient public keys are loaded from local files with `--recipient`.

## Common mTLS options

All secret commands require the transport mTLS identity:

```bash
--server-url https://localhost:8443 \
--cert client_alice.crt \
--key client_alice.key \
--ca /etc/custodia/ca.crt
```

The same values may be provided through environment variables:

```bash
export CUSTODIA_BASE_URL=https://localhost:8443
export CUSTODIA_CLIENT_CERT=client_alice.crt
export CUSTODIA_CLIENT_KEY=client_alice.key
export CUSTODIA_CA_CERT=/etc/custodia/ca.crt
export CUSTODIA_CLIENT_ID=client_alice
export CUSTODIA_CRYPTO_KEY=client_alice.x25519.json
```

## Put an encrypted secret

Create a plaintext file locally:

```bash
printf 'super secret demo value' > secret.txt
chmod 600 secret.txt
```

Create an encrypted secret. The caller is automatically added as a recipient, so the creator can read the secret later:

```bash
custodia-client secret put \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --client-id client_alice \
  --crypto-key client_alice.x25519.json \
  --name smoke-demo \
  --value-file secret.txt
```

The command prints JSON containing `secret_id` and `version_id`.

## Get and decrypt a secret

```bash
custodia-client secret get \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --client-id client_alice \
  --crypto-key client_alice.x25519.json \
  --secret-id <secret_id> \
  --out secret.readback.txt
```

Plaintext output files are written with mode `0600`. Use `--out -` to write plaintext to stdout. Avoid stdout in shell history or shared terminals for real secrets.

## Share a secret with another client

Bob must have a registered mTLS client certificate and a local application public key file. Alice needs Bob's public key file from a trusted channel:

```bash
custodia-client secret share \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --client-id client_alice \
  --crypto-key client_alice.x25519.json \
  --secret-id <secret_id> \
  --target-client-id client_bob \
  --recipient client_bob=client_bob.x25519.pub.json \
  --permissions 4
```

The CLI opens Alice's current envelope locally, rewraps the existing DEK for Bob, and sends only Bob's opaque envelope to the server.

## Create a new encrypted version

Create a rotated plaintext file and include all intended recipients for the new version:

```bash
printf 'rotated secret demo value' > secret.v2.txt
chmod 600 secret.v2.txt

custodia-client secret version put \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --client-id client_alice \
  --crypto-key client_alice.x25519.json \
  --secret-id <secret_id> \
  --value-file secret.v2.txt \
  --recipient client_bob=client_bob.x25519.pub.json \
  --permissions 7
```

The creator is automatically included as a recipient. Other authorized clients must be provided explicitly with `--recipient` so they can read the new version.

## List authorized secrets

```bash
custodia-client secret list \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --limit 50
```

## List versions and access grants

Inspect version metadata for a secret without decrypting payloads:

```bash
custodia-client secret versions \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --secret-id <secret_id> \
  --limit 50
```

Inspect the server-side access grants for a secret. The output contains grant metadata and never includes recipient envelopes or plaintext:

```bash
custodia-client secret access list \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --secret-id <secret_id> \
  --limit 50
```

## Revoke a client's future access

Revoke a target client's future server-side access to a secret. This does not make already downloaded ciphertext/envelope material undecryptable; for strong revocation, create a new encrypted version with only the remaining authorized recipients.

```bash
custodia-client secret access revoke \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --secret-id <secret_id> \
  --target-client-id client_bob \
  --yes
```

## Delete a secret

Delete a secret from future server-side reads. This is a destructive metadata operation and requires explicit confirmation.

```bash
custodia-client secret delete \
  --server-url https://localhost:8443 \
  --cert client_alice.crt \
  --key client_alice.key \
  --ca /etc/custodia/ca.crt \
  --secret-id <secret_id> \
  --yes
```

## Security notes

- mTLS private keys identify the client to Custodia.
- X25519 key files are application encryption keys and must stay local to the client/operator.
- Recipient public keys must be pinned or resolved outside Custodia.
- The CLI does not use the Web Console and does not send plaintext to the server.
- `custodia-admin certificate bundle` packages mTLS transport material only; it does not include application crypto keys.
