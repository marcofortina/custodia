# Custodia client CLI

`custodia-client` is the end-user encrypted secrets CLI. It is separate from `custodia-admin`: the admin CLI manages server metadata, certificates and audit workflows, while `custodia-client` creates, reads, shares and rotates secrets with client-side encryption.

The CLI never sends plaintext, DEKs, mTLS private keys or application private keys to the server. It may publish an application public key and fingerprint with `key publish`; secret writes still send only ciphertext, versioned `crypto_metadata` and opaque recipient envelopes.

## Namespace/key addressing

The normal client workflow addresses secrets by `namespace + key`, with `namespace=default` when omitted. The full create, read, update, share, revoke and delete semantics are documented in [`SECRET_KEYSPACE_MODEL.md`](SECRET_KEYSPACE_MODEL.md). Generated server ids are internal details and are not needed for normal CLI flows.

## Standard client profile

For most commands, pass a client id instead of repeating every path:

```bash
export CLIENT_ID=client_alice
```

`custodia-client` derives the local profile directory from the XDG config location:

```text
$XDG_CONFIG_HOME/custodia/client_alice
```

or, when `XDG_CONFIG_HOME` is not set:

```text
$HOME/.config/custodia/client_alice
```

The default profile files are:

```text
client_alice.key
client_alice.csr
client_alice.crt
ca.crt
client_alice.x25519.json
client_alice.x25519.pub.json
client_alice.config.json
```

Use `--config`, explicit path flags or environment variables only for advanced automation.

## Profile management

Inspect local profiles without exposing private key material:

```bash
custodia-client profile list
custodia-client profile path --client-id "$CLIENT_ID"
custodia-client profile show --client-id "$CLIENT_ID"
```

`profile list` reads only the standard per-user profile base directory and returns valid client ids found under `$XDG_CONFIG_HOME/custodia`, or `$HOME/.config/custodia` when `XDG_CONFIG_HOME` is not set. It never reads `/etc/custodia-client`.

`profile path` prints the resolved standard profile directory for the selected client id. `profile show` prints file presence and public/reference paths such as the profile directory, config file, CSR, certificate, CA, server URL and public application key. It deliberately does not print mTLS private-key paths, application private-key paths, private-key content, tokens or secret values.

Delete a local profile only with explicit confirmation:

```bash
custodia-client profile delete --client-id "$CLIENT_ID" --yes
```

Deletion removes the local per-user profile directory and all files inside it. It does not revoke the client on the server, delete secrets, revoke access grants or rotate application keys. Use the admin/client lifecycle commands separately for server-side revocation.

## Client mTLS material

The preferred remote-client workflow uses a short-lived enrollment token created by an admin. The client generates its mTLS private key locally, submits only a CSR to Custodia, and receives only public certificate material.

On the server/admin host, create a one-shot enrollment token:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

Transfer the printed server URL and token to the client host. Enrollment verifies TLS normally by default; use `--insecure` only for disposable first-run labs with an untrusted local CA. For production-style enrollment, trust the Custodia CA first with [`CLIENT_TRUSTED_CA.md`](CLIENT_TRUSTED_CA.md). Then set the printed values on the client host and enroll the client. Do not paste the literal placeholder token:

```bash
export CUSTODIA_SERVER_URL="https://SERVER_IP_OR_HOSTNAME:8443"
export CUSTODIA_ENROLLMENT_TOKEN="ENROLLMENT_TOKEN"

custodia-client mtls enroll \
  --client-id "$CLIENT_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$CUSTODIA_ENROLLMENT_TOKEN"
```

This writes the mTLS private key, CSR, signed certificate and CA certificate into the standard client profile. The mTLS private key remains local to the client host.

If enrollment fails, read the `hint:` line printed by the CLI before retrying. Token errors usually require a fresh one-shot token. TLS trust errors require trusting the Custodia CA, using a `--server-url` host/IP covered by the server certificate SANs, or using `--insecure` only for a disposable lab bootstrap. DNS/network errors mean the client host cannot reach the API listener. A `404` usually means the URL points at the wrong listener. Existing local profile files are checked before the token is claimed, so refusing to overwrite local material does not consume the enrollment token.

Manual CSR signing remains available for advanced/offline workflows with `custodia-client mtls generate-csr`, `custodia-admin client sign-csr` and `custodia-client mtls install-cert`.

## Application encryption key

Generate a local X25519 application key pair for the same client identity:

```bash
custodia-client key generate --client-id "$CLIENT_ID"
```

The private key file is local secret material and is written with mode `0600`. The public key file is not secret material, but clients still need a trust policy for it. Publish the application public key and its fingerprint to Custodia after writing the reusable profile:

```bash
custodia-client config write --client-id "$CLIENT_ID"
custodia-client key publish --client-id "$CLIENT_ID"
```

`key publish` uploads only the X25519 public key and fingerprint for the authenticated mTLS client. It never uploads the X25519 private key, plaintext, DEKs or envelopes. Other clients can use that server-published metadata for normal `--recipient CLIENT_ID` resolution, while pinned/offline workflows can still pass `--recipient CLIENT_ID=/path/to/public.json`. Inspect a private key without exposing it with:

```bash
custodia-client key inspect --key "$HOME/.config/custodia/$CLIENT_ID/$CLIENT_ID.x25519.json"
```

The command prints the client id, crypto scheme and derived public-key fingerprint only.

## Reusable client config

Write a local JSON config file after enrollment and application key generation if you have not already done so before `key publish`:

```bash
custodia-client config write --client-id "$CLIENT_ID"
```

The config file stores paths and identifiers, not private key material, but it is still written with mode `0600` because it references local secret-bearing files. Validate the profile and its referenced local mTLS/crypto files with:

```bash
custodia-client config check --client-id "$CLIENT_ID"
```

`config check` is local/offline: it validates the HTTPS URL, certificate/key pair, CA bundle and optional crypto key without contacting Custodia. This catches most path/key mistakes before running put/get/share commands.

You can also run an online current-client check:

```bash
custodia-client doctor --client-id "$CLIENT_ID" --online
```

## Environment variables and explicit config

The same profile can be selected with:

```bash
export CUSTODIA_CLIENT_ID=client_alice
```

Advanced automation may still use explicit files:

```bash
export CUSTODIA_CLIENT_CONFIG=/path/to/client_alice.config.json
export CUSTODIA_BASE_URL=https://localhost:8443
export CUSTODIA_CLIENT_CERT=/path/to/client_alice.crt
export CUSTODIA_CLIENT_KEY=/path/to/client_alice.key
export CUSTODIA_CA_CERT=/path/to/ca.crt
export CUSTODIA_CRYPTO_KEY=/path/to/client_alice.x25519.json
```

Explicit flags and environment variables override values loaded from the config file. In `secret` subcommands, `--key` identifies the secret; when using raw mTLS paths instead of `--client-id`/`--config`, pass the mTLS private key as `--mtls-key` or through `CUSTODIA_CLIENT_KEY`.

## Put an encrypted secret

Create a plaintext file outside the client profile:

```bash
printf 'super secret demo value' > "$HOME/custodia-smoke-secret.txt"
chmod 600 "$HOME/custodia-smoke-secret.txt"
```

Create an encrypted secret. The caller is automatically added as a recipient, so the creator can read the secret later:

```bash
custodia-client secret put \
  --client-id "$CLIENT_ID" \
  --key smoke-demo \
  --value-file "$HOME/custodia-smoke-secret.txt"
```

When `--namespace` is omitted the CLI uses `default`. The command prints JSON containing internal server identifiers for audit/debugging, but follow-up user flows should address the secret by `namespace/key`.

## Get and decrypt a secret

```bash
custodia-client secret get \
  --client-id "$CLIENT_ID" \
  --key smoke-demo \
  --out "$HOME/custodia-smoke-secret.readback.txt"
```

Plaintext output files are written with mode `0600`. Use `--out -` to write plaintext to stdout. Avoid stdout in shell history or shared terminals for real secrets.

## Share a secret with another client

Bob must have a registered mTLS client certificate and must have published his application public key with `custodia-client key publish`. Alice can then share by target client id:

```bash
custodia-client secret share \
  --client-id client_alice \
  --key smoke-demo \
  --target-client-id client_bob \
  --permissions read
```

The CLI opens Alice's current envelope locally, resolves Bob's public key from server-published metadata unless a pinned `--recipient client_bob=/path/to/client_bob.x25519.pub.json` override is supplied, rewraps the existing DEK for Bob, and sends only Bob's opaque envelope to the server.

`--permissions` accepts readable names (`read`, `write`, `share`, `all`) or comma-separated combinations such as `read,write`. Numeric bitmasks remain accepted for advanced/debug workflows.

## Create a new encrypted version

Create a rotated plaintext file and include all intended recipients for the new version:

```bash
printf 'rotated secret demo value' > "$HOME/custodia-smoke-secret.v2.txt"
chmod 600 "$HOME/custodia-smoke-secret.v2.txt"

custodia-client secret update \
  --client-id client_alice \
  --key smoke-demo \
  --value-file "$HOME/custodia-smoke-secret.v2.txt" \
  --recipient client_bob \
  --permissions all
```

The creator is automatically included as a recipient. Other authorized clients must be provided explicitly with `--recipient CLIENT_ID` so the CLI can resolve their server-published public keys. Use `--recipient CLIENT_ID=/path/to/public.json` for pinned/offline overrides.

## List authorized secrets

```bash
custodia-client secret list --client-id "$CLIENT_ID" --limit 50
```

## List versions and access grants

Inspect version metadata for a secret without decrypting payloads:

```bash
custodia-client secret versions \
  --client-id "$CLIENT_ID" \
  --key smoke-demo \
  --limit 50
```

Inspect the server-side access grants for a secret. The output contains grant metadata and never includes recipient envelopes or plaintext:

```bash
custodia-client secret access list \
  --client-id "$CLIENT_ID" \
  --key smoke-demo \
  --limit 50
```

## Revoke a client's future access

Revoke a target client's future server-side access to a secret. This does not make already downloaded ciphertext/envelope material undecryptable; for strong revocation, create a new encrypted version with only the remaining authorized recipients.

```bash
custodia-client secret access revoke \
  --client-id client_alice \
  --key smoke-demo \
  --target-client-id client_bob \
  --yes
```

## Delete a secret

Delete semantics depend on ownership. Owners delete only when no active shares remain, unless `--cascade` is supplied. Non-owners delete only their own visibility/access to a shared key.

```bash
custodia-client secret delete \
  --client-id "$CLIENT_ID" \
  --key smoke-demo \
  --yes
```

For owner-side destructive cleanup of an actively shared key:

```bash
custodia-client secret delete \
  --client-id "$CLIENT_ID" \
  --key smoke-demo \
  --cascade \
  --yes
```

## Security notes

- mTLS private keys identify the client to Custodia and stay in the per-user profile.
- X25519 key files are application encryption keys and must stay local to the client/operator.
- Recipient public keys can be resolved from Custodia's authenticated public-key metadata or pinned explicitly with `--recipient CLIENT_ID=/path/to/public.json`; Custodia is not a trust oracle for key substitution.
- The CLI does not use the Web Console and does not send plaintext to the server.
- `custodia-admin certificate bundle` packages mTLS transport material only; it does not include application crypto keys.

## End-to-end Alice/Bob smoke test

For a complete first-run workflow that registers two mTLS clients, issues certificates, creates local application keys, stores an encrypted secret, shares it and rotates it, see [`CUSTODIA_ALICE_BOB_SMOKE.md`](CUSTODIA_ALICE_BOB_SMOKE.md).
