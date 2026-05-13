# Alice/Bob encrypted smoke test

This smoke test provisions two clients with client-side mTLS CSR generation, creates an encrypted secret as Alice, shares it with Bob, creates a new version, revokes Bob's future access, and deletes the secret.

The commands assume the server side is already running. Each client is enrolled with a short-lived token created on the server/admin host.

## 1. Provision Alice

On the server/admin host, create an enrollment token and transfer the printed server URL and token to Alice. Enrollment verifies TLS normally by default. This smoke test usually runs with the locally generated lab CA not installed in Alice's trust store yet, so the first disposable lab enrollment uses `--insecure`. For real remote clients, install/trust the Custodia CA first with [`CLIENT_TRUSTED_CA.md`](CLIENT_TRUSTED_CA.md) and remove `--insecure`:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

On Alice's client host, set the values printed by the server/admin host. Do not paste the literal placeholder token:

```bash
export ALICE_ID=client_alice
export CUSTODIA_SERVER_URL="https://SERVER_IP_OR_HOSTNAME:8443"
export ALICE_ENROLLMENT_TOKEN="ENROLLMENT_TOKEN"

custodia-client mtls enroll \
  --client-id "$ALICE_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$ALICE_ENROLLMENT_TOKEN" \
  --insecure

custodia-client key generate --client-id "$ALICE_ID"
custodia-client config write --client-id "$ALICE_ID"
custodia-client key publish --client-id "$ALICE_ID"
custodia-client config check --client-id "$ALICE_ID"
custodia-client doctor --client-id "$ALICE_ID" --online
```

`key publish` uploads only Alice's application public key and fingerprint. Alice's application private key remains local.

## 2. Alice creates and reads a secret

On Alice's client host:

```bash
ALICE_NAMESPACE=default
ALICE_KEY=alice-bob-demo
ALICE_SECRET="$HOME/custodia-alice-secret.txt"
ALICE_READBACK="$HOME/custodia-alice-readback.txt"

printf 'super secret demo value' > "$ALICE_SECRET"
chmod 600 "$ALICE_SECRET"

custodia-client secret put \
  --client-id "$ALICE_ID" \
  --namespace "$ALICE_NAMESPACE" \
  --key "$ALICE_KEY" \
  --value-file "$ALICE_SECRET"

custodia-client secret get \
  --client-id "$ALICE_ID" \
  --namespace "$ALICE_NAMESPACE" \
  --key "$ALICE_KEY" \
  --out "$ALICE_READBACK"

cat "$ALICE_READBACK"
```

Expected output:

```text
super secret demo value
```

## 3. Provision Bob

On the server/admin host, create a second enrollment token and transfer the printed server URL and token to Bob. Enrollment verifies TLS normally by default. This smoke test usually runs with the locally generated lab CA not installed in Bob's trust store yet, so the first disposable lab enrollment uses `--insecure`. For real remote clients, install/trust the Custodia CA first with [`CLIENT_TRUSTED_CA.md`](CLIENT_TRUSTED_CA.md) and remove `--insecure`:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

On Bob's client host, set the values printed by the server/admin host. Do not reuse Alice's token and do not paste the literal placeholder token:

```bash
export BOB_ID=client_bob
export CUSTODIA_SERVER_URL="https://SERVER_IP_OR_HOSTNAME:8443"
export BOB_ENROLLMENT_TOKEN="ENROLLMENT_TOKEN"

custodia-client mtls enroll \
  --client-id "$BOB_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$BOB_ENROLLMENT_TOKEN" \
  --insecure

custodia-client key generate --client-id "$BOB_ID"
custodia-client config write --client-id "$BOB_ID"
custodia-client key publish --client-id "$BOB_ID"
custodia-client config check --client-id "$BOB_ID"
custodia-client doctor --client-id "$BOB_ID" --online
```

`key publish` uploads only Bob's application public key and fingerprint. Bob's application private key remains local.

Before Alice shares the secret, Bob should not be able to decrypt it:

```bash
ALICE_NAMESPACE=default
ALICE_KEY=alice-bob-demo

if custodia-client secret get --client-id "$BOB_ID" --namespace "$ALICE_NAMESPACE" --key "$ALICE_KEY" --out "$HOME/custodia-bob-before-share.txt"; then
  echo "unexpected Bob access before share" >&2
  exit 1
fi
```

## 4. Alice shares with Bob

Bob has already published his application public key to Custodia metadata. On Alice's client host, set Bob's client id and share the secret:

```bash
ALICE_ID=client_alice
ALICE_NAMESPACE=default
ALICE_KEY=alice-bob-demo
BOB_ID=client_bob

custodia-client secret share \
  --client-id "$ALICE_ID" \
  --namespace "$ALICE_NAMESPACE" \
  --key "$ALICE_KEY" \
  --target-client-id "$BOB_ID" \
  --permissions read
```

The CLI resolves Bob's server-published public key and uploads only Bob's opaque envelope. If you need an offline or pinned-key workflow, Bob must transfer his application public key to Alice through a trusted channel and Alice can pass `--recipient "$BOB_ID=/path/to/client_bob.x25519.pub.json"`.

Transfer the namespace/key values to Bob. On Bob's client host:

```bash
ALICE_NAMESPACE=default
ALICE_KEY=alice-bob-demo
BOB_READBACK="$HOME/custodia-bob-readback.txt"

custodia-client secret get \
  --client-id "$BOB_ID" \
  --namespace "$ALICE_NAMESPACE" \
  --key "$ALICE_KEY" \
  --out "$BOB_READBACK"

cat "$BOB_READBACK"
```

Expected output:

```text
super secret demo value
```

## 5. Alice creates a new version for Alice and Bob

On Alice's client host:

```bash
ALICE_SECRET_V2="$HOME/custodia-alice-secret-v2.txt"
printf 'rotated secret value' > "$ALICE_SECRET_V2"
chmod 600 "$ALICE_SECRET_V2"

custodia-client secret update \
  --client-id "$ALICE_ID" \
  --namespace "$ALICE_NAMESPACE" \
  --key "$ALICE_KEY" \
  --value-file "$ALICE_SECRET_V2" \
  --recipient "$BOB_ID" \
  --permissions all
```

Bob can read the latest version:

```bash
custodia-client secret get \
  --client-id "$BOB_ID" \
  --namespace "$ALICE_NAMESPACE" \
  --key "$ALICE_KEY" \
  --out "$HOME/custodia-bob-readback-v2.txt"

cat "$HOME/custodia-bob-readback-v2.txt"
```

Expected output:

```text
rotated secret value
```

## 6. Revoke Bob's future access

On Alice's client host:

```bash
custodia-client secret access revoke \
  --client-id "$ALICE_ID" \
  --namespace "$ALICE_NAMESPACE" \
  --key "$ALICE_KEY" \
  --target-client-id "$BOB_ID" \
  --yes
```

After revocation, future server-side reads for Bob should fail:

```bash
ALICE_NAMESPACE=default
ALICE_KEY=alice-bob-demo

if custodia-client secret get --client-id "$BOB_ID" --namespace "$ALICE_NAMESPACE" --key "$ALICE_KEY" --out "$HOME/custodia-bob-after-revoke.txt"; then
  echo "unexpected Bob access after revoke" >&2
  exit 1
fi
```

## 7. Delete the smoke secret

On Alice's client host:

```bash
custodia-client secret delete \
  --client-id "$ALICE_ID" \
  --namespace "$ALICE_NAMESPACE" \
  --key "$ALICE_KEY" \
  --yes
```

Client mTLS private keys and application private keys stayed on each client host. The server only handled CSRs, signed certificates, application public-key metadata, ciphertext, crypto metadata and opaque envelopes.
