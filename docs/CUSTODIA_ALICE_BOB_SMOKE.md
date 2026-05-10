# Alice/Bob encrypted smoke test

This smoke test provisions two clients with client-side mTLS CSR generation, creates an encrypted secret as Alice, shares it with Bob, creates a new version, revokes Bob's future access, and deletes the secret.

The commands assume the server side is already running. Each client is enrolled with a short-lived token created on the server/admin host.

## 1. Provision Alice

On the server/admin host, create an enrollment token and transfer the printed server URL and token to Alice. Enrollment verifies TLS normally by default; use `--insecure` only for disposable first-run labs with an untrusted local CA:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

On Alice's client host:

```bash
export ALICE_ID=client_alice

custodia-client mtls enroll \
  --client-id "$ALICE_ID" \
  --server-url "https://SERVER_IP_OR_HOSTNAME:8443" \
  --enrollment-token "ENROLLMENT_TOKEN"

custodia-client key generate --client-id "$ALICE_ID"
custodia-client config write --client-id "$ALICE_ID"
custodia-client config check --client-id "$ALICE_ID"
custodia-client doctor --client-id "$ALICE_ID" --online
```

## 2. Alice creates and reads a secret

On Alice's client host:

```bash
ALICE_SECRET="$HOME/custodia-alice-secret.txt"
ALICE_CREATE="$HOME/custodia-alice-secret.create.json"
ALICE_READBACK="$HOME/custodia-alice-readback.txt"

printf 'super secret demo value' > "$ALICE_SECRET"
chmod 600 "$ALICE_SECRET"

custodia-client secret put \
  --client-id "$ALICE_ID" \
  --name alice-bob-demo \
  --value-file "$ALICE_SECRET" \
  > "$ALICE_CREATE"

SECRET_ID="$(python3 - <<'PY'
import json, os
print(json.load(open(os.path.expanduser('~/custodia-alice-secret.create.json')))['secret_id'])
PY
)"

custodia-client secret get \
  --client-id "$ALICE_ID" \
  --secret-id "$SECRET_ID" \
  --out "$ALICE_READBACK"

cat "$ALICE_READBACK"
```

Expected output:

```text
super secret demo value
```

## 3. Provision Bob

On the server/admin host, create a second enrollment token and transfer the printed server URL and token to Bob. Enrollment verifies TLS normally by default; use `--insecure` only for disposable first-run labs with an untrusted local CA:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

On Bob's client host:

```bash
export BOB_ID=client_bob

custodia-client mtls enroll \
  --client-id "$BOB_ID" \
  --server-url "https://SERVER_IP_OR_HOSTNAME:8443" \
  --enrollment-token "ENROLLMENT_TOKEN"

custodia-client key generate --client-id "$BOB_ID"
custodia-client config write --client-id "$BOB_ID"
custodia-client config check --client-id "$BOB_ID"
custodia-client doctor --client-id "$BOB_ID" --online
```

Before Alice shares the secret, Bob should not be able to decrypt it:

```bash
if custodia-client secret get --client-id "$BOB_ID" --secret-id "$SECRET_ID" --out "$HOME/custodia-bob-before-share.txt"; then
  echo "unexpected Bob access before share" >&2
  exit 1
fi
```

## 4. Alice shares with Bob

Transfer Bob's application public key to Alice through a trusted channel. On Alice's client host, set the path to Bob's received public key:

```bash
BOB_PUBLIC_KEY="$HOME/$BOB_ID.x25519.pub.json"
```

Then share the secret:

```bash
custodia-client secret share \
  --client-id "$ALICE_ID" \
  --secret-id "$SECRET_ID" \
  --target-client-id "$BOB_ID" \
  --recipient "$BOB_ID=$BOB_PUBLIC_KEY" \
  --permissions 4
```

Transfer the `SECRET_ID` value to Bob. On Bob's client host:

```bash
BOB_READBACK="$HOME/custodia-bob-readback.txt"

custodia-client secret get \
  --client-id "$BOB_ID" \
  --secret-id "$SECRET_ID" \
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

custodia-client secret version put \
  --client-id "$ALICE_ID" \
  --secret-id "$SECRET_ID" \
  --value-file "$ALICE_SECRET_V2" \
  --recipient "$BOB_ID=$BOB_PUBLIC_KEY" \
  --permissions 7
```

Bob can read the latest version:

```bash
custodia-client secret get \
  --client-id "$BOB_ID" \
  --secret-id "$SECRET_ID" \
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
  --secret-id "$SECRET_ID" \
  --target-client-id "$BOB_ID" \
  --yes
```

After revocation, future server-side reads for Bob should fail:

```bash
if custodia-client secret get --client-id "$BOB_ID" --secret-id "$SECRET_ID" --out "$HOME/custodia-bob-after-revoke.txt"; then
  echo "unexpected Bob access after revoke" >&2
  exit 1
fi
```

## 7. Delete the smoke secret

On Alice's client host:

```bash
custodia-client secret delete \
  --client-id "$ALICE_ID" \
  --secret-id "$SECRET_ID" \
  --yes
```

Client mTLS private keys and application private keys stayed on each client host. The server only handled CSRs, signed certificates, ciphertext, crypto metadata and opaque envelopes.
