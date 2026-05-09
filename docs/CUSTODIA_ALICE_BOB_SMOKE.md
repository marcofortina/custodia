# Alice/Bob encrypted secret smoke test

This runbook verifies a fresh Custodia install end to end with two mTLS clients and local application encryption keys.

It uses the preferred CSR flow: each client generates its own mTLS private key and CSR locally; the server signs only the CSR.

## Assumptions

The Lite server and signer are running:

```bash
sudo systemctl status custodia-server --no-pager
sudo systemctl status custodia-signer --no-pager
sudo ss -ltnp | grep -E ':(8443|9444)'
```

Set common paths:

```bash
export API=https://localhost:8443
export SIGNER=https://localhost:9444
export ADMIN_CA=/etc/custodia/ca.crt
export ADMIN_CERT=/etc/custodia/admin.crt
export ADMIN_KEY=/etc/custodia/admin.key
export WORK="$HOME/.config/custodia/alice-bob-smoke"
export ISSUE_ROOT=/var/lib/custodia/client-issue
export ALICE_ID=client_alice
export BOB_ID=client_bob

rm -rf "$WORK"
install -d -m 0700 "$WORK/alice" "$WORK/bob"
sudo install -o "$USER" -g "$USER" -m 0644 "$ADMIN_CA" "$WORK/ca.crt"
export CA="$WORK/ca.crt"
```

## 1. Generate Alice CSR locally and sign it

```bash
custodia-client mtls generate-csr \
  --client-id "$ALICE_ID" \
  --private-key-out "$WORK/alice/$ALICE_ID.key" \
  --csr-out "$WORK/alice/$ALICE_ID.csr"
```

Transfer Alice's CSR to the server/admin host when Alice is remote. Sign it:

```bash
ALICE_ISSUE_DIR="$ISSUE_ROOT/$ALICE_ID"
sudo rm -rf "$ALICE_ISSUE_DIR"
sudo install -d -o custodia -g custodia -m 0700 "$ALICE_ISSUE_DIR"
sudo install -o custodia -g custodia -m 0644 "$WORK/alice/$ALICE_ID.csr" "$ALICE_ISSUE_DIR/$ALICE_ID.csr"

sudo -u custodia custodia-admin \
  --server-url "$API" \
  --cert "$ADMIN_CERT" \
  --key "$ADMIN_KEY" \
  --ca "$ADMIN_CA" \
  client sign-csr \
  --signer-url "$SIGNER" \
  --client-id "$ALICE_ID" \
  --csr-file "$ALICE_ISSUE_DIR/$ALICE_ID.csr" \
  --certificate-out "$ALICE_ISSUE_DIR/$ALICE_ID.crt"

sudo install -o "$USER" -g "$USER" -m 0644 "$ALICE_ISSUE_DIR/$ALICE_ID.crt" "$WORK/alice/$ALICE_ID.crt"
sudo rm -rf "$ALICE_ISSUE_DIR"
```

Transfer Alice's signed certificate and `ca.crt` back to Alice when Alice is remote.

## 2. Generate Alice application crypto key and config

```bash
custodia-client key generate \
  --client-id "$ALICE_ID" \
  --private-key-out "$WORK/alice/$ALICE_ID.x25519.json" \
  --public-key-out "$WORK/alice/$ALICE_ID.x25519.pub.json"

ALICE_CONFIG="$WORK/alice/$ALICE_ID.config.json"

custodia-client config write \
  --out "$ALICE_CONFIG" \
  --server-url "$API" \
  --cert "$WORK/alice/$ALICE_ID.crt" \
  --key "$WORK/alice/$ALICE_ID.key" \
  --ca "$CA" \
  --client-id "$ALICE_ID" \
  --crypto-key "$WORK/alice/$ALICE_ID.x25519.json"

custodia-client config check --config "$ALICE_CONFIG"
custodia-client doctor --config "$ALICE_CONFIG" --online
```

## 3. Alice creates and reads an encrypted secret

```bash
printf 'super secret demo value' > "$WORK/alice/secret.txt"
chmod 600 "$WORK/alice/secret.txt"

custodia-client secret put \
  --config "$ALICE_CONFIG" \
  --name smoke-demo \
  --value-file "$WORK/alice/secret.txt" \
  > "$WORK/alice/secret.create.json"

SECRET_ID=$(python3 - <<'PY'
import json, os
print(json.load(open(os.environ['WORK'] + '/alice/secret.create.json'))['secret_id'])
PY
)

echo "$SECRET_ID" > "$WORK/secret.id"

custodia-client secret get \
  --config "$ALICE_CONFIG" \
  --secret-id "$SECRET_ID" \
  --out "$WORK/alice/readback.txt"

cat "$WORK/alice/readback.txt"
```

Expected output:

```text
super secret demo value
```

## 4. Generate Bob CSR locally and sign it

```bash
custodia-client mtls generate-csr \
  --client-id "$BOB_ID" \
  --private-key-out "$WORK/bob/$BOB_ID.key" \
  --csr-out "$WORK/bob/$BOB_ID.csr"
```

Transfer Bob's CSR to the server/admin host when Bob is remote. Sign it:

```bash
BOB_ISSUE_DIR="$ISSUE_ROOT/$BOB_ID"
sudo rm -rf "$BOB_ISSUE_DIR"
sudo install -d -o custodia -g custodia -m 0700 "$BOB_ISSUE_DIR"
sudo install -o custodia -g custodia -m 0644 "$WORK/bob/$BOB_ID.csr" "$BOB_ISSUE_DIR/$BOB_ID.csr"

sudo -u custodia custodia-admin \
  --server-url "$API" \
  --cert "$ADMIN_CERT" \
  --key "$ADMIN_KEY" \
  --ca "$ADMIN_CA" \
  client sign-csr \
  --signer-url "$SIGNER" \
  --client-id "$BOB_ID" \
  --csr-file "$BOB_ISSUE_DIR/$BOB_ID.csr" \
  --certificate-out "$BOB_ISSUE_DIR/$BOB_ID.crt"

sudo install -o "$USER" -g "$USER" -m 0644 "$BOB_ISSUE_DIR/$BOB_ID.crt" "$WORK/bob/$BOB_ID.crt"
sudo rm -rf "$BOB_ISSUE_DIR"
```

Transfer Bob's signed certificate and `ca.crt` back to Bob when Bob is remote.

## 5. Generate Bob application crypto key and config

```bash
custodia-client key generate \
  --client-id "$BOB_ID" \
  --private-key-out "$WORK/bob/$BOB_ID.x25519.json" \
  --public-key-out "$WORK/bob/$BOB_ID.x25519.pub.json"

BOB_CONFIG="$WORK/bob/$BOB_ID.config.json"

custodia-client config write \
  --out "$BOB_CONFIG" \
  --server-url "$API" \
  --cert "$WORK/bob/$BOB_ID.crt" \
  --key "$WORK/bob/$BOB_ID.key" \
  --ca "$CA" \
  --client-id "$BOB_ID" \
  --crypto-key "$WORK/bob/$BOB_ID.x25519.json"

custodia-client config check --config "$BOB_CONFIG"
custodia-client doctor --config "$BOB_CONFIG" --online
```

Before sharing, Bob should not be able to read Alice's secret:

```bash
custodia-client secret get \
  --config "$BOB_CONFIG" \
  --secret-id "$SECRET_ID" \
  --out "$WORK/bob.before-share.txt"
```

Expected: non-zero exit with an authorization error.

## 6. Alice shares the secret with Bob

Transfer Bob's public key `$WORK/bob/$BOB_ID.x25519.pub.json` to Alice through a trusted channel when Bob is remote.

```bash
custodia-client secret share \
  --config "$ALICE_CONFIG" \
  --secret-id "$SECRET_ID" \
  --target-client-id "$BOB_ID" \
  --recipient "$BOB_ID=$WORK/bob/$BOB_ID.x25519.pub.json" \
  --permissions 4
```

Transfer the `SECRET_ID` value to Bob when Bob is remote. Bob can now read and decrypt the secret locally:

```bash
custodia-client secret get \
  --config "$BOB_CONFIG" \
  --secret-id "$SECRET_ID" \
  --out "$WORK/bob/readback.txt"

cat "$WORK/bob/readback.txt"
```

Expected output:

```text
super secret demo value
```

## 7. Create a new encrypted version as Alice

```bash
printf 'rotated secret value' > "$WORK/alice/secret-v2.txt"
chmod 600 "$WORK/alice/secret-v2.txt"

custodia-client secret version put \
  --config "$ALICE_CONFIG" \
  --secret-id "$SECRET_ID" \
  --value-file "$WORK/alice/secret-v2.txt" \
  --recipient "$BOB_ID=$WORK/bob/$BOB_ID.x25519.pub.json" \
  > "$WORK/alice/version.create.json"
```

Bob reads the latest version:

```bash
custodia-client secret get \
  --config "$BOB_CONFIG" \
  --secret-id "$SECRET_ID" \
  --out "$WORK/bob/readback-v2.txt"

cat "$WORK/bob/readback-v2.txt"
```

Expected output:

```text
rotated secret value
```

## 8. Revoke Bob's future access

```bash
custodia-client secret access revoke \
  --config "$ALICE_CONFIG" \
  --secret-id "$SECRET_ID" \
  --target-client-id "$BOB_ID" \
  --yes
```

Bob's future reads should fail:

```bash
custodia-client secret get \
  --config "$BOB_CONFIG" \
  --secret-id "$SECRET_ID" \
  --out "$WORK/bob.after-revoke.txt"
```

Expected: non-zero exit with an authorization error.

## 9. Delete the smoke secret

```bash
custodia-client secret delete \
  --config "$ALICE_CONFIG" \
  --secret-id "$SECRET_ID" \
  --yes
```

## Security notes

- The vault never receives plaintext, DEKs, application private keys or recipient private keys.
- Client mTLS private keys are generated locally by `custodia-client mtls generate-csr` and are not staged on the server.
- Recipient public keys are local files exchanged through a trusted channel outside Custodia.
- Revocation stops future server-side reads. Material already downloaded by authorized clients remains outside server control.
