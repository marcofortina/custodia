# Alice/Bob encrypted secret smoke test

This runbook verifies a fresh Custodia install end to end with two mTLS clients and local application encryption keys.

It covers:

1. registering `client_alice` and issuing her mTLS certificate;
2. generating Alice's local X25519 application key;
3. creating and reading an encrypted secret as Alice;
4. registering `client_bob` and issuing his mTLS certificate;
5. sharing Alice's secret with Bob;
6. reading the shared secret as Bob;
7. creating a new encrypted version;
8. revoking Bob's future access.

The vault never receives plaintext, DEKs, private keys or recipient public keys. Recipient public keys are local files exchanged through a trusted channel outside Custodia.

## Assumptions

The Lite server and signer are running:

```bash
sudo systemctl status custodia --no-pager
sudo systemctl status custodia-signer --no-pager
sudo ss -ltnp | grep -E ':(8443|9444)'
```

Set common paths:

```bash
export API=https://localhost:8443
export SIGNER=https://localhost:9444
export CA=/etc/custodia/ca.crt
export ADMIN_CERT=/etc/custodia/admin.crt
export ADMIN_KEY=/etc/custodia/admin.key
export WORK=/tmp/custodia-alice-bob

mkdir -p "$WORK"
chmod 700 "$WORK"
```

## 1. Register and issue Alice

Register Alice metadata in the vault:

```bash
custodia-admin \
  --server-url "$API" \
  --cert "$ADMIN_CERT" \
  --key "$ADMIN_KEY" \
  --ca "$CA" \
  client create \
  --client-id client_alice \
  --mtls-subject client_alice
```

Generate Alice's mTLS key and CSR locally:

```bash
custodia-admin client csr \
  --client-id client_alice \
  --private-key-out "$WORK/client_alice.key" \
  --csr-out "$WORK/client_alice.csr"
```

Sign Alice's CSR through `custodia-signer` and extract the certificate:

```bash
custodia-admin \
  --server-url "$SIGNER" \
  --cert "$ADMIN_CERT" \
  --key "$ADMIN_KEY" \
  --ca "$CA" \
  certificate sign \
  --client-id client_alice \
  --csr-file "$WORK/client_alice.csr" \
  > "$WORK/client_alice.sign.json"

custodia-admin certificate extract \
  --input "$WORK/client_alice.sign.json" \
  --certificate-out "$WORK/client_alice.crt"
```

Optionally create a local handoff bundle:

```bash
custodia-admin certificate bundle \
  --certificate "$WORK/client_alice.crt" \
  --private-key "$WORK/client_alice.key" \
  --ca "$CA" \
  --out "$WORK/client_alice-mtls.zip"
```

Verify Alice's mTLS identity:

```bash
custodia-client secret list \
  --server-url "$API" \
  --cert "$WORK/client_alice.crt" \
  --key "$WORK/client_alice.key" \
  --ca "$CA"
```

## 2. Generate Alice's application crypto key

```bash
custodia-client key generate \
  --client-id client_alice \
  --private-key-out "$WORK/client_alice.x25519.json" \
  --public-key-out "$WORK/client_alice.x25519.pub.json"

custodia-client key inspect --key "$WORK/client_alice.x25519.json"
```

Create a reusable Alice profile and validate it offline:

```bash
custodia-client config write \
  --out "$WORK/client_alice.config.json" \
  --server-url "$API" \
  --cert "$WORK/client_alice.crt" \
  --key "$WORK/client_alice.key" \
  --ca "$CA" \
  --client-id client_alice \
  --crypto-key "$WORK/client_alice.x25519.json"

custodia-client config check --config "$WORK/client_alice.config.json"
```

## 3. Alice creates and reads an encrypted secret

```bash
printf 'super secret demo value' > "$WORK/secret.txt"
chmod 600 "$WORK/secret.txt"

custodia-client secret put \
  --config "$WORK/client_alice.config.json" \
  --name smoke-demo \
  --value-file "$WORK/secret.txt" \
  > "$WORK/secret.create.json"

SECRET_ID=$(python3 - <<'PY'
import json, os
print(json.load(open(os.environ['WORK'] + '/secret.create.json'))['secret_id'])
PY
)

echo "$SECRET_ID" > "$WORK/secret.id"
```

Read it back as Alice:

```bash
custodia-client secret get \
  --config "$WORK/client_alice.config.json" \
  --secret-id "$SECRET_ID" \
  --out "$WORK/alice.readback.txt"

cat "$WORK/alice.readback.txt"
```

Expected output:

```text
super secret demo value
```

## 4. Register and issue Bob

```bash
custodia-admin \
  --server-url "$API" \
  --cert "$ADMIN_CERT" \
  --key "$ADMIN_KEY" \
  --ca "$CA" \
  client create \
  --client-id client_bob \
  --mtls-subject client_bob

custodia-admin client csr \
  --client-id client_bob \
  --private-key-out "$WORK/client_bob.key" \
  --csr-out "$WORK/client_bob.csr"

custodia-admin \
  --server-url "$SIGNER" \
  --cert "$ADMIN_CERT" \
  --key "$ADMIN_KEY" \
  --ca "$CA" \
  certificate sign \
  --client-id client_bob \
  --csr-file "$WORK/client_bob.csr" \
  > "$WORK/client_bob.sign.json"

custodia-admin certificate extract \
  --input "$WORK/client_bob.sign.json" \
  --certificate-out "$WORK/client_bob.crt"
```

Generate and validate Bob's application key/config:

```bash
custodia-client key generate \
  --client-id client_bob \
  --private-key-out "$WORK/client_bob.x25519.json" \
  --public-key-out "$WORK/client_bob.x25519.pub.json"

custodia-client config write \
  --out "$WORK/client_bob.config.json" \
  --server-url "$API" \
  --cert "$WORK/client_bob.crt" \
  --key "$WORK/client_bob.key" \
  --ca "$CA" \
  --client-id client_bob \
  --crypto-key "$WORK/client_bob.x25519.json"

custodia-client config check --config "$WORK/client_bob.config.json"
```

Before sharing, Bob should not be able to read Alice's secret:

```bash
custodia-client secret get \
  --config "$WORK/client_bob.config.json" \
  --secret-id "$SECRET_ID" \
  --out "$WORK/bob.before-share.txt"
```

Expected: non-zero exit with an authorization error.

## 5. Alice shares the secret with Bob

Alice uses Bob's public key file from the trusted local channel:

```bash
custodia-client secret share \
  --config "$WORK/client_alice.config.json" \
  --secret-id "$SECRET_ID" \
  --target-client-id client_bob \
  --recipient "client_bob=$WORK/client_bob.x25519.pub.json" \
  --permissions 4
```

Bob can now read and decrypt the secret locally:

```bash
custodia-client secret get \
  --config "$WORK/client_bob.config.json" \
  --secret-id "$SECRET_ID" \
  --out "$WORK/bob.readback.txt"

cat "$WORK/bob.readback.txt"
```

Expected output:

```text
super secret demo value
```

## 6. Alice creates a new encrypted version

For a strong rotation, create a new version and include every client that must keep access:

```bash
printf 'rotated secret demo value' > "$WORK/secret.v2.txt"
chmod 600 "$WORK/secret.v2.txt"

custodia-client secret version put \
  --config "$WORK/client_alice.config.json" \
  --secret-id "$SECRET_ID" \
  --value-file "$WORK/secret.v2.txt" \
  --recipient "client_bob=$WORK/client_bob.x25519.pub.json" \
  --permissions 7
```

Inspect metadata:

```bash
custodia-client secret versions --config "$WORK/client_alice.config.json" --secret-id "$SECRET_ID" --limit 10
custodia-client secret access list --config "$WORK/client_alice.config.json" --secret-id "$SECRET_ID" --limit 10
```

## 7. Revoke Bob's future access

```bash
custodia-client secret access revoke \
  --config "$WORK/client_alice.config.json" \
  --secret-id "$SECRET_ID" \
  --target-client-id client_bob \
  --yes
```

This is future server-side revocation. Material Bob already downloaded may remain decryptable offline; for strong revocation, create a new encrypted version without Bob as a recipient.

## Cleanup

```bash
rm -rf "$WORK"
```
