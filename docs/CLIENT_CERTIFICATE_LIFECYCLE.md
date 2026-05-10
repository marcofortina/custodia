# Client certificate lifecycle

Custodia clients use mTLS for transport identity and a separate client-side application key for encrypted payloads. The preferred remote-client workflow keeps the mTLS private key on the client host: the client generates a CSR, the server/admin host signs the CSR, and only the signed certificate plus public CA certificate return to the client.

## Client-side CSR flow

On the client host:

```bash
export CLIENT_ID=client_alice
custodia-client mtls generate-csr --client-id "$CLIENT_ID"
```

This creates the standard per-user profile under `$XDG_CONFIG_HOME/custodia/$CLIENT_ID`, or `$HOME/.config/custodia/$CLIENT_ID` when `XDG_CONFIG_HOME` is not set, and writes:

```text
client_alice.key
client_alice.csr
```

Transfer only `client_alice.csr` to the server/admin host. Do not transfer `client_alice.key`.

On the server/admin host:

```bash
sudo -u custodia custodia-admin \
  --server-url "$CUSTODIA_API" \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  client sign-csr \
  --signer-url "$CUSTODIA_SIGNER" \
  --client-id "$CLIENT_ID" \
  --csr-file "$CLIENT_ID.csr" \
  --certificate-out "$CLIENT_ID.crt"
```

Transfer the signed certificate and public CA certificate back to the client host.

On the client host:

```bash
custodia-client mtls install-cert \
  --client-id "$CLIENT_ID" \
  --cert-file "$CLIENT_ID.crt" \
  --ca-file ca.crt
```

Then generate the local application encryption key and write the client profile:

```bash
custodia-client key generate --client-id "$CLIENT_ID"

custodia-client config write \
  --client-id "$CLIENT_ID" \
  --server-url "$CUSTODIA_API"

custodia-client config check --client-id "$CLIENT_ID"
custodia-client doctor --client-id "$CLIENT_ID" --online
```

## Legacy all-in-one issuance

`custodia-admin client issue` can still generate and sign client mTLS material in one step for local lab setups. Do not use that path for remote clients when you want the mTLS private key to be generated and retained only on the client workstation.

## Rotation and revocation

To rotate a client mTLS certificate, generate a new CSR on the client host and sign it with `custodia-admin client sign-csr`. To revoke access, use the admin lifecycle commands documented in the CLI/manpage and keep the revocation evidence with the audit trail.

Application encryption keys are independent from mTLS certificates. Rotating mTLS credentials does not rotate encrypted-secret recipient keys; use `custodia-client key generate` and new secret versions when you need application-key rotation.
