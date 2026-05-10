# Client certificate lifecycle

Custodia clients use mTLS for transport identity and a separate client-side application key for encrypted payloads. The preferred remote-client workflow keeps the mTLS private key on the client host: the client generates a CSR, the server/admin host signs the CSR, and only the signed certificate plus public CA certificate return to the client.

## Enrollment token flow

On the server/admin host, create a short-lived enrollment token:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

Transfer the printed server URL, enrollment token and server certificate SHA-256 fingerprint to the client host. On the client host:

```bash
export CLIENT_ID=client_alice

custodia-client mtls enroll \
  --client-id "$CLIENT_ID" \
  --server-url "https://SERVER_IP_OR_HOSTNAME:8443" \
  --enrollment-token "ENROLLMENT_TOKEN" \
  --server-cert-sha256 "SERVER_CERT_SHA256"
```

This creates the standard per-user profile under `$XDG_CONFIG_HOME/custodia/$CLIENT_ID`, or `$HOME/.config/custodia/$CLIENT_ID` when `XDG_CONFIG_HOME` is not set. The mTLS private key and CSR are generated locally; only the CSR and token are sent to Custodia. The response installs the signed certificate and public CA certificate into the client profile.

Then generate the local application encryption key and write the client profile:

```bash
custodia-client key generate --client-id "$CLIENT_ID"
custodia-client config write --client-id "$CLIENT_ID"
custodia-client config check --client-id "$CLIENT_ID"
custodia-client doctor --client-id "$CLIENT_ID" --online
```

## Manual CSR flow

For advanced/offline workflows, use `custodia-client mtls generate-csr` on the client host, sign the CSR with `custodia-admin client sign-csr` on the server/admin host, and install the returned public material with `custodia-client mtls install-cert`. Do not transfer the mTLS private key to the server.

## Legacy all-in-one issuance

`custodia-admin client issue` can still generate and sign client mTLS material in one step for local lab setups. Do not use that path for remote clients when you want the mTLS private key to be generated and retained only on the client workstation.

## Rotation and revocation

To rotate a client mTLS certificate, create a new enrollment token and rerun `custodia-client mtls enroll`, or use the manual CSR flow when an offline handoff is required. To revoke access, use the admin lifecycle commands documented in the CLI/manpage and keep the revocation evidence with the audit trail.

Application encryption keys are independent from mTLS certificates. Rotating mTLS credentials does not rotate encrypted-secret recipient keys; use `custodia-client key generate` and new secret versions when you need application-key rotation.
