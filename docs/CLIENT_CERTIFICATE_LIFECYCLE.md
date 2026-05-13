# Client certificate lifecycle

Custodia clients use mTLS for transport identity and a separate client-side application key for encrypted payloads. The preferred remote-client workflow keeps the mTLS private key on the client host: the client generates a CSR, the server/admin host signs the CSR, and only the signed certificate plus public CA certificate return to the client.

## Enrollment token flow

On the server/admin host, create a short-lived enrollment token:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

Transfer the printed server URL and enrollment token to the client host. Enrollment uses normal TLS certificate validation by default; the server URL must match the server certificate SAN. For production-style enrollment, trust the Custodia CA first with [`CLIENT_TRUSTED_CA.md`](CLIENT_TRUSTED_CA.md). For disposable first-run labs where the local CA is not trusted yet, add `--insecure` to the enrollment command only for that bootstrap run. On the client host:

```bash
export CLIENT_ID=client_alice
export CUSTODIA_SERVER_URL="https://SERVER_IP_OR_HOSTNAME:8443"
export CUSTODIA_ENROLLMENT_TOKEN="ENROLLMENT_TOKEN"

custodia-client mtls enroll \
  --client-id "$CLIENT_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$CUSTODIA_ENROLLMENT_TOKEN"
```

Disposable lab only, when the local CA is not trusted yet:

```bash
custodia-client mtls enroll \
  --client-id "$CLIENT_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$CUSTODIA_ENROLLMENT_TOKEN" \
  --insecure
```

This creates the standard per-user profile under `$XDG_CONFIG_HOME/custodia/$CLIENT_ID`, or `$HOME/.config/custodia/$CLIENT_ID` when `XDG_CONFIG_HOME` is not set. The mTLS private key and CSR are generated locally; only the CSR and token are sent to Custodia. The response installs the signed certificate and public CA certificate into the client profile.

### Enrollment troubleshooting

`custodia-client mtls enroll` prints an operator hint when the claim fails. Treat the hint as the first remediation step, but keep the token private and do not paste it into logs or issues.

Common failures:

- `invalid_or_expired_token`, `invalid_token`, `401` or `403`: create a fresh one-shot token on the server/admin host, copy it exactly and retry. Tokens are short-lived and may be single-use.
- TLS trust or `unknown authority`: install/trust the Custodia CA first, or use `--insecure` only for a disposable lab bootstrap where that risk is explicit.
- certificate SAN or hostname mismatch: use the `server.url` host or IP that is present in the server certificate SANs, or rebootstrap/reissue the server certificate with the reachable DNS/IP.
- DNS/network failure: verify that `--server-url` resolves from the client host and reaches the API listener on port `8443`.
- `404`: verify that `--server-url` points to the Custodia API listener, not the Web Console or signer listener.
- existing local profile files: choose a new `--client-id`, remove only the stale profile files you intentionally want to replace, or keep the existing enrolled profile. The CLI checks local targets before claiming the token so a local overwrite error does not consume the token.

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
