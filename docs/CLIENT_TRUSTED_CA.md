# Client trusted CA setup

Use this runbook when enrolling a real remote Custodia client without `--insecure`.
Disposable labs can use `--insecure` for first-run bootstrap with an untrusted local CA, but real client hosts should trust the Custodia server CA before `custodia-client mtls enroll`.

## Runbook metadata

| Field | Value |
| --- | --- |
| Audience | Operators preparing Alice/Bob client-only Linux hosts for production-style enrollment. |
| Prerequisites | A reachable Custodia server URL, the Custodia server CA certificate transferred through a trusted channel, and sudo/root access on the client host to update the OS trust store. |
| Outcome | `custodia-client mtls enroll` can run with normal TLS verification and without `--insecure`. |
| Do not continue if | The server URL host is not present in the server certificate SANs, the CA file did not come from a trusted channel, or the host cannot update its OS trust store. |

## 1. Set the expected server URL and CA file

On the client host, set the server URL exactly as the client will use it:

```bash
export CUSTODIA_SERVER_URL="https://custodia.example.internal:8443"
export CUSTODIA_CA_FILE="$HOME/custodia-ca.crt"
```

Transfer the Custodia CA certificate to `$CUSTODIA_CA_FILE` through your trusted operator channel. Do not fetch a CA certificate from the same unauthenticated HTTPS endpoint you are trying to trust.

## 2. Debian or Ubuntu trust store

```bash
sudo install -m 0644 "$CUSTODIA_CA_FILE" /usr/local/share/ca-certificates/custodia-ca.crt
sudo update-ca-certificates
```

Verify the public liveness endpoint through normal TLS verification:

```bash
curl --fail --silent --show-error "$CUSTODIA_SERVER_URL/live"
```

## 3. Fedora, RHEL or compatible trust store

```bash
sudo install -m 0644 "$CUSTODIA_CA_FILE" /etc/pki/ca-trust/source/anchors/custodia-ca.crt
sudo update-ca-trust extract
```

Verify the public liveness endpoint through normal TLS verification:

```bash
curl --fail --silent --show-error "$CUSTODIA_SERVER_URL/live"
```

## 4. Enroll without `--insecure`

After the trust-store update succeeds, enroll with the server URL and one-shot token printed by the server/admin host:

```bash
export CUSTODIA_CLIENT_ID=client_alice
export CUSTODIA_ENROLLMENT_TOKEN="ENROLLMENT_TOKEN"

custodia-client mtls enroll \
  --client-id "$CUSTODIA_CLIENT_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$CUSTODIA_ENROLLMENT_TOKEN"
```

The enrollment command stores the returned `ca.crt` inside the standard per-user Custodia profile for future client operations. The OS trust-store step is still required before enrollment because the first HTTPS request must verify the server certificate.

## 5. Cleanup and rotation notes

Keep the OS trust store managed by your normal platform process. When the Custodia CA changes, repeat the trust-store update before issuing new enrollment tokens.

Do not keep using `--insecure` as a workaround for production client hosts. It is reserved for disposable first-run labs with an untrusted local CA.
