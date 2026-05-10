# File permissions

Custodia keeps server runtime files and client-side profiles separate.

## Server files

For source installs, prepare the server runtime directories with restrictive ownership:

```bash
sudo install -d -m 0750 -o custodia -g custodia \
  /etc/custodia /var/lib/custodia /var/lib/custodia/backups /var/log/custodia
```

Typical server-side modes:

| Path | Owner | Mode | Notes |
| --- | --- | --- | --- |
| `/etc/custodia` | `custodia:custodia` | `0750` | Server config/cert directory. Do not loosen this for clients. |
| `/etc/custodia/*.key` | `custodia:custodia` | `0600` | Server/admin/CA private keys. |
| `/etc/custodia/*.crt` | `custodia:custodia` | `0644` | Public certificates, but parent directory remains restricted. |
| `/etc/custodia/*.yaml` | `custodia:custodia` | `0640` | Runtime config. |
| `/var/lib/custodia` | `custodia:custodia` | `0750` | Lite SQLite/runtime state. |
| `/var/lib/custodia/backups` | `custodia:custodia` | `0750` | Lite backup target. |
| `/var/log/custodia` | `custodia:custodia` | `0750` | Server logs. |

Do not `chmod 755 /etc/custodia` to make a client work. Copy the public CA certificate into that user's client profile instead.

## Client files

Client-only hosts do not need `/etc/custodia`, `/var/lib/custodia`, `/var/log/custodia`, a `custodia` service user or server systemd units.

Passing `--client-id client_alice` stores client-side files under `$XDG_CONFIG_HOME/custodia/client_alice`, or `$HOME/.config/custodia/client_alice` when `XDG_CONFIG_HOME` is not set.

Typical client-side modes:

| File | Mode | Notes |
| --- | --- | --- |
| `<client_id>.key` | `0600` | mTLS private key generated on the client host. |
| `<client_id>.csr` | `0644` | CSR transferred to the server/admin host. |
| `<client_id>.crt` | `0644` | Signed public mTLS certificate returned by the server/admin host. |
| `ca.crt` | `0644` | Public CA certificate copied into the client profile. |
| `<client_id>.x25519.json` | `0600` | Application encryption private key. |
| `<client_id>.x25519.pub.json` | `0644` | Public application key for trusted handoff. |
| `<client_id>.config.json` | `0600` | Local config referencing the files above. |

Example client provisioning flow:

```bash
export CLIENT_ID=client_alice
custodia-client mtls generate-csr --client-id "$CLIENT_ID"
# Transfer the CSR to the server/admin host.
# Transfer the signed certificate and public CA certificate back to this client host.
custodia-client mtls install-cert --client-id "$CLIENT_ID" --cert-file "$CLIENT_ID.crt" --ca-file ca.crt
custodia-client key generate --client-id "$CLIENT_ID"
custodia-client config write --client-id "$CLIENT_ID" --server-url "$CUSTODIA_API"
custodia-client config check --client-id "$CLIENT_ID"
```
