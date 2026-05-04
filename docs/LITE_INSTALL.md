# Custodia Lite installation guide

For a first install on a clean Ubuntu or Fedora host, start with [`docs/QUICKSTART.md`](QUICKSTART.md). This document remains the lower-level Lite installation reference.

Custodia Lite is a single-node profile of the same Custodia codebase. It removes
mandatory external runtime services while preserving the security model: API
mTLS, opaque ciphertext/envelope handling, authorization grants, Web MFA and
audit integrity.

## Artifact

Build or install a Lite artifact that includes the SQLite build tag:

```bash
make build-sqlite
```

The standard build intentionally fails closed for `CUSTODIA_STORE_BACKEND=sqlite`.

## Directories

Recommended single-node layout:

```text
/etc/custodia              configuration and certificates
/var/lib/custodia          SQLite database
/var/lib/custodia/backups  SQLite backups
/var/log/custodia          service logs and local audit artifacts
```

Create a dedicated service user and restrict permissions:

```bash
sudo useradd --system --home /var/lib/custodia --shell /usr/sbin/nologin custodia
sudo install -d -o custodia -g custodia -m 0750 /etc/custodia /var/lib/custodia /var/lib/custodia/backups /var/log/custodia
```

Certificate material under `/etc/custodia` should be readable only by the
`custodia` user. Prefer an offline CA or an encrypted local CA key where possible.

## Bootstrap local CA material

For a first Lite installation, generate local CA and certificate material with:

```bash
sudo -u custodia custodia-admin ca bootstrap-local \
  --out-dir /etc/custodia \
  --admin-client-id admin \
  --server-name localhost \
  --generate-ca-passphrase
```

Use `--ca-passphrase-file FILE` when you already have a passphrase file managed by your secret-handling process.

## Configuration

Start from the sample profile:

```bash
sudo cp /usr/share/custodia/examples/config.lite.yaml /etc/custodia/config.yaml
sudo chown custodia:custodia /etc/custodia/config.yaml
sudo chmod 0640 /etc/custodia/config.yaml
```

Review every certificate path before starting the service.

## Run

Use the systemd unit example in `deploy/examples/custodia-lite.service` or run
manually for a first smoke test:

```bash
custodia-server --config /etc/custodia/config.yaml
```

## Security checklist

- keep API mTLS enabled;
- keep Web MFA required;
- protect `/etc/custodia` and `/var/lib/custodia` with restrictive permissions;
- use a CA key passphrase or offline CA when possible;
- backup SQLite with the online backup helper, not with blind file copies;
- periodically run audit export/verify;
- use a firewall or reverse proxy; do not expose the service unfiltered to the Internet;
- move to FULL when you need HA, WORM/SIEM, PKCS#11/HSM or distributed rate limiting.
