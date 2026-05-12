# Bare-metal Full install

This runbook is for installing `custodia-server` plus `custodia-signer` on a bare-metal or VM host with the Full profile. It intentionally does not install PostgreSQL/CockroachDB, Valkey, HSM/PKCS#11, WORM storage or SIEM for you. Those are production dependencies that must already exist and have their own evidence, backup and operational owners.

Use [`QUICKSTART.md`](QUICKSTART.md) for the first Lite run. Use this runbook when you already know the Full dependency endpoints and want a copyable checklist that avoids accidentally running Lite defaults in production.

## 1. Pre-flight decisions

Record these values before touching the host:

```text
CUSTODIA_SERVER_NAME=DNS name or stable IP used by browsers and remote clients
CUSTODIA_API_URL=https://${CUSTODIA_SERVER_NAME}:8443
PostgreSQL/CockroachDB URL with TLS policy
Valkey URL with TLS/auth policy
PKCS#11 or HSM signer integration path
Audit shipment/WORM/SIEM target
Admin mTLS subject, usually admin
```

Set the server name in the shell before running commands that derive URLs from it:

```bash
CUSTODIA_SERVER_NAME=custodia.example.internal
# or, for an IP-address-based lab only:
# CUSTODIA_SERVER_NAME=192.0.2.10
```

Rules:

- Do not use `localhost` as `CUSTODIA_SERVER_NAME` for a real Full deployment.
- Do not keep `storage.backend: sqlite` in Full.
- Do not keep `rate_limit.backend: memory` in Full.
- Do not point `signer.pkcs11_sign_command` at a helper that is not installed and executable on the signer host.
- Decide whether the first Web MFA path is TOTP-only or passkey-backed. If you do not already have a WebAuthn/passkey assertion verifier command, keep passkeys disabled and use TOTP for the first production rehearsal.
- Do not start services until config validation and production checks are clean.

## 2. Install binaries from source

Use this path only when the server host intentionally builds from a Git checkout.

```bash
sudo apt update
sudo apt install -y ca-certificates curl git make openssl python3 golang-go

git clone https://github.com/marcofortina/custodia.git
cd custodia

go version
make build-server man
sudo make install-server PREFIX=/usr/local
```

Create the runtime user and directories for source installs:

```bash
if ! id custodia >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  sudo useradd --system --home-dir /var/lib/custodia --shell "$NOLOGIN" custodia
fi
```

```bash
sudo install -d -m 0750 -o custodia -g custodia \
  /etc/custodia /var/lib/custodia /var/lib/custodia/backups /var/log/custodia
```

Copy the Full examples installed from the source tree before editing them. Without this step `/etc/custodia/custodia-server.yaml` does not exist yet:

```bash
sudo install -d -m 0750 -o root -g custodia /etc/custodia
sudo cp /usr/local/share/doc/custodia/custodia-server.full.yaml.example /etc/custodia/custodia-server.yaml
sudo cp /usr/local/share/doc/custodia/custodia-signer.yaml.example /etc/custodia/custodia-signer.yaml
sudo chown custodia:custodia /etc/custodia/custodia-server.yaml /etc/custodia/custodia-signer.yaml
sudo chmod 0640 /etc/custodia/custodia-server.yaml /etc/custodia/custodia-signer.yaml
CUSTODIA_DOC_DIR=/usr/local/share/doc/custodia
```

## 3. Install binaries from DEB/RPM packages

Use [`LINUX_PACKAGES.md`](LINUX_PACKAGES.md) to install release artifacts. The package path creates the `custodia` user and runtime directories for you.

After installation, copy the Full examples into `/etc/custodia`:

```bash
sudo install -d -m 0750 -o root -g custodia /etc/custodia
sudo cp /usr/share/doc/custodia/custodia-server.full.yaml.example /etc/custodia/custodia-server.yaml
sudo cp /usr/share/doc/custodia/custodia-signer.yaml.example /etc/custodia/custodia-signer.yaml
sudo chown custodia:custodia /etc/custodia/custodia-server.yaml /etc/custodia/custodia-signer.yaml
sudo chmod 0640 /etc/custodia/custodia-server.yaml /etc/custodia/custodia-signer.yaml
CUSTODIA_DOC_DIR=/usr/share/doc/custodia
```

## 4. Place TLS, client CA and signer material

Full deployment may use enterprise PKI, a platform CA, an offline CA ceremony or another audited certificate workflow. Custodia only requires that the files referenced by YAML exist and are readable by the `custodia` service user.

Minimum expected files:

```text
/etc/custodia/server.crt
/etc/custodia/server.key
/etc/custodia/client-ca.crt
/etc/custodia/client.crl.pem
/etc/custodia/admin.crt
/etc/custodia/admin.key
```

For a file-backed signer, the signer config also needs:

```text
/etc/custodia/ca.crt
/etc/custodia/ca.key
/etc/custodia/ca.pass
```

For Full production, prefer PKCS#11/HSM-backed signing. If `custodia-signer.yaml` uses:

```yaml
ca:
  key_provider: pkcs11
  pkcs11_sign_command: /usr/local/bin/custodia-pkcs11-sign
```

then `/usr/local/bin/custodia-pkcs11-sign` must exist, be executable by the `custodia` user and be covered by the HSM evidence/runbook. SoftHSM is acceptable only for lab rehearsal when real HSM access is unavailable.

Recommended permissions. These commands are safe even when an HSM-backed host has no local `*.key` or `*.pass` files:

```bash
sudo find /etc/custodia -maxdepth 1 \( -name '*.crt' -o -name '*.pem' \) \
  -exec chown custodia:custodia {} + \
  -exec chmod 0644 {} +
sudo find /etc/custodia -maxdepth 1 \( -name '*.key' -o -name '*.pass' \) \
  -exec chown custodia:custodia {} + \
  -exec chmod 0600 {} +
```

Adjust the file names if your host uses narrower names or hardware-backed keys without local private-key files.

## 5. Edit Full server config

Start from the copied Full example and replace every placeholder:

```bash
sudo editor /etc/custodia/custodia-server.yaml
```

Required production-oriented settings:

```yaml
profile: full
server:
  url: "https://custodia.example.internal:8443"
storage:
  backend: postgres
  database_url: "postgresql://custodia@db.example.com:5432/custodia?sslmode=require"
rate_limit:
  backend: valkey
  valkey_url: "rediss://valkey.example.com:6379/0"
tls:
  client_ca_file: /etc/custodia/client-ca.crt
  client_crl_file: /etc/custodia/client.crl.pem
  cert_file: /etc/custodia/server.crt
  key_file: /etc/custodia/server.key
deployment:
  mode: production
  database_ha_target: cockroachdb-multi-region
  audit_shipment_sink: s3-object-lock://custodia-audit-prod
signer:
  key_provider: pkcs11
  ca_cert_file: /etc/custodia/ca.crt
  pkcs11_sign_command: /usr/local/bin/custodia-pkcs11-sign
admin_client_ids:
  - admin
```

The installed Full example enables passkey fields as a production-oriented template. If you do not have a passkey assertion verifier installed yet, make the first run TOTP-only before starting services:

```yaml
web:
  mfa_required: true
  passkey_enabled: false
```

If you keep passkeys enabled, install the verifier command first and set the relying-party ID to the browser hostname operators will use:

```yaml
web:
  mfa_required: true
  passkey_enabled: true
  passkey_rp_id: custodia.example.internal
  passkey_rp_name: Custodia
  passkey_assertion_verify_command: /usr/local/bin/verify-passkey-assertion
```

Do not leave passkey placeholders in a production Full config.

## 6. Edit signer config

```bash
sudo editor /etc/custodia/custodia-signer.yaml
```

For a Full HSM-backed signer, do not leave the file-backed CA key settings in place unless this is an explicitly accepted lab profile. The signer admin subject must match the server-to-signer client certificate subject.

## 7. Configure Web MFA

Append Web TOTP and session material once:

```bash
sudo custodia-admin web totp configure --account admin
```

Store the TOTP provisioning URI in the operator authenticator/password manager. Do not paste it into tickets or commit logs.

## 8. Validate before start

Config validation reads the runtime YAML files:

```bash
sudo -u custodia custodia-server config validate --config /etc/custodia/custodia-server.yaml
sudo -u custodia custodia-signer config validate --config /etc/custodia/custodia-signer.yaml
```

Production readiness checks use a separate offline environment file. It is **not** a systemd `EnvironmentFile` and must not be installed as runtime config. Copy the installed template, replace every placeholder and keep it readable only by the operator or release reviewer:

```bash
test -n "${CUSTODIA_DOC_DIR:-}" || { echo "set CUSTODIA_DOC_DIR from the source/package install step first" >&2; exit 1; }
sudo cp "$CUSTODIA_DOC_DIR/production-readiness.env.example" /etc/custodia/production-readiness.env
sudo chown root:root /etc/custodia/production-readiness.env
sudo chmod 0600 /etc/custodia/production-readiness.env
sudo editor /etc/custodia/production-readiness.env
```

If you opened a new shell before this step, set the documentation directory again:

```bash
# Source install:
CUSTODIA_DOC_DIR=/usr/local/share/doc/custodia
# Package install:
CUSTODIA_DOC_DIR=/usr/share/doc/custodia
```

Run the offline gate explicitly with `--env-file`:

```bash
sudo custodia-admin production check --env-file /etc/custodia/production-readiness.env
```

If production evidence files are part of your release gate, run:

```bash
sudo custodia-admin production evidence-check --env-file /etc/custodia/production-readiness.env
```

Do not continue with placeholder database URLs, memory rate limiting, SQLite storage, missing CRL, missing Web MFA or missing signer/HSM evidence.

## 9. Start and verify services

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now custodia-server custodia-signer
sudo systemctl status custodia-server --no-pager
sudo systemctl status custodia-signer --no-pager
```

Admin API checks:

```bash
sudo -u custodia custodia-admin doctor
sudo -u custodia custodia-admin status read
sudo -u custodia custodia-admin diagnostics read
```

Operator endpoint smoke from the server/admin host:

```bash
test -n "${CUSTODIA_SERVER_NAME:-}" || { echo "set CUSTODIA_SERVER_NAME first" >&2; exit 1; }
export CUSTODIA_OPERATIONAL_CONFIRM=YES
export CUSTODIA_SERVER_URL="https://${CUSTODIA_SERVER_NAME}:8443"
export CUSTODIA_WEB_URL="https://${CUSTODIA_SERVER_NAME}:9443"
export CUSTODIA_ADMIN_CERT=/etc/custodia/admin.crt
export CUSTODIA_ADMIN_KEY=/etc/custodia/admin.key
export CUSTODIA_CA_CERT=/etc/custodia/ca.crt
```

For a source install from the repository checkout, either helper works:

```bash
sudo -E ./scripts/operational-readiness-smoke.sh endpoint-check
sudo -E /usr/local/sbin/custodia-operational-readiness-smoke endpoint-check
```

For a package install, use the installed helper:

```bash
sudo -E /usr/sbin/custodia-operational-readiness-smoke endpoint-check
```

Use an operator-only temporary directory instead of `/etc/custodia` if running the smoke from a separate workstation.
