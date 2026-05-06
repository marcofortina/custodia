# Custodia quickstart

This guide is the first-run path for a clean Linux host. It covers two supported ways to start Custodia Lite:

1. install the release package on Debian, Ubuntu or Fedora;
2. clone the GitHub repository, build from source and install a local Lite node.

If you are not developing Custodia, use the package install path. The source install path is for contributors, packagers and local build testing.

The quickstart intentionally uses the single-node Lite profile. Lite keeps the Custodia security model: API mTLS, client-side cryptography, opaque ciphertext/envelope storage, Web MFA and audit integrity. It only removes mandatory external services such as PostgreSQL, Valkey, HSM and WORM shipment.

## 1. Choose an install path

Use the package path for a normal machine install. Use the source path only when you are developing Custodia, testing patches or building packages yourself.

| Path | Best for | Installs to |
| --- | --- | --- |
| Package install | Operators and first-time users | `/usr/bin`, `/etc/custodia`, `/var/lib/custodia` |
| Source install | Developers, packagers and local testing | `/usr/local/bin`, `/etc/custodia`, `/var/lib/custodia` |

Recommended first run: install the package, complete the Lite bootstrap, verify the API, then open the web console.

Both paths converge at [Prepare the Lite runtime directories](#4-prepare-the-lite-runtime-directories).

## 2. Install package-path prerequisites

Install only these prerequisites when you are following the recommended package install path. The source build path has its own larger dependency set in [Clone, build and install from source](#3b-clone-build-and-install-from-source).

### Debian or Ubuntu

```bash
sudo apt update
sudo apt install -y ca-certificates curl openssl sqlite3 python3
```

### Fedora

```bash
sudo dnf install -y ca-certificates curl openssl sqlite python3
```

## 3. Install Custodia

Custodia can be installed either from release packages or from a source checkout. Pick one of the two paths below.

### 3A. Install from release packages

Package install does not require a cloned repository. Download the release artifacts from GitHub into one directory on the target host. Replace `0.1.0` and `1` with the release values you want to install:

```bash
OWNER=marcofortina
REPO=custodia
VERSION=0.1.0
REVISION=1
BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download/v${VERSION}"

# Debian/Ubuntu package
curl -fLO "${BASE_URL}/custodia-server_${VERSION}-${REVISION}_amd64.deb"

# Fedora package
curl -fLO "${BASE_URL}/custodia-server-${VERSION}-${REVISION}.x86_64.rpm"

curl -fLO "${BASE_URL}/SHA256SUMS"
curl -fLO "${BASE_URL}/artifacts-manifest.json"
```

Verify the downloaded artifacts before installing them. `--ignore-missing` keeps the check usable when you downloaded only the package for your distribution:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

The package file you are about to install must report `OK`.

### Debian or Ubuntu

Run the command from the directory that contains the downloaded `.deb` file:

```bash
sudo apt install -y "./custodia-server_${VERSION}-${REVISION}_amd64.deb"
```

### Fedora

Run the command from the directory that contains the downloaded `.rpm` file:

```bash
sudo dnf install -y "./custodia-server-${VERSION}-${REVISION}.x86_64.rpm"
```

The package installs:

```text
/usr/bin/custodia-server
/usr/bin/custodia-admin
/usr/bin/custodia-signer
/usr/lib/systemd/system/custodia.service
/usr/lib/systemd/system/custodia-signer.service
/usr/share/custodia/examples/
/etc/custodia/
/var/lib/custodia/
/var/log/custodia/
```

Continue with [Prepare the Lite runtime directories](#4-prepare-the-lite-runtime-directories).

### 3B. Clone, build and install from source

This is the advanced path. Use it when you want to build the binaries yourself or validate local changes before packaging.

Install the full source-build dependency set before cloning and testing the repository.

#### Debian or Ubuntu

```bash
sudo apt update
sudo apt install -y ca-certificates curl git make openssl sqlite3 python3 python3-pip python3-cryptography python3-requests nodejs npm golang-go openjdk-21-jdk g++ pkg-config libcurl4-openssl-dev libssl-dev rpm cpio
```

#### Fedora

```bash
sudo dnf install -y ca-certificates curl git make openssl sqlite python3 python3-pip python3-cryptography python3-requests nodejs npm golang java-devel gcc-c++ pkgconf-pkg-config libcurl-devel openssl-devel rpm-build cpio dpkg
```

Fedora keeps the default JDK behind the generic `java-devel` virtual provide. Avoid pinning a specific OpenJDK package in this quickstart because Fedora releases may retire older JDK streams.

The Python SDK tests import the client directly from the source tree, but they still need the runtime dependencies declared by `clients/python/pyproject.toml`. The distro packages above provide `requests` and `cryptography` without requiring a system-wide `pip install`.

#### Rust toolchain for source builds

Rust is only required when you want to run all SDK tests from source. Install it with your distro package manager or with `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustc --version
cargo --version
```

Custodia currently supports Cargo/Rust `1.86` or newer.

Clone the repository:

```bash
git clone https://github.com/marcofortina/custodia.git
cd custodia
```

Run the local checks that do not require production external services:

```bash
make license-check
make test-client-crypto
make test-python-client
make test-node-client
make test-java-client
make test-cpp-client
make test-rust-client
make test-bash-client
go test -p=1 -timeout 60s ./...
```

Build Lite-capable binaries. The `sqlite` build tag is required for the single-node Lite profile:

```bash
mkdir -p dist/local/bin
go build -buildvcs=false -tags sqlite -o dist/local/bin/custodia-server ./cmd/custodia-server
go build -buildvcs=false -o dist/local/bin/custodia-admin ./cmd/custodia-admin
go build -buildvcs=false -o dist/local/bin/custodia-signer ./cmd/custodia-signer
```

Install the binaries and the Lite systemd unit:

```bash
sudo install -m 0755 dist/local/bin/custodia-server /usr/local/bin/custodia-server
sudo install -m 0755 dist/local/bin/custodia-admin /usr/local/bin/custodia-admin
sudo install -m 0755 dist/local/bin/custodia-signer /usr/local/bin/custodia-signer
sudo install -m 0644 deploy/examples/custodia-lite.service /etc/systemd/system/custodia.service
sudo install -m 0644 deploy/examples/custodia-signer-lite.service /etc/systemd/system/custodia-signer.service
```

Create the service user if it does not exist yet:

```bash
if ! id custodia >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  sudo useradd --system --home-dir /var/lib/custodia --shell "$NOLOGIN" custodia
fi
```

Generate release-style packages from the clone when you want artifacts instead of a direct `/usr/local` install:

```bash
VERSION=0.1.0 REVISION=1 make package-linux
VERSION=0.1.0 REVISION=1 make package-checksums
cd dist/packages && sha256sum -c SHA256SUMS
```

Then install the generated `.deb` or `.rpm` and follow [Install from release packages](#3a-install-from-release-packages). If you keep the direct `/usr/local` install, continue with the runtime setup below.

## 4. Prepare the Lite runtime directories

The package path creates the directories for you, while the source path may not. The first local CA bootstrap writes certificate material, so let the `custodia` service user own the configuration directory during the first setup:

```bash
sudo install -d -m 0750 -o custodia -g custodia /etc/custodia /var/lib/custodia /var/log/custodia
```

This is acceptable for a single-node Lite bootstrap. After the first setup, keep `/etc/custodia` readable only by trusted operators and the `custodia` service user.

## 5. Bootstrap local CA and admin certificates

Generate a self-managed local CA, server TLS certificate, initial admin mTLS certificate, empty CRL and Lite YAML config:

```bash
sudo -u custodia custodia-admin ca bootstrap-local \
  --out-dir /etc/custodia \
  --admin-client-id admin \
  --server-name localhost \
  --generate-ca-passphrase
```

Expected files:

```text
/etc/custodia/admin.crt
/etc/custodia/admin.key
/etc/custodia/ca.crt
/etc/custodia/ca.key
/etc/custodia/ca.pass
/etc/custodia/client-ca.crt
/etc/custodia/client.crl.pem
/etc/custodia/config.lite.yaml
/etc/custodia/server.crt
/etc/custodia/server.key
```

For a public DNS name, replace `localhost` with the DNS name clients will use. The value is embedded into the server certificate SAN.

## 6. Create the runtime config

Start from the generated Lite config:

```bash
sudo install -m 0640 -o custodia -g custodia /etc/custodia/config.lite.yaml /etc/custodia/config.yaml
```

Generate the Web TOTP secret with `custodia-admin`, then append it to the runtime config:

```bash
TOTP_OUTPUT="$(custodia-admin web totp generate --account admin --format json)"
printf '%s\n' "${TOTP_OUTPUT}"

TOTP_SECRET="$(printf '%s' "${TOTP_OUTPUT}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["totp_secret"])')"
SESSION_SECRET="$(openssl rand -base64 48)"

sudo tee -a /etc/custodia/config.yaml >/dev/null <<CONFIG
web_totp_secret: "${TOTP_SECRET}"
web_session_secret: "${SESSION_SECRET}"
CONFIG

printf 'Add this TOTP secret to your authenticator app: %s\n' "${TOTP_SECRET}"
unset TOTP_OUTPUT TOTP_SECRET SESSION_SECRET
```

The JSON output also contains an `otpauth://` provisioning URI. Use manual entry in Google Authenticator, Aegis, 1Password, Bitwarden or another TOTP-compatible authenticator if your app cannot scan/import that URI directly. Treat the TOTP secret like an admin credential.

## 7. Start Custodia services

Start the vault API/Web process and the separate Lite signer process:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now custodia custodia-signer
sudo systemctl status custodia --no-pager
sudo systemctl status custodia-signer --no-pager
```

The signer listens on `:9444` only when `custodia-signer.service` is running. It is intentionally separate from `custodia-server` so the vault API process does not own the CA private key.

Custodia mirrors service logs to both systemd/journald and `/var/log/custodia/custodia.log`. Journald remains the primary service manager log stream, while the file gives operators a simple local artifact to copy, tail or archive. The signer audit log is written to `/var/log/custodia/signer-audit.jsonl` when the Lite signer unit is used.

If either service fails, inspect the logs:

```bash
sudo journalctl -u custodia -n 100 --no-pager
sudo journalctl -u custodia-signer -n 100 --no-pager
sudo tail -n 100 /var/log/custodia/custodia.log
```

If the vault service fails before file logging is initialized, the error will be in `journalctl`. After initialization, the same application log lines are mirrored to `/var/log/custodia/custodia.log`.

Common startup failures:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `permission denied` under `/etc/custodia` | bootstrap files are not readable by the `custodia` service user | check ownership and modes with `sudo ls -la /etc/custodia` |
| SQLite backend is unknown | binary was built without the `sqlite` build tag | install the release package or rebuild with `go build -tags sqlite` |
| TLS certificate error on startup | `tls_cert_file` or `tls_key_file` path is wrong | compare `/etc/custodia/config.yaml` with files in `/etc/custodia` |
| `mfa_not_configured` in logs | web MFA secrets were not added to config | repeat step 6 and restart the service |
| `custodia-signer` is not listening on `9444` | signer service was not enabled or failed to read CA material | run `sudo systemctl status custodia-signer --no-pager` and check `/etc/custodia/ca.*` ownership/modes |

## 8. Verify the API with the admin mTLS certificate

The generated admin certificate is a client certificate. Use it with `custodia-admin`:

```bash
sudo custodia-admin \
  --server-url https://localhost:8443 \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  status read
```

Expected result: JSON status metadata. It must not contain plaintext secrets, DEKs, private keys or envelopes.

You can also inspect runtime diagnostics:

```bash
sudo custodia-admin \
  --server-url https://localhost:8443 \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  diagnostics read
```

## 9. Open the web console

Custodia's web console also requires admin mTLS and TOTP. Create a temporary browser-importable PKCS#12 bundle:

```bash
sudo openssl pkcs12 -export \
  -in /etc/custodia/admin.crt \
  -inkey /etc/custodia/admin.key \
  -certfile /etc/custodia/ca.crt \
  -out /tmp/custodia-admin.p12 \
  -name "Custodia Admin"

sudo chown "$USER:$USER" /tmp/custodia-admin.p12
chmod 0600 /tmp/custodia-admin.p12
```

Import `/tmp/custodia-admin.p12` into your browser certificate store, then open the dedicated web listener:

```text
https://localhost:9443/web/login
```

After import, remove the temporary bundle:

```bash
rm -f /tmp/custodia-admin.p12
```

The web console is metadata-only. It does not decrypt or display secret plaintext.

### First web login troubleshooting

| Browser or server error | Meaning | Fix |
| --- | --- | --- |
| `ERR_BAD_SSL_CLIENT_AUTH_CERT` or similar | the browser did not present the admin client certificate | import `/tmp/custodia-admin.p12`, restart the browser if needed, and choose the `Custodia Admin` certificate |
| HTTP `403` on `/web/login` | the client certificate was missing, expired or not signed by the configured CA | recreate/import the PKCS#12 bundle from `/etc/custodia/admin.crt` and `/etc/custodia/admin.key` |
| `mfa_not_configured` | `web_totp_secret` or `web_session_secret` is missing from `/etc/custodia/config.yaml` | repeat step 6 and restart `custodia` |
| TOTP code rejected | clock drift or wrong secret in the authenticator app | check host time sync and re-add the printed TOTP secret manually |

## 10. Optional firewall rules

For a first local test on the same machine, no firewall rule is required. If remote clients must connect, expose only the required ports and prefer a private network or hardened reverse proxy.

### Debian or Ubuntu with UFW

```bash
sudo ufw allow 8443/tcp
sudo ufw allow 9443/tcp
# Optional: expose the signer only to trusted admin hosts when remote CSR signing is required.
# sudo ufw allow from ADMIN_IP to any port 9444 proto tcp
```

### Fedora with firewalld

```bash
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=9443/tcp
# Optional: expose the signer only to trusted admin hosts when remote CSR signing is required.
# sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="ADMIN_IP" port port="9444" protocol="tcp" accept'
sudo firewall-cmd --reload
```

Do not expose a fresh Lite node directly to the Internet without a network access policy, firewall review, backup plan and certificate rotation process.

## 11. Basic backup check

SQLite backups should use an online backup flow, not blind file copies of the live database. Run the backup as the `custodia` service user so the backup is created with the same access boundary as the running service.

With only the installed package, use SQLite's online `.backup` command:

```bash
sudo install -d -m 0750 -o custodia -g custodia /var/lib/custodia/backups
BACKUP_PATH="/var/lib/custodia/backups/custodia-$(date -u +%Y%m%dT%H%M%SZ).db"
sudo -u custodia sqlite3 /var/lib/custodia/custodia.db \
  ".backup '${BACKUP_PATH}'"
sudo chmod 0640 "${BACKUP_PATH}"
```

From a cloned repository, you can also use the included helper. Run it as `custodia` and use the helper's `CUSTODIA_SQLITE_DB` / `CUSTODIA_SQLITE_BACKUP_DIR` variables:

```bash
sudo install -d -m 0750 -o custodia -g custodia /var/lib/custodia/backups
sudo -u custodia env \
  CUSTODIA_SQLITE_DB=/var/lib/custodia/custodia.db \
  CUSTODIA_SQLITE_BACKUP_DIR=/var/lib/custodia/backups \
  ./scripts/sqlite-backup.sh
```

## 12. Copy/paste validation block

After the service starts, this block should complete without errors:

```bash
sudo systemctl is-active --quiet custodia
sudo systemctl is-active --quiet custodia-signer

sudo custodia-admin \
  --server-url https://localhost:8443 \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  status read >/tmp/custodia-status.json

test -s /tmp/custodia-status.json
sudo test -f /etc/custodia/config.yaml
sudo test -f /etc/custodia/admin.crt
sudo test -f /etc/custodia/admin.key
sudo test -f /etc/custodia/ca.crt
sudo test -f /etc/custodia/ca.key
sudo test -f /etc/custodia/ca.pass
sudo test -d /var/lib/custodia
sudo test -d /var/log/custodia
rm -f /tmp/custodia-status.json
```

If this block passes, the API side of the Lite node is ready for first use. Complete the web login test separately because browser certificate import is interactive.

## 13. First-run checklist

Before considering the node ready for real data:

- `systemctl status custodia` is healthy;
- `systemctl status custodia-signer` is healthy when you need client certificate issuance;
- `custodia-admin status read` succeeds with the admin certificate;
- `/etc/custodia` is mode `0750` or stricter;
- private keys under `/etc/custodia` are mode `0600`;
- the CA passphrase file is backed up or the CA key is moved offline;
- the admin browser PKCS#12 bundle was removed after import;
- SQLite backup/restore was tested;
- audit export/verify was scheduled;
- remote firewall exposure was reviewed.

## 14. What to read next

- Lite profile: `docs/LITE_PROFILE.md`
- Lite configuration: `docs/LITE_CONFIG.md`
- Client certificate lifecycle: `docs/CLIENT_CERTIFICATE_LIFECYCLE.md`
- Lite CA bootstrap: `docs/LITE_CA_BOOTSTRAP.md`
- Linux packages: `docs/LINUX_PACKAGES.md`
- Web MFA: `docs/WEB_MFA.md`
- Backup and restore: `docs/LITE_BACKUP_RESTORE.md`
- Upgrade to Full: `docs/LITE_TO_FULL_UPGRADE.md`


Client certificate shortcut after installing the signer:

```bash
sudo custodia-admin \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  client issue \
  --vault-url https://localhost:8443 \
  --signer-url https://localhost:9444 \
  --client-id client_alice \
  --out-dir ./client_alice
```

This creates local mTLS material and `client_alice-mtls.zip`; application encryption keys are still generated separately with `custodia-client key generate`.
