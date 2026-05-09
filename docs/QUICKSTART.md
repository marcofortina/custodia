# Custodia quickstart

This guide is the first-run path for a clean Linux host. It covers both supported install methods:

1. install DEB/RPM packages;
2. clone the repository, build from source, and install locally.

Custodia uses the same binaries for Lite, Full and custom deployments. Lite or Full behavior is selected by YAML/environment configuration, not by installing different server products.

The guided runtime path below uses the single-node Lite profile because it is the smallest honest first run. Lite keeps the Custodia security model: API mTLS, client-side cryptography, opaque ciphertext/envelope storage, Web MFA and audit integrity. Full/custom deployments use the same binaries but require real external infrastructure such as PostgreSQL/CockroachDB, Valkey, HSM/PKCS#11, WORM/SIEM shipment and production evidence gates.

## 1. Choose an install path

| Path | Best for | Installs to |
| --- | --- | --- |
| Package install | Operators and first-time users | `/usr/bin`, `/etc/custodia`, `/var/lib/custodia` |
| Source install | Maintainers, developers, packagers and local testing | `/usr/local/bin`, `/usr/local/share/custodia`, `/etc/custodia`, `/var/lib/custodia` |

Pick one install path, then continue with the common runtime setup.

## 2. Install from DEB/RPM packages

Package install does not require a cloned repository. Download the release artifacts from GitHub into one directory on the target host. Replace `0.1.0` and `1` with the release values you want to install.

```bash
OWNER=marcofortina
REPO=custodia
VERSION=0.1.0
REVISION=1
BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download/v${VERSION}"
```

### Debian or Ubuntu

```bash
sudo apt update
sudo apt install -y ca-certificates curl openssl sqlite3 python3

curl -fLO "${BASE_URL}/custodia-server_${VERSION}-${REVISION}_amd64.deb"
curl -fLO "${BASE_URL}/custodia-client_${VERSION}-${REVISION}_amd64.deb"
curl -fLO "${BASE_URL}/custodia-sdk_${VERSION}-${REVISION}_all.deb"
curl -fLO "${BASE_URL}/SHA256SUMS"
curl -fLO "${BASE_URL}/artifacts-manifest.json"

sha256sum --ignore-missing -c SHA256SUMS

sudo apt install -y \
  "./custodia-server_${VERSION}-${REVISION}_amd64.deb" \
  "./custodia-client_${VERSION}-${REVISION}_amd64.deb" \
  "./custodia-sdk_${VERSION}-${REVISION}_all.deb"
```

### Fedora

```bash
sudo dnf install -y ca-certificates curl openssl sqlite python3

curl -fLO "${BASE_URL}/custodia-server-${VERSION}-${REVISION}.x86_64.rpm"
curl -fLO "${BASE_URL}/custodia-client-${VERSION}-${REVISION}.x86_64.rpm"
curl -fLO "${BASE_URL}/custodia-sdk-${VERSION}-${REVISION}.noarch.rpm"
curl -fLO "${BASE_URL}/SHA256SUMS"
curl -fLO "${BASE_URL}/artifacts-manifest.json"

sha256sum --ignore-missing -c SHA256SUMS

sudo dnf install -y \
  "./custodia-server-${VERSION}-${REVISION}.x86_64.rpm" \
  "./custodia-client-${VERSION}-${REVISION}.x86_64.rpm" \
  "./custodia-sdk-${VERSION}-${REVISION}.noarch.rpm"
```

Package split:

| Package | Installs |
| --- | --- |
| `custodia-server` | `custodia-server`, `custodia-admin`, `custodia-signer`, systemd units, examples and server docs. |
| `custodia-client` | `custodia-client` CLI and its manpage. |
| `custodia-sdk` | SDK source snapshots, the sourceable Bash SDK helper, shared crypto test vectors and SDK docs. |

Continue with [Configure the server profile](#4-configure-the-server-profile).

## 3. Install from source

Use this path when you intentionally want to build the binaries yourself. It installs the same Custodia artifacts used by package installs: server tools, client tools, SDK snapshots and manpages.

### 3.1 Source prerequisites

#### Debian or Ubuntu

```bash
sudo apt update
sudo apt install -y ca-certificates curl git make openssl sqlite3 python3 golang-go
```

#### Fedora

```bash
sudo dnf install -y ca-certificates curl git make openssl sqlite python3 golang
```

Custodia source builds require Go `1.25.x` or newer, matching `go.mod`. Some distribution packages may lag behind. Check before building:

```bash
go version
```

If your system Go is older, either install Go `1.25.x` or allow Go's toolchain download mechanism. In offline or proxied environments, prepare the Go toolchain before running the build targets.

### 3.2 Optional full SDK/package validation extras

Skip this section for a normal source install of Custodia itself. These packages are only for maintainers who want the same checkout to run the full non-Go SDK test matrix or build DEB/RPM artifacts.

#### Debian or Ubuntu

```bash
sudo apt install -y \
  python3-pip python3-cryptography python3-requests \
  nodejs npm openjdk-21-jdk g++ pkg-config \
  libcurl4-openssl-dev libssl-dev rpm cpio
```

#### Fedora

```bash
sudo dnf install -y \
  python3-pip python3-cryptography python3-requests \
  nodejs npm java-devel gcc-c++ pkgconf-pkg-config \
  libcurl-devel openssl-devel rpm-build cpio dpkg
```

Rust is only required for Rust SDK tests:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustc --version
cargo --version
```

### 3.3 Clone, build and install

```bash
git clone https://github.com/marcofortina/custodia.git
cd custodia
```

Build the artifacts you want to install. For a server node plus local client smoke tests:

```bash
make build-server build-client man
sudo make install-server PREFIX=/usr/local
sudo make install-client PREFIX=/usr/local
```

For a client-only workstation:

```bash
make build-client man
sudo make install-client PREFIX=/usr/local
```

For SDK source snapshots:

```bash
make build-sdk
sudo make install-sdk PREFIX=/usr/local
```

To install everything from source:

```bash
make build-server build-client build-sdk man
sudo make install PREFIX=/usr/local
```

`make install` does not build as root. If it reports missing binaries, manpages or SDK snapshots, run the relevant build target as your normal user first. Maintainers can still run `make` to execute the Go test suite, build all default artifacts, generate manpages and prepare the SDK source snapshot.

To build local DEB/RPM packages from the checkout instead of installing directly:

```bash
VERSION=0.1.0 REVISION=1 PACKAGE_NAMES="server client sdk" make package-linux
VERSION=0.1.0 REVISION=1 make package-checksums
cd dist/packages && sha256sum -c SHA256SUMS
```

Then install the generated packages and follow [Install from DEB/RPM packages](#2-install-from-debrpm-packages).

### 3.4 Prepare server runtime directories for source installs

```bash
if ! id custodia >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  sudo useradd --system --home-dir /var/lib/custodia --shell "$NOLOGIN" custodia
fi
```

```bash
sudo install -d -m 0750 -o custodia -g custodia \
  /etc/custodia /var/lib/custodia /var/log/custodia
```

## 4. Configure the server profile

The same installed binaries can run Lite, Full or custom profiles. This quickstart configures Lite.

Set the name clients and browsers will use to reach the server. For local-only tests use `localhost`. For a remote server, use its IP address or DNS hostname; the value is embedded into the server certificate SAN.

```bash
CUSTODIA_SERVER_NAME=localhost
# Example for a remote host:
# CUSTODIA_SERVER_NAME=custodia.example.internal
# CUSTODIA_SERVER_NAME=192.0.2.10
```

Generate a self-managed CA, server TLS certificate, initial admin mTLS certificate, empty CRL and Lite YAML config:

```bash
sudo -u custodia custodia-admin ca bootstrap-local \
  --out-dir /etc/custodia \
  --admin-client-id admin \
  --server-name "$CUSTODIA_SERVER_NAME" \
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
/etc/custodia/custodia-server.yaml
/etc/custodia/custodia-signer.yaml
/etc/custodia/server.crt
/etc/custodia/server.key
```

For Full/custom deployments, keep the same binaries and replace the runtime configuration. Start from `/usr/share/custodia/examples/custodia-server.full.yaml` or `deploy/examples/custodia-server.full.yaml`, then configure real external dependencies such as PostgreSQL/CockroachDB, Valkey, PKCS#11/HSM signer material, audit shipment/WORM evidence and production readiness checks. Do not treat Lite's SQLite/memory defaults as Full production settings.

## 5. Configure first admin web access

The bootstrap command wrote `/etc/custodia/custodia-server.yaml`. Generate Web MFA material and append it once:

```bash
sudo custodia-admin web totp configure \
  --config /etc/custodia/custodia-server.yaml \
  --account admin
```

The command always prints the TOTP secret and provisioning URI. If `qrencode` is installed, it also prints an ANSI terminal QR code; otherwise it prints a hint and continues. The TOTP secret and provisioning URI are sensitive. Do not commit, paste or share install logs containing them.

Start services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now custodia-server custodia-signer
sudo systemctl status custodia-server --no-pager
sudo systemctl status custodia-signer --no-pager
```

If startup fails:

```bash
sudo journalctl -u custodia-server -n 100 --no-pager
sudo journalctl -u custodia-signer -n 100 --no-pager
sudo tail -n 100 /var/log/custodia/custodia.log
```

## 6. Verify the admin API

Use the same host name or IP embedded in the server certificate:

```bash
CUSTODIA_API="https://${CUSTODIA_SERVER_NAME}:8443"
CUSTODIA_SIGNER="https://${CUSTODIA_SERVER_NAME}:9444"
```

Run the read-only doctor after the server and signer are configured:

```bash
sudo -u custodia custodia-admin doctor \
  --server-config /etc/custodia/custodia-server.yaml \
  --signer-config /etc/custodia/custodia-signer.yaml
```

Read API status with the generated admin mTLS certificate:

```bash
sudo -u custodia custodia-admin \
  --server-url "$CUSTODIA_API" \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  status read
```

Expected result: JSON status metadata. It must not contain plaintext secrets, DEKs, private keys or envelopes.

Diagnostics:

```bash
sudo -u custodia custodia-admin \
  --server-url "$CUSTODIA_API" \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  diagnostics read
```

## 7. Open the Web Console

Custodia's Web Console requires admin mTLS and TOTP. Create a temporary browser-importable PKCS#12 bundle:

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

Import `/tmp/custodia-admin.p12` into your browser certificate store, then open:

```text
https://SERVER_IP_OR_HOSTNAME:9443/web/login
```

Replace `SERVER_IP_OR_HOSTNAME` with the same value used as `CUSTODIA_SERVER_NAME`. For a local-only install, use:

```text
https://localhost:9443/web/login
```

After importing it into the browser, remove the temporary bundle:

```bash
rm -f /tmp/custodia-admin.p12
```

The Web Console is metadata-only. It does not decrypt or display secret plaintext.

## 8. Configure two clients and run an encrypted smoke test

The preferred remote-client flow generates each client mTLS private key and CSR on the client workstation. The server signs only the CSR. When the client is on a separate host, transfer the CSR to the server/admin host, then transfer the signed certificate and public CA certificate back to the client.

Create persistent local work directories outside `/tmp` for the smoke test:

```bash
export WORK="$HOME/.config/custodia/quickstart-smoke"
export ISSUE_ROOT="/var/lib/custodia/client-issue"
export ALICE_ID=client_alice
export BOB_ID=client_bob

rm -rf "$WORK"
install -d -m 0700 "$WORK/alice" "$WORK/bob"
sudo install -o "$USER" -g "$USER" -m 0644 /etc/custodia/ca.crt "$WORK/ca.crt"
```

Generate Alice's mTLS private key and CSR on Alice's workstation:

```bash
custodia-client mtls generate-csr \
  --client-id "$ALICE_ID" \
  --private-key-out "$WORK/alice/$ALICE_ID.key" \
  --csr-out "$WORK/alice/$ALICE_ID.csr"
```

Transfer `$WORK/alice/$ALICE_ID.csr` to the server/admin host when Alice is remote. Sign Alice's CSR on the server/admin host:

```bash
ALICE_ISSUE_DIR="$ISSUE_ROOT/$ALICE_ID"
sudo rm -rf "$ALICE_ISSUE_DIR"
sudo install -d -o custodia -g custodia -m 0700 "$ALICE_ISSUE_DIR"
sudo install -o custodia -g custodia -m 0644 "$WORK/alice/$ALICE_ID.csr" "$ALICE_ISSUE_DIR/$ALICE_ID.csr"

sudo -u custodia custodia-admin \
  --server-url "$CUSTODIA_API" \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  client sign-csr \
  --signer-url "$CUSTODIA_SIGNER" \
  --client-id "$ALICE_ID" \
  --csr-file "$ALICE_ISSUE_DIR/$ALICE_ID.csr" \
  --certificate-out "$ALICE_ISSUE_DIR/$ALICE_ID.crt"

sudo install -o "$USER" -g "$USER" -m 0644 "$ALICE_ISSUE_DIR/$ALICE_ID.crt" "$WORK/alice/$ALICE_ID.crt"
sudo rm -rf "$ALICE_ISSUE_DIR"
```

Transfer `$ALICE_ID.crt` and `ca.crt` back to Alice when Alice is remote. Configure Alice's local application encryption key and reusable client profile:

```bash
custodia-client key generate \
  --client-id "$ALICE_ID" \
  --private-key-out "$WORK/alice/$ALICE_ID.x25519.json" \
  --public-key-out "$WORK/alice/$ALICE_ID.x25519.pub.json"

ALICE_CONFIG="$WORK/alice/$ALICE_ID.config.json"

custodia-client config write \
  --out "$ALICE_CONFIG" \
  --server-url "$CUSTODIA_API" \
  --cert "$WORK/alice/$ALICE_ID.crt" \
  --key "$WORK/alice/$ALICE_ID.key" \
  --ca "$WORK/ca.crt" \
  --client-id "$ALICE_ID" \
  --crypto-key "$WORK/alice/$ALICE_ID.x25519.json"

custodia-client config check --config "$ALICE_CONFIG"
custodia-client doctor --config "$ALICE_CONFIG" --online
```

Create and read back an encrypted secret as Alice:

```bash
printf 'super secret demo value' > "$WORK/alice/secret.txt"
chmod 600 "$WORK/alice/secret.txt"

custodia-client secret put \
  --config "$ALICE_CONFIG" \
  --name smoke-demo \
  --value-file "$WORK/alice/secret.txt" \
  > "$WORK/alice/secret.create.json"

SECRET_ID="$(python3 - <<'PY'
import json, os
print(json.load(open(os.environ['WORK'] + '/alice/secret.create.json'))['secret_id'])
PY
)"

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

Generate Bob's mTLS private key and CSR on Bob's workstation:

```bash
custodia-client mtls generate-csr \
  --client-id "$BOB_ID" \
  --private-key-out "$WORK/bob/$BOB_ID.key" \
  --csr-out "$WORK/bob/$BOB_ID.csr"
```

Transfer `$WORK/bob/$BOB_ID.csr` to the server/admin host when Bob is remote. Sign Bob's CSR on the server/admin host:

```bash
BOB_ISSUE_DIR="$ISSUE_ROOT/$BOB_ID"
sudo rm -rf "$BOB_ISSUE_DIR"
sudo install -d -o custodia -g custodia -m 0700 "$BOB_ISSUE_DIR"
sudo install -o custodia -g custodia -m 0644 "$WORK/bob/$BOB_ID.csr" "$BOB_ISSUE_DIR/$BOB_ID.csr"

sudo -u custodia custodia-admin \
  --server-url "$CUSTODIA_API" \
  --cert /etc/custodia/admin.crt \
  --key /etc/custodia/admin.key \
  --ca /etc/custodia/ca.crt \
  client sign-csr \
  --signer-url "$CUSTODIA_SIGNER" \
  --client-id "$BOB_ID" \
  --csr-file "$BOB_ISSUE_DIR/$BOB_ID.csr" \
  --certificate-out "$BOB_ISSUE_DIR/$BOB_ID.crt"

sudo install -o "$USER" -g "$USER" -m 0644 "$BOB_ISSUE_DIR/$BOB_ID.crt" "$WORK/bob/$BOB_ID.crt"
sudo rm -rf "$BOB_ISSUE_DIR"
```

Transfer `$BOB_ID.crt` and `ca.crt` back to Bob when Bob is remote. Configure Bob's local application encryption key and reusable client profile:

```bash
custodia-client key generate \
  --client-id "$BOB_ID" \
  --private-key-out "$WORK/bob/$BOB_ID.x25519.json" \
  --public-key-out "$WORK/bob/$BOB_ID.x25519.pub.json"

BOB_CONFIG="$WORK/bob/$BOB_ID.config.json"

custodia-client config write \
  --out "$BOB_CONFIG" \
  --server-url "$CUSTODIA_API" \
  --cert "$WORK/bob/$BOB_ID.crt" \
  --key "$WORK/bob/$BOB_ID.key" \
  --ca "$WORK/ca.crt" \
  --client-id "$BOB_ID" \
  --crypto-key "$WORK/bob/$BOB_ID.x25519.json"

custodia-client config check --config "$BOB_CONFIG"
custodia-client doctor --config "$BOB_CONFIG" --online
```

Transfer Bob's public key `$WORK/bob/$BOB_ID.x25519.pub.json` to Alice through a trusted channel. Alice can then share the secret with Bob:

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

Delete the smoke secret when the test is complete:

```bash
custodia-client secret delete \
  --config "$ALICE_CONFIG" \
  --secret-id "$SECRET_ID" \
  --yes
```

The vault received only ciphertext, crypto metadata and opaque envelopes. Plaintext, mTLS private keys and application private keys stayed local to each client. Deletion prevents future server-side reads; material already downloaded by authorized clients remains outside server control.

For a complete two-client version/revoke workflow, follow [`docs/CUSTODIA_ALICE_BOB_SMOKE.md`](CUSTODIA_ALICE_BOB_SMOKE.md).

## 9. Basic backup check for Lite

SQLite backups should use an online backup flow, not blind file copies of the live database:

```bash
sudo install -d -m 0750 -o custodia -g custodia /var/lib/custodia/backups
BACKUP_PATH="/var/lib/custodia/backups/custodia-$(date -u +%Y%m%dT%H%M%SZ).db"
sudo -u custodia sqlite3 /var/lib/custodia/custodia.db \
  ".backup '${BACKUP_PATH}'"
sudo chmod 0640 "${BACKUP_PATH}"
```

From a cloned repository, you can also use the helper:

```bash
sudo -u custodia env \
  CUSTODIA_SQLITE_DB=/var/lib/custodia/custodia.db \
  CUSTODIA_SQLITE_BACKUP_DIR=/var/lib/custodia/backups \
  ./scripts/sqlite-backup.sh
```

## 10. First-run checklist

Before considering the node ready for real data:

- `systemctl status custodia-server` is healthy;
- `systemctl status custodia-signer` is healthy when you need client certificate issuance;
- `custodia-admin doctor` passes against the server and signer configs;
- `custodia-admin status read` succeeds with the admin certificate;
- the Web Console opens through the configured host name/IP and requires TOTP;
- `custodia-client config check` succeeds for Alice and Bob;
- `custodia-client doctor --online` succeeds for Alice and Bob;
- encrypted `secret put`, `secret share`, `secret get` and `secret delete` work;
- `/etc/custodia` is mode `0750` or stricter;
- private keys under `/etc/custodia` are mode `0600`;
- the CA passphrase file is backed up or the CA key is moved offline;
- the admin browser PKCS#12 bundle was removed after import;
- SQLite backup/restore was tested;
- remote firewall exposure was reviewed.

## 11. Diagnose the installation

Run the read-only doctor after the server and signer are configured:

```bash
sudo -u custodia custodia-admin doctor \
  --server-config /etc/custodia/custodia-server.yaml \
  --signer-config /etc/custodia/custodia-signer.yaml
```

For client-side checks:

```bash
custodia-client doctor --config "$ALICE_CONFIG"
```

For an online mTLS reachability check with the non-admin client identity:

```bash
custodia-client doctor --config "$ALICE_CONFIG" --online
```

## 12. What to read next

- Lite profile: [`docs/LITE_PROFILE.md`](LITE_PROFILE.md)
- Lite configuration: [`docs/LITE_CONFIG.md`](LITE_CONFIG.md)
- Configuration reference: [`docs/CONFIG_REFERENCE.md`](CONFIG_REFERENCE.md)
- File ownership and permissions: [`docs/FILE_PERMISSIONS.md`](FILE_PERMISSIONS.md)
- Client certificate lifecycle: [`docs/CLIENT_CERTIFICATE_LIFECYCLE.md`](CLIENT_CERTIFICATE_LIFECYCLE.md)
- Client CLI: [`docs/CUSTODIA_CLIENT_CLI.md`](CUSTODIA_CLIENT_CLI.md)
- Alice/Bob encrypted smoke test: [`docs/CUSTODIA_ALICE_BOB_SMOKE.md`](CUSTODIA_ALICE_BOB_SMOKE.md)
- Linux packages: [`docs/LINUX_PACKAGES.md`](LINUX_PACKAGES.md)
- Web MFA: [`docs/WEB_MFA.md`](WEB_MFA.md)
- Bash SDK helper: [`docs/BASH_SDK.md`](BASH_SDK.md)
- Backup and restore: [`docs/LITE_BACKUP_RESTORE.md`](LITE_BACKUP_RESTORE.md)
- Upgrade to Full: [`docs/LITE_TO_FULL_UPGRADE.md`](LITE_TO_FULL_UPGRADE.md)
