# Custodia quickstart

This guide is the bare-metal first-run path for a clean Linux host. It covers both supported bare-metal install methods:

1. install DEB/RPM packages;
2. clone the repository, build from source, and install locally.

For the full deployment/profile map, including Kubernetes, read [`DEPLOYMENT_MATRIX.md`](DEPLOYMENT_MATRIX.md). Custodia uses the same binaries for Lite, Full and custom deployments. Lite or Full behavior is selected by YAML/environment configuration, not by installing different server products.

The guided runtime path below uses the single-node Lite profile because it is the smallest honest first run. Lite keeps the Custodia security model: API mTLS, client-side cryptography, opaque ciphertext/envelope storage, Web MFA and audit integrity. Full/custom deployments use the same binaries but require real external infrastructure such as PostgreSQL/CockroachDB, Valkey, HSM/PKCS#11, WORM/SIEM shipment and production evidence gates.

## Runbook metadata

| Field | Value |
| --- | --- |
| Audience | First-time bare-metal operators, developers and package evaluators. |
| Prerequisites | A clean Linux host and either release packages or a Git checkout with the documented toolchain. |
| Outcome | A Lite server/signer install with Web MFA, admin checks and the first encrypted client smoke path. |
| Do not continue if | You need Kubernetes or Full production dependencies; use the dedicated Kubernetes or Full runbooks first. |

## 1. Choose an install path

| Bare-metal path | Best for | Installs to |
| --- | --- | --- |
| Package install | Operators and first-time users | `/usr/bin`, `/etc/custodia`, `/var/lib/custodia` |
| Source install / Git clone | Maintainers, developers, packagers and local testing | `/usr/local/bin`, `/usr/local/share/custodia`, `/etc/custodia`, `/var/lib/custodia` |

Pick one bare-metal install path, then continue with the common runtime setup. Kubernetes is a separate deployment target and is intentionally not driven by `systemctl`; use [`KUBERNETES_INSTALL.md`](KUBERNETES_INSTALL.md) instead.

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
| `custodia-server` | `custodia-server`, `custodia-admin`, `custodia-signer`, systemd units, server docs, YAML examples and the SQLite backup helper. |
| `custodia-client` | `custodia-client` CLI, manpage and client smoke documentation. |
| `custodia-sdk` | SDK source snapshots, the sourceable Bash SDK helper, shared crypto test vectors and SDK docs. |

For a client-only workstation, install only `custodia-client`. Do not install `custodia-server` on Alice/Bob hosts unless that host is intentionally also a server/admin host.

Debian or Ubuntu client-only install:

```bash
sudo apt update
sudo apt install -y ca-certificates curl openssl

curl -fLO "${BASE_URL}/custodia-client_${VERSION}-${REVISION}_amd64.deb"
curl -fLO "${BASE_URL}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS

sudo apt install -y "./custodia-client_${VERSION}-${REVISION}_amd64.deb"
```

Fedora client-only install:

```bash
sudo dnf install -y ca-certificates curl openssl

curl -fLO "${BASE_URL}/custodia-client-${VERSION}-${REVISION}.x86_64.rpm"
curl -fLO "${BASE_URL}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS

sudo dnf install -y "./custodia-client-${VERSION}-${REVISION}.x86_64.rpm"
```

Continue with [Configure the server profile](#4-configure-the-server-profile) for server/admin hosts. For client-only Alice/Bob hosts, skip server setup and continue when the server/admin host provides the printed server URL plus enrollment token in [Configure two clients and run an encrypted smoke test](#8-configure-two-clients-and-run-an-encrypted-smoke-test).

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

Build the artifacts you want to install. For a server-only host:

```bash
make build-server man
sudo make install-server PREFIX=/usr/local
```

For a server node plus local client smoke tests:

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
  /etc/custodia /var/lib/custodia /var/lib/custodia/backups /var/log/custodia
```

## 4. Configure the server profile

The same installed binaries can run Lite, Full or custom profiles. This quickstart configures Lite.

Set the name clients and browsers will use to reach the server. The value is embedded into the server certificate SAN. Never use `localhost` as the server name: it teaches the wrong endpoint, breaks real remote clients and should stay limited to internal loopback SAN compatibility. IP addresses are supported, but a stable DNS name is strongly recommended because it survives address changes and is easier to rotate operationally.

```bash
CUSTODIA_SERVER_NAME="$(hostname -f)"
# Examples:
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

For Full/custom deployments, keep the same binaries and replace the runtime configuration. Start from `/usr/share/doc/custodia/custodia-server.full.yaml.example`, `/usr/local/share/doc/custodia/custodia-server.full.yaml.example` or `deploy/examples/custodia-server.full.yaml`, then configure real external dependencies such as PostgreSQL/CockroachDB, Valkey, PKCS#11/HSM signer material, audit shipment/WORM evidence and production readiness checks. Do not treat Lite's SQLite/memory defaults as Full production settings. Use [`BARE_METAL_FULL_INSTALL.md`](BARE_METAL_FULL_INSTALL.md) for the copyable Full bare-metal checklist.

## 5. Configure first admin web access

The bootstrap command wrote `/etc/custodia/custodia-server.yaml`. Generate Web MFA material and append it once:

```bash
sudo custodia-admin web totp configure --account admin
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

Run the read-only doctor after the server and signer are configured. The default paths are `/etc/custodia/custodia-server.yaml` and `/etc/custodia/custodia-signer.yaml`:

```bash
sudo -u custodia custodia-admin doctor
```

Read API status with the generated admin mTLS certificate. The command reads the server URL and admin mTLS paths from `/etc/custodia/custodia-server.yaml`:

```bash
sudo -u custodia custodia-admin status read
```

Expected result: JSON status metadata. It must not contain plaintext secrets, DEKs, private keys or envelopes.

Diagnostics:

```bash
sudo -u custodia custodia-admin diagnostics read
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

Use the same DNS name or IP address configured as `CUSTODIA_SERVER_NAME`.

After importing it into the browser, remove the temporary bundle:

```bash
rm -f /tmp/custodia-admin.p12
```

The Web Console is metadata-only. It does not decrypt or display secret plaintext.

## 8. Configure two clients and run an encrypted smoke test

Custodia client profiles are per-user. Passing `--client-id client_alice` stores client-side material under `$XDG_CONFIG_HOME/custodia/client_alice`, or `$HOME/.config/custodia/client_alice` when `XDG_CONFIG_HOME` is not set. Do not use `/etc/custodia` for client-only hosts.

Create a short-lived enrollment token on the server/admin host:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

The command reads `/etc/custodia/custodia-server.yaml`, contacts the configured server URL, and prints a one-shot enrollment token plus the server URL. Transfer those values to the client host. The token is sensitive and expires quickly. When operating through the Web Console, use **Client Enrollments** to create the same one-shot token without shell access to the server or Kubernetes pod.

Enrollment uses normal TLS certificate validation by default. The server URL must match the server certificate SAN. This Quickstart uses a locally generated lab CA that is not installed in the client trust store yet, so the first disposable lab enrollment uses `--insecure`. For real remote clients, install/trust the Custodia CA first and remove `--insecure`; use [`CLIENT_TRUSTED_CA.md`](CLIENT_TRUSTED_CA.md) for the copyable Linux trust-store steps.

Set Alice's client id and the enrollment values on Alice's workstation. Use the server URL and token printed by the server/admin host; do not paste the literal placeholder values below:

```bash
export ALICE_ID=client_alice
export CUSTODIA_SERVER_URL="https://SERVER_IP_OR_HOSTNAME:8443"
export ALICE_ENROLLMENT_TOKEN="ENROLLMENT_TOKEN"
```

Enroll Alice from Alice's workstation:

```bash
custodia-client mtls enroll \
  --client-id "$ALICE_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$ALICE_ENROLLMENT_TOKEN" \
  --insecure
```

This generates Alice's mTLS private key and CSR locally, sends only the CSR plus token to Custodia, receives Alice's signed certificate plus `ca.crt`, and installs the public material into Alice's standard client profile. The mTLS private key never leaves Alice's workstation.

Configure Alice's local application encryption key, reusable client profile and server-published public-key metadata:

```bash
custodia-client key generate --client-id "$ALICE_ID"
custodia-client config write --client-id "$ALICE_ID"
custodia-client key publish --client-id "$ALICE_ID"
custodia-client config check --client-id "$ALICE_ID"
custodia-client doctor --client-id "$ALICE_ID" --online
```

`key publish` uploads only Alice's application public key and fingerprint. Alice's application private key remains local.

Create and read back an encrypted secret as Alice. Keep demo plaintext/output files outside the client profile:

```bash
SMOKE_NAMESPACE=default
SMOKE_KEY=smoke-demo
SMOKE_SECRET="$HOME/custodia-smoke-secret.txt"
SMOKE_READBACK="$HOME/custodia-smoke-secret.readback.txt"

printf 'super secret demo value' > "$SMOKE_SECRET"
chmod 600 "$SMOKE_SECRET"

custodia-client secret put --client-id "$ALICE_ID" --namespace "$SMOKE_NAMESPACE" --key "$SMOKE_KEY" --value-file "$SMOKE_SECRET"

custodia-client secret get --client-id "$ALICE_ID" --namespace "$SMOKE_NAMESPACE" --key "$SMOKE_KEY" --out "$SMOKE_READBACK"

cat "$SMOKE_READBACK"
```

Expected output:

```text
super secret demo value
```

Create another enrollment token for Bob on the server/admin host:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

Transfer Bob's enrollment values to Bob. Enroll Bob from Bob's workstation. This disposable lab flow still uses the locally generated untrusted CA, so the example keeps `--insecure`. Remove it for real remote clients after installing/trusting the Custodia CA with [`CLIENT_TRUSTED_CA.md`](CLIENT_TRUSTED_CA.md):

```bash
export BOB_ID=client_bob
export CUSTODIA_SERVER_URL="https://SERVER_IP_OR_HOSTNAME:8443"
export BOB_ENROLLMENT_TOKEN="ENROLLMENT_TOKEN"

custodia-client mtls enroll \
  --client-id "$BOB_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$BOB_ENROLLMENT_TOKEN" \
  --insecure
```

Configure Bob's local application encryption key, reusable client profile and server-published public-key metadata:

```bash
custodia-client key generate --client-id "$BOB_ID"
custodia-client config write --client-id "$BOB_ID"
custodia-client key publish --client-id "$BOB_ID"
custodia-client config check --client-id "$BOB_ID"
custodia-client doctor --client-id "$BOB_ID" --online
```

`key publish` uploads only Bob's application public key and fingerprint. Bob's application private key remains local. Alice can then share the secret with Bob by client id; the CLI resolves Bob's published public key from Custodia metadata:

```bash
ALICE_ID=client_alice
SMOKE_NAMESPACE=default
SMOKE_KEY=smoke-demo
BOB_ID=client_bob

custodia-client secret share --client-id "$ALICE_ID" --namespace "$SMOKE_NAMESPACE" --key "$SMOKE_KEY" --target-client-id "$BOB_ID" --permissions read
```

Transfer the namespace/key values to Bob when Bob is remote. Bob can now read and decrypt the shared secret locally without knowing any owner or internal server id:

```bash
SMOKE_NAMESPACE=default
SMOKE_KEY=smoke-demo
BOB_READBACK="$HOME/custodia-smoke-bob.readback.txt"

custodia-client secret get --client-id "$BOB_ID" --namespace "$SMOKE_NAMESPACE" --key "$SMOKE_KEY" --out "$BOB_READBACK"

cat "$BOB_READBACK"
```

Expected output:

```text
super secret demo value
```

Revoke Bob's future server-side access and delete the smoke secret when the test is complete:

```bash
custodia-client secret access revoke --client-id "$ALICE_ID" --namespace "$SMOKE_NAMESPACE" --key "$SMOKE_KEY" --target-client-id "$BOB_ID" --yes

custodia-client secret delete --client-id "$ALICE_ID" --namespace "$SMOKE_NAMESPACE" --key "$SMOKE_KEY" --yes
```

The vault received only ciphertext, crypto metadata and opaque envelopes. Plaintext, mTLS private keys and application private keys stayed local to each client. Access revocation and deletion prevent future server-side reads; material already downloaded by authorized clients remains outside server control.

For a complete two-client version/revoke workflow, follow [`docs/CUSTODIA_ALICE_BOB_SMOKE.md`](CUSTODIA_ALICE_BOB_SMOKE.md). For a release-candidate end-to-end rehearsal that follows this Quickstart across server, Alice, Bob, Web Console checkpoints and Lite backup, use [`docs/END_TO_END_OPERATOR_SMOKE.md`](END_TO_END_OPERATOR_SMOKE.md).

## 9. Basic backup check for Lite

SQLite backups should use an online backup flow, not blind file copies of the live database:

```bash
if [ -x /usr/local/sbin/custodia-sqlite-backup ]; then
  CUSTODIA_SQLITE_BACKUP=/usr/local/sbin/custodia-sqlite-backup
else
  CUSTODIA_SQLITE_BACKUP=/usr/sbin/custodia-sqlite-backup
fi

sudo -u custodia env \
  CUSTODIA_SQLITE_DB=/var/lib/custodia/custodia.db \
  CUSTODIA_SQLITE_BACKUP_DIR=/var/lib/custodia/backups \
  "$CUSTODIA_SQLITE_BACKUP"
```

## 10. First-run checklist

Before considering the node ready for real data:

- `systemctl status custodia-server` is healthy;
- `systemctl status custodia-signer` is healthy when you need client certificate issuance;
- `custodia-admin doctor` passes against the default server and signer configs;
- `custodia-admin status read` succeeds using the admin transport defaults from `/etc/custodia/custodia-server.yaml`;
- the Web Console opens through the configured host name/IP and requires TOTP;
- `custodia-client config check` succeeds for Alice and Bob;
- `custodia-client key publish` succeeds for Alice and Bob;
- `custodia-client doctor --online` succeeds for Alice and Bob;
- encrypted `secret put`, `secret share`, `secret get` and `secret delete` work by namespace/key;
- `/etc/custodia` is mode `0750` or stricter;
- private keys under `/etc/custodia` are mode `0600`;
- the CA passphrase file is backed up or the CA key is moved offline;
- the admin browser PKCS#12 bundle was removed after import;
- SQLite backup/restore was tested;
- remote firewall exposure was reviewed.

## 11. Diagnose the installation

Run the read-only doctor after the server and signer are configured:

```bash
sudo -u custodia custodia-admin doctor
```

For client-side checks:

```bash
custodia-client doctor --client-id "$ALICE_ID"
```

For an online mTLS reachability check with the non-admin client identity:

```bash
custodia-client doctor --client-id "$ALICE_ID" --online
```

## 12. What to read next

- Deployment matrix: [`docs/DEPLOYMENT_MATRIX.md`](DEPLOYMENT_MATRIX.md)
- Kubernetes install: [`docs/KUBERNETES_INSTALL.md`](KUBERNETES_INSTALL.md)
- Kubernetes Lite backup and restore: [`docs/KUBERNETES_LITE_BACKUP_RESTORE.md`](KUBERNETES_LITE_BACKUP_RESTORE.md)
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
