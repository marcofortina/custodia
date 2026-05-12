# Linux DEB/RPM packages

Custodia can build local Linux installation packages without introducing an external packaging tool such as `fpm`.

The repository produces three package families. Server packages are universal by default: the packaging script builds Go binaries with `SERVER_BUILD_TAGS="sqlite postgres"` unless explicitly overridden. Lite and Full behavior are selected by runtime configuration, not by installing different server products:

| Package | Architecture | Contents | Intended use |
| --- | --- | --- | --- |
| `custodia-server` | host arch | `custodia-server`, `custodia-admin`, `custodia-signer`, systemd units, server docs, YAML examples and SQLite backup helper | Install and operate a Custodia node. |
| `custodia-client` | host arch | encrypted `/usr/bin/custodia-client` CLI | Operator workstations, CI and client-side smoke tests. |
| `custodia-sdk` | `all` / `noarch` | SDK source snapshots, the sourceable Bash SDK helper, shared crypto vectors and SDK docs | Application developers integrating Custodia. |

This split is intentional. Operating-system packages are good for deployable binaries and local source snapshots. Language SDK distribution should still use language-native channels when the project starts publishing real public packages:

- Go module import path;
- Python wheel/sdist;
- npm package;
- Maven/Gradle artifact;
- CMake/vcpkg/conan package;
- Cargo crate.

Creating one `.deb`/`.rpm` per SDK language would add distro-package maintenance overhead before those registry workflows exist. The `custodia-sdk` package keeps source snapshots, shared vectors and SDK documentation installable while avoiding premature language-registry package names that would look officially published.

## Build DEB packages

```bash
VERSION=0.1.0 REVISION=1 make package-deb
# Override only for specialized diagnostics, for example to build only PostgreSQL support:
SERVER_BUILD_TAGS=postgres VERSION=0.1.0 REVISION=1 make package-deb
```

Artifacts are written to:

```text
dist/packages/
```

Expected files:

```text
custodia-server_<version>-<revision>_<arch>.deb
custodia-client_<version>-<revision>_<arch>.deb
custodia-sdk_<version>-<revision>_all.deb
```

## Build RPM packages

`rpmbuild` is required:

```bash
VERSION=0.1.0 REVISION=1 make package-rpm
```

Expected files:

```text
custodia-server-<version>-<revision>.<arch>.rpm
custodia-client-<version>-<revision>.<arch>.rpm
custodia-sdk-<version>-<revision>.noarch.rpm
```

## Build both formats

```bash
VERSION=0.1.0 REVISION=1 make package-linux
```

## Build metadata

The package script stamps Go binaries with the same metadata used by normal release builds:

```bash
VERSION=0.1.0 \
REVISION=1 \
COMMIT="$(git rev-parse --short=12 HEAD)" \
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
make package-linux
```

## First-run quickstart

For a guided install on a clean Debian, Ubuntu or Fedora host, use [`docs/QUICKSTART.md`](QUICKSTART.md). The quickstart uses the package layout below and does not require a cloned source tree on the target host.

## Server package layout

`custodia-server` installs:

```text
/usr/bin/custodia-server
/usr/bin/custodia-admin
/usr/bin/custodia-signer
/usr/lib/systemd/system/custodia-server.service
/usr/lib/systemd/system/custodia-signer.service
/usr/sbin/custodia-sqlite-backup
/usr/share/doc/custodia/
/etc/custodia/
/var/lib/custodia/
/var/lib/custodia/backups/
/var/log/custodia/
```

Package install scripts create a system user/group named `custodia` when the package manager supports the usual `useradd`/`adduser` flow.

The package does **not** install a live `/etc/custodia/custodia-server.yaml` by default, to avoid silently starting with unsafe local settings. Copy and review an example first:

```bash
sudo install -d -m 0750 -o root -g custodia /etc/custodia
sudo cp /usr/share/doc/custodia/custodia-server.lite.yaml.example /etc/custodia/custodia-server.yaml
sudo cp /usr/share/doc/custodia/custodia-signer.yaml.example /etc/custodia/custodia-signer.yaml
sudo chown custodia:custodia /etc/custodia/custodia-server.yaml /etc/custodia/custodia-signer.yaml
sudo chmod 0640 /etc/custodia/custodia-server.yaml /etc/custodia/custodia-signer.yaml
sudo editor /etc/custodia/custodia-server.yaml
sudo editor /etc/custodia/custodia-signer.yaml
sudo systemctl enable --now custodia-server custodia-signer
```

Set `server.url` in `custodia-server.yaml` to the HTTPS API URL that remote clients will use. `custodia-admin client enrollment create` prints that configured URL with each one-shot enrollment token.

## Client package layout

`custodia-client` installs:

```text
/usr/bin/custodia-client
/usr/share/man/man1/custodia-client.1.gz
/usr/share/doc/custodia-client/
```

`/usr/bin/custodia-client` is the Go encrypted secrets CLI for local put/get/share/version workflows, client-side config validation, online doctor checks and mTLS CSR generation.

## SDK package layout

`custodia-sdk` installs:

```text
/usr/share/custodia/sdk/
/usr/share/custodia/sdk/testdata/client-crypto/
/usr/share/custodia/sdk/clients/bash/custodia.bash
/usr/share/doc/custodia-sdk/
```

The Go source snapshot includes `go.mod`, `pkg/client` and the internal client-crypto package required by that public Go SDK surface. Other language SDK source snapshots are installed under `/usr/share/custodia/sdk/clients/`.

## CI

GitHub Actions runs:

```bash
make release-check
make package-deb
make package-rpm
```

The generated `.deb` and `.rpm` files are uploaded as workflow artifacts.

## Release checksums and manifest

After building packages, generate release verification files:

```bash
VERSION=0.1.0 REVISION=1 make package-linux
VERSION=0.1.0 REVISION=1 make package-checksums
```

This writes:

- `dist/packages/SHA256SUMS` with SHA-256 digests for every `.deb` and `.rpm` artifact.
- `dist/packages/artifacts-manifest.json` with artifact names, package types, byte sizes, SHA-256 digests, version, revision, source commit and generation time.

Operators should verify downloaded artifacts before installation:

```bash
cd dist/packages
sha256sum -c SHA256SUMS
```

The manifest is intentionally metadata-only and does not include package contents.

## Package smoke checks

After building packages, run extraction-based smoke checks:

```bash
VERSION=0.1.0 REVISION=1 make package-linux
make package-smoke
```

The smoke check does not install packages into the host system. It extracts `.deb` artifacts with `dpkg-deb` and `.rpm` artifacts with `rpm2cpio`, then verifies the expected binaries, server documentation examples, SQLite backup helper, SDK source snapshots, shared test vectors, encrypted client CLI and Bash helper entrypoint.

For server packages, the smoke check executes `custodia-admin version` because it is side-effect free. It verifies that both `custodia-server.service` and `custodia-signer.service` are packaged, but it does not start `custodia-server` or `custodia-signer`; runtime startup belongs to deployment or integration tests with real configuration and certificates.

## Clean-install package smoke

Before publishing release artifacts, validate the package manager path on disposable clean machines:

```bash
# Safe local wiring check only.
make package-install-smoke

# On a clean Debian/Ubuntu or Fedora/RHEL-compatible test machine:
export PACKAGE_DIR=/path/to/dist/packages
export CUSTODIA_PACKAGE_INSTALL_FORMAT=deb   # or rpm
export CUSTODIA_PACKAGE_INSTALL_CONFIRM=YES
sudo -E ./scripts/package-install-smoke.sh install-verify
```

The clean-install smoke uses `dpkg -i` or `rpm -Uvh --replacepkgs`, then checks the installed package database, binaries, manpages, docs, SDK snapshots, systemd units, server runtime user/directories and service enablement state. It does not enable or start services. See [`PACKAGE_INSTALL_SMOKE.md`](PACKAGE_INSTALL_SMOKE.md).

## GitHub release workflow

The manual GitHub Actions workflow `.github/workflows/release.yml` builds release artifacts from a selected commit. It runs the repository release check, builds `.deb` and `.rpm` packages, generates `SHA256SUMS` and `artifacts-manifest.json`, smoke-tests the package contents and uploads all release files as workflow artifacts.

To publish a GitHub release, run the workflow with:

- `version`: semantic version without the leading `v`, for example `0.1.0`;
- `revision`: package revision, usually `1`;
- `create_release`: `true`;
- `prerelease`: `true` only for prerelease builds.

The workflow creates or updates tag release `vVERSION` and uploads the package artifacts plus checksum files.


## Runtime file permissions

Packages create the `custodia` user and the main runtime directories. Install runtime YAML, certificates and private keys with the ownership and modes documented in [`FILE_PERMISSIONS.md`](FILE_PERMISSIONS.md).
