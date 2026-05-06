# Linux DEB/RPM packages

Custodia can build local Linux installation packages without introducing an external packaging tool such as `fpm`.

The repository produces two package families. Server packages are Lite-capable by default: the packaging script builds Go binaries with `SERVER_BUILD_TAGS=sqlite` unless explicitly overridden:

| Package | Architecture | Contents | Intended use |
| --- | --- | --- | --- |
| `custodia-server` | host arch | `custodia-server`, `custodia-admin`, `custodia-signer`, systemd unit, examples and server docs | Install and operate a Custodia node. |
| `custodia-clients` | `all` / `noarch` | SDK source snapshots, shared crypto vectors, SDK docs and `/usr/bin/custodia-client` Bash helper | Developer/CI/ops client integration. |

This split is intentional. Operating-system packages are good for deployable binaries and local source snapshots. Language SDK distribution should still use language-native channels when the project starts publishing real public packages:

- Go module import path;
- Python wheel/sdist;
- npm package;
- Maven/Gradle artifact;
- CMake/vcpkg/conan package;
- Cargo crate.

Creating one `.deb`/`.rpm` per SDK language would add distro-package maintenance overhead before those registry workflows exist. The current `custodia-clients` package keeps the repository installable while avoiding premature package names that would look officially published.

## Build DEB packages

```bash
VERSION=0.1.0 REVISION=1 make package-deb
# Override only if you intentionally do not want the default Lite-capable SQLite build:
SERVER_BUILD_TAGS= VERSION=0.1.0 REVISION=1 make package-deb
```

Artifacts are written to:

```text
dist/packages/
```

Expected files:

```text
custodia-server_<version>-<revision>_<arch>.deb
custodia-clients_<version>-<revision>_all.deb
```

## Build RPM packages

`rpmbuild` is required:

```bash
VERSION=0.1.0 REVISION=1 make package-rpm
```

Expected files:

```text
custodia-server-<version>-<revision>.<arch>.rpm
custodia-clients-<version>-<revision>.noarch.rpm
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
/usr/lib/systemd/system/custodia.service
/usr/lib/systemd/system/custodia-signer.service
/usr/share/custodia/examples/
/usr/share/doc/custodia-server/
/etc/custodia/
/var/lib/custodia/
/var/log/custodia/
```

Package install scripts create a system user/group named `custodia` when the package manager supports the usual `useradd`/`adduser` flow.

The package does **not** install a live `/etc/custodia/config.yaml` by default, to avoid silently starting with unsafe local settings. Copy and review an example first:

```bash
sudo install -d -m 0750 -o root -g custodia /etc/custodia
sudo cp /usr/share/custodia/examples/config.lite.yaml /etc/custodia/config.yaml
sudo editor /etc/custodia/config.yaml
sudo systemctl enable --now custodia custodia-signer
```

## Client package layout

`custodia-clients` installs:

```text
/usr/bin/custodia-client
/usr/share/custodia/clients/
/usr/share/custodia/testdata/client-crypto/
/usr/share/doc/custodia-clients/
```

The Go source snapshot includes `go.mod`, `pkg/client` and the internal client-crypto package required by that public Go SDK surface. `/usr/bin/custodia-client` is the Go encrypted secrets CLI for local put/get/share/version workflows. The Bash transport helper is still shipped under `/usr/share/custodia/clients/bash/custodia.sh` for CI and raw REST/mTLS smoke tests.

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

The smoke check does not install packages into the host system. It extracts `.deb` artifacts with `dpkg-deb` and `.rpm` artifacts with `rpm2cpio`, then verifies the expected binaries, examples, SDK source snapshots, shared test vectors and Bash helper entrypoint.

For server packages, the smoke check executes `custodia-admin version` because it is side-effect free. It verifies that both `custodia.service` and `custodia-signer.service` are packaged, but it does not start `custodia-server` or `custodia-signer`; runtime startup belongs to deployment or integration tests with real configuration and certificates.

## GitHub release workflow

The manual GitHub Actions workflow `.github/workflows/release.yml` builds release artifacts from a selected commit. It runs the repository release check, builds `.deb` and `.rpm` packages, generates `SHA256SUMS` and `artifacts-manifest.json`, smoke-tests the package contents and uploads all release files as workflow artifacts.

To publish a GitHub release, run the workflow with:

- `version`: semantic version without the leading `v`, for example `0.1.0`;
- `revision`: package revision, usually `1`;
- `create_release`: `true`;
- `prerelease`: `true` only for prerelease builds.

The workflow creates or updates tag release `vVERSION` and uploads the package artifacts plus checksum files.
