# Package clean-install smoke

This smoke validates the Linux package install path on a disposable clean release-candidate machine. It is intentionally separate from `make package-smoke`:

- `make package-smoke` extracts `.deb` and `.rpm` artifacts into a temporary directory and checks their payloads without touching the host package database.
- `scripts/package-install-smoke.sh install-verify` first extracts the selected artifacts and validates the expected package manifest, then installs them through the host package manager and verifies the installed layout, package database, runtime directories, systemd units, manpages and side-effect-free CLI entrypoints.

Use this smoke after building release-candidate packages and before publishing artifacts. Run it on clean Debian/Ubuntu and Fedora/RHEL-compatible machines, not on a developer workstation with existing Custodia packages or real data.

## Runbook metadata

| Field | Value |
| --- | --- |
| Audience | Release engineers validating DEB/RPM package installation on clean machines. |
| Prerequisites | Fresh generated packages copied to a disposable Debian/Ubuntu or Fedora/RHEL-compatible host. |
| Outcome | Package-manager installation evidence without automatic service enablement/start side effects. |
| Do not continue if | The host has existing Custodia state, minimized doc/manpage filters or production data. |

## Build artifacts first

From the repository checkout used to produce the release candidate:

```bash
VERSION=0.1.0 REVISION=1 PACKAGE_NAMES="server client sdk" make package-linux
VERSION=0.1.0 REVISION=1 make package-checksums
cd dist/packages && sha256sum -c SHA256SUMS
```

Copy the relevant artifacts to the clean test machine. The smoke reads packages from `dist/packages` by default; override `PACKAGE_DIR` when artifacts live elsewhere.

## Safe wiring check

This target does not install anything. It validates script wiring, artifact discovery and package payload manifests so stale or incomplete artifacts fail before a clean VM is modified:

```bash
make package-install-smoke
```

Equivalent explicit command:

```bash
./scripts/package-install-smoke.sh check-only
```

## Debian/Ubuntu clean install

On a clean Debian or Ubuntu VM/container containing the generated `.deb` artifacts:

```bash
sudo apt update
sudo apt install -y ca-certificates adduser curl

export PACKAGE_DIR=/path/to/dist/packages
export CUSTODIA_PACKAGE_INSTALL_FORMAT=deb
export CUSTODIA_PACKAGE_INSTALL_SCOPE=all
export CUSTODIA_PACKAGE_INSTALL_CONFIRM=YES
sudo -E ./scripts/package-install-smoke.sh install-verify
```

Before installation, the smoke extracts each selected `.deb` and verifies it against the repository package manifest. That catches stale or incomplete artifacts, including missing compressed manpages, before the VM package database is modified.

The smoke also checks Debian `dpkg` path filters before installing. Minimal container images often ship `/etc/dpkg/dpkg.cfg.d/excludes` entries such as `path-exclude=/usr/share/man/*` or `path-exclude=/usr/share/doc/*`; those hosts intentionally discard manpages/docs during `dpkg -i` even when the artifact payload is correct. Use a full clean VM, or disable those filters for the disposable smoke machine, when validating release packages.

The smoke then installs `custodia-server`, `custodia-client` and `custodia-sdk` with `dpkg -i` and verifies:

- all three packages are registered as installed;
- `custodia-server`, `custodia-admin`, `custodia-signer` and `custodia-client` exist under `/usr/bin`;
- `custodia-sqlite-backup` exists under `/usr/sbin`;
- server, signer, admin and client manpages are installed;
- server and signer systemd units are installed but not enabled automatically;
- the `custodia` user/group and runtime directories are created with expected ownership and modes;
- server YAML examples, client docs, SDK source snapshots and crypto vectors are present;
- `custodia-admin version` and `custodia-client help` run without side effects.

The smoke does **not** start `custodia-server` or `custodia-signer`. Runtime startup belongs to the Quickstart, operator E2E smoke and deployment-specific tests that create real config, certificates and enrollment material.

## Fedora/RHEL-compatible clean install

On a clean Fedora/RHEL-compatible VM/container containing the generated `.rpm` artifacts:

```bash
sudo dnf install -y ca-certificates curl shadow-utils rpm

export PACKAGE_DIR=/path/to/dist/packages
export CUSTODIA_PACKAGE_INSTALL_FORMAT=rpm
export CUSTODIA_PACKAGE_INSTALL_SCOPE=all
export CUSTODIA_PACKAGE_INSTALL_CONFIRM=YES
sudo -E ./scripts/package-install-smoke.sh install-verify
```

Before installation, the smoke extracts each selected `.rpm` through `rpm2cpio`/`cpio` and verifies it against the repository package manifest. The same installed-layout checks then run through the RPM package database.

## Partial package scopes

Use partial scopes when validating split installation hosts:

```bash
# Server/admin node only.
export CUSTODIA_PACKAGE_INSTALL_SCOPE=server
sudo -E ./scripts/package-install-smoke.sh install-verify

# Client workstation only.
export CUSTODIA_PACKAGE_INSTALL_SCOPE=client
sudo -E ./scripts/package-install-smoke.sh install-verify

# SDK documentation/source snapshot only.
export CUSTODIA_PACKAGE_INSTALL_SCOPE=sdk
sudo -E ./scripts/package-install-smoke.sh install-verify
```

`server-client` validates a combined server/admin host that also carries the local client CLI for smoke tests.

## Existing installs

By default the smoke fails if any selected Custodia package is already installed. That keeps clean-install validation honest and prevents accidental upgrades over real state.

For an explicit upgrade/reinstall rehearsal on a disposable host, opt in:

```bash
export CUSTODIA_PACKAGE_INSTALL_ALLOW_EXISTING=true
export CUSTODIA_PACKAGE_INSTALL_CONFIRM=YES
sudo -E ./scripts/package-install-smoke.sh install-verify
```

Do not use this override on production hosts.
