# Custodia release check

`make release-check` is the local pre-release gate for the repository baseline. For the 1.0.0 release scope, see [`RELEASE_NOTES_1_0_0.md`](RELEASE_NOTES_1_0_0.md). For final release-candidate sign-off, use [`RELEASE_READINESS_MATRIX.md`](RELEASE_READINESS_MATRIX.md).

It runs:

- keyspace public workflow guardrails;
- Helm chart render guardrails when `helm` is installed;
- Lite backup/restore smoke wiring;
- Go unit tests for all packages;
- server, admin CLI and signer builds;
- Python client syntax compilation and tests;
- Node.js syntax checks and tests;
- Java, C++, Rust and Bash client checks;
- packaging checks in CI through `make package-deb` and `make package-rpm`, producing `custodia-server`, `custodia-client` and `custodia-sdk`;
- formal verification checks when TLC is installed.

## Usage

```bash
make release-check
make helm-check
make package-install-smoke
make lite-backup-restore-smoke
make operator-e2e-smoke
make kubernetes-runtime-smoke
make operational-readiness-smoke
```

If Helm is not installed, the script skips chart render checks with a warning; release pipelines that publish Kubernetes artifacts should install Helm and run `make helm-check` as a required job. `make helm-check` renders the committed Full and Lite example values and verifies that unsafe combinations such as Lite without PVC and Full with SQLite fail closed.

`make lite-backup-restore-smoke` is a safe wiring check for the disposable Lite backup/restore smoke in [`LITE_BACKUP_RESTORE_SMOKE.md`](LITE_BACKUP_RESTORE_SMOKE.md). `make package-install-smoke` is a safe artifact-discovery check for the clean-install package smoke; the real install path in [`PACKAGE_INSTALL_SMOKE.md`](PACKAGE_INSTALL_SMOKE.md) must be run manually on disposable Debian/Ubuntu and Fedora/RHEL-compatible release-candidate machines. `make operator-e2e-smoke` is a safe wiring check for the opt-in end-to-end smoke harness; the destructive roles in [`END_TO_END_OPERATOR_SMOKE.md`](END_TO_END_OPERATOR_SMOKE.md) must be run manually on disposable release-candidate hosts. `make kubernetes-runtime-smoke` is a safe wiring check for the Kubernetes runtime smoke helper; the real cluster check in [`KUBERNETES_RUNTIME_SMOKE.md`](KUBERNETES_RUNTIME_SMOKE.md) must be run manually against a release-candidate cluster. `make operational-readiness-smoke` is a safe wiring check for the read-only endpoint smoke in [`OPERATIONAL_READINESS_SMOKE.md`](OPERATIONAL_READINESS_SMOKE.md); the real endpoint check must be run manually against a bootstrapped server or exposed Kubernetes release.

If TLC is not installed, the script skips formal verification with a warning. Production release pipelines should install TLC and run `make formal-check` as a required job.

## Release-candidate sign-off

`make release-check` is only the repository baseline. Before publishing a release candidate, also follow [`RELEASE_READINESS_MATRIX.md`](RELEASE_READINESS_MATRIX.md) for package clean-install checks, Lite backup/restore smoke, source operator smoke, Kubernetes runtime smoke, operational endpoint smoke and production evidence gates.

## Scope

This gate validates repository artifacts only. It does not prove that production has a real HSM, WORM bucket, HA database or revocation distribution topology; those are validated by the production readiness gate and external infrastructure evidence.

## Keyspace public workflow guardrail

`make release-check` runs `scripts/release-keyspace-check.sh` before the full test suite. The guardrail fails if public CLI, SDK or Web Console documentation reintroduces `--secret-id` or public SDK helpers that address normal user workflows by internal secret identifiers.

The check intentionally allows `secret_id` in storage, audit, response correlation and documented operator/internal-id paths.

## Linux packages

Local release candidates can build installable packages with:

```bash
make package-deb
make package-rpm
# Or build both formats explicitly:
VERSION=1.0.0 REVISION=1 PACKAGE_NAMES="server client sdk" make package-linux
```

For a fully automated local release flow, use the release publisher:

```bash
VERSION=1.0.0 REVISION=1 ./scripts/release-publish.sh dry-run
VERSION=1.0.0 REVISION=1 RELEASE_CONFIRM=YES ./scripts/release-publish.sh draft
```

This runs repository checks, builds DEB/RPM packages, generates `SHA256SUMS`, `artifacts-manifest.json`, `release-provenance.json` and `custodia-sbom.spdx.json`, creates the annotated tag, pushes the branch/tag, creates the GitHub release and uploads/verifies all assets. Use `publish` instead of `draft` only when you intentionally want the release to be public immediately.

After a GitHub release already exists, upload or replace only the selected package artifacts plus `SHA256SUMS`, `artifacts-manifest.json`, `release-provenance.json` and `custodia-sbom.spdx.json` with:

```bash
VERSION=1.0.0 REVISION=1 CUSTODIA_RELEASE_TAG=v1.0.0 make github-release-upload-assets
```

The CI workflow builds both formats and uploads the generated artifacts. See [`LINUX_PACKAGES.md`](LINUX_PACKAGES.md).
