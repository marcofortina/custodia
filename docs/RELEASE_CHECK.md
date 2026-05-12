# Custodia release check

`make release-check` is the local pre-release gate for the repository baseline. For the 0.1.0 release scope, see [`RELEASE_NOTES_0_1_0.md`](RELEASE_NOTES_0_1_0.md).

It runs:

- keyspace public workflow guardrails;
- Helm chart render guardrails when `helm` is installed;
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
```

If Helm is not installed, the script skips chart render checks with a warning; release pipelines that publish Kubernetes artifacts should install Helm and run `make helm-check` as a required job. If TLC is not installed, the script skips formal verification with a warning. Production release pipelines should install TLC and run `make formal-check` as a required job.

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
VERSION=0.1.0 REVISION=1 PACKAGE_NAMES="server client sdk" make package-linux
```

The CI workflow builds both formats and uploads the generated artifacts. See [`LINUX_PACKAGES.md`](LINUX_PACKAGES.md).
