# Custodia release check

`make release-check` is the local pre-release gate for the repository baseline.

It runs:

- Go unit tests for all packages;
- server, admin CLI and signer builds;
- Python client syntax compilation and tests;
- Node.js syntax checks and tests;
- Java, C++, Rust and Bash client checks;
- packaging checks in CI through `make package-deb` and `make package-rpm`;
- formal verification checks when TLC is installed.

## Usage

```bash
make release-check
```

If TLC is not installed, the script skips formal verification with a warning. Production release pipelines should install TLC and run `make formal-check` as a required job.

## Scope

This gate validates repository artifacts only. It does not prove that production has a real HSM, WORM bucket, HA database or revocation distribution topology; those are validated by the production readiness gate and external infrastructure evidence.

## Linux packages

Local release candidates can build installable packages with:

```bash
make package-deb
make package-rpm
```

The CI workflow builds both formats and uploads the generated artifacts. See [`LINUX_PACKAGES.md`](LINUX_PACKAGES.md).
