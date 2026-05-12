# Release readiness matrix

This matrix is the operator-facing sign-off map for a Custodia release candidate.
It ties repository checks, package checks, deployment checks and external
production evidence together without pretending that one command can prove a
whole production environment.

Custodia has three deployment targets:

- bare metal from source;
- bare metal from DEB/RPM packages;
- Kubernetes from a Git-built image plus the Helm chart.

Lite, Full and custom are runtime profiles selected by configuration. They are
not different products and they are not different server binaries.

## Gate summary

| Gate | Where it runs | Required for | Command / runbook |
| --- | --- | --- | --- |
| Repository baseline | developer/CI checkout | every release candidate | `make release-check` |
| Helm render safety | developer/CI checkout with Helm | Kubernetes artifacts | `make helm-check` |
| Package payload smoke | developer/CI checkout | DEB/RPM artifacts | `make package-smoke` |
| Package clean install smoke | disposable clean Debian/Ubuntu and Fedora/RHEL-compatible machines | package publication | [`PACKAGE_INSTALL_SMOKE.md`](PACKAGE_INSTALL_SMOKE.md) |
| Lite backup/restore smoke | developer/CI checkout with `sqlite3` | Lite-capable release candidates | [`LITE_BACKUP_RESTORE_SMOKE.md`](LITE_BACKUP_RESTORE_SMOKE.md) |
| Bare-metal/source operator smoke | disposable release-candidate hosts | source install and first-use UX | [`END_TO_END_OPERATOR_SMOKE.md`](END_TO_END_OPERATOR_SMOKE.md) |
| Kubernetes runtime smoke | already installed release-candidate cluster | Kubernetes promotion | [`KUBERNETES_RUNTIME_SMOKE.md`](KUBERNETES_RUNTIME_SMOKE.md) |
| Operational readiness smoke | running bare-metal or Kubernetes endpoint | endpoint promotion | [`OPERATIONAL_READINESS_SMOKE.md`](OPERATIONAL_READINESS_SMOKE.md) |
| Production config gate | offline production evidence workstation | production promotion | [`PRODUCTION_READINESS_GATE.md`](PRODUCTION_READINESS_GATE.md) |
| Security hardening final review | release manager / security reviewer | production-ready claim | [`SECURITY_HARDENING_FINAL_REVIEW.md`](SECURITY_HARDENING_FINAL_REVIEW.md) |
| External evidence gate | offline production evidence workstation | Fort Knox production claim | [`PRODUCTION_EVIDENCE.md`](PRODUCTION_EVIDENCE.md) |

## Minimal release-candidate command set

Run these from the repository checkout before publishing artifacts:

```bash
make release-check
make helm-check
make package-smoke
make package-install-smoke
make lite-backup-restore-smoke
make operator-e2e-smoke
make kubernetes-runtime-smoke
make operational-readiness-smoke
```

The last four `make` targets are intentionally safe wiring checks. They do not
install packages, mutate clusters, start services or contact production
endpoints. The real checks are opt-in and documented in their runbooks.

## Manual promotion evidence

A release candidate is not ready for publication until the following evidence is
captured for the exact commit and artifacts being shipped:

- `make release-check` output;
- `make helm-check` output, including expected negative Helm validation tests;
- package checksum/SBOM output when packages are published;
- clean-install smoke output for DEB and RPM packages when those formats are
  published;
- Lite backup/restore smoke output when the release claims Lite support;
- source/bare-metal operator smoke evidence for the public Quickstart path;
- Kubernetes runtime smoke evidence for Kubernetes artifacts;
- operational readiness smoke evidence for at least one bootstrapped endpoint;
- completed security hardening final review with findings and promotion decision;
- `custodia-admin production check` output for the production environment file;
- `custodia-admin production evidence-check` output for external infrastructure
  evidence.

## Stop conditions

Stop promotion immediately when any of the following happens:

- repository tests or release checks fail;
- Helm unsafe combinations render instead of failing closed;
- Lite Kubernetes renders without a PVC or with more than one server replica;
- package payload manifests miss binaries, systemd units, manpages, docs or
  example YAMLs;
- package clean-install smoke runs on a minimized Debian image that drops
  `/usr/share/man` or `/usr/share/doc` through `dpkg` path-exclude filters;
- operational smoke cannot reach `/live`, `/ready`, admin status, diagnostics or
  revocation status through the expected TLS/mTLS boundary;
- the security hardening final review has open critical findings;
- production readiness reports a critical finding;
- external evidence files are missing or point to placeholders.

## Boundary of the matrix

This matrix proves release readiness and deployment rehearsal. It does not prove
external production controls by itself. The following remain operator evidence
items:

- real HSM/PKCS#11 or TPM-backed signer custody;
- WORM/Object Lock/SIEM retention guarantees;
- database HA/failover and RPO/RTO results;
- Valkey cluster availability and failover evidence;
- zero-trust network policy enforcement;
- air-gapped backup retention;
- penetration testing;
- disaster-recovery rehearsal.

Do not close these gaps by weakening Custodia's boundary. The server must remain
metadata-only: no plaintext, no DEKs, no application private keys, no server-side
recipient-envelope generation and no public-key trust decision.
