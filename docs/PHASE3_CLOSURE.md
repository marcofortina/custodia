# Custodia Phase 3 closure boundary

Phase 3 is closed in this repository as a code, runbook, deployment-readiness and verification baseline.

## Closed inside the repository

- signer service boundary and client certificate lifecycle;
- CRL loading and distribution endpoint;
- revocation status monitoring;
- audit export, verification, archive and shipment artifacts;
- deployment HA metadata and runbooks;
- production readiness checker;
- executable access invariants and TLA+ model files;
- release check script and CI workflow.

## Not provable inside the repository

The repository cannot prove that external infrastructure exists or behaves correctly. Operators must provide environment evidence for:

- PKCS#11/HSM-backed signing provider;
- WORM/object-lock retention policy;
- SIEM ingestion pipeline;
- HA database topology and failover evidence;
- CRL/OCSP distribution monitoring;
- TLC execution in CI or a release pipeline.

## Release gate order

1. `make release-check`
2. `make formal-check` where TLC is installed
3. `CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-check`
4. verify audit archive shipment manifest against the target WORM/SIEM sink evidence
5. verify database HA and signer HSM evidence outside the repo
