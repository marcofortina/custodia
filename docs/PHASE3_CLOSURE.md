# Custodia Phase 3 closure boundary

Phase 3 is closed in this repository as a deployment, HA/DR, audit-retention, verification and production-evidence baseline.

## Goal

Phase 3 made the Fort Knox operational dependencies concrete without pretending that local source code can prove physical infrastructure.

The repository now provides deployable or rehearsal-ready paths for:

- signer isolation and CA custody boundaries;
- PKCS#11 signing through a fail-closed external command bridge;
- SoftHSM development and CI rehearsal for the PKCS#11 path;
- CRL loading, CRL distribution and CRL-backed revocation serial checks;
- audit export, verification, archive and shipment;
- S3/Object Lock audit shipment and MinIO Object Lock smoke testing;
- database HA rehearsal with k3s and CockroachDB;
- deployment HA metadata and runbooks;
- executable access invariants and TLA+ formal artifacts;
- production readiness and external evidence gates;
- release check and CI workflow.

## Closed inside the repository

- Dedicated `custodia-signer` service boundary.
- PKCS#11 command signer provider and SoftHSM helper scripts.
- CRL distribution endpoint and CRL-backed revocation serial responder.
- `custodia-admin` helpers for CRL fetch and serial status checks.
- Audit export integrity, archive bundles, filesystem shipment and S3/Object Lock shipment.
- MinIO Object Lock Compose profile and smoke script.
- k3s/CockroachDB three-node rehearsal profile and smoke script.
- Deployment HA metadata exposed in status and Helm values.
- Production readiness checker and external evidence checker.
- Release check script and CI workflow.
- Formal model files and `make formal-check` integration.

## Not provable inside the repository

The repository cannot prove that external infrastructure exists or behaves correctly. Operators must provide production evidence for:

- real HSM/PKCS#11/TPM-backed non-exportable signing keys;
- real WORM/Object Lock retention policy and SIEM retention behavior;
- real database HA topology, failover drills, backup and PITR;
- real Valkey HA and network policy posture;
- zero-trust network controls in the target cluster;
- CRL/OCSP distribution monitoring and revocation drills;
- TLC/formal verification execution in CI or a dedicated pipeline;
- penetration-test and release artifact evidence.

## Release gate order

1. `make release-check`
2. `make passkey-assertion-verifier-template-check`
3. `make formal-check` where TLC is installed
4. `CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-check`
5. `CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-evidence-check`
6. optional lab/rehearsal gates when the matching infrastructure is running:
   - `make softhsm-dev-token`
   - `make minio-object-lock-smoke`
   - `make k3s-cockroachdb-smoke`
7. verify audit archive shipment evidence against the target WORM/SIEM sink
8. verify database HA, signer HSM, revocation drill and penetration-test evidence outside the repo

## Production boundary

Phase 3 repository closure means the code, scripts, runbooks and gates are present. It does not mean the deployment is production-certified until the operator supplies the external evidence above.

Do not replace production evidence with SoftHSM, MinIO or k3s smoke results. Those profiles are repository/lab rehearsal tools.

## Closure statement

Phase 3 is closed at repository level when the release gates pass, production/evidence gates are configured, and the external Fort Knox evidence package is attached to the release.
