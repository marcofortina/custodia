# Production external evidence gate

Custodia can verify the repository, binaries and configuration baseline locally, but the Fort Knox design also requires evidence from infrastructure that does not live inside this repository.

`vault-admin production evidence-check --env-file FILE` verifies that the production environment file points to every required external evidence artifact.

## Required evidence files

| Environment key | Evidence expected |
| --- | --- |
| `CUSTODIA_EVIDENCE_HSM_ATTESTATION_FILE` | HSM/PKCS#11 or TPM attestation showing the CA signing key is non-exportable. |
| `CUSTODIA_EVIDENCE_WORM_RETENTION_FILE` | Object-lock/WORM retention policy or ledger retention proof for audit archives. |
| `CUSTODIA_EVIDENCE_DATABASE_HA_FILE` | Database HA topology, failover drill and RPO/RTO result. |
| `CUSTODIA_EVIDENCE_VALKEY_CLUSTER_FILE` | Valkey cluster topology and failover/replication evidence. |
| `CUSTODIA_EVIDENCE_ZERO_TRUST_NETWORK_FILE` | Kubernetes/network policy proof showing no flat network path to the vault. |
| `CUSTODIA_EVIDENCE_AIR_GAP_BACKUP_FILE` | Air-gapped backup record for CA and operational materials. |
| `CUSTODIA_EVIDENCE_PEN_TEST_FILE` | Annual penetration-test report or acceptance record. |
| `CUSTODIA_EVIDENCE_FORMAL_VERIFICATION_FILE` | TLC/formal verification execution artifact. |
| `CUSTODIA_EVIDENCE_REVOCATION_DRILL_FILE` | CRL/OCSP revocation drill result. |
| `CUSTODIA_EVIDENCE_RELEASE_CHECK_FILE` | Release-check output for the exact shipped commit/image. |

The checker intentionally validates references, not the confidential content of those artifacts. Artifact content and storage are controlled by the operator's compliance process.

## Gate order

```bash
make release-check
CUSTODIA_PRODUCTION_ENV_FILE=deploy/examples/production.env.example make production-check
CUSTODIA_PRODUCTION_ENV_FILE=deploy/examples/production.env.example make production-evidence-check
```

A release is not Fort Knox production-ready until both production configuration and external evidence gates pass.
