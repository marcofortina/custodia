# Custodia disaster recovery runbook

Custodia is stateless at the API layer. DR depends on the database, Valkey and certificate revocation/signing infrastructure described in the Fort Knox analysis.

## Recovery objectives

| Scenario | Target |
| --- | --- |
| Single pod failure | Kubernetes self-heals through Deployment replicas |
| Node/AZ disruption | topology spread + PDB keep available replicas |
| Database corruption | restore PostgreSQL/CockroachDB backup/PITR |
| Regional disaster | promote cold standby and rotate DNS/LB targets |

## Failover sequence

1. Freeze writes at the ingress/load balancer when corruption or split-brain is suspected.
2. Verify latest audit export hash before cutover.
3. Restore database from PITR or promote the standby database.
4. Repoint `CUSTODIA_DATABASE_URL` secret.
5. Restart pods or let Helm checksum rollout trigger replacement.
6. Verify `/live`, `/ready`, `/v1/status` and `/v1/audit-events/verify`.
7. Keep old audit exports immutable for forensic comparison.

## Degraded mode

If CRL/OCSP or the revocation distribution path is unavailable, sensitive operations must fail closed. Previously downloaded opaque secret material can still exist client-side; strong revocation still requires a new secret version with fresh client-side ciphertext and envelopes.
