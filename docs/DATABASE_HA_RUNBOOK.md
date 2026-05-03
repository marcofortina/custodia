# Custodia database HA runbook

Custodia is stateless at the API layer. Database HA is therefore the primary availability boundary for secret metadata, access grants, audit events, ciphertext blobs and recipient envelopes.

## Supported production patterns

### CockroachDB multi-region

Use this when active/active regional availability is required. Configure `CUSTODIA_DATABASE_URL` with the CockroachDB PostgreSQL-compatible endpoint and set:

```bash
CUSTODIA_DEPLOYMENT_MODE=multi-region
CUSTODIA_DATABASE_HA_TARGET=cockroachdb
```

### PostgreSQL Patroni / managed PostgreSQL HA

Use this when one primary plus automated failover is acceptable. Configure `CUSTODIA_DATABASE_URL` through the managed writer endpoint and set:

```bash
CUSTODIA_DEPLOYMENT_MODE=single-region-ha
CUSTODIA_DATABASE_HA_TARGET=patroni
```

## Operational gates

- `/ready` must fail when the database health check fails.
- `GET /v1/status` must expose the configured `deployment_mode` and `database_ha_target`.
- Database backups must be PITR-capable and tested through the backup/restore runbook.
- Audit archive shipments must be copied to a sink outside the primary database failure domain.

## Failover validation

1. Trigger or simulate database failover.
2. Verify `/ready` during and after the failover window.
3. Verify `vault-admin status read` after reconnection.
4. Verify one metadata read, one audit export and one audit archive shipment.
5. Run `vault-admin audit verify` to ensure the audit chain remains valid after failover.

## Boundary

This runbook does not embed a database cluster into the Helm chart. Production DB HA belongs to CockroachDB, Patroni, a cloud managed PostgreSQL HA service or an equivalent external control plane.
