# Custodia k3s CockroachDB HA profile

This profile provides a local/k3s-friendly CockroachDB topology for exercising the
Custodia PostgreSQL-compatible store in an HA-like deployment.

It is not a replacement for a managed multi-region database or a production
CockroachDB operator. It exists to make the Fort Knox database-HA boundary
concrete and testable in the repository.

## Components

- `namespace.yaml` creates the `custodia-db` namespace.
- `cockroachdb-services.yaml` exposes internal CockroachDB SQL and gossip ports.
- `cockroachdb-statefulset.yaml` runs a three-node CockroachDB cluster.
- `cockroachdb-init-job.yaml` initializes the cluster and creates the `custodia`
  database.

## Quick start

```bash
kubectl apply -f deploy/k3s/cockroachdb/namespace.yaml
kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-services.yaml
kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-statefulset.yaml
kubectl rollout status statefulset/cockroachdb -n custodia-db
kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-init-job.yaml
```

The development SQL endpoint is:

```text
postgresql://root@cockroachdb-public.custodia-db.svc.cluster.local:26257/custodia?sslmode=disable
```

Production must replace this insecure development profile with TLS-enabled
CockroachDB, managed CockroachDB, or a tested PostgreSQL/Patroni equivalent.
