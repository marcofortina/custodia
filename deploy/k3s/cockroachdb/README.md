# Custodia Kubernetes CockroachDB lab profile

This profile provides a local Kubernetes/CockroachDB topology for exercising the
Custodia PostgreSQL-compatible store in an HA-like lab deployment.

It is not a replacement for a managed multi-region database or a production
CockroachDB operator. It exists to make the Full-profile database boundary
concrete and testable in the repository.

## Components

- `namespace.yaml` creates the `custodia-db` namespace.
- `cockroachdb-services.yaml` exposes internal CockroachDB SQL and gossip ports.
- `cockroachdb-statefulset.yaml` runs a three-node CockroachDB cluster.
- `cockroachdb-init-job.yaml` initializes the cluster and creates the `custodia`
  database.

The StatefulSet starts pods with `podManagementPolicy: Parallel` because a fresh
CockroachDB cluster is not Ready until after `cockroach init` runs. Do not wait
for StatefulSet rollout before running the init Job on a fresh lab cluster: the
readiness probe returns `503` until initialization completes.

## Quick start

```bash
kubectl apply -f deploy/k3s/cockroachdb/namespace.yaml
kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-services.yaml
kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-statefulset.yaml

for pod in cockroachdb-0 cockroachdb-1 cockroachdb-2; do
  kubectl -n custodia-db wait --for=jsonpath='{.status.phase}'=Running "pod/${pod}" --timeout=180s
done

kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-init-job.yaml
kubectl wait --for=condition=complete job/cockroachdb-init -n custodia-db --timeout=180s
kubectl rollout status statefulset/cockroachdb -n custodia-db --timeout=300s
kubectl apply -f deploy/k3s/cockroachdb/custodia-database-secret.example.yaml
```

The development SQL endpoint is:

```text
postgresql://root@cockroachdb-public.custodia-db.svc.cluster.local:26257/custodia?sslmode=disable
```

Pair this lab database with the Valkey lab profile in `deploy/k3s/valkey/` when
you need to render or smoke-test the Full Helm values end to end.

Production must replace this insecure development profile with TLS-enabled
CockroachDB, managed CockroachDB, PostgreSQL/Patroni, a cloud-managed
PostgreSQL-compatible service, or another independently governed HA database
service with backup, restore, monitoring and incident-response evidence.
