# k3s CockroachDB HA profile

This guide makes the database HA boundary testable in a local or lab k3s cluster.
It is intended for repository verification and operator rehearsal, not as a
replacement for a managed CockroachDB or PostgreSQL/Patroni production platform.
For the generic Kubernetes install path, including the `custodia-server` and
`custodia-signer` chart resources, read [`KUBERNETES_INSTALL.md`](KUBERNETES_INSTALL.md).

## Apply CockroachDB

```bash
make k3s-cockroachdb-apply
make k3s-cockroachdb-smoke
```

The profile deploys three CockroachDB pods in the `custodia-db` namespace and
initializes the `custodia` database.

## Wire Custodia

Create the Custodia namespace and database secret:

```bash
kubectl create namespace custodia --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/k3s/cockroachdb/custodia-database-secret.example.yaml
```

Install the chart using the sample values:

```bash
helm upgrade --install custodia deploy/helm/custodia \
  --namespace custodia \
  --values deploy/k3s/cockroachdb/custodia-values.example.yaml
```

## Production boundary

The sample uses CockroachDB insecure mode to keep the k3s profile small and
reproducible. Production must use TLS-enabled SQL, real credentials, encrypted
storage, backup/PITR, monitored ranges and tested failover.
