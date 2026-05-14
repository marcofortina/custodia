# Custodia Kubernetes Valkey lab profile

This profile provides a lab-only Valkey Deployment and Service for exercising
Custodia Full/custom Kubernetes flows that require the Valkey-backed rate-limit
and coordination path.

It is not a replacement for a production Valkey/Redis-compatible service. Use it
only for disposable lab, CI or smoke rehearsal unless the deployment is governed
like production infrastructure.

## Components

- `custodia-valkey-deployment.yaml` runs one Valkey pod in the `custodia`
  namespace.
- `custodia-valkey-service.yaml` exposes the pod as an internal ClusterIP
  service.
- `custodia-valkey-secret.example.yaml` creates the `custodia-valkey` Secret
  expected by the Helm chart.

## Quick start

```bash
kubectl create namespace custodia --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/k3s/valkey/custodia-valkey-deployment.yaml
kubectl apply -f deploy/k3s/valkey/custodia-valkey-service.yaml
kubectl -n custodia rollout status deploy/custodia-lab-valkey
kubectl apply -f deploy/k3s/valkey/custodia-valkey-secret.example.yaml
kubectl -n custodia get secret custodia-valkey
```

The development Valkey endpoint is:

```text
redis://custodia-lab-valkey:6379/0
```

The short service name is intentional because the Custodia server runs in the same namespace as the Valkey lab service. Avoid hard-coding a cluster DNS suffix in lab Secrets.

## Production replacement

Production must replace this single-pod lab service with a governed Valkey or
Redis-compatible deployment, managed service, or platform service with explicit
HA, backup, monitoring, access control, network policy, upgrade and incident
response evidence.
