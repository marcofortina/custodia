# Custodia Kubernetes install

This guide is the Kubernetes deployment path for `custodia-server` plus `custodia-signer`.
It assumes you build the container image from a Git checkout, then install the Helm chart.
For the full deployment/profile map, read [`DEPLOYMENT_MATRIX.md`](DEPLOYMENT_MATRIX.md).

Kubernetes uses the same runtime profiles as bare metal:

- `profile: lite` for lab/single-node-style clusters where SQLite persistence, local signer material and PVC backup handling are explicitly accepted;
- `profile: full` for production-oriented clusters with external PostgreSQL/CockroachDB, Valkey, HSM/PKCS#11 signer integration, WORM/SIEM/object-lock evidence and readiness gates.

## 1. Build the image from a Git clone

```bash
git clone https://github.com/marcofortina/custodia.git
cd custodia

CUSTODIA_VERSION=0.1.0
CUSTODIA_COMMIT="$(git rev-parse --short=12 HEAD)"
CUSTODIA_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

DOCKER_BUILDKIT=1 docker build \
  -f deploy/Dockerfile \
  --build-arg CUSTODIA_VERSION="$CUSTODIA_VERSION" \
  --build-arg CUSTODIA_COMMIT="$CUSTODIA_COMMIT" \
  --build-arg CUSTODIA_DATE="$CUSTODIA_DATE" \
  -t registry.example.internal/custodia/custodia-server:${CUSTODIA_VERSION} .
```

Push the image to the registry used by your cluster:

```bash
docker push registry.example.internal/custodia/custodia-server:${CUSTODIA_VERSION}
```

The image contains `custodia-server`, `custodia-admin` and `custodia-signer`. The chart runs `custodia-server` and `custodia-signer` as separate Deployments from the same image.

## 2. Prepare namespace and secrets

```bash
kubectl create namespace custodia --dry-run=client -o yaml | kubectl apply -f -
```

Create the API/Web mTLS secret. The server certificate SAN must match `config.serverURL` and the external name clients/browsers use:

```bash
kubectl -n custodia create secret generic custodia-mtls \
  --from-file=tls.crt=/path/to/server.crt \
  --from-file=tls.key=/path/to/server.key \
  --from-file=ca.crt=/path/to/client-ca.crt
```

Create the signer CA material secret. For Lite/lab this can come from local bootstrap output. For Full/production prefer HSM/PKCS#11-backed signing and keep CA private material out of ordinary cluster Secrets when your platform supports that:

```bash
kubectl -n custodia create secret generic custodia-signer-ca \
  --from-file=ca.crt=/path/to/ca.crt \
  --from-file=ca.key=/path/to/ca.key \
  --from-file=ca.pass=/path/to/ca.pass \
  --from-file=client.crl.pem=/path/to/client.crl.pem
```

Create the server-to-signer mTLS client secret. The certificate subject must be listed in `signer.adminSubjects`:

```bash
kubectl -n custodia create secret generic custodia-signer-client \
  --from-file=tls.crt=/path/to/admin.crt \
  --from-file=tls.key=/path/to/admin.key \
  --from-file=ca.crt=/path/to/ca.crt
```

For Full profile, create external database and Valkey URL secrets:

```bash
kubectl -n custodia create secret generic custodia-database \
  --from-literal=database-url='postgres://custodia:REDACTED@postgres.example.internal:5432/custodia?sslmode=require'

kubectl -n custodia create secret generic custodia-valkey \
  --from-literal=valkey-url='redis://valkey.example.internal:6379/0'
```

## 3. Install Full profile with Helm

Start from the committed example and edit only environment-specific values:

```bash
cp deploy/helm/custodia/values-full.example.yaml custodia-full-values.yaml
```

The example keeps durable state outside the pod in PostgreSQL/CockroachDB and Valkey. Review every placeholder before installing.

Install or upgrade:

```bash
helm upgrade --install custodia deploy/helm/custodia \
  --namespace custodia \
  --values custodia-full-values.yaml
```

## 4. Lite profile in Kubernetes

Lite in Kubernetes is intentionally explicit because SQLite must use persistent storage and must run with one server replica. Start from the committed example and edit only environment-specific values:

```bash
cp deploy/helm/custodia/values-lite.example.yaml custodia-lite-values.yaml
```

Install with the same Helm command and your Lite values file. Do not set `persistence.enabled: false` for Lite. Without a PVC, SQLite state would live on the pod filesystem and can be lost when the pod is recreated, rescheduled or replaced during upgrades. A PVC is not a backup: read [`KUBERNETES_LITE_BACKUP_RESTORE.md`](KUBERNETES_LITE_BACKUP_RESTORE.md) before using Lite for anything you care about.

## 4.1 Helm fail-closed checks

The chart intentionally rejects unsafe Lite combinations before rendering Kubernetes manifests:

- `profile: lite` with `replicaCount` other than `1`;
- `profile: lite` with `persistence.enabled: false`;
- `profile: lite` without `config.storeBackend: sqlite`;
- `profile: lite` without a `file:` SQLite URL;
- `profile: lite` with Valkey-style rate limiting.

Use `profile: full` for HA deployments backed by PostgreSQL/CockroachDB and Valkey. Use `profile: custom` only when a maintainer has reviewed the non-standard combination.

## 5. Chart validation

Run the chart render guardrail before committing values changes:

```bash
make helm-check
```

The check renders the Full and Lite example values and verifies that unsafe combinations fail closed, including Lite without PVC and Full with SQLite.

## 6. SoftHSM and MinIO boundaries

SoftHSM may be used when a real HSM is unavailable in development, CI or lab clusters. It is not proof of production HSM coverage.

MinIO with Object Lock may be used to exercise S3/WORM audit shipment flows when a production object-lock service is unavailable. Treat it as dev/smoke unless the deployment has production-grade retention governance, durability, credentials, backup and operational controls.

## 7. Normal administration

Kubernetes operators should not need `kubectl exec` into application pods for normal online operations. Use the Web Console/API over admin mTLS and Web MFA for metadata-only administration such as status, diagnostics, client views, future client revocation, client-CRL status, access request views, audit views and one-shot enrollment token creation through `/web/client-enrollments`.

Bootstrap, Kubernetes Secret creation, Helm values, CA/HSM material placement, external database provisioning and backup plumbing remain deployment/runbook tasks outside the Web Console.

## 8. Verify

```bash
kubectl -n custodia get deploy,svc,pvc
kubectl -n custodia rollout status deploy/custodia-custodia
kubectl -n custodia rollout status deploy/custodia-custodia-signer
```

Expose the API/Web services through your ingress, gateway or port-forward according to your cluster policy. The API and Web Console require mTLS; the health listener should remain private.
