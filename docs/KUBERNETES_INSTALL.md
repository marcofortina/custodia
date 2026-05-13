# Custodia Kubernetes install

This guide is the Kubernetes deployment path for `custodia-server` plus `custodia-signer`.
It assumes you build the container image from a Git checkout, then install the Helm chart.
For the full deployment/profile map, read [`DEPLOYMENT_MATRIX.md`](DEPLOYMENT_MATRIX.md).

Kubernetes uses the same runtime profiles as bare metal:

- `profile: lite` for lab/single-node-style clusters where SQLite persistence, local signer material and PVC backup handling are explicitly accepted;
- `profile: full` for production-oriented clusters with external PostgreSQL/CockroachDB, Valkey, HSM/PKCS#11 signer integration, WORM/SIEM/object-lock evidence and readiness gates.

## Runbook metadata

| Field | Value |
| --- | --- |
| Audience | Operators deploying Custodia with the Helm chart from a Git-built image. |
| Prerequisites | Docker, kubectl, Helm, registry access, cluster permissions and bootstrap material prepared for the target namespace. |
| Outcome | A Helm-installed server/signer release with profile-specific storage, signer and Web MFA wiring. |
| Do not continue if | Kubernetes Secrets, external Full dependencies or certificate SANs are not ready. |

## 1. Prerequisites

Run these commands from an operator workstation or build host with access to the target cluster and image registry:

```bash
docker version
kubectl version --client
helm version
git --version
make --version
openssl version
# Required only when building custodia-admin locally for Kubernetes bootstrap material.
go version
```

You also need:

- permission to push `registry.example.internal/custodia/custodia-server:<tag>` or your chosen image name;
- permission to create/update the target namespace and Secrets;
- a DNS name or stable IP that will be used in `config.serverURL` and in the server certificate SANs;
- for Full, existing PostgreSQL/CockroachDB, Valkey and signer/HSM integration endpoints.

## 2. Build the image from a Git clone

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

The base image built by `deploy/Dockerfile` does **not** include a production PKCS#11/HSM bridge such as `/usr/local/bin/custodia-pkcs11-sign`. For Kubernetes Full, do not install the committed Full values with this base image unchanged. Either build a custom image that includes the PKCS#11 signing bridge and required libraries, or configure `signer.pkcs11SignCommandDelivery: volume` with explicit `signer.extraVolumes` and `signer.extraVolumeMounts` before installing.

## 3. Prepare namespace and secrets

Create the target namespace first:

```bash
kubectl create namespace custodia --dry-run=client -o yaml | kubectl apply -f -
```

The chart expects Kubernetes Secrets for API/Web mTLS, signer material, server-to-signer mTLS and Web MFA. Follow [`KUBERNETES_BOOTSTRAP_MATERIAL.md`](KUBERNETES_BOOTSTRAP_MATERIAL.md) to generate Lite/lab bootstrap material on an operator workstation and create the required Secrets without `kubectl exec` into application pods. That runbook also adds the internal signer Service DNS names to the server certificate SANs, which is required because the API server verifies the signer TLS certificate when creating enrollment certificates.

At minimum, the install must provide these Secrets before `helm upgrade --install`:

| Secret | Purpose | Expected keys |
| --- | --- | --- |
| `custodia-mtls` | API/Web TLS plus signer TLS, and client CA/CRL | `tls.crt`, `tls.key`, `ca.crt`, `client.crl.pem` |
| `custodia-signer-ca` | Lite/lab file-backed signer material | `ca.crt`, `ca.key`, `ca.pass`, `client.crl.pem` |
| `custodia-signer-client` | server-to-signer mTLS client | `tls.crt`, `tls.key`, `ca.crt` |
| `custodia-web-mfa` | Web TOTP and session material | `totp-secret`, `session-secret` |

For Full production with PKCS#11/HSM, do not infer from the Lite/lab table that `ca.key` and `ca.pass` must be stored in a Kubernetes Secret. The signer Secret should contain only the public CA/CRL material needed by the pod, while private signing happens through the configured PKCS#11/HSM command delivery path.

For Full profile, create external database and Valkey URL secrets:

```bash
kubectl -n custodia create secret generic custodia-database \
  --from-literal=database-url='postgres://custodia:REDACTED@postgres.example.internal:5432/custodia?sslmode=require'

kubectl -n custodia create secret generic custodia-valkey \
  --from-literal=valkey-url='redis://valkey.example.internal:6379/0'
```

## 4. Install Full profile with Helm

Start from the committed example and edit only environment-specific values:

```bash
cp deploy/helm/custodia/values-full.example.yaml custodia-full-values.yaml
```

The example keeps durable state outside the pod in PostgreSQL/CockroachDB and Valkey. Review every placeholder before installing. If `signer.keyProvider: pkcs11`, the signer container must actually deliver the command configured in `signer.pkcs11SignCommand`. Set `signer.pkcs11SignCommandDelivery` to `custom-image` when the helper is baked into a custom image, or `volume` when `signer.extraVolumes` and `signer.extraVolumeMounts` mount it at runtime. The chart rejects Full PKCS#11 values that do not declare this delivery model.

Stop here if you only built the base image from step 2 and left `signer.pkcs11SignCommandDelivery: custom-image` unchanged. That value means the image already contains the command. If it does not, the chart can render but enrollment signing will fail later when the signer tries to execute the missing command.

Install or upgrade:

```bash
helm upgrade --install custodia deploy/helm/custodia \
  --namespace custodia \
  --values custodia-full-values.yaml
```

## 5. Lite profile in Kubernetes

Lite in Kubernetes is intentionally explicit because SQLite must use persistent storage and must run with one server replica. Start from the committed example and edit only environment-specific values:

```bash
cp deploy/helm/custodia/values-lite.example.yaml custodia-lite-values.yaml
```

Install with the same Helm command and your Lite values file. Do not set `persistence.enabled: false` for Lite. Without a PVC, SQLite state would live on the pod filesystem and can be lost when the pod is recreated, rescheduled or replaced during upgrades. A PVC is not a backup: read [`KUBERNETES_LITE_BACKUP_RESTORE.md`](KUBERNETES_LITE_BACKUP_RESTORE.md) before using Lite for anything you care about.

## 5.1 Helm fail-closed checks

The chart intentionally rejects unsafe Lite/Full combinations before rendering Kubernetes manifests:

- `profile: lite` with `replicaCount` other than `1`;
- `profile: lite` with `persistence.enabled: false`;
- `profile: lite` without `config.storeBackend: sqlite`;
- `profile: lite` without a `file:` SQLite URL;
- `profile: lite` with Valkey-style rate limiting;
- Lite/Full Web installs without `web.mfaSecretName` and secret keys;
- `profile: full` with SQLite or memory rate limiting;
- `profile: full` with `signer.keyProvider: pkcs11` but no declared command delivery model.

Use `profile: full` for HA deployments backed by PostgreSQL/CockroachDB and Valkey. Use `profile: custom` only when a maintainer has reviewed the non-standard combination.

## 6. Chart validation

Run the chart render guardrail before committing values changes:

```bash
make helm-check
```

The check renders the Full and Lite example values and verifies that unsafe combinations fail closed, including Lite without PVC, Full with SQLite, missing Web MFA Secret wiring and Full PKCS#11 without command delivery.

## 7. SoftHSM and MinIO boundaries

SoftHSM may be used when a real HSM is unavailable in development, CI or lab clusters. It is not proof of production HSM coverage.

MinIO with Object Lock may be used to exercise S3/WORM audit shipment flows when a production object-lock service is unavailable. Treat it as dev/smoke unless the deployment has production-grade retention governance, durability, credentials, backup and operational controls.

## 8. Normal administration

Kubernetes operators should not need `kubectl exec` into application pods for normal online operations. Use the Web Console/API over admin mTLS and Web MFA for metadata-only administration such as status, diagnostics, client views, future client revocation, client-CRL status, CRL PEM download, CRL serial checks, secret version/access metadata, future access-grant revocation, access request views, audit views, browser-downloadable audit JSONL exports and one-shot enrollment token creation through `/web/client-enrollments`.

Bootstrap, Kubernetes Secret creation, Helm values, CA/HSM material placement, external database provisioning and backup plumbing remain deployment/runbook tasks outside the Web Console. Use [`KUBERNETES_BOOTSTRAP_MATERIAL.md`](KUBERNETES_BOOTSTRAP_MATERIAL.md) for the copyable bootstrap material flow.

## 9. Verify

```bash
kubectl -n custodia get deploy,svc,pvc
kubectl -n custodia rollout status deploy/custodia-custodia
kubectl -n custodia rollout status deploy/custodia-custodia-signer
```

Expose the API/Web services through your ingress, gateway or port-forward according to your cluster policy. The API and Web Console require mTLS; the health listener should remain private.

After the release is installed, run the read-only Kubernetes runtime smoke from [`KUBERNETES_RUNTIME_SMOKE.md`](KUBERNETES_RUNTIME_SMOKE.md):

```bash
export CUSTODIA_K8S_NAMESPACE=custodia
export CUSTODIA_HELM_RELEASE=custodia
export CUSTODIA_K8S_PROFILE=full
export CUSTODIA_K8S_CONFIRM=YES
./scripts/kubernetes-runtime-smoke.sh cluster-check
```

For Lite, set `CUSTODIA_K8S_PROFILE=lite`; the smoke also checks that a server PVC is present.
