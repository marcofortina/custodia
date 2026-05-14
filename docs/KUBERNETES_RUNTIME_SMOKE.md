# Custodia Kubernetes runtime smoke

This runbook validates that a rendered and installed Custodia Helm release is alive in a real Kubernetes cluster. It complements [`KUBERNETES_INSTALL.md`](KUBERNETES_INSTALL.md) and `make helm-check`:

- `make helm-check` proves that the chart renders and unsafe values fail before deployment;
- this runbook proves that an installed release has the expected server/signer Deployments, Services, rollout state and Lite PVC when applicable;
- the Web Console checks prove that normal Kubernetes administration does not require `kubectl exec` into application pods.

For post-release smoke, run the helper from the same release tag/source archive used to build the image and install the Helm chart. Do not validate a public release with scripts from `master` unless you are explicitly testing a future fix.

The smoke is intentionally read-only. It does not install charts, create Secrets, read Secret data, exec into pods or mutate cluster state.

## Runbook metadata

| Field | Value |
| --- | --- |
| Audience | Operators validating an already installed Kubernetes release without mutating cluster state. |
| Prerequisites | A Helm release, namespace, profile selection and read-only kubectl access to cluster objects. |
| Outcome | Evidence that deployments, services, rollouts and Lite PVC expectations match the installed profile. |
| Do not continue if | The Helm install is incomplete or you need to create Secrets/charts first. |

## 1. Preconditions

Complete [`KUBERNETES_INSTALL.md`](KUBERNETES_INSTALL.md) first. At minimum, the cluster must already have:

- a namespace, for example `custodia`;
- a Helm release, for example `custodia`;
- `custodia-server` and `custodia-signer` Deployments from the same Git-built image;
- API/Web mTLS Secret material;
- signer CA/server-to-signer Secret material;
- Full profile external database/Valkey Secrets, or Lite profile PVC-backed SQLite storage;
- an ingress, gateway or port-forward policy for operator access to the mTLS Web Console.

Do not use this runbook to hide broken install steps. If the install is not complete, go back to [`KUBERNETES_INSTALL.md`](KUBERNETES_INSTALL.md).

## 2. Repository checks before touching a cluster

From the Git checkout:

```bash
make helm-check
bash -n scripts/kubernetes-runtime-smoke.sh scripts/release-check.sh
./scripts/kubernetes-runtime-smoke.sh check-only
```

These checks do not contact a Kubernetes cluster.

## 3. Read-only cluster smoke

Set the namespace, release name and profile explicitly:

```bash
export CUSTODIA_K8S_NAMESPACE=custodia
export CUSTODIA_HELM_RELEASE=custodia
export CUSTODIA_K8S_PROFILE=full
# For Lite clusters:
# export CUSTODIA_K8S_PROFILE=lite
export CUSTODIA_K8S_CONFIRM=YES
# Optional: require the chart bootstrap Job to exist and be complete.
# export CUSTODIA_BOOTSTRAP_JOB_REQUIRED=YES
# Optional: require chart-managed server/signer NetworkPolicies to exist.
# export CUSTODIA_NETWORK_POLICY_REQUIRED=YES
```

Run the read-only smoke:

```bash
./scripts/kubernetes-runtime-smoke.sh cluster-check
```

The helper verifies:

- current Kubernetes context is reachable;
- namespace exists, and stops with an actionable message instead of creating it;
- Helm release exists when `helm` is installed;
- release ConfigMap exists and matches the selected profile;
- Lite uses SQLite/memory and Full uses PostgreSQL/Valkey wiring;
- server Deployment is present and rolled out;
- signer Deployment is present and rolled out;
- server and signer pods report Ready;
- server Service exposes the API port;
- signer Service remains ClusterIP-only and exposes only the signer port;
- optional chart bootstrap Job completed when present;
- optional server/signer NetworkPolicy resources exist when `CUSTODIA_NETWORK_POLICY_REQUIRED=YES`;
- Lite profile has a PVC selected by the server labels.

If the chart uses `fullnameOverride` or custom Deployment names, provide overrides instead of guessing:

```bash
export CUSTODIA_SERVER_DEPLOYMENT=my-custodia-server
export CUSTODIA_SIGNER_DEPLOYMENT=my-custodia-signer
./scripts/kubernetes-runtime-smoke.sh cluster-check
```

## 4. Web Console runtime smoke

Use the Web Console over admin mTLS and Web MFA. Do not `kubectl exec` into an application pod for these online checks.

Open the Web Console URL configured by your ingress/gateway/port-forward policy and verify:

1. **Status** renders and reports the expected deployment mode/profile metadata.
2. **Runtime Diagnostics** renders without leaking plaintext, ciphertext, DEKs, recipient envelopes or private keys.
3. **Client Enrollments** can create a short-lived one-shot enrollment token.
4. A remote client can enroll with that token, generate an application key, write config and publish its public key metadata.
5. **Clients** shows the enrolled client metadata.
6. **Revocation Status** renders, downloads the client CRL PEM and checks a certificate serial.
7. **Audit Events** renders and **Audit Export** downloads JSONL with integrity headers.
8. **Secret Metadata** can inspect versions/access grants for a known `namespace/key` without rendering secret material.
9. Revoking future access from **Secret Metadata** denies future client reads after the client retries online.
10. Revoking a client from **Clients** updates revocation metadata and is reflected in the CRL/status checks.

For Alice/Bob client behavior, follow [`END_TO_END_OPERATOR_SMOKE.md`](END_TO_END_OPERATOR_SMOKE.md) using the Kubernetes Web Console to create enrollment tokens instead of running `custodia-admin` inside a pod.

## 5. Full dependency wiring smoke

For `profile=full`, prove that the Helm values are wired to the database and
Valkey dependencies before testing signer or Web Console workflows. In a lab
cluster, the disposable examples are:

```bash
kubectl apply -f deploy/k3s/cockroachdb/namespace.yaml
kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-services.yaml
kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-statefulset.yaml
kubectl apply -f deploy/k3s/cockroachdb/custodia-postgres-schema-configmap.yaml

for pod in cockroachdb-0 cockroachdb-1 cockroachdb-2; do
  kubectl -n custodia-db wait --for=jsonpath='{.status.phase}'=Running "pod/${pod}" --timeout=180s
done

kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-init-job.yaml
kubectl wait --for=condition=complete job/cockroachdb-init -n custodia-db --timeout=180s
kubectl rollout status statefulset/cockroachdb -n custodia-db --timeout=300s
kubectl -n custodia-db exec cockroachdb-0 -- \
  ./cockroach sql --insecure \
  --host=cockroachdb-public.custodia-db.svc \
  --database=custodia \
  -e 'SHOW TABLES;'
kubectl apply -f deploy/k3s/cockroachdb/custodia-database-secret.example.yaml

kubectl apply -f deploy/k3s/valkey/custodia-valkey-deployment.yaml
kubectl apply -f deploy/k3s/valkey/custodia-valkey-service.yaml
kubectl -n custodia rollout status deploy/custodia-lab-valkey
kubectl apply -f deploy/k3s/valkey/custodia-valkey-secret.example.yaml
```

Then verify the Secret wiring expected by the chart:

```bash
kubectl -n custodia get secret custodia-database custodia-valkey
helm template custodia deploy/helm/custodia \
  --values deploy/k3s/cockroachdb/custodia-values.example.yaml \
  >/tmp/custodia-full-lab-render.yaml
grep -E 'CUSTODIA_STORE_BACKEND|CUSTODIA_RATE_LIMIT_BACKEND|custodia-database|custodia-valkey' /tmp/custodia-full-lab-render.yaml
```

These examples are lab/smoke dependencies only. Production must replace them
with governed PostgreSQL/CockroachDB and Valkey services with HA, backup,
monitoring, credential rotation, network policy and incident-response evidence.

On a fresh CockroachDB lab cluster, the pods are expected to report `Ready=false`
until the init Job completes. A `503` readiness response before `cockroach init`
is not a storage failure by itself.

For ad-hoc in-pod health checks, prefer the same HTTP client behavior used by
normal operators and keep the timeout at least as large as the Kubernetes probe.
Do not use raw `nc` output as readiness evidence; it can close the HTTP request
stream early and produce a misleading `store_unavailable` response while the
kubelet probe and a normal client report the pod Ready. Use `wget` or `curl`
instead:

```bash
SERVER_POD="$(kubectl -n custodia get pod -l app.kubernetes.io/component=server -o jsonpath='{.items[0].metadata.name}')"
kubectl -n custodia exec "$SERVER_POD" -- \
  wget -T 10 -S -O - http://127.0.0.1:8080/ready
```

## 6. MinIO/Object Lock audit shipment lab smoke

When a production WORM/Object Lock sink is not available, the repository includes a lab-only MinIO profile under `deploy/k3s/minio/`. It is useful for proving that the audit shipment smoke can reach an S3-compatible endpoint with Object Lock retention enabled. It is not production WORM evidence by itself.

Apply the disposable lab profile:

```bash
kubectl apply -f deploy/k3s/minio/custodia-minio-secret.example.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-pvc.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-deployment.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-service.yaml
kubectl -n custodia rollout status deploy/custodia-lab-minio --timeout=180s
kubectl apply -f deploy/k3s/minio/custodia-minio-init-job.yaml
kubectl -n custodia wait --for=condition=complete job/custodia-lab-minio-init --timeout=180s
kubectl -n custodia logs job/custodia-lab-minio-init
```

Expose MinIO only for the smoke window:

```bash
kubectl -n custodia port-forward svc/custodia-lab-minio 9000:9000
```

In another shell, run the Object Lock smoke helper. This path requires the MinIO `mc` client on the operator workstation:

```bash
export CUSTODIA_AUDIT_S3_ENDPOINT=http://127.0.0.1:9000
export CUSTODIA_AUDIT_S3_ACCESS_KEY_ID=custodia-minio-lab
export CUSTODIA_AUDIT_S3_SECRET_ACCESS_KEY=custodia-minio-lab-CHANGE-ME
export CUSTODIA_AUDIT_S3_BUCKET=custodia-audit
make minio-object-lock-smoke
```

If the workstation does not have `mc`, use the in-cluster one-shot smoke Job documented in `deploy/k3s/minio/README.md`. The in-cluster path reads credentials through `secretKeyRef` and should log:

```text
Object locking 'COMPLIANCE' is configured for 30DAYS.
custodia MinIO Object Lock smoke OK
```

Expected evidence:

- MinIO pod is `1/1 Running`;
- `custodia-lab-minio-init` Job is `Complete`;
- init Job logs end with `custodia MinIO Object Lock lab bucket ready`;
- either `make minio-object-lock-smoke` passes from a workstation with `mc`, or the in-cluster smoke Job logs `custodia MinIO Object Lock smoke OK`.

Production must replace this single-pod MinIO lab with a governed WORM/Object Lock/SIEM sink and external retention evidence.

## 7. Lite persistence smoke

For `profile=lite`, prove persistence explicitly:

1. run the Alice/Bob smoke and write a secret;
2. restart the server Deployment through normal Kubernetes rollout mechanics;
3. wait for `./scripts/kubernetes-runtime-smoke.sh cluster-check` to pass again;
4. read the same secret from the client;
5. run the backup/restore runbook in [`KUBERNETES_LITE_BACKUP_RESTORE.md`](KUBERNETES_LITE_BACKUP_RESTORE.md).

A PVC is required, but a PVC is not a backup. Do not treat a successful pod restart as backup coverage.

## 8. Failure handling

Stop at the first mismatch. Typical causes:

- wrong namespace or Helm release name; if the namespace does not exist, complete the install runbook first or set `CUSTODIA_K8S_NAMESPACE` to the namespace that already contains the release;
- custom chart fullname without `CUSTODIA_SERVER_DEPLOYMENT` / `CUSTODIA_SIGNER_DEPLOYMENT` overrides;
- missing signer Deployment or Service;
- pods not ready because Secret keys do not match the chart values;
- `server.url` does not match the external DNS/IP and certificate SANs;
- Lite values missing PVC-backed SQLite storage;
- Lite runtime ConfigMap not using SQLite/memory;
- Full runtime ConfigMap not using PostgreSQL/Valkey;
- signer Service accidentally exposed as NodePort/LoadBalancer;
- server or signer NetworkPolicy missing when `CUSTODIA_NETWORK_POLICY_REQUIRED=YES`;
- optional bootstrap Job missing or incomplete when `CUSTODIA_BOOTSTRAP_JOB_REQUIRED=YES`;
- Full values accidentally pointing at SQLite or memory-only rate limiting.

Fix the underlying chart values, Secrets, certificates, storage or external dependencies. Do not bypass the smoke with `kubectl exec` or ad-hoc pod changes.

## Next operator endpoint check

After the cluster object smoke passes and the API/Web Console are exposed through the intended ingress, load balancer or temporary port-forward, run [`OPERATIONAL_READINESS_SMOKE.md`](OPERATIONAL_READINESS_SMOKE.md) from an operator workstation. That second smoke validates `/live`, `/ready`, admin status/diagnostics, revocation status and Web login reachability without `kubectl exec` or Secret reads.
