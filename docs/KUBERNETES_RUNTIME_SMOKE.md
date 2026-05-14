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
```

Run the read-only smoke:

```bash
./scripts/kubernetes-runtime-smoke.sh cluster-check
```

The helper verifies:

- current Kubernetes context is reachable;
- namespace exists, and stops with an actionable message instead of creating it;
- Helm release exists when `helm` is installed;
- server Deployment is present and rolled out;
- signer Deployment is present and rolled out;
- server and signer Services exist;
- server and signer pods are visible;
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
  --host=cockroachdb-public.custodia-db.svc.cluster.local \
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

## 6. Lite persistence smoke

For `profile=lite`, prove persistence explicitly:

1. run the Alice/Bob smoke and write a secret;
2. restart the server Deployment through normal Kubernetes rollout mechanics;
3. wait for `./scripts/kubernetes-runtime-smoke.sh cluster-check` to pass again;
4. read the same secret from the client;
5. run the backup/restore runbook in [`KUBERNETES_LITE_BACKUP_RESTORE.md`](KUBERNETES_LITE_BACKUP_RESTORE.md).

A PVC is required, but a PVC is not a backup. Do not treat a successful pod restart as backup coverage.

## 7. Failure handling

Stop at the first mismatch. Typical causes:

- wrong namespace or Helm release name; if the namespace does not exist, complete the install runbook first or set `CUSTODIA_K8S_NAMESPACE` to the namespace that already contains the release;
- custom chart fullname without `CUSTODIA_SERVER_DEPLOYMENT` / `CUSTODIA_SIGNER_DEPLOYMENT` overrides;
- missing signer Deployment or Service;
- pods not ready because Secret keys do not match the chart values;
- `server.url` does not match the external DNS/IP and certificate SANs;
- Lite values missing PVC-backed SQLite storage;
- Full values accidentally pointing at SQLite or memory-only rate limiting.

Fix the underlying chart values, Secrets, certificates, storage or external dependencies. Do not bypass the smoke with `kubectl exec` or ad-hoc pod changes.

## Next operator endpoint check

After the cluster object smoke passes and the API/Web Console are exposed through the intended ingress, load balancer or temporary port-forward, run [`OPERATIONAL_READINESS_SMOKE.md`](OPERATIONAL_READINESS_SMOKE.md) from an operator workstation. That second smoke validates `/live`, `/ready`, admin status/diagnostics, revocation status and Web login reachability without `kubectl exec` or Secret reads.
