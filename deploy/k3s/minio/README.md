# Custodia Kubernetes MinIO Object Lock lab profile

This profile provides a lab-only MinIO deployment with Object Lock enabled for exercising Custodia audit archive shipment flows when a production WORM/Object Lock service is not available.

It is not a replacement for production WORM/SIEM/Object Lock evidence. Use it only for disposable lab, CI or smoke rehearsal unless the deployment is governed like production infrastructure with durable storage, retention policy ownership, credential management, backup, monitoring and incident response evidence.

## Components

- `custodia-minio-secret.example.yaml` creates lab-only MinIO root credentials.
- `custodia-minio-pvc.yaml` creates a PVC for the MinIO data directory.
- `custodia-minio-deployment.yaml` runs one MinIO pod in the `custodia` namespace.
- `custodia-minio-service.yaml` exposes MinIO as an internal ClusterIP service.
- `custodia-minio-init-job.yaml` creates the `custodia-audit` bucket with Object Lock and default COMPLIANCE retention.

## Quick start

Review the example Secret before applying it. Do not reuse the example password outside disposable labs.

```bash
kubectl create namespace custodia --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/k3s/minio/custodia-minio-secret.example.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-pvc.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-deployment.yaml
kubectl apply -f deploy/k3s/minio/custodia-minio-service.yaml
kubectl -n custodia rollout status deploy/custodia-lab-minio --timeout=180s
kubectl apply -f deploy/k3s/minio/custodia-minio-init-job.yaml
kubectl -n custodia wait --for=condition=complete job/custodia-lab-minio-init --timeout=180s
kubectl -n custodia logs job/custodia-lab-minio-init
```

The expected init Job log ends with:

```text
custodia MinIO Object Lock lab bucket ready
```

## Object Lock smoke from an operator workstation

Expose the lab service only for the smoke window:

```bash
kubectl -n custodia port-forward svc/custodia-lab-minio 9000:9000
```

In another shell, run the existing repository smoke helper. This path requires the MinIO `mc` client on the operator workstation:

```bash
export CUSTODIA_AUDIT_S3_ENDPOINT=http://127.0.0.1:9000
export CUSTODIA_AUDIT_S3_ACCESS_KEY_ID=custodia-minio-lab
export CUSTODIA_AUDIT_S3_SECRET_ACCESS_KEY=custodia-minio-lab-CHANGE-ME
export CUSTODIA_AUDIT_S3_BUCKET=custodia-audit
make minio-object-lock-smoke
```

Stop the port-forward after collecting evidence.

If `mc` is not installed on the workstation, run an in-cluster one-shot smoke Job instead. This reuses the existing lab Secret through `secretKeyRef` so credentials are not placed on the shell command line:

```bash
kubectl -n custodia delete job custodia-minio-object-lock-smoke --ignore-not-found
kubectl -n custodia apply -f - <<'YAML'
apiVersion: batch/v1
kind: Job
metadata:
  name: custodia-minio-object-lock-smoke
spec:
  backoffLimit: 1
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: smoke
          image: minio/mc:latest
          imagePullPolicy: IfNotPresent
          env:
            - name: MINIO_ROOT_USER
              valueFrom:
                secretKeyRef:
                  name: custodia-minio-lab
                  key: root-user
            - name: MINIO_ROOT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: custodia-minio-lab
                  key: root-password
            - name: CUSTODIA_AUDIT_S3_BUCKET
              valueFrom:
                secretKeyRef:
                  name: custodia-minio-lab
                  key: bucket
          command:
            - /bin/sh
            - -ec
            - |
              mc alias set local http://custodia-lab-minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
              mc stat "local/${CUSTODIA_AUDIT_S3_BUCKET}" >/dev/null
              mc retention info "local/${CUSTODIA_AUDIT_S3_BUCKET}"
              echo "custodia MinIO Object Lock smoke OK"
YAML
kubectl -n custodia wait --for=condition=complete job/custodia-minio-object-lock-smoke --timeout=120s
kubectl -n custodia logs job/custodia-minio-object-lock-smoke
kubectl -n custodia delete job custodia-minio-object-lock-smoke
```

## Resetting the lab bucket

Object Lock must be enabled at bucket creation time. If the lab PVC was initialized before Object Lock was configured, reset the disposable lab data and rerun the init Job:

```bash
kubectl -n custodia delete job custodia-lab-minio-init --ignore-not-found
kubectl -n custodia scale deploy/custodia-lab-minio --replicas=0
kubectl -n custodia delete pvc custodia-minio-data
kubectl apply -f deploy/k3s/minio/custodia-minio-pvc.yaml
kubectl -n custodia scale deploy/custodia-lab-minio --replicas=1
kubectl -n custodia rollout status deploy/custodia-lab-minio --timeout=180s
kubectl apply -f deploy/k3s/minio/custodia-minio-init-job.yaml
kubectl -n custodia wait --for=condition=complete job/custodia-lab-minio-init --timeout=180s
```

## Production replacement

Production must replace this single-pod lab service with a governed WORM/Object Lock/SIEM sink such as AWS S3 Object Lock, a managed S3-compatible service with legal retention controls, or an enterprise archive platform. Required evidence includes retention policy, bucket/versioning/Object Lock state, IAM/credential controls, backup/durability, monitoring, network policy and incident-response ownership.
