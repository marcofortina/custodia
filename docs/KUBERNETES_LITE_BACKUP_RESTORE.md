# Kubernetes Lite backup and restore

Kubernetes Lite uses SQLite on a PersistentVolumeClaim. The PVC prevents data loss
when the pod is recreated or rescheduled, but it is not a backup. Treat PVC
snapshotting and off-cluster copies as mandatory for any Lite environment whose
data matters.

Do not use `kubectl exec` into the Custodia application pod as the normal backup
interface. Backups should be implemented through storage snapshots, a dedicated
maintenance job, or a cold copy procedure that never requires an operator shell
inside the running application container.

## Recommended backup model

Use your storage platform snapshot mechanism for the PVC backing
`/var/lib/custodia`, then copy snapshots to off-cluster storage according to your
retention policy.

Minimum operator checklist:

1. Identify the PVC used by the Lite release.
2. Configure scheduled volume snapshots or storage-native backups.
3. Copy backup artifacts off-cluster or to separately governed storage.
4. Record restore instructions next to the Helm values used for the release.
5. Test restore before relying on the environment.

A Helm install using `profile: lite` must set `persistence.enabled=true`. The
chart fails closed without it because SQLite data on the pod filesystem is not
durable.

## Cold backup fallback

Use this only for lab/small deployments when storage snapshots are unavailable.
It requires downtime.

1. Stop writes by scaling the server deployment to zero:

```bash
kubectl -n custodia scale deploy/custodia-custodia --replicas=0
```

2. Copy the SQLite database from the PVC using a temporary maintenance pod
approved by your cluster policy.

3. Store the copied database off-cluster with restricted access.

4. Scale the server deployment back to one replica:

```bash
kubectl -n custodia scale deploy/custodia-custodia --replicas=1
```

Use the real Deployment name from your Helm release; do not copy this example
blindly if your release name is not `custodia`.

## Restore checklist

1. Stop the server deployment.
2. Restore the selected snapshot or database copy onto the PVC.
3. Verify ownership and permissions expected by the container security context.
4. Start the server deployment.
5. Run status, diagnostics and an encrypted client smoke test.
6. Verify audit continuity before declaring the environment healthy.

## Full profile boundary

Full profile should not use this runbook. Production-oriented Kubernetes
deployments keep durable state in external PostgreSQL/CockroachDB and Valkey,
with their own HA, backup, retention and restore procedures.
