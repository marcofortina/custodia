#!/usr/bin/env bash
set -euo pipefail

namespace="${CUSTODIA_COCKROACHDB_NAMESPACE:-custodia-db}"
service="${CUSTODIA_COCKROACHDB_SERVICE:-cockroachdb-public}"

echo "checking CockroachDB pods in namespace ${namespace}"
kubectl -n "${namespace}" wait --for=condition=Ready pod -l app.kubernetes.io/name=cockroachdb --timeout=180s

echo "checking CockroachDB SQL endpoint ${service}.${namespace}"
kubectl -n "${namespace}" run cockroachdb-smoke --rm -i --restart=Never \
  --image=cockroachdb/cockroach:v24.3.5 -- \
  sql --insecure --host="${service}.${namespace}.svc.cluster.local" --execute="SELECT 1;"
