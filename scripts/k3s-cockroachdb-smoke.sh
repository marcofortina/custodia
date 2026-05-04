#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

namespace="${CUSTODIA_COCKROACHDB_NAMESPACE:-custodia-db}"
service="${CUSTODIA_COCKROACHDB_SERVICE:-cockroachdb-public}"

echo "checking CockroachDB pods in namespace ${namespace}"
kubectl -n "${namespace}" wait --for=condition=Ready pod -l app.kubernetes.io/name=cockroachdb --timeout=180s

echo "checking CockroachDB SQL endpoint ${service}.${namespace}"
kubectl -n "${namespace}" run cockroachdb-smoke --rm -i --restart=Never \
  --image=cockroachdb/cockroach:v24.3.5 -- \
  sql --insecure --host="${service}.${namespace}.svc.cluster.local" --execute="SELECT 1;"
