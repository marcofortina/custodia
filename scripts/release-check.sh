#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

# Package staging trees can contain Go source snapshots under dist/package-work.
# Keep release checks scoped to the repository source tree, not generated package contents.
rm -rf "$root_dir/dist/package-work"

: "${GO:=go}"

./scripts/check-license-headers.sh
./scripts/release-keyspace-check.sh
./scripts/helm-render-check.sh
$GO test -p=1 -timeout 60s ./...
$GO build ./cmd/custodia-server ./cmd/custodia-signer
$GO build -o /tmp/custodia-admin-check ./cmd/custodia-admin
python3 -m py_compile clients/python/custodia_client/__init__.py clients/python/custodia_client/types.py clients/python/custodia_client/crypto.py
python3 -m unittest discover -s clients/python/tests
node --check clients/node/src/index.js
node --check clients/node/src/crypto.js
bash -n clients/bash/custodia.bash
npm test --prefix clients/node
make test-java-client
make test-cpp-client
make test-rust-client
make test-bash-client
bash -n scripts/check-formal.sh scripts/pkcs11-sign-command.sh scripts/softhsm-dev-token.sh scripts/minio-object-lock-smoke.sh scripts/k3s-cockroachdb-smoke.sh scripts/passkey-assertion-verify-command.sh scripts/sqlite-backup.sh scripts/lite-upgrade-check.sh scripts/helm-render-check.sh scripts/operator-e2e-smoke.sh scripts/kubernetes-runtime-smoke.sh

if command -v tlc >/dev/null 2>&1; then
  ./scripts/check-formal.sh
else
  echo "TLC not found; skipping formal-check. Run make formal-check where TLC is installed." >&2
fi

if [ "${CUSTODIA_RUN_MINIO_SMOKE:-false}" = "true" ]; then
  ./scripts/minio-object-lock-smoke.sh
else
  echo "CUSTODIA_RUN_MINIO_SMOKE not true; skipping MinIO Object Lock smoke check." >&2
fi


if [ "${CUSTODIA_RUN_K3S_COCKROACHDB_SMOKE:-false}" = "true" ]; then
  ./scripts/k3s-cockroachdb-smoke.sh
else
  echo "CUSTODIA_RUN_K3S_COCKROACHDB_SMOKE not true; skipping k3s CockroachDB smoke check." >&2
fi

if [ -n "${CUSTODIA_PRODUCTION_ENV_FILE:-}" ]; then
  $GO run ./cmd/custodia-admin production check --env-file "$CUSTODIA_PRODUCTION_ENV_FILE"
  $GO run ./cmd/custodia-admin production evidence-check --env-file "$CUSTODIA_PRODUCTION_ENV_FILE"
else
  echo "CUSTODIA_PRODUCTION_ENV_FILE not set; skipping production configuration and external evidence gates." >&2
fi
