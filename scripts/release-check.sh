#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

: "${GO:=go}"

$GO test -p=1 -timeout 60s ./...
$GO build ./cmd/custodia-server ./cmd/vault-admin ./cmd/custodia-signer
python3 -m py_compile clients/python/custodia_client/__init__.py

if command -v tlc >/dev/null 2>&1; then
  ./scripts/check-formal.sh
else
  echo "TLC not found; skipping formal-check. Run make formal-check where TLC is installed." >&2
fi
