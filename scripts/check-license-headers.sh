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

failures=0

fail() {
  printf 'license-check: %s\n' "$*" >&2
  failures=$((failures + 1))
}

has_spdx() {
  grep -q 'SPDX-License-Identifier: AGPL-3.0-only' "$1"
}

check_spdx_file() {
  local file="$1"
  if ! has_spdx "$file"; then
    fail "missing SPDX header: $file"
  fi
}

check_json_field() {
  local file="$1" field="$2" expected="$3"
  python3 - "$file" "$field" "$expected" <<'PY'
import json
import sys
path, field, expected = sys.argv[1:4]
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)
if data.get(field) != expected:
    raise SystemExit(1)
PY
}

while IFS= read -r file; do
  case "$file" in
    ./.git/*|./dist/*|*/target/*|*/__pycache__/*|*.pyc|*.lock) continue ;;
  esac
  file="${file#./}"
  check_spdx_file "$file"
done < <(
  find . \
    \( -path './.git' -o -path './dist' -o -path './clients/rust/target' \) -prune -o \
    -type f \
    \( \
      -name '*.go' -o -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.d.ts' -o \
      -name '*.java' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.h' -o -name '*.rs' -o \
      -name '*.sh' -o -name 'Dockerfile' -o -name 'Makefile' -o \
      -name '*.yml' -o -name '*.yaml' -o -name '*.service' -o -name '*.sql' -o \
      -name '*.tla' -o -name '*.cfg' -o -name '*.toml' -o -name '*.env.example' \
    \) -print
)

if ! check_json_field clients/node/package.json license AGPL-3.0-only; then
  fail "clients/node/package.json must declare license AGPL-3.0-only"
fi
if ! python3 - <<'PY'
import json
with open('clients/node/package.json', encoding='utf-8') as handle:
    data = json.load(handle)
if data.get('author') != 'Marco Fortina':
    raise SystemExit(1)
PY
then
  fail "clients/node/package.json must declare author Marco Fortina"
fi

if ! python3 - <<'PY'
import json
with open('deploy/helm/custodia/values.schema.json', encoding='utf-8') as handle:
    data = json.load(handle)
comment = data.get('$comment', '')
if 'SPDX-License-Identifier: AGPL-3.0-only' not in comment:
    raise SystemExit(1)
PY
then
  fail "deploy/helm/custodia/values.schema.json must declare SPDX in $comment"
fi

if grep -RIn 'SPDX-License-Identifier' testdata/client-crypto/v1 >/dev/null 2>&1; then
  fail "test vector JSON files must stay comment-free and fixture-only"
fi

if [ "$failures" -ne 0 ]; then
  exit 1
fi

printf 'license-check: OK\n'
