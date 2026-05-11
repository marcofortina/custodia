#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

failures=0

fail() {
  printf 'release-keyspace-check: ERROR: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    fail "missing required file: $path"
  fi
}

for path in \
  README.md \
  docs/CUSTODIA_CLIENT_CLI.md \
  docs/CLIENT_LIBRARIES.md \
  docs/GO_CLIENT_SDK.md \
  docs/PYTHON_CLIENT_SDK.md \
  docs/NODE_CLIENT_SDK.md \
  docs/CPP_CLIENT_SDK.md \
  docs/JAVA_CLIENT_SDK.md \
  docs/RUST_CLIENT_SDK.md \
  docs/WEB_CONSOLE.md \
  docs/man/custodia-admin.1.in \
  docs/man/custodia-client.1.in \
  cmd/custodia-admin/main.go \
  cmd/custodia-client/main.go \
  pkg/client/public_transport.go \
  pkg/client/crypto_client.go \
  clients/python/custodia_client/__init__.py \
  clients/python/custodia_client/crypto.py \
  clients/node/src/index.js \
  clients/node/src/index.d.ts \
  clients/node/src/crypto.js \
  clients/cpp/include/custodia/client.hpp \
  clients/cpp/src/client.cpp \
  clients/cpp/src/crypto.cpp \
  clients/java/src/main/java/dev/custodia/client/CustodiaClient.java \
  clients/java/src/main/java/dev/custodia/client/CryptoCustodiaClient.java \
  clients/rust/src/lib.rs \
  clients/rust/src/crypto.rs
 do
  require_file "$path"
done

check_absent() {
  local pattern="$1"
  shift
  local matches
  matches="$(grep -nE -- "$pattern" "$@" 2>/dev/null || true)"
  if [[ -n "$matches" ]]; then
    fail "forbidden public keyspace regression pattern '$pattern' found:\n$matches"
  fi
}

cli_workflow_files=(
  README.md
  docs/CUSTODIA_CLIENT_CLI.md
  docs/man/custodia-admin.1.in
  docs/man/custodia-client.1.in
  cmd/custodia-admin/main.go
  cmd/custodia-client/main.go
)
check_absent '--secret-id' "${cli_workflow_files[@]}"

# Go SDK: internal-id methods may remain in internal-model helpers, but not in public transport/high-level crypto APIs.
check_absent 'func \(c \*Client\) (GetSecretPayload|ShareSecretPayload|CreateSecretVersionPayload|ListSecretVersionMetadata|ListSecretAccessMetadata|DeleteSecretPayload|RevokeAccess)\(' pkg/client/public_transport.go
check_absent 'func \(c \*CryptoClient\) (ReadDecryptedSecret|ShareEncryptedSecret|CreateEncryptedSecretVersion)\(' pkg/client/crypto_client.go

# Python SDK public workflow helpers must stay namespace/key based.
check_absent '^    def (get_secret|share_secret|create_secret_version|delete_secret|list_secret_versions|list_secret_access|revoke_access|request_access_grant|activate_access_grant)\(' clients/python/custodia_client/__init__.py clients/python/custodia_client/crypto.py

# Node SDK public workflow helpers must stay namespace/key based.
check_absent '^[[:space:]]*(getSecretPayload|shareSecretPayload|createSecretVersionPayload|deleteSecretPayload|listSecretVersionMetadata|listSecretAccessMetadata|revokeAccess|createAccessGrant|activateAccessGrantPayload)\(' clients/node/src/index.js clients/node/src/crypto.js
check_absent '(getSecretPayload|shareSecretPayload|createSecretVersionPayload|deleteSecretPayload|listSecretVersionMetadata|listSecretAccessMetadata|revokeAccess|createAccessGrant|activateAccessGrantPayload)\(' clients/node/src/index.d.ts

# Native SDK public workflow helpers must stay namespace/key based.
check_absent '(get_secret_payload|share_secret_payload|create_secret_version_payload|delete_secret_payload|list_secret_version_metadata|list_secret_access_metadata|revoke_access|create_access_grant|activate_access_grant_payload)\(' clients/cpp/include/custodia/client.hpp clients/cpp/src/client.cpp clients/rust/src/lib.rs
check_absent '(getSecretPayload|shareSecretPayload|createSecretVersionPayload|deleteSecretPayload|listSecretVersionMetadata|listSecretAccessMetadata|revokeAccess|createAccessGrant|activateAccessGrantPayload)\(' clients/java/src/main/java/dev/custodia/client/CustodiaClient.java

# High-level native crypto helpers must also remain namespace/key based.
check_absent '(read_decrypted_secret|share_encrypted_secret|create_encrypted_secret_version)\(' clients/cpp/include/custodia/client.hpp clients/cpp/src/crypto.cpp clients/rust/src/lib.rs clients/rust/src/crypto.rs
check_absent '(readDecryptedSecret|shareEncryptedSecret|createEncryptedSecretVersion)\(' clients/java/src/main/java/dev/custodia/client/CryptoCustodiaClient.java clients/node/src/crypto.js clients/node/src/index.d.ts
check_absent '^    def (read_decrypted_secret|share_encrypted_secret|create_encrypted_secret_version)\(' clients/python/custodia_client/crypto.py

if (( failures > 0 )); then
  exit 1
fi

echo 'release-keyspace-check: OK'
