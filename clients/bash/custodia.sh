#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

# Custodia Bash transport helper.
#
# This helper is intentionally transport-first. Native Bash code never encrypts,
# decrypts, opens envelopes, manages DEKs or resolves recipient public keys.
# Optional encrypted flows are delegated to an external crypto provider.

custodia_require_config() {
  : "${CUSTODIA_BASE_URL:?CUSTODIA_BASE_URL is required}"
  : "${CUSTODIA_CLIENT_CERT:?CUSTODIA_CLIENT_CERT is required}"
  : "${CUSTODIA_CLIENT_KEY:?CUSTODIA_CLIENT_KEY is required}"
  : "${CUSTODIA_CA_CERT:?CUSTODIA_CA_CERT is required}"
}

custodia_base_url() {
  printf '%s' "${CUSTODIA_BASE_URL%/}"
}

custodia_user_agent() {
  printf '%s' "${CUSTODIA_USER_AGENT:-custodia-bash-transport/0.0.0}"
}


custodia_urlencode() {
  if [ "$#" -ne 1 ]; then
    echo "usage: custodia_urlencode VALUE" >&2
    return 2
  fi

  local value="$1"
  local encoded=""
  local char hex i
  LC_ALL=C
  for ((i = 0; i < ${#value}; i += 1)); do
    char="${value:i:1}"
    case "$char" in
      [a-zA-Z0-9.~_-]) encoded+="$char" ;;
      *)
        printf -v hex '%%%02X' "'$char"
        encoded+="$hex"
        ;;
    esac
  done
  printf '%s' "$encoded"
}

custodia_require_provider_field() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_require_provider_field FILE FIELD" >&2
    return 2
  fi
  if ! grep -Eq '"'"$2"'"[[:space:]]*:' "$1"; then
    echo "crypto provider output is missing required field: $2" >&2
    return 65
  fi
}

custodia_validate_provider_output() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_validate_provider_output OPERATION OUTPUT_JSON" >&2
    return 2
  fi

  local operation="$1"
  local output_file="$2"
  case "$operation" in
    create-encrypted-secret)
      custodia_require_provider_field "$output_file" name || return $?
      custodia_require_provider_field "$output_file" ciphertext || return $?
      custodia_require_provider_field "$output_file" crypto_metadata || return $?
      custodia_require_provider_field "$output_file" envelopes || return $?
      custodia_require_provider_field "$output_file" envelope || return $?
      ;;
    share-encrypted-secret)
      custodia_require_provider_field "$output_file" version_id || return $?
      custodia_require_provider_field "$output_file" target_client_id || return $?
      custodia_require_provider_field "$output_file" envelope || return $?
      ;;
    create-encrypted-secret-version)
      custodia_require_provider_field "$output_file" ciphertext || return $?
      custodia_require_provider_field "$output_file" crypto_metadata || return $?
      custodia_require_provider_field "$output_file" envelopes || return $?
      custodia_require_provider_field "$output_file" envelope || return $?
      ;;
    read-decrypted-secret)
      custodia_require_provider_field "$output_file" plaintext_b64 || return $?
      ;;
  esac
}


# The Bash helper delegates encryption to an external provider. It validates
# provider output shape but intentionally never implements HPKE or DEK handling
# in shell.
custodia_require_crypto_provider() {
  : "${CUSTODIA_CRYPTO_PROVIDER:?CUSTODIA_CRYPTO_PROVIDER is required for encrypted commands}"
  if ! command -v "$CUSTODIA_CRYPTO_PROVIDER" >/dev/null 2>&1; then
    echo "CUSTODIA_CRYPTO_PROVIDER is not executable or not found: $CUSTODIA_CRYPTO_PROVIDER" >&2
    return 2
  fi
}

custodia_crypto_provider() {
  custodia_require_crypto_provider || return $?
  if [ "$#" -ne 3 ]; then
    echo "usage: custodia_crypto_provider OPERATION INPUT_JSON OUTPUT_JSON" >&2
    return 2
  fi

  local operation="$1"
  local input_file="$2"
  local output_file="$3"

  # The operation name is passed as argv. Secret material must travel through
  # stdin/stdout JSON only, never as command-line arguments.
  "$CUSTODIA_CRYPTO_PROVIDER" "$operation" < "$input_file" > "$output_file"
  local status=$?
  if [ "$status" -ne 0 ]; then
    return "$status"
  fi
  custodia_validate_provider_output "$operation" "$output_file"
}

custodia_curl() {
  custodia_require_config
  if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: custodia_curl METHOD PATH [BODY_FILE]" >&2
    return 2
  fi

  local method="$1"
  local path="$2"
  local body_file="${3:-}"
  local url
  url="$(custodia_base_url)$path"

  local args=(
    --fail-with-body
    --silent
    --show-error
    --request "$method"
    --cert "$CUSTODIA_CLIENT_CERT"
    --key "$CUSTODIA_CLIENT_KEY"
    --cacert "$CUSTODIA_CA_CERT"
    --header "Accept: application/json"
    --header "User-Agent: $(custodia_user_agent)"
  )

  if [ -n "$body_file" ]; then
    args+=(--header "Content-Type: application/json" --data-binary "@$body_file")
  fi

  curl "${args[@]}" "$url"
}

custodia_status() {
  custodia_curl GET /v1/status
}

custodia_version() {
  custodia_curl GET /v1/version
}

custodia_diagnostics() {
  custodia_curl GET /v1/diagnostics
}

custodia_me() {
  custodia_curl GET /v1/me
}

custodia_list_clients() {
  custodia_curl GET /v1/clients
}

custodia_list_secrets() {
  custodia_curl GET /v1/secrets
}

custodia_create_secret_raw() {
  if [ "$#" -ne 1 ]; then
    echo "usage: custodia_create_secret_raw PAYLOAD_JSON" >&2
    return 2
  fi
  custodia_curl POST /v1/secrets "$1"
}

custodia_get_secret_raw() {
  if [ "$#" -ne 1 ]; then
    echo "usage: custodia_get_secret_raw SECRET_ID" >&2
    return 2
  fi
  custodia_curl GET "/v1/secrets/$(custodia_urlencode "$1")"
}

custodia_share_secret_raw() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_share_secret_raw SECRET_ID PAYLOAD_JSON" >&2
    return 2
  fi
  custodia_curl POST "/v1/secrets/$(custodia_urlencode "$1")/share" "$2"
}

custodia_create_secret_version_raw() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_create_secret_version_raw SECRET_ID PAYLOAD_JSON" >&2
    return 2
  fi
  custodia_curl POST "/v1/secrets/$(custodia_urlencode "$1")/versions" "$2"
}

custodia_create_secret_encrypted() {
  if [ "$#" -ne 1 ]; then
    echo "usage: custodia_create_secret_encrypted REQUEST_JSON" >&2
    return 2
  fi

  local payload_file
  payload_file="$(mktemp)" || return 1
  custodia_crypto_provider create-encrypted-secret "$1" "$payload_file"
  local provider_status=$?
  if [ "$provider_status" -ne 0 ]; then
    rm -f "$payload_file"
    return "$provider_status"
  fi
  custodia_create_secret_raw "$payload_file"
  local status=$?
  rm -f "$payload_file"
  return "$status"
}

custodia_read_secret_decrypted() {
  if [ "$#" -ne 1 ]; then
    echo "usage: custodia_read_secret_decrypted SECRET_ID" >&2
    return 2
  fi

  local raw_file
  raw_file="$(mktemp)" || return 1
  custodia_get_secret_raw "$1" > "$raw_file" || {
    rm -f "$raw_file"
    return 1
  }
  local plaintext_file
  plaintext_file="$(mktemp)" || {
    rm -f "$raw_file"
    return 1
  }
  custodia_crypto_provider read-decrypted-secret "$raw_file" "$plaintext_file"
  local status=$?
  if [ "$status" -eq 0 ]; then
    cat "$plaintext_file"
  fi
  rm -f "$raw_file" "$plaintext_file"
  return "$status"
}

custodia_share_secret_encrypted() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_share_secret_encrypted SECRET_ID REQUEST_JSON" >&2
    return 2
  fi

  local payload_file
  payload_file="$(mktemp)" || return 1
  custodia_crypto_provider share-encrypted-secret "$2" "$payload_file"
  local provider_status=$?
  if [ "$provider_status" -ne 0 ]; then
    rm -f "$payload_file"
    return "$provider_status"
  fi
  custodia_share_secret_raw "$1" "$payload_file"
  local status=$?
  rm -f "$payload_file"
  return "$status"
}

custodia_create_secret_version_encrypted() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_create_secret_version_encrypted SECRET_ID REQUEST_JSON" >&2
    return 2
  fi

  local payload_file
  payload_file="$(mktemp)" || return 1
  custodia_crypto_provider create-encrypted-secret-version "$2" "$payload_file"
  local provider_status=$?
  if [ "$provider_status" -ne 0 ]; then
    rm -f "$payload_file"
    return "$provider_status"
  fi
  custodia_create_secret_version_raw "$1" "$payload_file"
  local status=$?
  rm -f "$payload_file"
  return "$status"
}

custodia_revoke_access() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_revoke_access SECRET_ID CLIENT_ID" >&2
    return 2
  fi
  custodia_curl DELETE "/v1/secrets/$(custodia_urlencode "$1")/access/$(custodia_urlencode "$2")"
}

custodia_audit_export() {
  custodia_curl GET /v1/audit-events/export
}

custodia_usage() {
  cat <<'USAGE'
Custodia Bash transport helper

Required environment:
  CUSTODIA_BASE_URL      https://vault.example:8443
  CUSTODIA_CLIENT_CERT   client certificate PEM path
  CUSTODIA_CLIENT_KEY    client private key PEM path
  CUSTODIA_CA_CERT       Custodia CA PEM path

Optional encrypted-flow environment:
  CUSTODIA_CRYPTO_PROVIDER  executable that implements the external provider protocol

Commands:
  status
  version
  diagnostics
  me
  list-clients
  list-secrets
  create-secret-raw PAYLOAD_JSON
  get-secret-raw SECRET_ID
  share-secret-raw SECRET_ID PAYLOAD_JSON
  create-secret-version-raw SECRET_ID PAYLOAD_JSON
  create-secret-encrypted REQUEST_JSON
  read-secret-decrypted SECRET_ID
  share-secret-encrypted SECRET_ID REQUEST_JSON
  create-secret-version-encrypted SECRET_ID REQUEST_JSON
  revoke-access SECRET_ID CLIENT_ID
  audit-export

Boundary:
  Native Bash remains transport-only. Encrypted commands require an external
  crypto provider and never implement crypto in shell code.
USAGE
}

custodia_main() {
  local command="${1:-}"
  if [ -z "$command" ]; then
    custodia_usage >&2
    return 2
  fi
  shift || true

  case "$command" in
    status) custodia_status "$@" ;;
    version) custodia_version "$@" ;;
    diagnostics) custodia_diagnostics "$@" ;;
    me) custodia_me "$@" ;;
    list-clients) custodia_list_clients "$@" ;;
    list-secrets) custodia_list_secrets "$@" ;;
    create-secret-raw) custodia_create_secret_raw "$@" ;;
    get-secret-raw) custodia_get_secret_raw "$@" ;;
    share-secret-raw) custodia_share_secret_raw "$@" ;;
    create-secret-version-raw) custodia_create_secret_version_raw "$@" ;;
    create-secret-encrypted) custodia_create_secret_encrypted "$@" ;;
    read-secret-decrypted) custodia_read_secret_decrypted "$@" ;;
    share-secret-encrypted) custodia_share_secret_encrypted "$@" ;;
    create-secret-version-encrypted) custodia_create_secret_version_encrypted "$@" ;;
    revoke-access) custodia_revoke_access "$@" ;;
    audit-export) custodia_audit_export "$@" ;;
    help|-h|--help) custodia_usage ;;
    *)
      echo "unknown command: $command" >&2
      custodia_usage >&2
      return 2
      ;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -euo pipefail
  custodia_main "$@"
fi
