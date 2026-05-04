#!/usr/bin/env bash
# Custodia Bash transport helper.
#
# This helper is intentionally transport-only. It never encrypts, decrypts,
# opens envelopes, manages DEKs or resolves recipient public keys.

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
  custodia_curl GET "/v1/secrets/$1"
}

custodia_share_secret_raw() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_share_secret_raw SECRET_ID PAYLOAD_JSON" >&2
    return 2
  fi
  custodia_curl POST "/v1/secrets/$1/share" "$2"
}

custodia_create_secret_version_raw() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_create_secret_version_raw SECRET_ID PAYLOAD_JSON" >&2
    return 2
  fi
  custodia_curl POST "/v1/secrets/$1/versions" "$2"
}

custodia_revoke_access() {
  if [ "$#" -ne 2 ]; then
    echo "usage: custodia_revoke_access SECRET_ID CLIENT_ID" >&2
    return 2
  fi
  custodia_curl DELETE "/v1/secrets/$1/access/$2"
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
  revoke-access SECRET_ID CLIENT_ID
  audit-export

Boundary:
  Transport-only. No encryption, decryption, DEK handling or HPKE envelopes.
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
