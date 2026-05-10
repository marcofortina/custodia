#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# Sourceable Bash helpers for the custodia-client CLI.
# This file intentionally delegates crypto and transport work to custodia-client.

custodia_config="${CUSTODIA_CLIENT_CONFIG:-}"
custodia_client_id="${CUSTODIA_CLIENT_ID:-}"

custodia_use_config() {
  if [ "$#" -ne 1 ]; then
    printf 'usage: custodia_use_config CONFIG\n' >&2
    return 2
  fi
  custodia_config="$1"
  export CUSTODIA_CLIENT_CONFIG="$custodia_config"
}

custodia_use_client_id() {
  if [ "$#" -ne 1 ]; then
    printf 'usage: custodia_use_client_id CLIENT_ID\n' >&2
    return 2
  fi
  custodia_client_id="$1"
  export CUSTODIA_CLIENT_ID="$custodia_client_id"
}

custodia_profile_args() {
  if [ -n "${custodia_config:-}" ]; then
    CUSTODIA_PROFILE_ARGS=(--config "$custodia_config")
    return 0
  fi
  if [ -n "${custodia_client_id:-}" ]; then
    CUSTODIA_PROFILE_ARGS=(--client-id "$custodia_client_id")
    return 0
  fi
  printf 'custodia profile is not set; run custodia_use_client_id CLIENT_ID or custodia_use_config CONFIG first\n' >&2
  return 2
}

custodia_config_check() {
  custodia_profile_args || return "$?"
  custodia-client config check "${CUSTODIA_PROFILE_ARGS[@]}"
}

custodia_doctor() {
  custodia_profile_args || return "$?"
  custodia-client doctor "${CUSTODIA_PROFILE_ARGS[@]}" "$@"
}

custodia_secret_put_file() {
  if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf 'usage: custodia_secret_put_file KEY VALUE_FILE [NAMESPACE]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local key="$1"
  local value_file="$2"
  local namespace="${3:-default}"
  custodia-client secret put "${CUSTODIA_PROFILE_ARGS[@]}" --namespace "$namespace" --key "$key" --value-file "$value_file"
}

custodia_secret_get_file() {
  if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf 'usage: custodia_secret_get_file KEY OUTPUT_FILE [NAMESPACE]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local key="$1"
  local output_file="$2"
  local namespace="${3:-default}"
  custodia-client secret get "${CUSTODIA_PROFILE_ARGS[@]}" --namespace "$namespace" --key "$key" --out "$output_file"
}

custodia_secret_update_file() {
  if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf 'usage: custodia_secret_update_file KEY VALUE_FILE [NAMESPACE]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local key="$1"
  local value_file="$2"
  local namespace="${3:-default}"
  custodia-client secret update "${CUSTODIA_PROFILE_ARGS[@]}" --namespace "$namespace" --key "$key" --value-file "$value_file"
}

custodia_secret_share() {
  if [ "$#" -lt 3 ] || [ "$#" -gt 5 ]; then
    printf 'usage: custodia_secret_share KEY TARGET_CLIENT_ID RECIPIENT_SPEC [PERMISSIONS] [NAMESPACE]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local key="$1"
  local target_client_id="$2"
  local recipient="$3"
  local permissions="${4:-4}"
  local namespace="${5:-default}"
  custodia-client secret share \
    "${CUSTODIA_PROFILE_ARGS[@]}" \
    --namespace "$namespace" \
    --key "$key" \
    --target-client-id "$target_client_id" \
    --recipient "$recipient" \
    --permissions "$permissions"
}

custodia_secret_revoke() {
  if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf 'usage: custodia_secret_revoke KEY TARGET_CLIENT_ID [NAMESPACE]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local key="$1"
  local target_client_id="$2"
  local namespace="${3:-default}"
  custodia-client secret access revoke \
    "${CUSTODIA_PROFILE_ARGS[@]}" \
    --namespace "$namespace" \
    --key "$key" \
    --target-client-id "$target_client_id" \
    --yes
}

custodia_secret_delete() {
  if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf 'usage: custodia_secret_delete KEY [NAMESPACE]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local key="$1"
  local namespace="${2:-default}"
  custodia-client secret delete "${CUSTODIA_PROFILE_ARGS[@]}" --namespace "$namespace" --key "$key" --yes
}

custodia_secret_delete_cascade() {
  if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf 'usage: custodia_secret_delete_cascade KEY [NAMESPACE]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local key="$1"
  local namespace="${2:-default}"
  custodia-client secret delete "${CUSTODIA_PROFILE_ARGS[@]}" --namespace "$namespace" --key "$key" --cascade --yes
}
