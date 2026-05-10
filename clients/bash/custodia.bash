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
  if [ "$#" -lt 2 ]; then
    printf 'usage: custodia_secret_put_file NAME VALUE_FILE [OUTPUT_JSON]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local name="$1"
  local value_file="$2"
  local output_file="${3:-}"
  if [ -n "$output_file" ]; then
    custodia-client secret put "${CUSTODIA_PROFILE_ARGS[@]}" --name "$name" --value-file "$value_file" > "$output_file"
  else
    custodia-client secret put "${CUSTODIA_PROFILE_ARGS[@]}" --name "$name" --value-file "$value_file"
  fi
}

custodia_secret_get_file() {
  if [ "$#" -ne 2 ]; then
    printf 'usage: custodia_secret_get_file SECRET_ID OUTPUT_FILE\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  custodia-client secret get "${CUSTODIA_PROFILE_ARGS[@]}" --secret-id "$1" --out "$2"
}

custodia_secret_share() {
  if [ "$#" -lt 3 ]; then
    printf 'usage: custodia_secret_share SECRET_ID TARGET_CLIENT_ID RECIPIENT_SPEC [PERMISSIONS]\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  local secret_id="$1"
  local target_client_id="$2"
  local recipient="$3"
  local permissions="${4:-4}"
  custodia-client secret share \
    "${CUSTODIA_PROFILE_ARGS[@]}" \
    --secret-id "$secret_id" \
    --target-client-id "$target_client_id" \
    --recipient "$recipient" \
    --permissions "$permissions"
}

custodia_secret_delete() {
  if [ "$#" -ne 1 ]; then
    printf 'usage: custodia_secret_delete SECRET_ID\n' >&2
    return 2
  fi
  custodia_profile_args || return "$?"
  custodia-client secret delete "${CUSTODIA_PROFILE_ARGS[@]}" --secret-id "$1" --yes
}
