#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# Sourceable Bash helpers for the custodia-client CLI.
# This file intentionally delegates crypto and transport work to custodia-client.

custodia_config="${CUSTODIA_CLIENT_CONFIG:-}"

custodia_use_config() {
  if [ "$#" -ne 1 ]; then
    printf 'usage: custodia_use_config CONFIG\n' >&2
    return 2
  fi
  custodia_config="$1"
  export CUSTODIA_CLIENT_CONFIG="$custodia_config"
}

custodia_require_config() {
  if [ -z "${custodia_config:-}" ]; then
    printf 'custodia config is not set; run custodia_use_config CONFIG first\n' >&2
    return 2
  fi
}

custodia_config_check() {
  custodia_require_config || return "$?"
  custodia-client config check --config "$custodia_config"
}

custodia_doctor() {
  custodia_require_config || return "$?"
  custodia-client doctor --config "$custodia_config" "$@"
}

custodia_secret_put_file() {
  if [ "$#" -lt 2 ]; then
    printf 'usage: custodia_secret_put_file NAME VALUE_FILE [OUTPUT_JSON]\n' >&2
    return 2
  fi
  custodia_require_config || return "$?"
  local name="$1"
  local value_file="$2"
  local output_file="${3:-}"
  if [ -n "$output_file" ]; then
    custodia-client secret put --config "$custodia_config" --name "$name" --value-file "$value_file" > "$output_file"
  else
    custodia-client secret put --config "$custodia_config" --name "$name" --value-file "$value_file"
  fi
}

custodia_secret_get_file() {
  if [ "$#" -ne 2 ]; then
    printf 'usage: custodia_secret_get_file SECRET_ID OUTPUT_FILE\n' >&2
    return 2
  fi
  custodia_require_config || return "$?"
  custodia-client secret get --config "$custodia_config" --secret-id "$1" --out "$2"
}

custodia_secret_share() {
  if [ "$#" -lt 3 ]; then
    printf 'usage: custodia_secret_share SECRET_ID TARGET_CLIENT_ID RECIPIENT_SPEC [PERMISSIONS]\n' >&2
    return 2
  fi
  custodia_require_config || return "$?"
  local secret_id="$1"
  local target_client_id="$2"
  local recipient="$3"
  local permissions="${4:-4}"
  custodia-client secret share \
    --config "$custodia_config" \
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
  custodia_require_config || return "$?"
  custodia-client secret delete --config "$custodia_config" --secret-id "$1" --yes
}
