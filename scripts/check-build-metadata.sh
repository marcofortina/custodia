#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

: "${VERSION:=}"
: "${COMMIT:=}"
: "${DATE:=}"

fail() {
  printf 'build-metadata-check: %s\n' "$*" >&2
  exit 1
}

case "${VERSION}" in
  ''|dev|0.0.0-dev|0.0.0_dev|unknown)
    fail 'VERSION must be an explicit release value, not dev/unknown'
    ;;
esac

case "${COMMIT}" in
  ''|unknown)
    fail 'COMMIT must be set to the source revision used for this build'
    ;;
esac

case "${DATE}" in
  ''|unknown)
    fail 'DATE must be set to the UTC build timestamp'
    ;;
esac

case "${DATE}" in
  ????-??-??T??:??:??Z) ;;
  *) fail 'DATE must use UTC RFC3339 form like 2026-05-07T12:34:56Z' ;;
esac

printf 'build-metadata-check: VERSION=%s COMMIT=%s DATE=%s\n' "${VERSION}" "${COMMIT}" "${DATE}" >&2
