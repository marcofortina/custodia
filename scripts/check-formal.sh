#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

TLC_CMD=${TLC:-tlc}

if ! command -v "${TLC_CMD}" >/dev/null 2>&1; then
  echo "TLC command '${TLC_CMD}' not found. Install TLA+ tools or set TLC=/path/to/tlc." >&2
  exit 2
fi

"${TLC_CMD}" -config formal/CustodiaAccess.cfg formal/CustodiaAccess.tla
