#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

# Template bridge for CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND.
# Production must replace this fail-closed template with an audited WebAuthn
# verifier that validates authenticatorData, clientDataJSON, signature and
# COSE credential-key material.
cat >/dev/null
printf '{"valid":false,"error":"passkey assertion verifier command is not configured"}\n'
