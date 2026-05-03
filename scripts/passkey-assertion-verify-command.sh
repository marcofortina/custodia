#!/usr/bin/env bash
set -euo pipefail

# Template bridge for CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND.
# Production must replace this fail-closed template with an audited WebAuthn
# verifier that validates authenticatorData, clientDataJSON, signature and
# COSE credential-key material.
cat >/dev/null
printf '{"valid":false,"error":"passkey assertion verifier command is not configured"}\n'
