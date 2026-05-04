#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

# Bridge command used by CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND.
# It reads {"digest":"base64","hash":"..."} on stdin and writes {"signature":"base64"}.
# The actual signing is delegated to pkcs11-tool so this script can target SoftHSM
# in development or a real PKCS#11 module in production.

pkcs11_tool="${CUSTODIA_PKCS11_TOOL:-pkcs11-tool}"
module="${CUSTODIA_PKCS11_MODULE:?CUSTODIA_PKCS11_MODULE is required}"
token_label="${CUSTODIA_PKCS11_TOKEN_LABEL:?CUSTODIA_PKCS11_TOKEN_LABEL is required}"
key_label="${CUSTODIA_PKCS11_KEY_LABEL:?CUSTODIA_PKCS11_KEY_LABEL is required}"
pin_file="${CUSTODIA_PKCS11_PIN_FILE:?CUSTODIA_PKCS11_PIN_FILE is required}"
mechanism="${CUSTODIA_PKCS11_MECHANISM:-ECDSA}"

pin="$(cat "$pin_file")"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

python3 - "$workdir/digest.bin" <<'PY'
import base64
import json
import sys
payload = json.load(sys.stdin)
digest = base64.b64decode(payload["digest"], validate=True)
with open(sys.argv[1], "wb") as handle:
    handle.write(digest)
PY

"$pkcs11_tool" \
  --module "$module" \
  --token-label "$token_label" \
  --pin "$pin" \
  --sign \
  --mechanism "$mechanism" \
  --label "$key_label" \
  --input-file "$workdir/digest.bin" \
  --output-file "$workdir/signature.bin" >/dev/null

python3 - "$workdir/signature.bin" <<'PY'
import base64
import json
import sys
with open(sys.argv[1], "rb") as handle:
    signature = base64.b64encode(handle.read()).decode("ascii")
print(json.dumps({"signature": signature}, separators=(",", ":")))
PY
