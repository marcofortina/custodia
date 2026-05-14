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
# For ECDSA, pkcs11-tool returns raw r||s bytes; Go x509 expects ASN.1 DER.
# The actual signing is delegated to pkcs11-tool so this script can target SoftHSM
# in development or a real PKCS#11 module in production.

pkcs11_tool="${CUSTODIA_PKCS11_TOOL:-pkcs11-tool}"
module="${CUSTODIA_PKCS11_MODULE:?CUSTODIA_PKCS11_MODULE is required}"
token_label="${CUSTODIA_PKCS11_TOKEN_LABEL:?CUSTODIA_PKCS11_TOKEN_LABEL is required}"
key_label="${CUSTODIA_PKCS11_KEY_LABEL:?CUSTODIA_PKCS11_KEY_LABEL is required}"
pin_file="${CUSTODIA_PKCS11_PIN_FILE:?CUSTODIA_PKCS11_PIN_FILE is required}"
mechanism="${CUSTODIA_PKCS11_MECHANISM:-ECDSA}"

pin="$(cat "$pin_file")"
workdir_parent="${CUSTODIA_PKCS11_WORKDIR:-/var/lib/softhsm}"
workdir="$(mktemp -d "$workdir_parent/pkcs11-sign.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

request_file="$workdir/request.json"
cat >"$request_file"

python3 - "$request_file" "$workdir/digest.bin" <<'PY'
import base64
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
digest = base64.b64decode(payload["digest"], validate=True)
with open(sys.argv[2], "wb") as handle:
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

python3 - "$workdir/signature.bin" "$mechanism" <<'PY'
import base64
import json
import sys


def der_len(length):
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def der_int(value):
    value = value.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return b"\x02" + der_len(len(value)) + value


def ecdsa_raw_to_der(signature):
    if len(signature) == 0 or len(signature) % 2 != 0:
        raise ValueError("invalid raw ECDSA signature length")
    midpoint = len(signature) // 2
    payload = der_int(signature[:midpoint]) + der_int(signature[midpoint:])
    return b"\x30" + der_len(len(payload)) + payload


with open(sys.argv[1], "rb") as handle:
    signature_bytes = handle.read()

mechanism = sys.argv[2].upper()
if mechanism == "ECDSA":
    signature_bytes = ecdsa_raw_to_der(signature_bytes)

signature = base64.b64encode(signature_bytes).decode("ascii")
print(json.dumps({"signature": signature}, separators=(",", ":")))
PY
