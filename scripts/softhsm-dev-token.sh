#!/usr/bin/env bash
set -euo pipefail

# Initializes a SoftHSM token and imports/generates a signer key for local PKCS#11 testing.
# This is a development helper only; SoftHSM stores key material on the filesystem.

token_label="${CUSTODIA_PKCS11_TOKEN_LABEL:-custodia-dev}"
so_pin="${CUSTODIA_SOFTHSM_SO_PIN:-0000}"
pin="${CUSTODIA_PKCS11_PIN:-1234}"
key_label="${CUSTODIA_PKCS11_KEY_LABEL:-custodia-signer-ca}"
key_id="${CUSTODIA_PKCS11_KEY_ID:-01}"
module="${CUSTODIA_PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}"

token_dir="${CUSTODIA_SOFTHSM_TOKEN_DIR:-.softhsm2/tokens}"
conf_file="${CUSTODIA_SOFTHSM_CONF:-.softhsm2/softhsm2.conf}"
mkdir -p "$token_dir" "$(dirname "$conf_file")"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$token_dir" > "$conf_file"
export SOFTHSM2_CONF="$conf_file"

slot_line="$(softhsm2-util --show-slots | awk -F: '/Slot [0-9]+/{print $2; exit}' | tr -d ' ')"
slot="${slot_line:-0}"
softhsm2-util --init-token --slot "$slot" --label "$token_label" --so-pin "$so_pin" --pin "$pin"

pkcs11-tool \
  --module "$module" \
  --token-label "$token_label" \
  --login \
  --pin "$pin" \
  --keypairgen \
  --key-type EC:prime256v1 \
  --id "$key_id" \
  --label "$key_label"

mkdir -p .dev-secrets
printf '%s' "$pin" > .dev-secrets/softhsm-pin
chmod 600 .dev-secrets/softhsm-pin
cat <<OUT
SoftHSM token initialized.

export SOFTHSM2_CONF=$conf_file
export CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11
export CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND=./scripts/pkcs11-sign-command.sh
export CUSTODIA_PKCS11_MODULE=$module
export CUSTODIA_PKCS11_TOKEN_LABEL=$token_label
export CUSTODIA_PKCS11_KEY_LABEL=$key_label
export CUSTODIA_PKCS11_PIN_FILE=.dev-secrets/softhsm-pin
OUT
