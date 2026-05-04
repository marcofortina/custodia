#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cat > "$tmp_dir/curl" <<'CURL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${CUSTODIA_BASH_TEST_CURL_LOG:?}"
previous=""
for arg in "$@"; do
  if [ "$previous" = "--data-binary" ]; then
    data_file="${arg#@}"
    printf 'BODY:%s\n' "$data_file" >> "${CUSTODIA_BASH_TEST_CURL_LOG:?}"
    cat "$data_file" >> "${CUSTODIA_BASH_TEST_CURL_LOG:?}"
    printf '\n' >> "${CUSTODIA_BASH_TEST_CURL_LOG:?}"
  fi
  previous="$arg"
done
case "$*" in
  *'/v1/secrets/secret-1'|*'/v1/secrets/secret%201%2Fwith%20slash')
    printf '{"secret_id":"secret-1","ciphertext":"opaque","envelope":"opaque"}\n'
    ;;
  *)
    printf '{"ok":true}\n'
    ;;
esac
CURL
chmod +x "$tmp_dir/curl"

cat > "$tmp_dir/provider" <<'PROVIDER'
#!/usr/bin/env bash
set -euo pipefail
operation="${1:?operation is required}"
input_file="${CUSTODIA_BASH_TEST_PROVIDER_INPUT_DIR:?}/$operation.json"
printf '%s\n' "$operation" >> "${CUSTODIA_BASH_TEST_PROVIDER_LOG:?}"
cat > "$input_file"
case "$operation" in
  create-encrypted-secret)
    printf '{"name":"db","ciphertext":"provider-ciphertext","crypto_metadata":{"schema":"hpke-v1"},"envelopes":[{"client_id":"alice","envelope":"provider-envelope"}]}\n'
    ;;
  read-decrypted-secret)
    grep -q '"ciphertext":"opaque"' "$input_file"
    printf '{"plaintext_b64":"c2VjcmV0"}\n'
    ;;
  share-encrypted-secret)
    printf '{"version_id":"version-1","target_client_id":"bob","envelope":"provider-envelope"}\n'
    ;;
  create-encrypted-secret-version)
    printf '{"ciphertext":"provider-version-ciphertext","crypto_metadata":{"schema":"hpke-v1"},"envelopes":[{"client_id":"alice","envelope":"provider-envelope"}]}\n'
    ;;
  *)
    printf 'unsupported operation: %s\n' "$operation" >&2
    exit 64
    ;;
esac
PROVIDER
chmod +x "$tmp_dir/provider"

export PATH="$tmp_dir:$PATH"
export CUSTODIA_BASH_TEST_CURL_LOG="$tmp_dir/curl.log"
export CUSTODIA_BASH_TEST_PROVIDER_LOG="$tmp_dir/provider.log"
export CUSTODIA_BASH_TEST_PROVIDER_INPUT_DIR="$tmp_dir/provider-inputs"
mkdir -p "$CUSTODIA_BASH_TEST_PROVIDER_INPUT_DIR"
export CUSTODIA_BASE_URL="https://vault.example.test:8443/"
export CUSTODIA_CLIENT_CERT="client.crt"
export CUSTODIA_CLIENT_KEY="client.key"
export CUSTODIA_CA_CERT="ca.crt"
export CUSTODIA_CRYPTO_PROVIDER="$tmp_dir/provider"

# shellcheck source=/dev/null
source "$root_dir/clients/bash/custodia.sh"

payload="$tmp_dir/payload.json"
printf '{"name":"db","ciphertext":"opaque","envelopes":[]}\n' > "$payload"
request="$tmp_dir/request.json"
printf '{"name":"db","plaintext_b64":"c2VjcmV0","recipients":["alice"]}\n' > "$request"

custodia_status > "$tmp_dir/status.out"
custodia_create_secret_raw "$payload" > "$tmp_dir/create.out"
custodia_get_secret_raw "secret 1/with slash" > "$tmp_dir/get.out"
custodia_share_secret_raw "secret-1" "$payload" > "$tmp_dir/share.out"
custodia_create_secret_encrypted "$request" > "$tmp_dir/create-encrypted.out"
custodia_read_secret_decrypted "secret 1/with slash" > "$tmp_dir/read-decrypted.out"
custodia_share_secret_encrypted "secret-1" "$request" > "$tmp_dir/share-encrypted.out"
custodia_create_secret_version_encrypted "secret-1" "$request" > "$tmp_dir/version-encrypted.out"

for output in status create share create-encrypted share-encrypted version-encrypted; do
  grep -q '"ok":true' "$tmp_dir/$output.out"
done

grep -q '"secret_id":"secret-1"' "$tmp_dir/get.out"
grep -q '"plaintext_b64":"c2VjcmV0"' "$tmp_dir/read-decrypted.out"

grep -q -- '--request GET' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- '--request POST' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- 'https://vault.example.test:8443/v1/status' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- 'https://vault.example.test:8443/v1/secrets/secret-1/share' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- 'https://vault.example.test:8443/v1/secrets/secret%201%2Fwith%20slash' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- 'https://vault.example.test:8443/v1/secrets/secret-1/versions' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- 'User-Agent: custodia-bash-transport/0.0.0' "$CUSTODIA_BASH_TEST_CURL_LOG"

grep -q '^create-encrypted-secret$' "$CUSTODIA_BASH_TEST_PROVIDER_LOG"
grep -q '^read-decrypted-secret$' "$CUSTODIA_BASH_TEST_PROVIDER_LOG"
grep -q '^share-encrypted-secret$' "$CUSTODIA_BASH_TEST_PROVIDER_LOG"
grep -q '^create-encrypted-secret-version$' "$CUSTODIA_BASH_TEST_PROVIDER_LOG"
grep -q '"plaintext_b64":"c2VjcmV0"' "$CUSTODIA_BASH_TEST_PROVIDER_INPUT_DIR/create-encrypted-secret.json"
grep -q '"ciphertext":"opaque"' "$CUSTODIA_BASH_TEST_PROVIDER_INPUT_DIR/read-decrypted-secret.json"

bash -n "$root_dir/clients/bash/custodia.sh"

# Provider outputs must be server-compatible payloads, not ad-hoc field names.
grep -q '"target_client_id":"bob"' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q '"envelope":"provider-envelope"' "$CUSTODIA_BASH_TEST_CURL_LOG"
! grep -q 'envelope_for_target' "$CUSTODIA_BASH_TEST_CURL_LOG"
