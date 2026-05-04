#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cat > "$tmp_dir/curl" <<'CURL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${CUSTODIA_BASH_TEST_CURL_LOG:?}"
printf '{"ok":true}\n'
CURL
chmod +x "$tmp_dir/curl"

export PATH="$tmp_dir:$PATH"
export CUSTODIA_BASH_TEST_CURL_LOG="$tmp_dir/curl.log"
export CUSTODIA_BASE_URL="https://vault.example.test:8443/"
export CUSTODIA_CLIENT_CERT="client.crt"
export CUSTODIA_CLIENT_KEY="client.key"
export CUSTODIA_CA_CERT="ca.crt"

# shellcheck source=/dev/null
source "$root_dir/clients/bash/custodia.sh"

payload="$tmp_dir/payload.json"
printf '{"name":"db","ciphertext":"opaque","envelopes":[]}\n' > "$payload"

custodia_status > "$tmp_dir/status.out"
custodia_create_secret_raw "$payload" > "$tmp_dir/create.out"
custodia_get_secret_raw "secret-1" > "$tmp_dir/get.out"
custodia_share_secret_raw "secret-1" "$payload" > "$tmp_dir/share.out"

for output in status create get share; do
  grep -q '"ok":true' "$tmp_dir/$output.out"
done

grep -q -- '--request GET' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- '--request POST' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- 'https://vault.example.test:8443/v1/status' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- 'https://vault.example.test:8443/v1/secrets/secret-1/share' "$CUSTODIA_BASH_TEST_CURL_LOG"
grep -q -- 'User-Agent: custodia-bash-transport/0.0.0' "$CUSTODIA_BASH_TEST_CURL_LOG"

bash -n "$root_dir/clients/bash/custodia.sh"
