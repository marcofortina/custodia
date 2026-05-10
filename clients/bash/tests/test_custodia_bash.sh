#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cat > "$tmp_dir/custodia-client" <<'CLIENT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${CUSTODIA_BASH_SDK_TEST_LOG:?}"
case "$*" in
  config\ check*) printf '{"status":"ok"}\n' ;;
  doctor*) printf 'doctor ok\n' ;;
  secret\ put*) printf '{"secret_id":"secret-1"}\n' ;;
  secret\ get*)
    out=""
    previous=""
    for arg in "$@"; do
      if [ "$previous" = "--out" ]; then out="$arg"; fi
      previous="$arg"
    done
    printf 'secret value\n' > "$out"
    ;;
  *) printf 'ok\n' ;;
esac
CLIENT
chmod +x "$tmp_dir/custodia-client"
export PATH="$tmp_dir:$PATH"
export CUSTODIA_BASH_SDK_TEST_LOG="$tmp_dir/client.log"

# shellcheck source=/dev/null
source "$root_dir/clients/bash/custodia.bash"

if custodia_config_check 2>/dev/null; then
  printf 'expected missing config failure\n' >&2
  exit 1
fi

config="$tmp_dir/client.json"
printf '{}\n' > "$config"
custodia_use_config "$config"
custodia_config_check >/dev/null
custodia_doctor --online >/dev/null
printf 'value\n' > "$tmp_dir/value.txt"
custodia_secret_put_file smoke-demo "$tmp_dir/value.txt" >/dev/null
custodia_secret_get_file smoke-demo "$tmp_dir/readback.txt"
custodia_secret_update_file smoke-demo "$tmp_dir/value.txt" >/dev/null
custodia_secret_share smoke-demo client_bob "client_bob=$tmp_dir/bob.pub.json" >/dev/null
custodia_secret_revoke smoke-demo client_bob >/dev/null
custodia_secret_delete smoke-demo >/dev/null
custodia_secret_delete_cascade smoke-demo >/dev/null

grep -q -- 'config check --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'doctor --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret put --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret get --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret share --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret update --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret access revoke --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret delete --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- '--key smoke-demo' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- '--namespace default' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- '--cascade' "$CUSTODIA_BASH_SDK_TEST_LOG"
