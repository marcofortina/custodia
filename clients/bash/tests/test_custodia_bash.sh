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
custodia_secret_put_file smoke-demo "$tmp_dir/value.txt" "$tmp_dir/create.json"
custodia_secret_get_file secret-1 "$tmp_dir/readback.txt"
custodia_secret_share secret-1 client_bob "client_bob=$tmp_dir/bob.pub.json" >/dev/null
custodia_secret_delete secret-1 >/dev/null

grep -q -- 'config check --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'doctor --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret put --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret get --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret share --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
grep -q -- 'secret delete --config' "$CUSTODIA_BASH_SDK_TEST_LOG"
