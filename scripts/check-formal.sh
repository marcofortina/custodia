#!/usr/bin/env bash
set -euo pipefail

TLC_CMD=${TLC:-tlc}

if ! command -v "${TLC_CMD}" >/dev/null 2>&1; then
  echo "TLC command '${TLC_CMD}' not found. Install TLA+ tools or set TLC=/path/to/tlc." >&2
  exit 2
fi

"${TLC_CMD}" -config formal/CustodiaAccess.cfg formal/CustodiaAccess.tla
