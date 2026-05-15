#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

: "${PACKAGE_DIR:=$root_dir/dist/packages}"
: "${MANIFEST_FILE:=$PACKAGE_DIR/artifacts-manifest.json}"
: "${CHECKSUM_FILE:=$PACKAGE_DIR/SHA256SUMS}"
: "${VERSION:=0.0.0-dev}"
: "${REVISION:=1}"
: "${PACKAGE_NAMES:=server client sdk}"
: "${COMMIT:=$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)}"
: "${DATE:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

if [ ! -d "$PACKAGE_DIR" ]; then
  echo "package-checksums: package directory not found: $PACKAGE_DIR" >&2
  echo "package-checksums: run make package-deb, make package-rpm or make package-linux first" >&2
  exit 2
fi

artifact_find_args() {
  local names
  # shellcheck disable=SC2206
  names=($PACKAGE_NAMES)
  if printf '%s\n' "${names[@]}" | grep -Fxq clients; then
    names+=(client sdk)
  fi

  local args=()
  local name
  for name in "${names[@]}"; do
    case "$name" in
      server|client|sdk)
        if [ "${#args[@]}" -gt 0 ]; then
          args+=(-o)
        fi
        args+=(-name "custodia-${name}_${VERSION}-${REVISION}_*.deb" -o -name "custodia-${name}-${VERSION}-${REVISION}.*.rpm")
        ;;
    esac
  done
  [ "${#args[@]}" -gt 0 ] || { echo "package-checksums: no supported PACKAGE_NAMES in: $PACKAGE_NAMES" >&2; exit 2; }
  printf '%s\0' "${args[@]}"
}

readarray -d '' find_args < <(artifact_find_args)
mapfile -t artifacts < <(find "$PACKAGE_DIR" -maxdepth 1 -type f \( "${find_args[@]}" \) | sort)
if [ "${#artifacts[@]}" -eq 0 ]; then
  echo "package-checksums: no release artifacts for VERSION=$VERSION REVISION=$REVISION PACKAGE_NAMES=$PACKAGE_NAMES in $PACKAGE_DIR" >&2
  exit 2
fi

: > "$CHECKSUM_FILE"
for artifact in "${artifacts[@]}"; do
  (
    cd "$PACKAGE_DIR"
    sha256sum "$(basename "$artifact")"
  ) >> "$CHECKSUM_FILE"
done

python3 - "$MANIFEST_FILE" "$PACKAGE_DIR" "$VERSION" "$REVISION" "$COMMIT" "$DATE" "${artifacts[@]}" <<'PY'
import hashlib
import json
import os
import sys

manifest_file, package_dir, version, revision, commit, date, *artifacts = sys.argv[1:]
entries = []
for path in artifacts:
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    name = os.path.basename(path)
    if name.endswith(".deb"):
        package_type = "deb"
    elif name.endswith(".rpm"):
        package_type = "rpm"
    else:
        package_type = "unknown"
    entries.append({
        "name": name,
        "type": package_type,
        "size_bytes": os.path.getsize(path),
        "sha256": digest,
    })
manifest = {
    "schema": "custodia.release-artifacts.v1",
    "version": version,
    "revision": revision,
    "commit": commit,
    "generated_at": date,
    "artifacts": entries,
}
os.makedirs(os.path.dirname(manifest_file), exist_ok=True)
with open(manifest_file, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

printf '%s\n' "package-checksums: wrote $CHECKSUM_FILE" "package-checksums: wrote $MANIFEST_FILE" >&2
