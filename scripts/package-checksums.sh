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
: "${COMMIT:=$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)}"
: "${DATE:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

if [ ! -d "$PACKAGE_DIR" ]; then
  echo "package-checksums: package directory not found: $PACKAGE_DIR" >&2
  echo "package-checksums: run make package-deb, make package-rpm or make package-linux first" >&2
  exit 2
fi

mapfile -t artifacts < <(find "$PACKAGE_DIR" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | sort)
if [ "${#artifacts[@]}" -eq 0 ]; then
  echo "package-checksums: no .deb or .rpm artifacts found in $PACKAGE_DIR" >&2
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
