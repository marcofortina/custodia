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

: "${VERSION:=dev}"
: "${COMMIT:=unknown}"
: "${DATE:=unknown}"
: "${OUT_DIR:=build/man/man1}"

template_dir="docs/man"

sed_escape() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

version_escaped="$(sed_escape "$VERSION")"
commit_escaped="$(sed_escape "$COMMIT")"
date_escaped="$(sed_escape "$DATE")"

if [ ! -d "$template_dir" ]; then
  echo "manpage template directory not found: $template_dir" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

found=0
for template in "$template_dir"/*.1.in; do
  [ -e "$template" ] || continue
  found=1
  name="$(basename "$template" .in)"
  output="$OUT_DIR/$name"
  sed \
    -e "s|@VERSION@|$version_escaped|g" \
    -e "s|@COMMIT@|$commit_escaped|g" \
    -e "s|@DATE@|$date_escaped|g" \
    "$template" > "$output"
  if grep -q '@VERSION@\|@COMMIT@\|@DATE@' "$output"; then
    echo "unexpanded build metadata token in $output" >&2
    exit 1
  fi
done

if [ "$found" -eq 0 ]; then
  echo "no manpage templates found in $template_dir" >&2
  exit 1
fi
