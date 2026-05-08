#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${1:-$root_dir/build/sdk}"

cd "$root_dir"
rm -rf "$out_dir"
mkdir -p \
  "$out_dir/clients" \
  "$out_dir/clients/go/pkg" \
  "$out_dir/clients/go/internal" \
  "$out_dir/testdata"

cp -R clients/python clients/node clients/java clients/cpp clients/rust "$out_dir/clients/"
install -m 0644 go.mod "$out_dir/clients/go/go.mod"
cp -R pkg/client "$out_dir/clients/go/pkg/"
cp -R internal/clientcrypto "$out_dir/clients/go/internal/"
cp -R testdata/client-crypto "$out_dir/testdata/"

find "$out_dir" -type d \( -name __pycache__ -o -name .pytest_cache -o -name node_modules -o -name target \) -prune -exec rm -rf {} +
find "$out_dir" -type f \( -name '*.pyc' -o -name '*.class' \) -delete
