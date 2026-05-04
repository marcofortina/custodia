#!/usr/bin/env sh
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -eu

out_dir=${1:-./.dev-certs}
mkdir -p "$out_dir"

openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout "$out_dir/ca.key" -out "$out_dir/ca.crt" \
  -subj "/CN=Custodia Dev CA"

openssl req -newkey rsa:2048 -nodes \
  -keyout "$out_dir/server.key" -out "$out_dir/server.csr" \
  -subj "/CN=localhost"
openssl x509 -req -in "$out_dir/server.csr" -CA "$out_dir/ca.crt" -CAkey "$out_dir/ca.key" -CAcreateserial \
  -out "$out_dir/server.crt" -days 365 -sha256

for client in client_alice client_bob admin; do
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$out_dir/${client}.key" -out "$out_dir/${client}.csr" \
    -subj "/CN=${client}"
  openssl x509 -req -in "$out_dir/${client}.csr" -CA "$out_dir/ca.crt" -CAkey "$out_dir/ca.key" -CAcreateserial \
    -out "$out_dir/${client}.crt" -days 365 -sha256
 done

cp "$out_dir/ca.crt" "$out_dir/custodia-ca.pem"
cp "$out_dir/ca.key" "$out_dir/custodia-ca-key.pem"

echo "Development certificates written to $out_dir"
