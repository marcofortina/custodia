/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

import { CustodiaClient, PermissionRead } from "../src/index.js";

export function buildClient({ transport } = {}) {
  return new CustodiaClient({
    serverUrl: "https://vault.example:8443",
    certFile: "client_alice.crt",
    keyFile: "client_alice.key",
    caFile: "ca.crt",
    ...(transport ? { transport } : {}),
  });
}

export async function createOpaqueSecret({ transport } = {}) {
  const client = buildClient({ transport });
  return client.createSecretPayload({
    namespace: "db01",
    key: "user:sys",
    ciphertext: "base64-opaque-ciphertext",
    envelopes: [{ client_id: "client_alice", envelope: "base64-opaque-envelope" }],
    permissions: PermissionRead,
    crypto_metadata: { version: "custodia.client-crypto.v1" },
  });
}
