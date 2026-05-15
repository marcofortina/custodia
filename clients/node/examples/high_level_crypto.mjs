/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

import {
  CryptoOptions,
  CustodiaClient,
  StaticPrivateKeyProvider,
  StaticPublicKeyResolver,
  X25519PrivateKeyHandle,
  deriveX25519RecipientPublicKey,
} from "../src/index.js";

const ALICE_PRIVATE_KEY = Buffer.from("11111111111111111111111111111111", "utf8");
const BOB_PRIVATE_KEY_FOR_EXAMPLE_ONLY = Buffer.from("22222222222222222222222222222222", "utf8");

export function buildCryptoClient({ transport, randomSource } = {}) {
  const client = new CustodiaClient({
    serverUrl: "https://vault.example:8443",
    certFile: "client_alice.crt",
    keyFile: "client_alice.key",
    caFile: "ca.crt",
    ...(transport ? { transport } : {}),
  });
  return client.withCrypto(new CryptoOptions({
    publicKeyResolver: new StaticPublicKeyResolver({
      client_alice: deriveX25519RecipientPublicKey("client_alice", ALICE_PRIVATE_KEY),
      client_bob: deriveX25519RecipientPublicKey("client_bob", BOB_PRIVATE_KEY_FOR_EXAMPLE_ONLY),
    }),
    privateKeyProvider: new StaticPrivateKeyProvider(
      new X25519PrivateKeyHandle({ clientID: "client_alice", privateKey: ALICE_PRIVATE_KEY }),
    ),
    ...(randomSource ? { randomSource } : {}),
  }));
}

export async function createEncryptedSecret({ transport, randomSource } = {}) {
  const crypto = buildCryptoClient({ transport, randomSource });
  return crypto.createEncryptedSecretByKey({
    namespace: "db01",
    key: "user:sys",
    plaintext: Buffer.from("correct horse battery staple", "utf8"),
    recipients: ["client_bob"],
  });
}
