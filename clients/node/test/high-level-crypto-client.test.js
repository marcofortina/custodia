/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CryptoCustodiaClient,
  CryptoOptions,
  CustodiaClient,
  StaticPrivateKeyProvider,
  StaticPublicKeyResolver,
  X25519PrivateKeyHandle,
  deriveX25519RecipientPublicKey,
} from "../src/index.js";

const ALICE_PRIVATE = Buffer.from("11111111111111111111111111111111", "utf8");
const BOB_PRIVATE = Buffer.from("22222222222222222222222222222222", "utf8");
const SECRET_ID = "550e8400-e29b-41d4-a716-446655440000";
const VERSION_ID = "660e8400-e29b-41d4-a716-446655440000";

test("creates encrypted secrets and decrypts returned payloads", async () => {
  const created = [];
  const transport = {
    async createSecretPayload(payload) {
      created.push(payload);
      return { secret_id: SECRET_ID, version_id: VERSION_ID };
    },
    async getSecretPayload(secretID) {
      assert.equal(secretID, SECRET_ID);
      const payload = created[0];
      return {
        secret_id: SECRET_ID,
        version_id: VERSION_ID,
        ciphertext: payload.ciphertext,
        crypto_metadata: payload.crypto_metadata,
        envelope: payload.envelopes.find((envelope) => envelope.client_id === "client_alice").envelope,
        permissions: payload.permissions,
      };
    },
  };

  const crypto = new CryptoCustodiaClient(transport, cryptoOptions([Buffer.alloc(32, 0x51), Buffer.alloc(12, 0x61), Buffer.alloc(32, 0x41)]));
  assert.deepEqual(await crypto.createEncryptedSecret({ name: "database-password", plaintext: Buffer.from("secret"), recipients: ["client_bob"] }), {
    secret_id: SECRET_ID,
    version_id: VERSION_ID,
  });

  assert.equal(created[0].envelopes.length, 2);
  assert.equal(created[0].envelopes[0].client_id, "client_alice");
  assert.equal(created[0].envelopes[1].client_id, "client_bob");
  assert.equal(created[0].crypto_metadata.aad.secret_name, "database-password");

  const decrypted = await crypto.readDecryptedSecret(SECRET_ID);
  assert.equal(decrypted.secretID, SECRET_ID);
  assert.equal(decrypted.versionID, VERSION_ID);
  assert.equal(decrypted.plaintext.toString("utf8"), "secret");
});

test("shares encrypted secrets by rewrapping the existing DEK", async () => {
  const created = [];
  const shared = [];
  const transport = {
    async createSecretPayload(payload) {
      created.push(payload);
      return { secret_id: SECRET_ID, version_id: VERSION_ID };
    },
    async getSecretPayload() {
      const payload = created[0];
      return {
        secret_id: SECRET_ID,
        version_id: VERSION_ID,
        ciphertext: payload.ciphertext,
        crypto_metadata: payload.crypto_metadata,
        envelope: payload.envelopes[0].envelope,
        permissions: payload.permissions,
      };
    },
    async shareSecretPayload(secretID, payload) {
      shared.push({ secretID, payload });
      return { status: "shared" };
    },
  };

  const crypto = new CryptoCustodiaClient(
    transport,
    cryptoOptions([Buffer.alloc(32, 0x51), Buffer.alloc(12, 0x61), Buffer.alloc(32, 0x41), Buffer.alloc(32, 0x44)]),
  );
  await crypto.createEncryptedSecret({ name: "database-password", plaintext: Buffer.from("secret") });
  assert.deepEqual(await crypto.shareEncryptedSecret({ secretID: SECRET_ID, targetClientID: "client_bob" }), { status: "shared" });

  assert.equal(shared.length, 1);
  assert.equal(shared[0].secretID, SECRET_ID);
  assert.equal(shared[0].payload.version_id, VERSION_ID);
  assert.equal(shared[0].payload.target_client_id, "client_bob");
  assert.equal(shared[0].payload.permissions, 4);
  assert.ok(shared[0].payload.envelope);
});

test("creates encrypted secret versions with secret-id AAD binding", async () => {
  const versions = [];
  const transport = {
    async createSecretVersionPayload(secretID, payload) {
      versions.push({ secretID, payload });
      return { secret_id: secretID, version_id: VERSION_ID };
    },
  };
  const crypto = new CryptoCustodiaClient(transport, cryptoOptions([Buffer.alloc(32, 0x53), Buffer.alloc(12, 0x63), Buffer.alloc(32, 0x43)]));

  await crypto.createEncryptedSecretVersion({ secretID: SECRET_ID, plaintext: Buffer.from("rotated") });

  assert.equal(versions[0].secretID, SECRET_ID);
  assert.equal(versions[0].payload.crypto_metadata.aad.secret_id, SECRET_ID);
  assert.equal(versions[0].payload.envelopes[0].client_id, "client_alice");
});

test("exposes withCrypto from the transport client", () => {
  const client = new CustodiaClient({
    serverUrl: "https://vault.example",
    certFile: "client.crt",
    keyFile: "client.key",
    caFile: "ca.crt",
    transport: async () => ({ status: 200, headers: {}, body: "{}" }),
  });

  assert.ok(client.withCrypto(cryptoOptions()).createEncryptedSecret);
});

function cryptoOptions(chunks = []) {
  const publicKeys = {
    client_alice: deriveX25519RecipientPublicKey("client_alice", ALICE_PRIVATE),
    client_bob: deriveX25519RecipientPublicKey("client_bob", BOB_PRIVATE),
  };
  return new CryptoOptions({
    publicKeyResolver: new StaticPublicKeyResolver(publicKeys),
    privateKeyProvider: new StaticPrivateKeyProvider(new X25519PrivateKeyHandle({ clientID: "client_alice", privateKey: ALICE_PRIVATE })),
    randomSource: (length) => chunks.shift() ?? Buffer.alloc(length, 0x42),
  });
}
