/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

import {
  CanonicalAADInputs,
  buildCanonicalAAD,
  canonicalAADSHA256,
  decodeEnvelope,
  deriveX25519PublicKey,
  openContentAES256GCM,
  openHPKEV1Envelope,
  parseMetadata,
  sealContentAES256GCM,
  sealHPKEV1Envelope,
} from "../src/crypto.js";

const VECTOR_DIR = new URL("../../../testdata/client-crypto/v1/", import.meta.url);

for (const name of [
  "create_secret_single_recipient.json",
  "create_secret_multi_recipient.json",
  "read_secret_authorized_recipient.json",
  "share_secret_add_recipient.json",
]) {
  test(`validates deterministic crypto vector ${name}`, async () => {
    const vector = await loadVector(name);
    const metadata = parseMetadata(vector.crypto_metadata);
    const aadInputs = CanonicalAADInputs.fromMapping(vector.aad_inputs);
    const aad = buildCanonicalAAD(metadata, aadInputs);
    assert.equal(aad.toString("utf8"), vector.canonical_aad);
    assert.equal(canonicalAADSHA256(aad), vector.canonical_aad_sha256);

    const dek = b64(vector.content_dek_b64);
    const nonce = b64(vector.content_nonce_b64);
    const plaintext = b64(vector.plaintext_b64);
    assert.equal(sealContentAES256GCM(dek, nonce, plaintext, aad).toString("base64"), vector.ciphertext);
    assert.deepEqual(openContentAES256GCM(dek, nonce, b64(vector.ciphertext), aad), plaintext);

    for (const recipient of vector.envelopes ?? [vector.envelope]) {
      const publicKey = b64(recipient.recipient_public_key_b64);
      assert.deepEqual(deriveX25519PublicKey(b64(recipient.recipient_private_key_b64)), publicKey);
      assert.equal(
        sealHPKEV1Envelope(publicKey, b64(recipient.sender_ephemeral_private_key_b64), dek, aad).toString("base64"),
        recipient.envelope,
      );
      assert.deepEqual(openHPKEV1Envelope(b64(recipient.recipient_private_key_b64), decodeEnvelope(recipient.envelope), aad), dek);
    }
  });
}

for (const name of ["tamper_ciphertext_fails.json", "aad_mismatch_fails.json"]) {
  test(`rejects ciphertext vector ${name}`, async () => {
    const vector = await loadVector(name);
    const metadata = parseMetadata(vector.crypto_metadata);
    const aad = buildCanonicalAAD(metadata, CanonicalAADInputs.fromMapping(vector.aad_inputs));
    const ciphertext = name === "tamper_ciphertext_fails.json" ? vector.tampered_ciphertext : vector.ciphertext;
    const effectiveAAD = name === "aad_mismatch_fails.json"
      ? buildCanonicalAAD(metadata, CanonicalAADInputs.fromMapping(vector.mismatch_aad_inputs))
      : aad;
    assert.throws(() => openContentAES256GCM(b64(vector.content_dek_b64), b64(vector.content_nonce_b64), b64(ciphertext), effectiveAAD));
  });
}

test("rejects wrong recipient vector", async () => {
  const vector = await loadVector("wrong_recipient_fails.json");
  const metadata = parseMetadata(vector.crypto_metadata);
  const aad = buildCanonicalAAD(metadata, CanonicalAADInputs.fromMapping(vector.aad_inputs));
  const recipient = vector.envelope;
  assert.throws(() => openHPKEV1Envelope(b64(recipient.wrong_recipient_private_key_b64), decodeEnvelope(recipient.envelope), aad));
});

async function loadVector(name) {
  const payload = await readFile(join(VECTOR_DIR.pathname, name), "utf8");
  return JSON.parse(payload);
}

function b64(value) {
  return Buffer.from(value, "base64");
}
