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

import { createEncryptedSecret } from "../examples/high_level_crypto.mjs";
import { createOpaqueSecret } from "../examples/keyspace_transport.mjs";
import { CustodiaClient, CryptoOptions, PermissionRead } from "../src/index.js";

const NODE_ROOT = new URL("../", import.meta.url);
const REPO_ROOT = new URL("../../../", import.meta.url);

test("package metadata documents npm identity and runtime support", async () => {
  const metadata = JSON.parse(await readFile(new URL("package.json", NODE_ROOT), "utf8"));

  assert.equal(metadata.name, "@custodia/client");
  assert.equal(metadata.private, true);
  assert.equal(metadata.license, "AGPL-3.0-only");
  assert.deepEqual(metadata.engines, { node: ">=20" });
  assert.equal(metadata.main, "src/index.js");
  assert.equal(metadata.types, "src/index.d.ts");
  assert.deepEqual(metadata.exports["."], {
    types: "./src/index.d.ts",
    import: "./src/index.js",
  });
  assert.equal(metadata.repository.directory, "clients/node");
  assert.ok(metadata.keywords.includes("client-side-encryption"));
});

test("examples compile and exercise supported public APIs", async () => {
  for (const name of ["keyspace_transport.mjs", "high_level_crypto.mjs"]) {
    const source = await readFile(new URL(`examples/${name}`, NODE_ROOT), "utf8");
    // Dynamic import above already verifies ESM parse/compile; this keeps the
    // test explicit about example coverage.
    assert.match(source, /CustodiaClient/);
  }

  const calls = [];
  const transport = async (request) => {
    calls.push(request);
    return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ ok: true }) };
  };
  const chunks = [Buffer.alloc(32, 0x51), Buffer.alloc(12, 0x61), Buffer.alloc(32, 0x41)];

  assert.deepEqual(await createOpaqueSecret({ transport }), { ok: true });
  assert.deepEqual(await createEncryptedSecret({ transport, randomSource: (length) => chunks.shift() ?? Buffer.alloc(length, 0x42) }), { ok: true });

  assert.equal(calls.length, 2);
  const opaquePayload = JSON.parse(calls[0].body);
  const encryptedPayload = JSON.parse(calls[1].body);
  assert.equal(opaquePayload.namespace, "db01");
  assert.equal(opaquePayload.key, "user:sys");
  assert.equal(opaquePayload.permissions, PermissionRead);
  assert.equal(encryptedPayload.namespace, "db01");
  assert.equal(encryptedPayload.key, "user:sys");
  assert.equal(encryptedPayload.envelopes.length, 2);
  assert.equal(encryptedPayload.envelopes[0].client_id, "client_alice");
  assert.equal(encryptedPayload.envelopes[1].client_id, "client_bob");
  assert.ok(!Object.hasOwn(opaquePayload, "plaintext"));
  assert.ok(!Object.hasOwn(encryptedPayload, "plaintext"));
});

test("public import surface remains available", () => {
  assert.equal(typeof CustodiaClient, "function");
  assert.equal(typeof CryptoOptions, "function");
});

test("registry publishing remains documentation gated", async () => {
  const readiness = await readFile(join(REPO_ROOT.pathname, "docs", "SDK_PUBLISHING_READINESS.md"), "utf8");
  const readme = await readFile(new URL("README.md", NODE_ROOT), "utf8");

  assert.match(readiness, /#42/);
  assert.match(readme, /No registry publishing is performed/);
});
