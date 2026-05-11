/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  CustodiaClient,
  CustodiaHttpError,
  PermissionAll,
  PermissionRead,
} from "../src/index.js";

function clientWithTransport(handler) {
  const calls = [];
  const client = new CustodiaClient({
    serverUrl: "https://vault.example:8443/api/",
    certFile: "client.crt",
    keyFile: "client.key",
    caFile: "ca.crt",
    transport: async (request) => {
      calls.push(request);
      return handler(request);
    },
  });
  return { client, calls };
}

test("sends opaque create secret payloads without interpreting crypto fields", async () => {
  const { client, calls } = clientWithTransport(async () => ({
    status: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secret_id: "secret-1", version_id: "version-1" }),
  }));

  const result = await client.createSecretPayload({
    key: "db_password",
    ciphertext: "base64-ciphertext",
    envelopes: [{ client_id: "client_alice", envelope: "base64-envelope" }],
    permissions: PermissionAll,
    crypto_metadata: { version: "custodia.client-crypto.v1" },
  });

  assert.deepEqual(result, { secret_id: "secret-1", version_id: "version-1" });
  assert.equal(calls[0].method, "POST");
  assert.equal(new URL(calls[0].url).pathname, "/v1/secrets");
  assert.deepEqual(JSON.parse(calls[0].body), {
    key: "db_password",
    ciphertext: "base64-ciphertext",
    envelopes: [{ client_id: "client_alice", envelope: "base64-envelope" }],
    permissions: PermissionAll,
    crypto_metadata: { version: "custodia.client-crypto.v1" },
  });
});

test("builds metadata list filters and escaped paths", async () => {
  const { client, calls } = clientWithTransport(async () => ({ status: 200, headers: {}, body: "{}" }));

  await client.listClientInfos({ limit: 25, active: true });
  await client.getSecretPayloadByKey("db01", "user:sys");
  await client.listAuditEventMetadata({
    limit: 10,
    outcome: "success",
    action: "secret.read",
    actor_client_id: "client_alice",
    resource_type: "secret",
    resource_id: "secret-1",
  });

  assert.equal(new URL(calls[0].url).pathname, "/v1/clients");
  assert.equal(new URL(calls[0].url).search, "?limit=25&active=true");
  assert.equal(new URL(calls[1].url).pathname, "/v1/secrets/by-key");
  assert.equal(new URL(calls[1].url).search, "?namespace=db01&key=user%3Asys");
  assert.equal(new URL(calls[2].url).pathname, "/v1/audit-events");
  assert.equal(
    new URL(calls[2].url).search,
    "?limit=10&outcome=success&action=secret.read&actor_client_id=client_alice&resource_type=secret&resource_id=secret-1",
  );
});

test("covers operational endpoints and export metadata", async () => {
  const { client, calls } = clientWithTransport(async (request) => {
    if (new URL(request.url).pathname === "/v1/audit-events/export") {
      return {
        status: 200,
        headers: {
          "x-custodia-audit-export-sha256": "abc123",
          "x-custodia-audit-export-events": "2",
        },
        body: '{"event":1}\n',
      };
    }
    return { status: 200, headers: {}, body: "{}" };
  });

  await client.statusInfo();
  await client.versionInfo();
  await client.diagnosticsInfo();
  await client.revocationStatusInfo();
  await client.revocationSerialStatusInfo("01AB");
  const artifact = await client.exportAuditEventArtifact({ limit: 2 });

  assert.deepEqual(
    calls.map((call) => new URL(call.url).pathname),
    [
      "/v1/status",
      "/v1/version",
      "/v1/diagnostics",
      "/v1/revocation/status",
      "/v1/revocation/serial",
      "/v1/audit-events/export",
    ],
  );
  assert.equal(new URL(calls[4].url).search, "?serial_hex=01AB");
  assert.deepEqual(artifact, { body: '{"event":1}\n', sha256: "abc123", eventCount: "2" });
});

test("covers share, grant activation, revoke and new-version transport paths", async () => {
  const { client, calls } = clientWithTransport(async () => ({ status: 200, headers: {}, body: "{}" }));

  await client.shareSecretPayloadByKey("db01", "user:sys", {
    version_id: "version-1",
    target_client_id: "client_bob",
    envelope: "base64-envelope",
    permissions: PermissionRead,
  });
  await client.createAccessGrant("secret-1", { target_client_id: "client_bob", permissions: PermissionRead });
  await client.activateAccessGrantPayload("secret-1", "client_bob", { envelope: "base64-envelope" });
  await client.revokeAccessByKey("db01", "user:sys", "client_bob");
  await client.createSecretVersionPayloadByKey("db01", "user:sys", {
    ciphertext: "base64-ciphertext-v2",
    envelopes: [{ client_id: "client_alice", envelope: "base64-envelope-v2" }],
  });

  assert.deepEqual(
    calls.map((call) => `${call.method} ${new URL(call.url).pathname}`),
    [
      "POST /v1/secrets/by-key/share",
      "POST /v1/secrets/secret-1/access-requests",
      "POST /v1/secrets/secret-1/access-requests/client_bob/activate",
      "DELETE /v1/secrets/by-key/access/client_bob",
      "POST /v1/secrets/by-key/versions",
    ],
  );
});

test("covers namespace key transport paths", async () => {
  const { client, calls } = clientWithTransport(async () => ({ status: 200, headers: {}, body: "{}" }));

  await client.getSecretPayloadByKey("db01", "user:sys");
  await client.listSecretVersionMetadataByKey("db01", "user:sys", 10);
  await client.listSecretAccessMetadataByKey("db01", "user:sys", 10);
  await client.shareSecretPayloadByKey("db01", "user:sys", {
    version_id: "version-1",
    target_client_id: "client_bob",
    envelope: "base64-envelope",
  });
  await client.revokeAccessByKey("db01", "user:sys", "client_bob");
  await client.createSecretVersionPayloadByKey("db01", "user:sys", {
    ciphertext: "base64-ciphertext-v2",
    envelopes: [{ client_id: "client_alice", envelope: "base64-envelope-v2" }],
  });
  await client.deleteSecretPayloadByKey("db01", "user:sys", { cascade: true });

  assert.deepEqual(
    calls.map((call) => `${call.method} ${new URL(call.url).pathname}${new URL(call.url).search}`),
    [
      "GET /v1/secrets/by-key?namespace=db01&key=user%3Asys",
      "GET /v1/secrets/by-key/versions?namespace=db01&key=user%3Asys&limit=10",
      "GET /v1/secrets/by-key/access?namespace=db01&key=user%3Asys&limit=10",
      "POST /v1/secrets/by-key/share?namespace=db01&key=user%3Asys",
      "DELETE /v1/secrets/by-key/access/client_bob?namespace=db01&key=user%3Asys",
      "POST /v1/secrets/by-key/versions?namespace=db01&key=user%3Asys",
      "DELETE /v1/secrets/by-key?namespace=db01&key=user%3Asys&cascade=true",
    ],
  );
});

test("validates bounded filters before sending requests", async () => {
  const { client, calls } = clientWithTransport(async () => ({ status: 200, headers: {}, body: "{}" }));

  assert.throws(() => client.listSecretMetadata(0), /limit must be between 1 and 500/);
  assert.throws(() => client.listAuditEventMetadata({ outcome: "ok" }), /outcome must be success/);
  assert.throws(() => client.listAccessGrantMetadata({ status: "done" }), /status filter is invalid/);
  assert.throws(() => client.revocationSerialStatusInfo("   "), /serialHex is required/);
  assert.equal(calls.length, 0);
});

test("raises typed HTTP errors without exposing request payloads in the message", async () => {
  const { client } = clientWithTransport(async () => ({
    status: 403,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ error: "forbidden" }),
  }));

  await assert.rejects(
    () => client.createSecretPayload({
      key: "secret",
      ciphertext: "sensitive-ciphertext",
      envelopes: [{ client_id: "client_alice", envelope: "sensitive-envelope" }],
    }),
    (error) => {
      assert.ok(error instanceof CustodiaHttpError);
      assert.equal(error.status, 403);
      assert.match(error.message, /HTTP 403/);
      assert.doesNotMatch(error.message, /sensitive-ciphertext|sensitive-envelope/);
      return true;
    },
  );
});
