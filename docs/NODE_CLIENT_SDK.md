# Custodia Node.js / TypeScript transport client

`clients/node` is the repository Node.js / TypeScript-facing transport client for Custodia. The initial Phase 5D scope is intentionally transport-only.

## Current scope

The Node client speaks the Custodia `/v1/*` REST API over mTLS and sends/receives already-opaque payloads:

- ciphertext strings are caller-provided;
- recipient envelopes are caller-provided;
- `crypto_metadata` is caller-provided;
- plaintext, DEKs, private keys and passphrases never enter the transport client.

The Node client does not implement the high-level crypto wrapper yet. It must not resolve recipient public keys through Custodia server or treat the vault as a key directory.

## Install from the monorepo

```bash
npm install ./clients/node
```

The package is marked private until a real public package name and release process are chosen.

## Transport example

```js
import { CustodiaClient, PermissionAll } from "@custodia/client";

const client = new CustodiaClient({
  serverUrl: "https://vault.example:8443",
  certFile: "client.crt",
  keyFile: "client.key",
  caFile: "ca.crt",
});

const created = await client.createSecretPayload({
  name: "database-password",
  ciphertext: "base64-opaque-ciphertext",
  envelopes: [
    { client_id: "client_alice", envelope: "base64-opaque-envelope" },
  ],
  permissions: PermissionAll,
  crypto_metadata: { version: "custodia.client-crypto.v1" },
});

console.log(created.secret_id, created.version_id);
```

## Public methods

The initial transport surface mirrors the Go/Python public transport helpers:

- `currentClientInfo()`;
- `listClientInfos({ limit, active })`;
- `getClientInfo(clientID)`;
- `createClientInfo(payload)`;
- `revokeClientInfo(payload)`;
- `createSecretPayload(payload)`;
- `getSecretPayload(secretID)`;
- `listSecretMetadata(limit)`;
- `listSecretVersionMetadata(secretID, limit)`;
- `listSecretAccessMetadata(secretID, limit)`;
- `shareSecretPayload(secretID, payload)`;
- `createAccessGrant(secretID, payload)`;
- `activateAccessGrantPayload(secretID, targetClientID, payload)`;
- `revokeAccess(secretID, clientID)`;
- `createSecretVersionPayload(secretID, payload)`;
- `listAccessGrantMetadata(filters)`;
- `statusInfo()`;
- `versionInfo()`;
- `diagnosticsInfo()`;
- `revocationStatusInfo()`;
- `revocationSerialStatusInfo(serialHex)`;
- `listAuditEventMetadata(filters)`;
- `exportAuditEventArtifact(filters)`.

HTTP errors are raised as `CustodiaHttpError` with status, response headers and response body. Error messages do not include request payloads.

## TypeScript surface

The package ships `src/index.d.ts` with the public transport request/response types and payload contracts. Runtime code remains dependency-free JavaScript using Node built-ins.

## Verification

Run:

```bash
make test-node-client
node --check clients/node/src/index.js
npm test --prefix clients/node
```
