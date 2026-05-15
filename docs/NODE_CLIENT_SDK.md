# Custodia Node.js / TypeScript client

`clients/node` is the repository Node.js / TypeScript-facing client for Custodia. It includes both the raw transport client and a high-level client-side crypto wrapper.

The runtime code is dependency-free JavaScript using Node built-ins. The intended npm package coordinate is `@custodia/client`; npm `@custodia` scope ownership must be controlled by the Custodia maintainer account or approved organization before any publish. The package remains `private` and registry publishing remains blocked by `SDK_PUBLISHING_READINESS.md` until the 0.5.0 gates are complete.

## Security boundary

The Node client follows the same boundary as Go and Python:

- the transport client only sends and receives opaque REST payloads over mTLS;
- the crypto client encrypts/decrypts locally;
- plaintext, DEKs, private keys and passphrases are never sent to the Custodia server;
- recipient public keys are resolved by the application through `PublicKeyResolver`; Custodia public-key metadata can be used as a discovery source but not as a trust decision;
- private keys are supplied by a local `PrivateKeyProvider`.

## Package and runtime support

- Runtime target: Node.js `>=20`; CI validates the package with Node.js 24.
- Module format: ESM (`type: module`).
- Type declarations: `src/index.d.ts`.
- Package export: `.` resolves to `src/index.js` and `src/index.d.ts`.
- Publish gate: keep `private: true` until `SDK_PUBLISHING_READINESS.md` and #42 are complete.

## Install from the monorepo

```bash
npm install ./clients/node
```

## Raw transport example

The checked example lives in `clients/node/examples/keyspace_transport.mjs` and is covered by `npm test --prefix clients/node`. It uses the public `namespace/key` transport helpers and sends only opaque ciphertext/envelope strings.

```js
import { createOpaqueSecret } from "./examples/keyspace_transport.mjs";

await createOpaqueSecret();
```

## High-level crypto example

The checked example lives in `clients/node/examples/high_level_crypto.mjs` and is covered by `npm test --prefix clients/node`. It encrypts plaintext locally and sends only ciphertext, crypto metadata and recipient envelopes to the server.

```js
import { createEncryptedSecret } from "./examples/high_level_crypto.mjs";

await createEncryptedSecret();
```

## Public transport methods

The transport surface mirrors the Go/Python public transport helpers:

- `currentClientInfo()`;
- `listClientInfos({ limit, active })`;
- `getClientInfo(clientID)`;
- `createClientInfo(payload)`;
- `revokeClientInfo(payload)`;
- `createSecretPayload(payload)`;
- `getSecretPayloadByKey(namespace, key)`;
- `listSecretMetadata(limit)`;
- `listSecretVersionMetadataByKey(namespace, key, limit)`;
- `listSecretAccessMetadataByKey(namespace, key, limit)`;
- `shareSecretPayloadByKey(namespace, key, payload)`;
- `revokeAccessByKey(namespace, key, clientID)`;
- `createSecretVersionPayloadByKey(namespace, key, payload)`;
- `deleteSecretPayloadByKey(namespace, key, { cascade })`;
- `listAccessGrantMetadata({ namespace, key, status, client_id, limit })`;
- `statusInfo()`;
- `versionInfo()`;
- `diagnosticsInfo()`;
- `revocationStatusInfo()`;
- `revocationSerialStatusInfo(serialHex)`;
- `listAuditEventMetadata(filters)`;
- `exportAuditEventArtifact(filters)`.

HTTP errors are raised as `CustodiaHttpError` with status, response headers and response body. Error messages do not include request payloads.

## Public crypto methods

The high-level crypto surface exposes:

- `client.withCrypto(options)`;
- `createEncryptedSecretByKey({ namespace, key, plaintext, recipients, permissions, expiresAt })`;
- `readDecryptedSecretByKey(namespace, key)`;
- `shareEncryptedSecretByKey({ namespace, key, targetClientID, permissions, expiresAt })`;
- `createEncryptedSecretVersionByKey({ namespace, key, plaintext, recipients, permissions, expiresAt })`.

The shared primitives and contracts are exported for integration tests and resolver/provider implementations:

- `CanonicalAADInputs`;
- `CryptoMetadata`;
- `buildCanonicalAAD(...)`;
- `sealContentAES256GCM(...)` / `openContentAES256GCM(...)`;
- `sealHPKEV1Envelope(...)` / `openHPKEV1Envelope(...)`;
- `X25519PrivateKeyHandle`;
- `StaticPrivateKeyProvider`;
- `StaticPublicKeyResolver`;
- `deriveX25519RecipientPublicKey(...)`.

## TypeScript surface

The package ships `src/index.d.ts` with the public transport request/response types, crypto contracts and high-level client payload contracts.

## Verification

Run:

```bash
make test-node-client
node --check clients/node/src/index.js
node --check clients/node/src/crypto.js
node --check clients/node/examples/keyspace_transport.mjs
node --check clients/node/examples/high_level_crypto.mjs
npm test --prefix clients/node
```
