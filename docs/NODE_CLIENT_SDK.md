# Custodia Node.js / TypeScript client

`clients/node` is the repository Node.js / TypeScript-facing client for Custodia. It includes both the raw transport client and a high-level client-side crypto wrapper.

The runtime code is dependency-free JavaScript using Node built-ins. The package remains `private` until a real public package name and release process are chosen.

## Security boundary

The Node client follows the same boundary as Go and Python:

- the transport client only sends and receives opaque REST payloads over mTLS;
- the crypto client encrypts/decrypts locally;
- plaintext, DEKs, private keys and passphrases are never sent to the Custodia server;
- recipient public keys are resolved by the application through `PublicKeyResolver`, not through the vault;
- private keys are supplied by a local `PrivateKeyProvider`.

## Install from the monorepo

```bash
npm install ./clients/node
```

## Raw transport example

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

## High-level crypto example

```js
import {
  CryptoOptions,
  CustodiaClient,
  StaticPrivateKeyProvider,
  StaticPublicKeyResolver,
  X25519PrivateKeyHandle,
  deriveX25519RecipientPublicKey,
} from "@custodia/client";

const client = new CustodiaClient({
  serverUrl: "https://vault.example:8443",
  certFile: "client.crt",
  keyFile: "client.key",
  caFile: "ca.crt",
});

const aliceKey = new X25519PrivateKeyHandle({
  clientID: "client_alice",
  privateKey: alicePrivateKeyBytes,
});

const crypto = client.withCrypto(new CryptoOptions({
  privateKeyProvider: new StaticPrivateKeyProvider(aliceKey),
  publicKeyResolver: new StaticPublicKeyResolver({
    client_alice: deriveX25519RecipientPublicKey("client_alice", alicePrivateKeyBytes),
    client_bob: bobRecipientPublicKey,
  }),
}));

await crypto.createEncryptedSecret({
  name: "database-password",
  plaintext: Buffer.from("secret"),
  recipients: ["client_bob"],
});

const decrypted = await crypto.readDecryptedSecret("550e8400-e29b-41d4-a716-446655440000");
console.log(decrypted.plaintext.toString("utf8"));
```

## Public transport methods

The transport surface mirrors the Go/Python public transport helpers:

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

## Public crypto methods

The high-level crypto surface exposes:

- `client.withCrypto(options)`;
- `createEncryptedSecret({ name, plaintext, recipients, permissions, expiresAt })`;
- `readDecryptedSecret(secretID)`;
- `shareEncryptedSecret({ secretID, targetClientID, permissions, expiresAt })`;
- `createEncryptedSecretVersion({ secretID, plaintext, recipients, permissions, expiresAt })`.

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
npm test --prefix clients/node
```
