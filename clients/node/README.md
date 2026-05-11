# Custodia Node.js client

This package contains the Node.js / TypeScript-facing Custodia client.

It includes:

- a raw transport client for opaque REST payloads over mTLS;
- a high-level crypto client that encrypts/decrypts locally and sends only ciphertext, metadata and envelopes to the server.

Runtime code uses Node built-ins only and does not add npm dependencies.

## Transport example

```js
import { CustodiaClient, PermissionAll } from "@custodia/client";

const client = new CustodiaClient({
  serverUrl: "https://vault.example:8443",
  certFile: "client.crt",
  keyFile: "client.key",
  caFile: "ca.crt",
});

const ref = await client.createSecretPayload({
  namespace: "db01",
  key: "user:sys",
  ciphertext: "base64-ciphertext",
  envelopes: [{ client_id: "client_alice", envelope: "base64-envelope" }],
  permissions: PermissionAll,
  crypto_metadata: { version: "custodia.client-crypto.v1" },
});

const secret = await client.getSecretPayloadByKey("db01", "user:sys");
console.log(ref.version_id, secret.key);
```

## Crypto example

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

const localKey = new X25519PrivateKeyHandle({ clientID: "client_alice", privateKey: alicePrivateKeyBytes });
const crypto = client.withCrypto(new CryptoOptions({
  privateKeyProvider: new StaticPrivateKeyProvider(localKey),
  publicKeyResolver: new StaticPublicKeyResolver({
    client_alice: deriveX25519RecipientPublicKey("client_alice", alicePrivateKeyBytes),
    client_bob: bobRecipientPublicKey,
  }),
}));

await crypto.createEncryptedSecretByKey({
  namespace: "db01",
  key: "user:sys",
  plaintext: Buffer.from("secret"),
  recipients: ["client_bob"],
});

const secret = await crypto.readDecryptedSecretByKey("db01", "user:sys");
console.log(secret.plaintext.toString("utf8"));
```

## Checks

```bash
npm test --prefix clients/node
node --check clients/node/src/index.js
node --check clients/node/src/crypto.js
```
