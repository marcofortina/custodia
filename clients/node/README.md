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
  name: "db_prod_password",
  ciphertext: "base64-ciphertext",
  envelopes: [{ client_id: "client_alice", envelope: "base64-envelope" }],
  permissions: PermissionAll,
  crypto_metadata: { version: "custodia.client-crypto.v1" },
});

console.log(ref.secret_id, ref.version_id);
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

await crypto.createEncryptedSecret({
  name: "db_prod_password",
  plaintext: Buffer.from("secret"),
  recipients: ["client_bob"],
});
```

## Checks

```bash
npm test --prefix clients/node
node --check clients/node/src/index.js
node --check clients/node/src/crypto.js
```
