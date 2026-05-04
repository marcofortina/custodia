# Custodia Node.js client

This package is the initial Node.js / TypeScript-facing transport client for Custodia.

The client only sends and receives already-opaque REST payloads over mTLS. It does not encrypt, decrypt, resolve recipient public keys, open envelopes, log secret material or implement the high-level crypto client.

## Example

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

## Checks

```bash
npm test --prefix clients/node
```
