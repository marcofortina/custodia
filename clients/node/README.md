# Custodia Node.js client

This package contains the Node.js / TypeScript-facing Custodia client.

It includes:

- a raw transport client for opaque REST payloads over mTLS;
- a high-level crypto client that encrypts/decrypts locally and sends only ciphertext, metadata and envelopes to the server.

Runtime code uses Node built-ins only and does not add npm dependencies.

## Package readiness

- Intended npm package name: `@custodia/client`.
- Required registry owner/control before publish: npm `@custodia` scope controlled by the Custodia maintainer account or approved organization.
- Runtime target: Node.js `>=20`; CI currently validates with Node.js 24.
- Module format: ESM (`type: module`) with TypeScript declarations from `src/index.d.ts`.
- Package exports: `.` resolves to `src/index.js` and `src/index.d.ts`.
- No registry publishing is performed from this package. Keep `private: true` until the SDK publishing readiness checklist is explicitly completed and approved as part of a release.

## Transport example

The repository ships a checked example at `examples/keyspace_transport.mjs`.

```js
import { createOpaqueSecret } from "./examples/keyspace_transport.mjs";

await createOpaqueSecret();
```

The transport example sends only opaque ciphertext and envelope strings. It does not perform local encryption; use the high-level crypto example when the Node SDK should create ciphertext and recipient envelopes locally.

## Crypto example

The repository ships a checked example at `examples/high_level_crypto.mjs`.

```js
import { createEncryptedSecret } from "./examples/high_level_crypto.mjs";

await createEncryptedSecret();
```

The crypto example encrypts plaintext locally and sends only ciphertext, crypto metadata and recipient envelopes to the server. Private keys stay in application-controlled local storage.

## Checks

```bash
npm test --prefix clients/node
node --check clients/node/src/index.js
node --check clients/node/src/crypto.js
node --check clients/node/examples/keyspace_transport.mjs
node --check clients/node/examples/high_level_crypto.mjs
```
