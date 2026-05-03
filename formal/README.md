# Custodia formal verification artifacts

This directory contains lightweight formal artifacts for the server-side authorization model.

Current files:

- `CustodiaAccess.tla` — TLA+ model for client activation, read grants, client revocation and strong secret-version revocation.
- `CustodiaAccess.cfg` — bounded model-checking configuration.

The model intentionally excludes client-side cryptography. Custodia stores opaque ciphertext and recipient envelopes; plaintext, DEK unwrap, recipient key discovery and browser/client cryptographic behavior are out of the server model.

## Run with TLC

Install the TLA+ tools, then run:

```bash
make formal-check
```

or directly:

```bash
java tlc2.TLC -config formal/CustodiaAccess.cfg formal/CustodiaAccess.tla
```

If your TLC launcher is named `tlc`, set `TLC=tlc`.
