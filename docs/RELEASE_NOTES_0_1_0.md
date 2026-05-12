# Custodia 0.1.0 release notes

Custodia 0.1.0 is the first pre-release baseline for the privacy-first encrypted secret vault.

The server remains a metadata-only control plane: it authenticates clients, validates authorization, stores opaque ciphertext and recipient envelopes, and records audit metadata. Plaintext, DEKs, private keys and application key resolution stay client-side.

## Highlights

- Universal server build with runtime-selected store backend.
- Deployment matrix covering bare-metal source install, DEB/RPM install and Kubernetes image/chart install.
- Lite profile with SQLite support and the same server binary as Full.
- PostgreSQL-compatible schema and runtime selection for Full deployments.
- Kubernetes Helm path for `custodia-server` plus `custodia-signer`, with Full/Lite example values and fail-closed Lite PVC guardrails.
- mTLS client identity and admin metadata workflows.
- Web console for operational metadata, diagnostics, client enrollment tokens, client revocation, secret version/access inspection, future access-grant revocation, revocation status, CRL PEM downloads, CRL serial checks, audit views and audit JSONL downloads.
- Client-side crypto SDKs for Go, Python, Node.js, C++, Java and Rust.
- Encrypted `custodia-client` CLI workflows for put/get/share/update/revoke/delete.
- Keyspace addressing for normal user workflows with `namespace/key`.
- Hash-chained audit events, browser/API JSONL exports and export verification helpers.
- Package builds for server, client and SDK artifacts.
- Release guardrails for build metadata, package manifests, install smoke, structured runtime YAML, Helm render safety, keyspace regressions and client crypto documentation.

## Namespace/key workflow

Normal public workflows use a caller-visible keyspace tuple:

```text
namespace + key
```

When `namespace` is omitted, clients use `default`. Shared readers resolve secrets from their visible keyspace without knowing the owner client id or generated internal identifiers.

The following workflows are keyspace-based across CLI, SDKs, API and Web Console where applicable:

- create;
- read;
- update/new version;
- share;
- revoke;
- delete;
- list versions;
- list access;
- request access;
- activate access;
- access-request filtering.

Generated `secret_id` values remain internal storage, foreign-key, audit and operator-correlation identifiers. They are intentionally not part of normal client workflows or client crypto AAD.

## Client crypto boundary

Client crypto binds protected metadata through AAD:

```text
namespace
key
secret_version
```

The server does not derive DEKs, decrypt ciphertext, unwrap envelopes or interpret application private keys. See [`CLIENT_CRYPTO_SPEC.md`](CLIENT_CRYPTO_SPEC.md) and [`CLIENT_CRYPTO_THREAT_MODEL.md`](CLIENT_CRYPTO_THREAT_MODEL.md).

## SDK parity

The repository includes Go, Python, Node.js, C++, Java and Rust SDKs. The canonical feature matrix is [`CLIENT_LIBRARIES.md`](CLIENT_LIBRARIES.md).

0.1.0 requires keyspace parity for normal public workflows across all SDKs. Release checks and package smoke tests guard this surface.

## Deployment targets and profiles

0.1.0 documents three install targets: bare-metal from source, bare-metal from DEB/RPM packages and Kubernetes from a Git-built image plus Helm chart. Lite, Full and custom are runtime profiles selected through configuration, not separate server products. Kubernetes Lite requires one server replica, SQLite on a PersistentVolumeClaim and an explicit backup plan; Kubernetes Full expects external PostgreSQL/CockroachDB, Valkey and production signer/evidence integrations.

## Runtime configuration

Runtime daemon YAML uses structured sections for server and signer settings. Flat top-level runtime scalar keys are rejected so configuration shape stays explicit and auditable for 0.1.0.

## Release checks

Before publishing 0.1.0 artifacts, run:

```bash
make release-check
make package-smoke
```

For cross-language confidence, also run the SDK-specific checks when they are available in the build environment:

```bash
make test-rust-client
make test-cpp-client
make test-python-client
make test-node-client
make test-java-client
```

## Known scope limits

0.1.0 is repository-level release readiness. Production deployments still require operator evidence for HSM/PKCS#11, WORM/SIEM shipment, HA database topology, backup/restore drills, penetration testing and external revocation distribution where required by the deployment profile.
