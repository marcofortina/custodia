# Custodia 1.0.0 release notes

Custodia 1.0.0 is the first public release of the project.

The previous `v0.x` tags are development checkpoints and milestone history. They are intentionally not maintained as public release lines. The 1.0.0 release folds that work into one complete release with the final security boundary, compatibility policy, release evidence bundle and install documentation.

## Product summary

Custodia is a privacy-first encrypted secrets vault for self-hosted and enterprise-controlled deployments.

The server is a metadata-only control plane. It authenticates clients, validates authorization, stores opaque encrypted payloads and recipient envelopes, and records operational/audit metadata. It must not receive or expose plaintext secrets, DEKs, client private keys or application private keys.

Client-side cryptography remains the security boundary:

- plaintext is produced and consumed by clients only;
- data-encryption keys are generated and wrapped client-side;
- secret ciphertext and recipient envelopes are opaque to the server;
- protected metadata is bound through client crypto AAD where applicable.

## Release highlights

- Universal server binary with runtime-selected Lite/Full/custom profiles.
- Lite profile with SQLite local storage.
- Full/custom profile support for PostgreSQL-compatible storage and external production dependencies.
- mTLS client identity and enrollment-token based client bootstrap.
- Web MFA/TOTP support for the Web Console.
- Metadata-only Web Console operations and diagnostics.
- Keyspace-based user workflow with `namespace/key` semantics.
- Encrypted CLI workflows for create/read/share/update/revoke/delete.
- Versioned secret update/read/share behavior.
- Audit trail and audit export support.
- Kubernetes Helm deployment path with Lite/Full guardrails.
- DEB/RPM package generation for:
  - `custodia-server`;
  - `custodia-client`;
  - `custodia-sdk`.
- SDK coverage and documentation for Go, Python, Node.js/TypeScript, Rust, Java and C++ surfaces where applicable.
- Versioned SDK test vectors and compatibility documentation.
- Release evidence bundle with:
  - package artifacts;
  - `SHA256SUMS`;
  - `artifacts-manifest.json`;
  - `release-provenance.json`;
  - `custodia-sbom.spdx.json`.

## Development checkpoint history folded into 1.0.0

The historical `v0.x` tags remain useful as repository checkpoints:

- `v0.1.0` established the first repository-level release-readiness baseline.
- `v0.1.1` stabilized package smoke, Kubernetes Lite smoke and release runbook evidence.
- `v0.2.0` focused on client UX and enrollment polish.
- `v0.3.0` focused on Web Console operations and metadata-only operator workflows.
- `v0.4.0` focused on Kubernetes production polish.
- `v0.5.0` focused on SDK maturity, package readiness, examples, compatibility matrix and test vectors.

Those tags are not treated as public supported release lines. The public release line starts with `v1.0.0`.

## Security boundary

The 1.0.0 security boundary is documented in:

- [`SECURITY_MODEL.md`](SECURITY_MODEL.md)
- [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`CLIENT_CRYPTO_SPEC.md`](CLIENT_CRYPTO_SPEC.md)
- [`CLIENT_CRYPTO_THREAT_MODEL.md`](CLIENT_CRYPTO_THREAT_MODEL.md)

Server-side exclusions are explicit:

- no plaintext secret material;
- no DEKs;
- no client private keys;
- no application private keys;
- no server-side decryption of client secret ciphertext;
- no server-side unwrapping of recipient envelopes.

The server stores metadata and opaque encrypted material only.

## Compatibility promise

The 1.0.0 compatibility policy is documented in [`API_COMPATIBILITY_POLICY.md`](API_COMPATIBILITY_POLICY.md).

The policy covers:

- API compatibility expectations;
- CLI compatibility expectations;
- config compatibility expectations;
- storage/schema migration expectations;
- SDK compatibility expectations;
- what can still change before 1.0.0 and what requires compatibility handling after 1.0.0.

## Installation targets

1.0.0 supports the documented installation targets:

- bare-metal from source;
- bare-metal from DEB/RPM packages;
- Kubernetes from repository-built image and Helm chart.

Lite, Full and custom are runtime profiles selected through configuration. They are not different products and they are not different server binaries.

## Package artifacts

The 1.0.0 release publishes:

- `custodia-server_1.0.0-1_amd64.deb`
- `custodia-server-1.0.0-1.x86_64.rpm`
- `custodia-client_1.0.0-1_amd64.deb`
- `custodia-client-1.0.0-1.x86_64.rpm`
- `custodia-sdk_1.0.0-1_all.deb`
- `custodia-sdk-1.0.0-1.noarch.rpm`

The release also publishes:

- `SHA256SUMS`
- `artifacts-manifest.json`
- `release-provenance.json`
- `custodia-sbom.spdx.json`

## Verification

Download the release assets and verify them before installing:

```bash
gh release download v1.0.0 --repo marcofortina/custodia
sha256sum --ignore-missing -c SHA256SUMS
python3 -m json.tool artifacts-manifest.json >/dev/null
python3 -m json.tool release-provenance.json >/dev/null
python3 -m json.tool custodia-sbom.spdx.json >/dev/null
```

For package smoke and clean-install validation, see:

- [`PACKAGE_INSTALL_SMOKE.md`](PACKAGE_INSTALL_SMOKE.md)
- [`RELEASE_PUBLISHING.md`](RELEASE_PUBLISHING.md)
- [`RELEASE_READINESS_MATRIX.md`](RELEASE_READINESS_MATRIX.md)

## Release-candidate gates

Before publishing 1.0.0, run the local release gates from a clean checkout:

```bash
make release-check
make helm-check
make test
```

Then run package and release evidence checks for the intended release bundle:

```bash
VERSION=1.0.0 REVISION=1 PACKAGE_FORMATS="deb rpm" ./scripts/package-linux.sh
VERSION=1.0.0 REVISION=1 PACKAGE_FORMATS="deb rpm" ./scripts/package-smoke.sh
VERSION=1.0.0 REVISION=1 RELEASE_REPO=marcofortina/custodia ./scripts/github-release-assets.sh prepare
```

The final GitHub release must be created for an existing annotated `v1.0.0` tag. Release helpers use `gh release create --verify-tag` to avoid implicit tag creation.

## Operational scope limits

Custodia 1.0.0 provides the documented product, API, CLI, packaging, SDK and deployment baseline. Production deployments still require operator-provided evidence for environment-specific controls, including:

- HSM/PKCS#11 integration where required;
- WORM/SIEM shipment where required;
- HA database topology;
- backup/restore drills;
- penetration testing;
- external revocation distribution where required;
- organization-specific key ceremony and change-management controls.
