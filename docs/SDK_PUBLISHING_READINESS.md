# Custodia SDK publishing readiness checklist

This checklist is the release gate for publishing Custodia SDKs to language package registries. It coordinates the language-specific SDK work tracked for the `0.5.0 — SDK maturity` milestone and keeps registry publishing blocked until the requirements below are complete.

The Linux `custodia-sdk` package is a separate artifact. It ships monorepo SDK source snapshots, shared crypto vectors and SDK documentation; it does not prove that native language registry packages are ready.

## Do not publish if

Do not publish any language SDK to an external registry when any of these is true:

- the target package name or namespace is not controlled by the Custodia maintainer account or approved organization;
- package metadata still says `private`, `publish = false`, placeholder versioning or unpublished coordinates;
- a language-specific readiness issue for the SDK is still open;
- shared crypto vector tests or compatibility matrix entries are missing for the shipped surface;
- CI cannot reproduce the language-specific test command;
- CodeQL or equivalent security findings affecting the SDK are still unresolved;
- release notes do not describe compatibility, known limitations and migration impact.

## Registry ownership and package-name gate

Registry ownership must be verified immediately before the first publish. The table documents the intended public package coordinates and the owner/control requirement; it does not claim that a registry reservation has already happened.

| SDK | Source path | Intended public package coordinate | Required owner/control before publish | Blocking issue |
| --- | --- | --- | --- | --- |
| Go | `pkg/client` | Go import path under the canonical Custodia repository or an approved dedicated module path | GitHub repository/module path controlled by the Custodia maintainer account or approved organization | #40 |
| Python | `clients/python` | `custodia-client` on PyPI | PyPI project ownership controlled by the Custodia maintainer account or approved organization | #41 |
| Node.js / TypeScript | `clients/node` | `@custodia/client` on npm | npm `@custodia` scope controlled by the Custodia maintainer account or approved organization | #42 |
| Rust | `clients/rust` | `custodia-client` on crates.io | crates.io crate ownership controlled by the Custodia maintainer account or approved organization | #43 |
| Java | `clients/java` | Maven coordinate aligned with package `dev.custodia.client`, for example `dev.custodia:custodia-client` once ownership is verified | Maven Central namespace ownership controlled by the Custodia maintainer account or approved organization | #44 |
| Test vectors and docs | `testdata/client-crypto/v1/`, `docs/` | Versioned shared fixtures and compatibility matrix shipped with every SDK release | Repository release assets and `custodia-sdk` package controlled by the Custodia maintainer account | #45, #46 |

C++ is currently shipped as monorepo source and through the Linux `custodia-sdk` package. Do not add a public C++ package registry target without a dedicated issue that defines the registry, package coordinate, owner and CI gate.

## Readiness checklist

All items must be complete before any registry publish command is run.

### Repository and API stability

- [ ] Go public SDK surface is stable enough for external consumers, ships package-level documentation and does not expose `custodia/internal/*` types.
- [ ] Transport APIs use `namespace/key` workflows and do not reintroduce `secret_id` in public SDK surfaces.
- [ ] High-level crypto APIs keep plaintext, DEKs, private keys and envelope internals local to the client.
- [ ] Deprecated or internal-model helpers are documented as non-registry public surface.
- [ ] Go SDK examples compile against current `namespace/key` transport semantics and high-level crypto helpers.

### Package metadata

- [x] Python `pyproject.toml` has package name, version, description, license, authors, readme, dependencies and project URLs documented; PyPI ownership verification remains required before publish.
- [x] Node `package.json` has scoped name, version, license, exports/types, engines and `private` retained until publish time.
- [x] Rust `Cargo.toml` has crate metadata, readme, repository and documentation links documented; `publish = false` remains until publish time.
- [x] Java `pom.xml` has Maven coordinates, Java 17 compiler metadata, license, SCM and package identity documented; Maven Central ownership verification remains required before publish.
- [ ] Package metadata names match the registry ownership table above.

### Tests and CI

- [ ] `make test` passes for the repository.
- [x] `make test-python-client` passes where Python dependencies are installed.
- [x] `make test-node-client` passes where Node.js dependencies are installed.
- [x] `make test-rust-client` passes where Rust is installed.
- [x] `make test-java-client` passes where a supported JDK is installed.
- [ ] Shared crypto vector tests pass for every SDK that ships high-level crypto. Java/Rust already cover the current v1 vectors; #45 remains the cross-language vector versioning gate.
- [ ] CI documents skipped language checks as toolchain skips, not silent success.

### Security and compatibility

- [x] Java CodeQL/static-IV triage is documented as safe for HPKE envelope AEAD nonces; content encryption still uses random AES-GCM nonces.
- [ ] SDK docs state that the server remains metadata-only and never receives plaintext, DEKs or private keys.
- [ ] Public-key resolution remains an application trust decision; server-published public keys are discovery metadata only.
- [ ] Compatibility matrix documents transport, crypto, vector and package status per language.
- [ ] Release notes describe compatibility, migration notes and known limitations.

### Publishing controls

- [ ] Registry credentials are held by the Custodia maintainer account or approved organization.
- [ ] First publish is performed from a clean tag or release commit, not from a dirty working tree.
- [ ] Dry-run/package verification is completed where the registry supports it.
- [ ] Registry publishing commands are not added to automation until all gates above are complete.
- [ ] Release evidence records package names, versions, checksums where applicable and registry URLs after publish.

## Completion rule

#34 can close when this checklist exists, is linked from the SDK documentation index, is shipped with the `custodia-sdk` package and clearly blocks external registry publishing until the language-specific issues complete.

Do not close #40, #41, #42, #43, #44, #45 or #46 from this coordination checklist alone.
