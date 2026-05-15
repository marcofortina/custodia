# Custodia SBOM artifacts

Custodia release builds can emit a lightweight SPDX 2.3 JSON SBOM.

Generate it after checking out the release source tree:

```bash
VERSION=1.0.0 make sbom
```

The output is:

```text
dist/sbom/custodia-sbom.spdx.json
```

The SBOM includes:

- the Custodia source package and source commit;
- Go module requirements from `go.mod`;
- Python dependencies from `clients/python/pyproject.toml`;
- Node dependencies from `clients/node/package.json`;
- Rust dependencies from `clients/rust/Cargo.toml` and, when present, `clients/rust/Cargo.lock`;
- explicit system-level dependencies used by the C++ and Java SDK builds.

The generated SBOM is dependency metadata only. It does not claim binary artifact signing. The release helper publishes it as `custodia-sbom.spdx.json` alongside `SHA256SUMS`, `artifacts-manifest.json` and `release-provenance.json` so operators can verify package checksums and inspect the release evidence bundle. Detached artifact signing can still be added later with a dedicated signing policy.
