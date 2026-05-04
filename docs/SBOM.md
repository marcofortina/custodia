# Custodia SBOM artifacts

Custodia release builds can emit a lightweight SPDX 2.3 JSON SBOM.

Generate it after checking out the release source tree:

```bash
VERSION=0.1.0 make sbom
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

The generated SBOM is dependency metadata only. It does not claim binary provenance or artifact signing. Release integrity is covered by `SHA256SUMS` and `artifacts-manifest.json`; artifact signing can be added later with a dedicated signing policy.
