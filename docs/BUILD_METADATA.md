# Build metadata

Custodia binaries expose build metadata through:

- `GET /v1/status` for admin API callers.
- `/web/status` for the admin metadata console.
- `custodia-admin version` for local admin CLI checks.
- `custodia-client version` for local encrypted client CLI checks.
- `custodia-server version` or `custodia-server --version` without loading runtime config.
- `custodia-signer version` or `custodia-signer --version` without loading CA/signer config.

`custodia-server help` and `custodia-signer help` also run before runtime initialization, so they are safe on a machine without `/var/log/custodia` or CA files.

Default development values are `dev`, `unknown`, `unknown`; those are compile-time fallbacks from `internal/build` when no release `-ldflags` are supplied. The Makefile now derives `COMMIT` and `DATE` from the local Git checkout/time for normal local builds, but `VERSION` intentionally remains `dev` unless a release value is provided. Release builds should set:

```bash
make build VERSION=v1.0.0 COMMIT=$(git rev-parse --short HEAD) DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
```

Docker builds accept equivalent build args. For the standard server image, keep both supported store backends enabled and let runtime configuration select the active backend:

```bash
docker build \
  --build-arg GO_BUILD_TAGS="sqlite postgres" \
  --build-arg CUSTODIA_VERSION=v1.0.0 \
  --build-arg CUSTODIA_COMMIT=$(git rev-parse --short HEAD) \
  --build-arg CUSTODIA_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -f deploy/Dockerfile .
```


## Release metadata guardrail

Use the release metadata gate before tagging or publishing artifacts:

```bash
make release-metadata-check VERSION=1.0.0
make release VERSION=1.0.0
```

The gate fails if `VERSION` is still `dev`/`unknown`, if `COMMIT` is missing, or if `DATE` is missing/non-RFC3339. This prevents accidentally publishing binaries or packages that report `dev unknown unknown`.


For reproducible release metadata and `SOURCE_DATE_EPOCH` usage, see [`REPRODUCIBLE_BUILDS.md`](REPRODUCIBLE_BUILDS.md).
