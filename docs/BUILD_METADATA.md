# Build metadata

Custodia binaries expose build metadata through:

- `GET /v1/status` for admin API callers.
- `/web/status` for the admin metadata console.
- `custodia-admin version` for local admin CLI checks.
- `custodia-client version` for local encrypted client CLI checks.
- `custodia-server version` or `custodia-server --version` without loading runtime config.
- `custodia-signer version` or `custodia-signer --version` without loading CA/signer config.

`custodia-server help` and `custodia-signer help` also run before runtime initialization, so they are safe on a machine without `/var/log/custodia` or CA files.

Default development values are `dev`, `unknown`, `unknown`; those are compile-time fallbacks from `internal/build` when no release `-ldflags` are supplied. Release builds should set:

```bash
make build VERSION=v0.1.0 COMMIT=$(git rev-parse --short HEAD) DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
```

Docker builds accept equivalent build args:

```bash
docker build \
  --build-arg CUSTODIA_VERSION=v0.1.0 \
  --build-arg CUSTODIA_COMMIT=$(git rev-parse --short HEAD) \
  --build-arg CUSTODIA_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -f deploy/Dockerfile .
```
