# Build metadata

Custodia binaries expose build metadata through:

- `GET /v1/status` for admin API callers.
- `/web/status` for the admin metadata console.
- `custodia-admin version` for local CLI checks.

Default development values are `dev`, `unknown`, `unknown`. Release builds should set:

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
