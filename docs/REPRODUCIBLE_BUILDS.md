# Reproducible build notes

Custodia releases should carry explicit build metadata and should avoid ambient local timestamps where possible. The build is Go-native and uses `-buildvcs=false` in documented source install commands so release metadata comes from the explicit linker flags controlled by the Makefile and packaging script.

## Required release metadata

Set these values for release builds:

```bash
VERSION=0.1.0
COMMIT="$(git rev-parse --short=12 HEAD)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

The release guardrail rejects `VERSION=dev` and `COMMIT`/`DATE` values left as `unknown`:

```bash
make release-metadata-check VERSION="$VERSION" COMMIT="$COMMIT" DATE="$DATE"
```

## SOURCE_DATE_EPOCH

For reproducible release metadata, derive `DATE` from `SOURCE_DATE_EPOCH`:

```bash
export SOURCE_DATE_EPOCH=1767225600
export VERSION=0.1.0
export COMMIT="$(git rev-parse --short=12 HEAD)"
export DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"

make release
```

When `DATE` is not provided, the Makefile also derives it from `SOURCE_DATE_EPOCH` when that variable is set.

## Package builds

Use the same metadata for packages:

```bash
VERSION="$VERSION" \
REVISION=1 \
COMMIT="$COMMIT" \
DATE="$DATE" \
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
PACKAGE_FORMATS="deb rpm" \
./scripts/package-linux.sh
```

The package script uses `SOURCE_DATE_EPOCH` for RPM changelog dates when present.

## Verification

After building, verify runtime metadata from each binary:

```bash
./custodia-server version
./custodia-admin version
./custodia-signer version
./custodia-client version
```

Expected format:

```text
<version> <commit> <date>
```

No release artifact should report `dev unknown unknown`.
