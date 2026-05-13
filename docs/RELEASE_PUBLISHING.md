# Release publishing runbook

Use this runbook to publish a Custodia release from a clean repository checkout.
It documents the full local flow driven by `scripts/release-publish.sh`, from
pre-flight checks through annotated tag creation, GitHub release asset upload and
post-release verification.

## Runbook metadata

| Field | Value |
| --- | --- |
| Audience | Maintainer publishing a Custodia release. |
| Prerequisites | Clean Git checkout, authenticated `gh`, package build tools, `helm` for chart checks, and a finalized release commit. |
| Outcome | Annotated Git tag, pushed branch/tag, GitHub release with DEB/RPM packages, `SHA256SUMS` and `artifacts-manifest.json`, plus verified downloadable assets. |
| Do not continue if | The working tree is dirty, tests fail, package smoke fails, `helm` is unavailable for a Kubernetes-capable release, or the tag does not point to the release commit. |

## 1. Pre-flight repository check

Start from the release commit:

```bash
cd ~/custodia
git status --short
git log --oneline -3
```

The working tree and index must be clean. Commit or stash local changes before
publishing.

Check the release tooling:

```bash
test -x scripts/release-publish.sh
test -x scripts/github-release-assets.sh
bash -n scripts/release-publish.sh scripts/github-release-assets.sh scripts/package-checksums.sh scripts/release-check.sh
```

## 2. Remove stale local tag when re-publishing

If a previous failed release attempt created a local tag, remove it before
rerunning the release flow unless you have verified that it already points to the
current release commit:

```bash
git tag --list 'v0.1.0'
git tag -d v0.1.0 2>/dev/null || true
```

Do not delete a published tag for a real release unless you are intentionally
replacing a failed draft/pre-release before users consume it.

## 3. Dry-run the release plan

```bash
VERSION=0.1.0 \
REVISION=1 \
RELEASE_REPO=marcofortina/custodia \
./scripts/release-publish.sh dry-run
```

Review the printed plan. Stop if the version, tag, repository, package
revision, release notes file or package directory is wrong.

## 4. Create a draft release

Prefer `draft` for normal publishing. It creates the annotated tag, pushes the
branch and tag, creates a GitHub draft release, uploads all assets and verifies
the remote asset list.

```bash
VERSION=0.1.0 \
REVISION=1 \
RELEASE_REPO=marcofortina/custodia \
RELEASE_CONFIRM=YES \
./scripts/release-publish.sh draft
```

The script runs:

- repository checks;
- `make release-check`;
- `make helm-check` when `RELEASE_RUN_HELM_CHECK=YES`;
- DEB/RPM package build;
- package smoke;
- package install smoke check-only;
- `SHA256SUMS` and `artifacts-manifest.json` generation;
- annotated tag creation;
- branch/tag push;
- GitHub draft release creation;
- release asset upload;
- remote asset verification.

Use `publish` only when you intentionally want to create a public release
without a draft review:

```bash
VERSION=0.1.0 \
REVISION=1 \
RELEASE_REPO=marcofortina/custodia \
RELEASE_CONFIRM=YES \
./scripts/release-publish.sh publish
```

## 5. Verify the draft release assets

```bash
gh release view v0.1.0 --repo marcofortina/custodia --json assets \
  --jq '.assets[].name' | sort
```

Expected assets:

```text
SHA256SUMS
artifacts-manifest.json
custodia-client-0.1.0-1.x86_64.rpm
custodia-client_0.1.0-1_amd64.deb
custodia-sdk-0.1.0-1.noarch.rpm
custodia-sdk_0.1.0-1_all.deb
custodia-server-0.1.0-1.x86_64.rpm
custodia-server_0.1.0-1_amd64.deb
```

If `SHA256SUMS` or `artifacts-manifest.json` is missing, do not publish the
draft. Re-run the asset helper:

```bash
VERSION=0.1.0 \
REVISION=1 \
CUSTODIA_GITHUB_REPO=marcofortina/custodia \
CUSTODIA_RELEASE_CONFIRM=YES \
./scripts/github-release-assets.sh all
```

## 6. Verify downloaded assets

Download the release from GitHub into a clean temporary directory and verify the
published checksum file:

```bash
rm -rf /tmp/custodia-release-check
mkdir -p /tmp/custodia-release-check
cd /tmp/custodia-release-check

gh release download v0.1.0 --repo marcofortina/custodia
sha256sum --ignore-missing -c SHA256SUMS
python3 -m json.tool artifacts-manifest.json >/dev/null
```

Do not publish the draft if checksum verification fails.

## 7. Verify annotated tag target

Annotated tags have their own object ID. Compare the release commit by
dereferencing the tag with `^{}`:

```bash
cd ~/custodia
git fetch --tags origin
git rev-parse HEAD
git rev-parse 'v0.1.0^{}'
git ls-remote --tags origin 'v0.1.0^{}'
```

All dereferenced commit hashes must match the intended release commit.

Do not compare `git rev-parse v0.1.0` directly to `HEAD`; for annotated tags it
prints the tag object hash, not the commit hash.

## 8. Publish the draft

After asset and tag verification:

```bash
gh release edit v0.1.0 --repo marcofortina/custodia --draft=false
```

Verify the public release:

```bash
gh release view v0.1.0 --repo marcofortina/custodia
```

## 9. Post-release smoke

On a clean disposable machine, install from the public GitHub release using
[`QUICKSTART.md`](QUICKSTART.md). At minimum, validate the package Lite path:

- package download from GitHub release;
- checksum verification;
- `custodia-server`, `custodia-client` and `custodia-sdk` installation;
- Lite bootstrap;
- Web TOTP setup;
- `custodia-admin doctor`;
- `status read` and `diagnostics read`;
- first client enrollment and encrypted secret smoke.

## Recovery notes

For a failed draft before publication, delete the GitHub draft and local/remote
tag only when you intentionally want to recreate the release from the current
commit:

```bash
gh release delete v0.1.0 --repo marcofortina/custodia --yes 2>/dev/null || true
git push origin :refs/tags/v0.1.0 2>/dev/null || true
git tag -d v0.1.0 2>/dev/null || true
```

Do not rewrite a published release/tag after users may have downloaded assets.
Publish a corrective release instead.
