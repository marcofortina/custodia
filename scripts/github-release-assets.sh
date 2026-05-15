#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

: "${PACKAGE_DIR:=$root_dir/dist/packages}"
: "${REVISION:=1}"
: "${COMMIT:=$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)}"
: "${DATE:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
: "${SBOM_FILE:=$PACKAGE_DIR/custodia-sbom.spdx.json}"
: "${PROVENANCE_FILE:=$PACKAGE_DIR/release-provenance.json}"

usage() {
  cat <<'USAGE'
Usage: scripts/github-release-assets.sh COMMAND

Commands:
  prepare   Generate SHA256SUMS, artifacts-manifest.json, SBOM and provenance, then validate them.
  upload    Prepare assets, then upload DEB/RPM/checksum/manifest/SBOM/provenance files to a GitHub release.
  verify    Verify that all local release assets are attached to the GitHub release.
  all       Run prepare, upload and verify.
  help      Show this help.

Required for all release commands:
  VERSION=0.1.0

Required for upload:
  CUSTODIA_RELEASE_CONFIRM=YES

Optional environment:
  REVISION=1
  PACKAGE_DIR=dist/packages
  CUSTODIA_RELEASE_TAG=v$VERSION
  CUSTODIA_GITHUB_REPO=owner/repo
  SBOM_FILE=dist/packages/custodia-sbom.spdx.json
  PROVENANCE_FILE=dist/packages/release-provenance.json

Generated release evidence:
  SHA256SUMS, artifacts-manifest.json, release-provenance.json
  custodia-sbom.spdx.json

Examples:
  VERSION=0.1.0 REVISION=1 ./scripts/github-release-assets.sh prepare
  VERSION=0.1.0 REVISION=1 CUSTODIA_RELEASE_CONFIRM=YES ./scripts/github-release-assets.sh upload
  VERSION=0.1.0 REVISION=1 ./scripts/github-release-assets.sh verify
USAGE
}

log() {
  printf 'github-release-assets: %s\n' "$*" >&2
}

fail() {
  printf 'github-release-assets: %s\n' "$*" >&2
  exit 1
}

require_version() {
  if [ -z "${VERSION:-}" ]; then
    fail "VERSION is required, for example: VERSION=0.1.0 REVISION=1 ./scripts/github-release-assets.sh prepare"
  fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

release_tag() {
  printf '%s\n' "${CUSTODIA_RELEASE_TAG:-v$VERSION}"
}

gh_repo_args() {
  if [ -n "${CUSTODIA_GITHUB_REPO:-}" ]; then
    printf '%s\n' --repo "$CUSTODIA_GITHUB_REPO"
  fi
}

collect_package_artifacts() {
  [ -d "$PACKAGE_DIR" ] || fail "package directory not found: $PACKAGE_DIR; run VERSION=$VERSION REVISION=$REVISION make package-linux first"
  mapfile -t package_artifacts < <(find "$PACKAGE_DIR" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | sort)
  [ "${#package_artifacts[@]}" -gt 0 ] || fail "no .deb or .rpm artifacts found in $PACKAGE_DIR"
}

generate_sbom() {
  require_command python3
  mkdir -p "$(dirname "$SBOM_FILE")"
  SBOM_DIR="$(dirname "$SBOM_FILE")" \
  SBOM_FILE="$SBOM_FILE" \
  VERSION="$VERSION" \
  COMMIT="$COMMIT" \
  DATE="$DATE" \
    ./scripts/generate-sbom.sh
  python3 -m json.tool "$SBOM_FILE" >/dev/null
}

generate_provenance() {
  require_command python3
  python3 - "$PROVENANCE_FILE" "$VERSION" "$REVISION" "$COMMIT" "$DATE" "$(release_tag)" \
    "${package_artifacts[@]}" "$PACKAGE_DIR/artifacts-manifest.json" "$SBOM_FILE" <<'RELEASE_PROVENANCE_PY'
import hashlib
import json
import os
import sys

provenance_file, version, revision, commit, generated_at, tag, *asset_paths = sys.argv[1:]

assets = []
for path in asset_paths:
    name = os.path.basename(path)
    if name.endswith(".deb"):
        role = "package/deb"
    elif name.endswith(".rpm"):
        role = "package/rpm"
    elif name == "artifacts-manifest.json":
        role = "package-manifest"
    elif name == "custodia-sbom.spdx.json":
        role = "sbom"
    else:
        role = "release-metadata"
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    assets.append({
        "name": name,
        "role": role,
        "size_bytes": os.path.getsize(path),
        "sha256": digest,
    })

provenance = {
    "schema": "custodia.release-provenance.v1",
    "version": version,
    "revision": revision,
    "commit": commit,
    "tag": tag,
    "generated_at": generated_at,
    "assets": assets,
}
os.makedirs(os.path.dirname(provenance_file), exist_ok=True)
with open(provenance_file, "w", encoding="utf-8") as fh:
    json.dump(provenance, fh, indent=2, sort_keys=True)
    fh.write("\n")
RELEASE_PROVENANCE_PY
}

append_release_metadata_checksums() {
  require_command python3
  python3 - "$PACKAGE_DIR/SHA256SUMS" "$PACKAGE_DIR/artifacts-manifest.json" "$PROVENANCE_FILE" "$SBOM_FILE" <<'RELEASE_CHECKSUMS_PY'
import hashlib
import os
import sys

checksum_file, *paths = sys.argv[1:]
with open(checksum_file, "a", encoding="utf-8") as out:
    for path in paths:
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        out.write(f"{digest}  {os.path.basename(path)}\n")
RELEASE_CHECKSUMS_PY
}

prepare_assets() {
  require_version
  require_command sha256sum
  require_command python3
  collect_package_artifacts

  log "generating release evidence for VERSION=$VERSION REVISION=$REVISION"
  VERSION="$VERSION" REVISION="$REVISION" COMMIT="$COMMIT" DATE="$DATE" PACKAGE_DIR="$PACKAGE_DIR" ./scripts/package-checksums.sh
  generate_sbom
  generate_provenance
  append_release_metadata_checksums

  (
    cd "$PACKAGE_DIR"
    sha256sum --ignore-missing -c SHA256SUMS
    python3 -m json.tool artifacts-manifest.json >/dev/null
    python3 -m json.tool "$(basename "$PROVENANCE_FILE")" >/dev/null
    python3 -m json.tool "$(basename "$SBOM_FILE")" >/dev/null
  )
  log "prepared $PACKAGE_DIR/SHA256SUMS, $PACKAGE_DIR/artifacts-manifest.json, $PROVENANCE_FILE and $SBOM_FILE"
}

collect_release_assets() {
  collect_package_artifacts
  release_assets=("${package_artifacts[@]}" "$PACKAGE_DIR/SHA256SUMS" "$PACKAGE_DIR/artifacts-manifest.json" "$PROVENANCE_FILE" "$SBOM_FILE")
  for asset in "${release_assets[@]}"; do
    [ -f "$asset" ] || fail "missing release asset: $asset; run prepare first"
  done
}

upload_assets() {
  require_version
  [ "${CUSTODIA_RELEASE_CONFIRM:-}" = "YES" ] || fail "refusing upload without CUSTODIA_RELEASE_CONFIRM=YES"
  require_command gh
  prepare_assets
  collect_release_assets

  tag="$(release_tag)"
  log "uploading ${#release_assets[@]} asset(s) to $tag"
  gh release upload "$tag" "${release_assets[@]}" --clobber $(gh_repo_args)
}

verify_assets() {
  require_version
  require_command gh
  collect_release_assets

  tag="$(release_tag)"
  log "verifying release assets on $tag"
  release_asset_names="$(gh release view "$tag" --json assets --jq '.assets[].name' $(gh_repo_args) | sort)"
  missing=0
  for asset in "${release_assets[@]}"; do
    name="$(basename "$asset")"
    if ! printf '%s\n' "$release_asset_names" | grep -Fxq "$name"; then
      printf 'github-release-assets: missing release asset: %s\n' "$name" >&2
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1
  log "release assets OK"
}

command_name="${1:-help}"
case "$command_name" in
  prepare)
    prepare_assets
    ;;
  upload)
    upload_assets
    ;;
  verify)
    prepare_assets
    verify_assets
    ;;
  all)
    upload_assets
    verify_assets
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "unknown command: $command_name" >&2
    usage >&2
    exit 2
    ;;
esac
