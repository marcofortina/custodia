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

usage() {
  cat <<'USAGE'
Usage: scripts/github-release-assets.sh COMMAND

Commands:
  prepare   Generate SHA256SUMS and artifacts-manifest.json, then validate them.
  upload    Prepare assets, then upload DEB/RPM/checksum/manifest files to a GitHub release.
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

prepare_assets() {
  require_version
  require_command sha256sum
  require_command python3
  collect_package_artifacts

  log "generating checksums and manifest for VERSION=$VERSION REVISION=$REVISION"
  VERSION="$VERSION" REVISION="$REVISION" COMMIT="$COMMIT" DATE="$DATE" PACKAGE_DIR="$PACKAGE_DIR" ./scripts/package-checksums.sh

  (
    cd "$PACKAGE_DIR"
    sha256sum --ignore-missing -c SHA256SUMS
    python3 -m json.tool artifacts-manifest.json >/dev/null
  )
  log "prepared $PACKAGE_DIR/SHA256SUMS and $PACKAGE_DIR/artifacts-manifest.json"
}

collect_release_assets() {
  collect_package_artifacts
  release_assets=("${package_artifacts[@]}" "$PACKAGE_DIR/SHA256SUMS" "$PACKAGE_DIR/artifacts-manifest.json")
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
