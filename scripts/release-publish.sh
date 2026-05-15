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

: "${VERSION:?VERSION is required, for example VERSION=1.0.0}"
: "${REVISION:=1}"
: "${RELEASE_TAG:=v$VERSION}"
: "${RELEASE_TITLE:=Custodia $VERSION}"
: "${RELEASE_REPO:=}"
: "${RELEASE_REMOTE:=origin}"
: "${RELEASE_NOTES_FILE:=docs/RELEASE_NOTES_${VERSION//./_}.md}"
: "${PACKAGE_DIR:=$root_dir/dist/packages}"
: "${PACKAGE_NAMES:=server client sdk}"
: "${RELEASE_CLEAN:=YES}"
: "${RELEASE_PUSH:=YES}"
: "${RELEASE_RUN_HELM_CHECK:=YES}"
: "${RELEASE_RUN_PACKAGE_INSTALL_CHECK:=YES}"
: "${RELEASE_ALLOW_EXISTING:=NO}"

log() {
  printf 'release-publish: %s\n' "$*" >&2
}

fail() {
  printf 'release-publish: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: scripts/release-publish.sh COMMAND

Commands:
  check-only  Validate local release tooling and environment.
  dry-run     Print the release plan without building, tagging, pushing or uploading.
  draft       Run checks, build packages, tag, push and create/update a GitHub draft release.
  publish     Run checks, build packages, tag, push and create/update a public GitHub release.
  help        Show this help.

Required:
  VERSION                       Release version, for example 1.0.0.
  RELEASE_CONFIRM=YES           Required for draft/publish.

Common environment:
  REVISION=1                    Package revision. Default: 1.
  RELEASE_TAG=v$VERSION         Git tag and GitHub release tag.
  RELEASE_TITLE="Custodia $VERSION"
  RELEASE_REPO=OWNER/REPO       Optional explicit GitHub repo for gh.
  RELEASE_NOTES_FILE=...        Default: docs/RELEASE_NOTES_<version_with_underscores>.md.
  RELEASE_CLEAN=YES             Remove dist/package-work before building. Default: YES.
  RELEASE_PUSH=YES              Push HEAD and tag before creating the release. Default: YES.
  RELEASE_RUN_HELM_CHECK=YES    Run make helm-check. Default: YES.
  RELEASE_ALLOW_EXISTING=NO     Allow uploading to an existing GitHub release. Default: NO.

Examples:
  VERSION=1.0.0 REVISION=1 ./scripts/release-publish.sh dry-run
  VERSION=1.0.0 REVISION=1 RELEASE_CONFIRM=YES ./scripts/release-publish.sh draft
  VERSION=1.0.0 REVISION=1 RELEASE_CONFIRM=YES ./scripts/release-publish.sh publish
USAGE
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

require_confirm() {
  if [ "${RELEASE_CONFIRM:-}" != "YES" ]; then
    fail "refusing $1 without RELEASE_CONFIRM=YES"
  fi
}

require_release_version() {
  case "$VERSION" in
    dev|0.0.0-dev|""|*[[:space:]]*)
      fail "VERSION must be a concrete release version, got: $VERSION"
      ;;
  esac
  case "$RELEASE_TAG" in
    v*) ;;
    *) fail "RELEASE_TAG must start with v, got: $RELEASE_TAG" ;;
  esac
}

gh_repo_args() {
  if [ -n "$RELEASE_REPO" ]; then
    printf '%s\n' --repo "$RELEASE_REPO"
  fi
}

release_exists() {
  gh release view "$RELEASE_TAG" $(gh_repo_args) >/dev/null 2>&1
}

require_clean_git() {
  git diff --quiet || fail "working tree has unstaged changes; commit or stash before publishing"
  git diff --cached --quiet || fail "index has staged changes; commit or reset before publishing"
}

run_baseline_checks() {
  log "running repository release checks"
  git diff --check
  python3 -m json.tool deploy/helm/custodia/values.schema.json >/dev/null
  bash -n \
    scripts/package-linux.sh \
    scripts/package-smoke.sh \
    scripts/package-install-smoke.sh \
    scripts/package-checksums.sh \
    scripts/github-release-assets.sh \
    scripts/release-publish.sh \
    scripts/helm-render-check.sh \
    scripts/release-check.sh \
    scripts/lite-backup-restore-smoke.sh \
    scripts/operational-readiness-smoke.sh
  make release-check
  if [ "$RELEASE_RUN_HELM_CHECK" = "YES" ]; then
    make helm-check
  fi
}

clean_artifacts() {
  if [ "$RELEASE_CLEAN" = "YES" ]; then
    log "cleaning package artifacts"
    rm -rf dist/packages dist/package-work
  fi
}

build_artifacts() {
  log "building DEB/RPM artifacts"
  VERSION="$VERSION" REVISION="$REVISION" PACKAGE_NAMES="$PACKAGE_NAMES" make package-linux
  VERSION="$VERSION" REVISION="$REVISION" PACKAGE_NAMES="$PACKAGE_NAMES" make package-smoke
  if [ "$RELEASE_RUN_PACKAGE_INSTALL_CHECK" = "YES" ]; then
    VERSION="$VERSION" REVISION="$REVISION" PACKAGE_NAMES="$PACKAGE_NAMES" make package-install-smoke
  fi
  VERSION="$VERSION" \
  REVISION="$REVISION" \
  PACKAGE_DIR="$PACKAGE_DIR" \
  PACKAGE_NAMES="$PACKAGE_NAMES" \
  CUSTODIA_RELEASE_TAG="$RELEASE_TAG" \
  CUSTODIA_GITHUB_REPO="$RELEASE_REPO" \
    ./scripts/github-release-assets.sh prepare
}

release_package_find_args() {
  local names
  # shellcheck disable=SC2206
  names=($PACKAGE_NAMES)
  if printf '%s\n' "${names[@]}" | grep -Fxq clients; then
    names+=(client sdk)
  fi

  local args=()
  local name
  for name in "${names[@]}"; do
    case "$name" in
      server|client|sdk)
        if [ "${#args[@]}" -gt 0 ]; then
          args+=(-o)
        fi
        args+=(-name "custodia-${name}_${VERSION}-${REVISION}_*.deb" -o -name "custodia-${name}-${VERSION}-${REVISION}.*.rpm")
        ;;
    esac
  done
  [ "${#args[@]}" -gt 0 ] || fail "no supported PACKAGE_NAMES in: $PACKAGE_NAMES"
  printf '%s\0' "${args[@]}"
}

local_release_assets() {
  local find_args
  readarray -d '' find_args < <(release_package_find_args)

  find "$PACKAGE_DIR" -maxdepth 1 -type f \
    \( "${find_args[@]}" \
    -o -name SHA256SUMS \
    -o -name artifacts-manifest.json \
    -o -name release-provenance.json \
    -o -name custodia-sbom.spdx.json \) | sort
}

verify_local_assets() {
  log "verifying local release assets"
  [ -d "$PACKAGE_DIR" ] || fail "missing package directory: $PACKAGE_DIR"

  local package_count
  package_count="$(local_release_assets | grep -E '\.(deb|rpm)$' | wc -l | tr -d ' ')"
  [ "$package_count" -gt 0 ] || fail "expected at least one package artifact in $PACKAGE_DIR"

  local metadata_asset
  for metadata_asset in SHA256SUMS artifacts-manifest.json release-provenance.json custodia-sbom.spdx.json; do
    [ -f "$PACKAGE_DIR/$metadata_asset" ] || fail "missing release metadata asset: $metadata_asset"
  done

  (
    cd "$PACKAGE_DIR"
    sha256sum --ignore-missing -c SHA256SUMS
    python3 -m json.tool artifacts-manifest.json >/dev/null
    python3 -m json.tool release-provenance.json >/dev/null
    python3 -m json.tool custodia-sbom.spdx.json >/dev/null
  )
}

ensure_tag() {
  log "checking git tag $RELEASE_TAG"
  if git rev-parse -q --verify "refs/tags/$RELEASE_TAG" >/dev/null; then
    tag_target="$(git rev-list -n 1 "$RELEASE_TAG")"
    head_target="$(git rev-parse HEAD)"
    [ "$tag_target" = "$head_target" ] || fail "existing tag $RELEASE_TAG does not point at HEAD"
    log "tag $RELEASE_TAG already points at HEAD"
  else
    git tag -a "$RELEASE_TAG" -m "$RELEASE_TITLE"
    log "created annotated tag $RELEASE_TAG"
  fi
}

push_release_refs() {
  if [ "$RELEASE_PUSH" != "YES" ]; then
    log "skipping git push because RELEASE_PUSH=$RELEASE_PUSH"
    return
  fi
  log "pushing HEAD and $RELEASE_TAG to $RELEASE_REMOTE"
  git push "$RELEASE_REMOTE" HEAD
  git push "$RELEASE_REMOTE" "$RELEASE_TAG"
}

create_release() {
  local mode="$1"
  [ -f "$RELEASE_NOTES_FILE" ] || fail "missing release notes file: $RELEASE_NOTES_FILE"

  if release_exists; then
    if [ "$RELEASE_ALLOW_EXISTING" != "YES" ]; then
      fail "GitHub release $RELEASE_TAG already exists; set RELEASE_ALLOW_EXISTING=YES to upload/replace assets"
    fi
    log "GitHub release $RELEASE_TAG already exists; reusing it"
    return
  fi

  args=(release create "$RELEASE_TAG" --verify-tag --title "$RELEASE_TITLE" --notes-file "$RELEASE_NOTES_FILE")
  if [ "$mode" = "draft" ]; then
    args+=(--draft)
  fi
  if [ -n "$RELEASE_REPO" ]; then
    args+=(--repo "$RELEASE_REPO")
  fi
  log "creating GitHub $mode release $RELEASE_TAG"
  gh "${args[@]}"
}

upload_release_assets() {
  log "uploading release assets"
  VERSION="$VERSION" \
  REVISION="$REVISION" \
  PACKAGE_DIR="$PACKAGE_DIR" \
  PACKAGE_NAMES="$PACKAGE_NAMES" \
  CUSTODIA_RELEASE_TAG="$RELEASE_TAG" \
  CUSTODIA_GITHUB_REPO="$RELEASE_REPO" \
  CUSTODIA_RELEASE_CONFIRM=YES \
    ./scripts/github-release-assets.sh upload
}

verify_remote_assets() {
  log "verifying remote release assets"
  mapfile -t local_names < <(local_release_assets | xargs -n1 basename | sort)
  mapfile -t remote_names < <(gh release view "$RELEASE_TAG" $(gh_repo_args) --json assets --jq '.assets[].name' | sort)
  for name in "${local_names[@]}"; do
    found=false
    for remote in "${remote_names[@]}"; do
      if [ "$remote" = "$name" ]; then
        found=true
        break
      fi
    done
    [ "$found" = true ] || fail "remote release $RELEASE_TAG is missing asset: $name"
  done
  log "remote release contains ${#local_names[@]} expected asset(s)"
}

check_only() {
  require_release_version
  require_command git
  require_command gh
  require_command make
  require_command python3
  require_command bash
  require_command sha256sum
  [ -f scripts/github-release-assets.sh ] || fail "missing scripts/github-release-assets.sh"
  [ -f scripts/package-checksums.sh ] || fail "missing scripts/package-checksums.sh"
  [ -f "$RELEASE_NOTES_FILE" ] || fail "missing release notes file: $RELEASE_NOTES_FILE"
  log "check-only OK"
}

print_plan() {
  cat <<EOF_PLAN
Release plan:
  version:             $VERSION
  revision:            $REVISION
  tag:                 $RELEASE_TAG
  title:               $RELEASE_TITLE
  repo:                ${RELEASE_REPO:-current gh repository}
  notes:               $RELEASE_NOTES_FILE
  package dir:         $PACKAGE_DIR
  package names:       $PACKAGE_NAMES
  clean artifacts:     $RELEASE_CLEAN
  push refs:           $RELEASE_PUSH
  run helm check:      $RELEASE_RUN_HELM_CHECK
  allow existing rel.: $RELEASE_ALLOW_EXISTING
EOF_PLAN
}

publish_flow() {
  local mode="$1"
  require_confirm "$mode"
  check_only
  require_clean_git
  print_plan
  run_baseline_checks
  clean_artifacts
  build_artifacts
  verify_local_assets
  ensure_tag
  push_release_refs
  create_release "$mode"
  upload_release_assets
  verify_remote_assets
  log "$mode release flow completed for $RELEASE_TAG"
}

command_name="${1:-help}"
case "$command_name" in
  check-only)
    check_only
    ;;
  dry-run)
    check_only
    print_plan
    ;;
  draft)
    publish_flow draft
    ;;
  publish)
    publish_flow publish
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
