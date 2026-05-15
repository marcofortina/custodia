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
: "${CUSTODIA_PACKAGE_INSTALL_FORMAT:=auto}"
: "${CUSTODIA_PACKAGE_INSTALL_SCOPE:=all}"
: "${CUSTODIA_PACKAGE_INSTALL_CONFIRM:=}"
: "${CUSTODIA_PACKAGE_INSTALL_ALLOW_EXISTING:=false}"

log() {
  printf 'package-install-smoke: %s\n' "$*" >&2
}

fail() {
  printf 'package-install-smoke: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF_USAGE'
Usage: scripts/package-install-smoke.sh <action>

Actions:
  check-only      Validate local tooling and artifact discovery without installing anything.
  install-verify  Install local Custodia packages on a clean VM/container and verify layout.
  verify-installed
                  Verify an already installed Custodia package set without installing.
  help            Show this help.

Environment:
  PACKAGE_DIR                              Directory containing built .deb/.rpm artifacts.
                                           Default: dist/packages.
  CUSTODIA_PACKAGE_INSTALL_FORMAT          auto, deb or rpm. Default: auto.
  CUSTODIA_PACKAGE_INSTALL_SCOPE           all, server, client, sdk, server-client.
                                           Default: all.
  CUSTODIA_PACKAGE_INSTALL_CONFIRM         Must be YES for install-verify.
  CUSTODIA_PACKAGE_INSTALL_ALLOW_EXISTING  Set true to allow upgrade/reinstall smoke.
                                           Default: false.

This smoke is intended for disposable clean release-candidate machines. It changes
the host package database and, for custodia-server, creates the custodia user and
runtime directories. It does not enable or start custodia-server or custodia-signer.
EOF_USAGE
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

require_root() {
  [ "${EUID:-$(id -u)}" -eq 0 ] || fail "install-verify must run as root on a disposable clean machine"
}

require_confirm() {
  [ "$CUSTODIA_PACKAGE_INSTALL_CONFIRM" = "YES" ] || fail "set CUSTODIA_PACKAGE_INSTALL_CONFIRM=YES to modify the package database"
}

package_names() {
  case "$CUSTODIA_PACKAGE_INSTALL_SCOPE" in
    all) printf '%s\n' custodia-server custodia-client custodia-sdk ;;
    server) printf '%s\n' custodia-server ;;
    client) printf '%s\n' custodia-client ;;
    sdk) printf '%s\n' custodia-sdk ;;
    server-client) printf '%s\n' custodia-server custodia-client ;;
    *) fail "unsupported CUSTODIA_PACKAGE_INSTALL_SCOPE=$CUSTODIA_PACKAGE_INSTALL_SCOPE" ;;
  esac
}

detect_format() {
  case "$CUSTODIA_PACKAGE_INSTALL_FORMAT" in
    deb|rpm) printf '%s\n' "$CUSTODIA_PACKAGE_INSTALL_FORMAT" ;;
    auto)
      if [ -d "$PACKAGE_DIR" ] && find "$PACKAGE_DIR" -maxdepth 1 -type f -name '*.deb' | grep -q .; then
        printf 'deb\n'
      elif [ -d "$PACKAGE_DIR" ] && find "$PACKAGE_DIR" -maxdepth 1 -type f -name '*.rpm' | grep -q .; then
        printf 'rpm\n'
      elif command -v dpkg >/dev/null 2>&1; then
        printf 'deb\n'
      elif command -v rpm >/dev/null 2>&1; then
        printf 'rpm\n'
      else
        fail "cannot detect package format; set CUSTODIA_PACKAGE_INSTALL_FORMAT=deb or rpm"
      fi
      ;;
    *) fail "unsupported CUSTODIA_PACKAGE_INSTALL_FORMAT=$CUSTODIA_PACKAGE_INSTALL_FORMAT" ;;
  esac
}

package_installed() {
  local format="$1"
  local name="$2"
  case "$format" in
    deb) dpkg-query -W -f='${Status}' "$name" 2>/dev/null | grep -q 'install ok installed' ;;
    rpm) rpm -q "$name" >/dev/null 2>&1 ;;
  esac
}

active_dpkg_path_filters() {
  local file line option kind pattern
  for file in /etc/dpkg/dpkg.cfg /etc/dpkg/dpkg.cfg.d/*; do
    [ -f "$file" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%%#*}"
      # shellcheck disable=SC2086
      set -- $line
      option="${1:-}"
      case "$option" in
        path-exclude=*|path-include=*)
          kind="${option%%=*}"
          pattern="${option#*=}"
          [ -n "$pattern" ] && printf '%s|%s\n' "$kind" "$pattern"
          ;;
      esac
    done < "$file"
  done
}

dpkg_path_filter_state() {
  local installed_path="$1"
  local state=keep
  local kind pattern
  while IFS='|' read -r kind pattern; do
    [ -n "$kind" ] || continue
    if [[ "$installed_path" == $pattern ]]; then
      case "$kind" in
        path-exclude) state=exclude ;;
        path-include) state=keep ;;
      esac
    fi
  done < <(active_dpkg_path_filters)
  printf '%s\n' "$state"
}

require_no_dpkg_payload_excludes() {
  local manifest path installed_path offender_count=0
  local -a offenders=()
  while IFS= read -r package_name; do
    manifest="$(manifest_for_package "$package_name")"
    require_path "$manifest"
    while IFS= read -r path || [ -n "$path" ]; do
      case "$path" in
        ''|'#'*) continue ;;
      esac
      installed_path="/$path"
      if [ "$(dpkg_path_filter_state "$installed_path")" = "exclude" ]; then
        offenders+=("$installed_path")
        offender_count=$((offender_count + 1))
      fi
    done < "$manifest"
  done < <(package_names)

  if [ "$offender_count" -gt 0 ]; then
    log "Debian dpkg path filters would drop expected Custodia package payload paths:"
    printf '  %s\n' "${offenders[@]}" >&2
    fail "disable dpkg path-exclude filters for the package clean-install smoke, or use a full clean VM instead of a minimized image that excludes /usr/share/man or /usr/share/doc"
  fi
}

require_clean_install_target() {
  local format="$1"
  local name
  [ "$CUSTODIA_PACKAGE_INSTALL_ALLOW_EXISTING" = "true" ] && return 0
  while IFS= read -r name; do
    if package_installed "$format" "$name"; then
      fail "$name is already installed; use a clean VM/container or set CUSTODIA_PACKAGE_INSTALL_ALLOW_EXISTING=true for upgrade smoke"
    fi
  done < <(package_names)
}


manifest_for_package() {
  case "$1" in
    custodia-server) printf '%s\n' scripts/package-manifest-custodia-server.expected ;;
    custodia-client) printf '%s\n' scripts/package-manifest-custodia-client.expected ;;
    custodia-sdk) printf '%s\n' scripts/package-manifest-custodia-sdk.expected ;;
    *) fail "unknown package name for manifest: $1" ;;
  esac
}

package_name_from_artifact() {
  local artifact="$1"
  case "$(basename "$artifact")" in
    custodia-server_*.deb|custodia-server-*.rpm) printf '%s\n' custodia-server ;;
    custodia-client_*.deb|custodia-client-*.rpm) printf '%s\n' custodia-client ;;
    custodia-sdk_*.deb|custodia-sdk-*.rpm) printf '%s\n' custodia-sdk ;;
    *) fail "cannot infer Custodia package name from artifact: $artifact" ;;
  esac
}

require_artifact_payload_path() {
  local artifact="$1"
  local root="$2"
  local path="$3"
  [ -e "$root/$path" ] || fail "artifact $(basename "$artifact") is missing payload path: $path; rebuild packages from the current tree and run make package-smoke before install-verify"
}

verify_artifact_manifest() {
  local artifact="$1"
  local root="$2"
  local package_name manifest path
  package_name="$(package_name_from_artifact "$artifact")"
  manifest="$(manifest_for_package "$package_name")"
  require_path "$manifest"
  while IFS= read -r path || [ -n "$path" ]; do
    case "$path" in
      ''|'#'*) continue ;;
    esac
    require_artifact_payload_path "$artifact" "$root" "$path"
  done < "$manifest"
}

preflight_deb_artifact() {
  local artifact="$1"
  require_command dpkg-deb
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  dpkg-deb --info "$artifact" >/dev/null
  dpkg-deb -x "$artifact" "$tmp/root"
  verify_artifact_manifest "$artifact" "$tmp/root"
  rm -rf "$tmp"
  trap - RETURN
}

preflight_rpm_artifact() {
  local artifact="$1"
  require_command rpm
  require_command rpm2cpio
  require_command cpio
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  rpm -qpi "$artifact" >/dev/null
  (cd "$tmp" && rpm2cpio "$artifact" | cpio -id --quiet)
  verify_artifact_manifest "$artifact" "$tmp"
  rm -rf "$tmp"
  trap - RETURN
}

preflight_artifacts() {
  local format="$1"
  shift
  local artifact
  for artifact in "$@"; do
    log "preflighting $(basename "$artifact") payload"
    case "$format" in
      deb) preflight_deb_artifact "$artifact" ;;
      rpm) preflight_rpm_artifact "$artifact" ;;
      *) fail "unsupported package format for preflight: $format" ;;
    esac
  done
}

artifact_for_package() {
  local format="$1"
  local name="$2"
  local pattern
  case "$format" in
    deb) pattern="${name}_*.deb" ;;
    rpm) pattern="${name}-*.rpm" ;;
  esac

  mapfile -t matches < <(find "$PACKAGE_DIR" -maxdepth 1 -type f -name "$pattern" | sort)
  [ "${#matches[@]}" -gt 0 ] || fail "no $format artifact found for $name in $PACKAGE_DIR"

  local release_matches=()
  local artifact
  for artifact in "${matches[@]}"; do
    case "$(basename "$artifact")" in
      *0.0.0_dev*|*0.0.0-dev*) ;;
      *) release_matches+=("$artifact") ;;
    esac
  done
  if [ "${#release_matches[@]}" -gt 0 ]; then
    matches=("${release_matches[@]}")
  fi

  printf '%s\n' "${matches[-1]}"
}

collect_artifacts() {
  local format="$1"
  local name
  while IFS= read -r name; do
    artifact_for_package "$format" "$name"
  done < <(package_names)
}

install_artifacts() {
  local format="$1"
  shift
  case "$format" in
    deb)
      require_command dpkg
      dpkg -i "$@"
      ;;
    rpm)
      require_command rpm
      rpm -Uvh --replacepkgs "$@"
      ;;
  esac
}

require_path() {
  local path="$1"
  [ -e "$path" ] || fail "missing installed path: $path"
}

require_executable_path() {
  local path="$1"
  require_path "$path"
  [ -x "$path" ] || fail "installed path is not executable: $path"
}

require_contains() {
  local path="$1"
  local needle="$2"
  require_path "$path"
  grep -Fq -- "$needle" "$path" || fail "$path does not contain expected text: $needle"
}

require_mode_owner() {
  local path="$1"
  local expected_mode="$2"
  local expected_owner="$3"
  local expected_group="$4"
  require_command stat
  require_path "$path"
  local actual
  actual="$(stat -c '%a %U %G' "$path")"
  [ "$actual" = "$expected_mode $expected_owner $expected_group" ] || fail "$path has $actual, expected $expected_mode $expected_owner $expected_group"
}

verify_not_enabled() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    fail "$unit is enabled; packages must not enable services automatically"
  fi
}

verify_server() {
  require_executable_path /usr/bin/custodia-server
  require_executable_path /usr/bin/custodia-admin
  require_executable_path /usr/bin/custodia-signer
  require_executable_path /usr/sbin/custodia-sqlite-backup
  require_executable_path /usr/sbin/custodia-operational-readiness-smoke
  require_path /usr/lib/systemd/system/custodia-server.service
  require_path /usr/lib/systemd/system/custodia-signer.service
  require_contains /usr/lib/systemd/system/custodia-server.service 'NoNewPrivileges=true'
  require_contains /usr/lib/systemd/system/custodia-server.service 'PrivateDevices=true'
  require_contains /usr/lib/systemd/system/custodia-server.service 'ProtectKernelTunables=true'
  require_contains /usr/lib/systemd/system/custodia-server.service 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
  require_contains /usr/lib/systemd/system/custodia-signer.service 'NoNewPrivileges=true'
  require_contains /usr/lib/systemd/system/custodia-signer.service 'PrivateDevices=true'
  require_contains /usr/lib/systemd/system/custodia-signer.service 'ProtectKernelTunables=true'
  require_contains /usr/lib/systemd/system/custodia-signer.service 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
  require_path /usr/share/man/man1/custodia-admin.1.gz
  require_path /usr/share/man/man1/custodia-server.1.gz
  require_path /usr/share/man/man1/custodia-signer.1.gz
  require_path /usr/share/doc/custodia/custodia-server.lite.yaml.example
  require_path /usr/share/doc/custodia/custodia-server.full.yaml.example
  require_path /usr/share/doc/custodia/custodia-signer.yaml.example
  getent passwd custodia >/dev/null 2>&1 || fail "custodia user was not created"
  getent group custodia >/dev/null 2>&1 || fail "custodia group was not created"
  require_mode_owner /etc/custodia 750 root custodia
  require_mode_owner /var/lib/custodia 750 custodia custodia
  require_mode_owner /var/lib/custodia/backups 750 custodia custodia
  require_mode_owner /var/log/custodia 750 custodia custodia
  /usr/bin/custodia-admin version >/dev/null
  verify_not_enabled custodia-server.service
  verify_not_enabled custodia-signer.service
}

verify_client() {
  require_executable_path /usr/bin/custodia-client
  require_path /usr/share/man/man1/custodia-client.1.gz
  require_path /usr/share/doc/custodia-client/CUSTODIA_CLIENT_CLI.md
  require_path /usr/share/doc/custodia-client/CUSTODIA_ALICE_BOB_SMOKE.md
  require_path /usr/share/doc/custodia-client/CLIENT_TRUSTED_CA.md
  /usr/bin/custodia-client help >/dev/null
}

verify_sdk() {
  require_path /usr/share/custodia/sdk/clients/go/go.mod
  require_path /usr/share/custodia/sdk/clients/go/pkg/client/client.go
  require_path /usr/share/custodia/sdk/clients/python/custodia_client/__init__.py
  require_path /usr/share/custodia/sdk/clients/node/package.json
  require_path /usr/share/custodia/sdk/clients/node/src/index.js
  require_path /usr/share/custodia/sdk/clients/node/src/index.d.ts
  require_path /usr/share/custodia/sdk/clients/node/examples/keyspace_transport.mjs
  require_path /usr/share/custodia/sdk/clients/node/examples/high_level_crypto.mjs
  require_path /usr/share/custodia/sdk/clients/java/src/main/java/dev/custodia/client/CustodiaClient.java
  require_path /usr/share/custodia/sdk/clients/cpp/include/custodia/client.hpp
  require_path /usr/share/custodia/sdk/clients/rust/Cargo.toml
  require_path /usr/share/custodia/sdk/clients/bash/custodia.bash
  require_path /usr/share/custodia/sdk/testdata/client-crypto/v1/create_secret_single_recipient.json
  require_path /usr/share/doc/custodia-sdk/SDK_RELEASE_POLICY.md
  require_path /usr/share/doc/custodia-sdk/SDK_PUBLISHING_READINESS.md
}

verify_packages_installed() {
  local format="$1"
  local name
  while IFS= read -r name; do
    package_installed "$format" "$name" || fail "$name is not installed according to the package database"
    case "$name" in
      custodia-server) verify_server ;;
      custodia-client) verify_client ;;
      custodia-sdk) verify_sdk ;;
      *) fail "unsupported package name $name" ;;
    esac
  done < <(package_names)
}

run_check_only() {
  if [ ! -d "$PACKAGE_DIR" ]; then
    log "check-only OK: package directory not found yet: $PACKAGE_DIR"
    return 0
  fi
  if ! find "$PACKAGE_DIR" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | grep -q .; then
    log "check-only OK: no package artifacts found yet in $PACKAGE_DIR"
    return 0
  fi
  local format
  format="$(detect_format)"
  case "$format" in
    deb)
      require_command dpkg
      ;;
    rpm)
      require_command rpm
      ;;
  esac
  mapfile -t artifacts < <(collect_artifacts "$format")
  preflight_artifacts "$format" "${artifacts[@]}"
  log "check-only OK: format=$format scope=$CUSTODIA_PACKAGE_INSTALL_SCOPE package_dir=$PACKAGE_DIR"
}

run_install_verify() {
  require_root
  require_confirm
  [ -d "$PACKAGE_DIR" ] || fail "package directory not found: $PACKAGE_DIR"
  local format
  format="$(detect_format)"
  case "$format" in
    deb)
      require_command dpkg
      require_no_dpkg_payload_excludes
      ;;
    rpm) require_command rpm ;;
  esac
  require_clean_install_target "$format"
  mapfile -t artifacts < <(collect_artifacts "$format")
  preflight_artifacts "$format" "${artifacts[@]}"
  log "installing ${#artifacts[@]} $format artifact(s) from $PACKAGE_DIR"
  install_artifacts "$format" "${artifacts[@]}"
  verify_packages_installed "$format"
  log "install-verify OK: format=$format scope=$CUSTODIA_PACKAGE_INSTALL_SCOPE"
}

run_verify_installed() {
  local format
  format="$(detect_format)"
  verify_packages_installed "$format"
  log "verify-installed OK: format=$format scope=$CUSTODIA_PACKAGE_INSTALL_SCOPE"
}

main() {
  local action="${1:-help}"
  case "$action" in
    check-only) run_check_only ;;
    install-verify) run_install_verify ;;
    verify-installed) run_verify_installed ;;
    help|-h|--help) usage ;;
    *) usage >&2; fail "unknown action: $action" ;;
  esac
}

main "$@"
