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

: "${GO:=go}"
: "${VERSION:=0.0.0-dev}"
: "${REVISION:=1}"
: "${COMMIT:=$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)}"
: "${DATE:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
: "${PACKAGE_FORMATS:=deb}"
: "${PACKAGE_NAMES:=server client sdk}"
: "${OUT_DIR:=$root_dir/dist/packages}"
: "${WORK_DIR:=$root_dir/dist/package-work}"
: "${ARCH:=$(uname -m)}"
: "${SERVER_BUILD_TAGS=sqlite postgres}"

ldflags="-X custodia/internal/build.Version=$VERSION -X custodia/internal/build.Commit=$COMMIT -X custodia/internal/build.Date=$DATE"

log() {
  printf 'package-linux: %s\n' "$*" >&2
}

has_word() {
  local needle="$1"
  shift
  for word in "$@"; do
    [ "$word" = "$needle" ] && return 0
  done
  return 1
}

normalize_deb_arch() {
  case "$1" in
    x86_64|amd64) printf amd64 ;;
    aarch64|arm64) printf arm64 ;;
    armv7l|armhf) printf armhf ;;
    *) printf '%s' "$1" ;;
  esac
}

normalize_rpm_arch() {
  case "$1" in
    x86_64|amd64) printf x86_64 ;;
    aarch64|arm64) printf aarch64 ;;
    armv7l|armhf) printf armv7hl ;;
    *) printf '%s' "$1" ;;
  esac
}

sanitize_rpm_version() {
  printf '%s' "$1" | tr '+-' '__' | tr -cd 'A-Za-z0-9._~'
}

rpm_changelog_date() {
  local epoch="${SOURCE_DATE_EPOCH:-}"
  if [ -z "$epoch" ]; then
    epoch="$(date -u +%s)"
  fi
  date -u -d "@$epoch" '+%a %b %e %Y'
}

server_build_tags_include() {
  case " $SERVER_BUILD_TAGS " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

build_tags_args() {
  if [ -n "$SERVER_BUILD_TAGS" ]; then
    printf '%s\n' -tags
    printf '%s\n' "$SERVER_BUILD_TAGS"
  fi
}

ensure_server_build_dependencies() {
  if server_build_tags_include sqlite; then
    log "ensuring SQLite driver module is available for universal server package"
    "$GO" mod download modernc.org/sqlite
  fi
}

prepare_server_build_source() {
  local build_src="$1"
  rm -rf "$build_src"
  mkdir -p "$build_src"
  tar \
    --exclude='./.git' \
    --exclude='./dist' \
    --exclude='./clients/rust/target' \
    -cf - . | tar -xf - -C "$build_src"
}

# Build binaries from a temporary copy when optional store tags are enabled so
# module resolution for tagged dependencies cannot mutate the working tree.
build_server_binaries() {
  mkdir -p "$WORK_DIR/bin"
  log "building Go server binaries with SERVER_BUILD_TAGS=${SERVER_BUILD_TAGS:-<none>}"
  local tags
  mapfile -t tags < <(build_tags_args)

  local build_root="$root_dir"
  local mod_args=()
  if server_build_tags_include sqlite; then
    build_root="$WORK_DIR/build-src"
    prepare_server_build_source "$build_root"
    # Resolve only the package build graph in the temporary tree.
    # Do not run `go mod tidy` here: it scans optional packages too and may
    # resolve unrelated backends to newer toolchains than this repository targets.
    (cd "$build_root" && "$GO" list -deps -mod=mod "${tags[@]}" ./cmd/custodia-server ./cmd/custodia-admin ./cmd/custodia-signer >/dev/null)
    mod_args=(-mod=mod)
  else
    ensure_server_build_dependencies
  fi

  (cd "$build_root" && "$GO" build -buildvcs=false "${mod_args[@]}" "${tags[@]}" -ldflags "$ldflags" -o "$WORK_DIR/bin/custodia-server" ./cmd/custodia-server)
  (cd "$build_root" && "$GO" build -buildvcs=false "${mod_args[@]}" "${tags[@]}" -ldflags "$ldflags" -o "$WORK_DIR/bin/custodia-admin" ./cmd/custodia-admin)
  (cd "$build_root" && "$GO" build -buildvcs=false "${mod_args[@]}" "${tags[@]}" -ldflags "$ldflags" -o "$WORK_DIR/bin/custodia-signer" ./cmd/custodia-signer)
}

build_manpages() {
  mkdir -p "$WORK_DIR/man/man1"
  log "building manual pages"
  VERSION="$VERSION" COMMIT="$COMMIT" DATE="$DATE" OUT_DIR="$WORK_DIR/man/man1" ./scripts/build-manpages.sh
}

install_manpages() {
  local stage="$1"
  shift
  local src="$WORK_DIR/man/man1"
  local name
  for name in "$@"; do
    if [ -f "$src/$name.1" ]; then
      install -d "$stage/usr/share/man/man1"
      gzip -n -c "$src/$name.1" > "$stage/usr/share/man/man1/$name.1.gz"
    fi
  done
}

build_client_binary() {
  mkdir -p "$WORK_DIR/bin"
  log "building Go client CLI"
  "$GO" build -buildvcs=false -ldflags "$ldflags" -o "$WORK_DIR/bin/custodia-client" ./cmd/custodia-client
}

stage_server() {
  local stage="$1"
  rm -rf "$stage"
  install -d "$stage/usr/bin" \
    "$stage/usr/sbin" \
    "$stage/usr/lib/systemd/system" \
    "$stage/usr/share/doc/custodia" \
    "$stage/etc/custodia" \
    "$stage/var/lib/custodia/backups" \
    "$stage/var/log/custodia"

  install -m 0755 "$WORK_DIR/bin/custodia-server" "$stage/usr/bin/custodia-server"
  install -m 0755 "$WORK_DIR/bin/custodia-admin" "$stage/usr/bin/custodia-admin"
  install -m 0755 "$WORK_DIR/bin/custodia-signer" "$stage/usr/bin/custodia-signer"
  install -m 0755 scripts/sqlite-backup.sh "$stage/usr/sbin/custodia-sqlite-backup"
  install -m 0644 LICENSE README.md "$stage/usr/share/doc/custodia/"
  install -m 0644 docs/QUICKSTART.md docs/DOCTOR.md docs/LITE_PROFILE.md docs/LITE_INSTALL.md docs/LITE_CONFIG.md docs/LITE_BACKUP_RESTORE.md docs/PRODUCTION_CHECKLIST.md docs/RELEASE_CHECK.md "$stage/usr/share/doc/custodia/"
  install -m 0644 deploy/examples/custodia-server.lite.yaml "$stage/usr/share/doc/custodia/custodia-server.lite.yaml.example"
  install -m 0644 deploy/examples/custodia-server.full.yaml "$stage/usr/share/doc/custodia/custodia-server.full.yaml.example"
  install -m 0644 deploy/examples/custodia-signer.yaml "$stage/usr/share/doc/custodia/custodia-signer.yaml.example"
  install_manpages "$stage" custodia-admin custodia-server custodia-signer

  cat > "$stage/usr/lib/systemd/system/custodia-server.service" <<'SERVICE'
[Unit]
Description=Custodia Vault Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=custodia
Group=custodia
ExecStart=/usr/bin/custodia-server --config /etc/custodia/custodia-server.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/custodia /var/log/custodia
ReadOnlyPaths=/etc/custodia
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SERVICE

  cat > "$stage/usr/lib/systemd/system/custodia-signer.service" <<'SERVICE'
[Unit]
Description=Custodia Certificate Signer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=custodia
Group=custodia
ExecStart=/usr/bin/custodia-signer --config /etc/custodia/custodia-signer.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/custodia
ReadWritePaths=/var/log/custodia
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
SERVICE
}

stage_client() {
  local stage="$1"
  rm -rf "$stage"
  install -d \
    "$stage/usr/bin" \
    "$stage/usr/share/doc/custodia-client"
  install -m 0755 "$WORK_DIR/bin/custodia-client" "$stage/usr/bin/custodia-client"
  install -m 0644 LICENSE README.md "$stage/usr/share/doc/custodia-client/"
  install -m 0644 docs/CUSTODIA_CLIENT_CLI.md docs/DOCTOR.md "$stage/usr/share/doc/custodia-client/"
  install_manpages "$stage" custodia-client
}

stage_sdk() {
  local stage="$1"
  rm -rf "$stage"
  install -d "$stage/usr/share/custodia/sdk" "$stage/usr/share/doc/custodia-sdk"
  ./scripts/build-sdk-snapshot.sh "$WORK_DIR/sdk"
  cp -R "$WORK_DIR/sdk/." "$stage/usr/share/custodia/sdk/"
  install -m 0644 LICENSE README.md "$stage/usr/share/doc/custodia-sdk/"
  install -m 0644 docs/CLIENT_LIBRARIES.md docs/CLIENT_CRYPTO_SPEC.md docs/SDK_RELEASE_POLICY.md docs/GO_CLIENT_SDK.md docs/PYTHON_CLIENT_SDK.md docs/NODE_CLIENT_SDK.md docs/JAVA_CLIENT_SDK.md docs/CPP_CLIENT_SDK.md docs/RUST_CLIENT_SDK.md "$stage/usr/share/doc/custodia-sdk/"
}

write_deb_control() {
  local pkg="$1"
  local arch="$2"
  local control_dir="$3"
  install -d "$control_dir"
  case "$pkg" in
    custodia-server)
      cat > "$control_dir/control" <<EOF_CONTROL
Package: custodia-server
Version: ${VERSION}-${REVISION}
Section: admin
Priority: optional
Architecture: ${arch}
Maintainer: Custodia maintainers <maintainers@example.invalid>
Depends: ca-certificates, adduser
Description: Custodia vault server and administration tools
 Custodia stores opaque encrypted secret payloads and authenticates API clients with mTLS.
 This package installs custodia-server, custodia-admin, custodia-signer, server documentation examples, the SQLite backup helper and systemd units.
EOF_CONTROL
      cat > "$control_dir/postinst" <<'EOF_POSTINST'
#!/bin/sh
set -e
if ! getent group custodia >/dev/null 2>&1; then
  addgroup --system custodia >/dev/null
fi
if ! getent passwd custodia >/dev/null 2>&1; then
  adduser --system --ingroup custodia --home /var/lib/custodia --shell /usr/sbin/nologin --no-create-home custodia >/dev/null
fi
install -d -m 0750 -o custodia -g custodia /var/lib/custodia /var/lib/custodia/backups /var/log/custodia
install -d -m 0750 -o root -g custodia /etc/custodia
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
exit 0
EOF_POSTINST
      chmod 0755 "$control_dir/postinst"
      ;;
    custodia-client)
      cat > "$control_dir/control" <<EOF_CONTROL
Package: custodia-client
Version: ${VERSION}-${REVISION}
Section: admin
Priority: optional
Architecture: ${arch}
Maintainer: Custodia maintainers <maintainers@example.invalid>
Depends: ca-certificates, curl
Description: Custodia encrypted secrets client CLI
 Custodia client tooling keeps plaintext, DEKs and private keys outside the server.
 This package installs the Go custodia-client CLI.
EOF_CONTROL
      ;;
    custodia-sdk)
      cat > "$control_dir/control" <<EOF_CONTROL
Package: custodia-sdk
Version: ${VERSION}-${REVISION}
Section: devel
Priority: optional
Architecture: all
Maintainer: Custodia maintainers <maintainers@example.invalid>
Depends: ca-certificates
Description: Custodia SDK source snapshots and crypto test vectors
 Custodia SDK source snapshots help application developers integrate with Custodia while keeping application cryptography client-side.
 This package installs SDK source snapshots, the sourceable Bash SDK helper, shared crypto test vectors and SDK documentation.
EOF_CONTROL
      ;;
  esac
}

build_deb() {
  local pkg="$1"
  local stage="$2"
  local arch="$3"
  local root="$WORK_DIR/deb/$pkg"
  rm -rf "$root"
  mkdir -p "$root"
  cp -a "$stage/." "$root/"
  write_deb_control "$pkg" "$arch" "$root/DEBIAN"
  mkdir -p "$OUT_DIR"
  local out="$OUT_DIR/${pkg}_${VERSION}-${REVISION}_${arch}.deb"
  log "building $out"
  dpkg-deb --root-owner-group --build "$root" "$out" >/dev/null
}

rpm_should_own_dir() {
  case "$1" in
    /etc/custodia|/var/lib/custodia|/var/lib/custodia/backups|/var/log/custodia|/usr/share/doc/custodia)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

rpm_file_list() {
  local stage="$1"
  find "$stage" -type d | sort | while read -r path; do
    local rel="${path#$stage}"
    [ -z "$rel" ] && continue
    if rpm_should_own_dir "$rel"; then
      printf '%%dir %s\n' "$rel"
    fi
  done
  find "$stage" \( -type f -o -type l \) | sort | while read -r path; do
    local rel="${path#$stage}"
    printf '%s\n' "$rel"
  done
}

build_rpm() {
  local pkg="$1"
  local stage="$2"
  local arch="$3"
  local rpm_version changelog_date
  rpm_version="$(sanitize_rpm_version "$VERSION")"
  changelog_date="$(rpm_changelog_date)"
  local top="$WORK_DIR/rpmbuild/$pkg"
  local spec="$WORK_DIR/$pkg.spec"
  rm -rf "$top"
  mkdir -p "$top/BUILD" "$top/BUILDROOT" "$top/RPMS" "$top/SOURCES" "$top/SPECS" "$top/SRPMS" "$OUT_DIR"

  local summary description requires pre post postun buildarch
  case "$pkg" in
    custodia-server)
      summary="Custodia vault server and administration tools"
      description="Custodia stores opaque encrypted secret payloads and authenticates API clients with mTLS. This package installs custodia-server, custodia-admin, custodia-signer, server documentation examples, the SQLite backup helper and systemd units."
      requires="Requires: ca-certificates"
      pre='getent group custodia >/dev/null 2>&1 || groupadd -r custodia
getent passwd custodia >/dev/null 2>&1 || useradd -r -g custodia -d /var/lib/custodia -s /sbin/nologin custodia
exit 0'
      post='install -d -m 0750 -o custodia -g custodia /var/lib/custodia /var/lib/custodia/backups /var/log/custodia
install -d -m 0750 -o root -g custodia /etc/custodia
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
exit 0'
      postun='if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
exit 0'
      buildarch="$arch"
      ;;
    custodia-client)
      summary="Custodia encrypted secrets client CLI"
      description="Custodia client tooling keeps plaintext, DEKs and private keys outside the server. This package installs the Go custodia-client CLI."
      requires="Requires: ca-certificates
Requires: curl"
      pre='exit 0'
      post='exit 0'
      postun='exit 0'
      buildarch="$arch"
      ;;
    custodia-sdk)
      summary="Custodia SDK source snapshots and crypto test vectors"
      description="Custodia SDK source snapshots help application developers integrate with Custodia while keeping application cryptography client-side. This package installs SDK source snapshots, the sourceable Bash SDK helper, shared crypto test vectors and SDK documentation."
      requires="Requires: ca-certificates"
      pre='exit 0'
      post='exit 0'
      postun='exit 0'
      buildarch="noarch"
      ;;
  esac

  {
    printf 'Name: %s\n' "$pkg"
    printf 'Version: %s\n' "$rpm_version"
    printf 'Release: %s%%{?dist}\n' "$REVISION"
    printf 'Summary: %s\n' "$summary"
    printf 'License: AGPL-3.0-only\n'
    printf 'BuildArch: %s\n' "$buildarch"
    printf 'AutoReqProv: no\n'
    printf '%s\n' "$requires"
    printf '\n%%description\n%s\n' "$description"
    printf '\n%%prep\n'
    printf '\n%%build\n'
    printf '\n%%install\nmkdir -p %%{buildroot}\ncp -a %q/. %%{buildroot}/\n' "$stage"
    printf '\n%%pre\n%s\n' "$pre"
    printf '\n%%post\n%s\n' "$post"
    printf '\n%%postun\n%s\n' "$postun"
    printf '\n%%files\n%%defattr(-,root,root,-)\n'
    rpm_file_list "$stage"
    printf '\n%%changelog\n* %s Custodia maintainers <maintainers@example.invalid> - %s-%s\n- Generated package.\n' "$changelog_date" "$rpm_version" "$REVISION"
  } > "$spec"

  log "building RPM for $pkg"
  rpmbuild -bb --define "_topdir $top" "$spec" >/dev/null
  find "$top/RPMS" -type f -name '*.rpm' -exec cp {} "$OUT_DIR/" \;
}

main() {
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR" "$OUT_DIR"

  local formats names
  # shellcheck disable=SC2206
  formats=($PACKAGE_FORMATS)
  # shellcheck disable=SC2206
  names=($PACKAGE_NAMES)

  if has_word rpm "${formats[@]}" && ! command -v rpmbuild >/dev/null 2>&1; then
    echo "rpmbuild is required for PACKAGE_FORMATS=rpm" >&2
    exit 2
  fi
  if has_word deb "${formats[@]}" && ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "dpkg-deb is required for PACKAGE_FORMATS=deb" >&2
    exit 2
  fi

  build_manpages

  local deb_arch rpm_arch
  deb_arch="$(normalize_deb_arch "$ARCH")"
  rpm_arch="$(normalize_rpm_arch "$ARCH")"

  if has_word server "${names[@]}"; then
    build_server_binaries
    local server_stage="$WORK_DIR/stage/custodia-server"
    stage_server "$server_stage"
    if has_word deb "${formats[@]}"; then build_deb custodia-server "$server_stage" "$deb_arch"; fi
    if has_word rpm "${formats[@]}"; then build_rpm custodia-server "$server_stage" "$rpm_arch"; fi
  fi

  if has_word clients "${names[@]}"; then
    log "PACKAGE_NAMES=clients is deprecated; building client and sdk packages"
    names+=(client sdk)
  fi

  if has_word client "${names[@]}"; then
    build_client_binary
    local client_stage="$WORK_DIR/stage/custodia-client"
    stage_client "$client_stage"
    if has_word deb "${formats[@]}"; then build_deb custodia-client "$client_stage" "$deb_arch"; fi
    if has_word rpm "${formats[@]}"; then build_rpm custodia-client "$client_stage" "$rpm_arch"; fi
  fi

  if has_word sdk "${names[@]}"; then
    local sdk_stage="$WORK_DIR/stage/custodia-sdk"
    stage_sdk "$sdk_stage"
    if has_word deb "${formats[@]}"; then build_deb custodia-sdk "$sdk_stage" "all"; fi
    if has_word rpm "${formats[@]}"; then build_rpm custodia-sdk "$sdk_stage" "noarch"; fi
  fi

  log "artifacts written to $OUT_DIR"
  find "$OUT_DIR" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) -print | sort
}

main "$@"
