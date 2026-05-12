# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

GO ?= go
VERSION ?= dev
GIT_COMMIT := $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE := $(shell if [ -n "$(SOURCE_DATE_EPOCH)" ]; then date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ; else date -u +%Y-%m-%dT%H:%M:%SZ; fi)
COMMIT ?= $(GIT_COMMIT)
DATE ?= $(BUILD_DATE)
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man
SHAREDIR ?= $(PREFIX)/share/custodia
DOCDIR ?= $(PREFIX)/share/doc
SYSTEMDUNITDIR ?= /etc/systemd/system
INSTALL ?= install
SERVER_BUILD_TAGS ?= sqlite postgres
SERVER_BUILD_TAGS_FLAG = $(if $(strip $(SERVER_BUILD_TAGS)),-tags "$(SERVER_BUILD_TAGS)")
LDFLAGS := -X custodia/internal/build.Version=$(VERSION) -X custodia/internal/build.Commit=$(COMMIT) -X custodia/internal/build.Date=$(DATE)

.DEFAULT_GOAL := all

.PHONY: all
all: test build man build-sdk

.PHONY: test
test:
	$(GO) test -p=1 -timeout 60s ./...

.PHONY: test-client-crypto
test-client-crypto:
	$(GO) test -p=1 -timeout 60s ./internal/clientcrypto

.PHONY: fmt
fmt:
	gofmt -w $$(find . -name '*.go')


.PHONY: clean
clean:
	rm -rf bin build/man build/sdk dist custodia-server custodia-admin custodia-signer custodia-client clients/rust/target
	rm -f ./*.test coverage.out

.PHONY: license-check
license-check:
	./scripts/check-license-headers.sh

.PHONY: release-metadata-check
release-metadata-check:
	VERSION="$(VERSION)" COMMIT="$(COMMIT)" DATE="$(DATE)" ./scripts/check-build-metadata.sh

.PHONY: release
release: release-metadata-check all

.PHONY: systemd-hardening-check
systemd-hardening-check:
	./scripts/check-systemd-hardening.sh

.PHONY: audit-log-permissions-check
audit-log-permissions-check:
	./scripts/check-audit-log-permissions.sh

.PHONY: helm-check
helm-check:
	./scripts/helm-render-check.sh

.PHONY: check
check: license-check systemd-hardening-check audit-log-permissions-check helm-check test build test-python-client test-node-client test-java-client test-cpp-client test-rust-client test-bash-client
	python3 -m py_compile clients/python/custodia_client/__init__.py clients/python/custodia_client/types.py clients/python/custodia_client/crypto.py
	node --check clients/node/src/index.js
	node --check clients/node/src/crypto.js
	bash -n clients/bash/custodia.bash

.PHONY: test-python-client
test-python-client:
	python3 -m unittest discover -s clients/python/tests

.PHONY: test-node-client
test-node-client:
	npm test --prefix clients/node

.PHONY: test-java-client
test-java-client:
	rm -rf /tmp/custodia-java-client-classes
	mkdir -p /tmp/custodia-java-client-classes
	javac -d /tmp/custodia-java-client-classes $$(find clients/java/src/main/java clients/java/src/test/java -name '*.java' | sort)
	java -cp /tmp/custodia-java-client-classes dev.custodia.client.CustodiaClientTest
	java -cp /tmp/custodia-java-client-classes dev.custodia.client.CustodiaCryptoClientTest

.PHONY: test-cpp-client
test-cpp-client:
	@if ! pkg-config --exists libcurl openssl; then \
		echo "libcurl and OpenSSL development packages are required for test-cpp-client" >&2; \
		exit 2; \
	fi
	g++ -std=c++20 -Wall -Wextra -Werror -Iclients/cpp/include clients/cpp/src/client.cpp clients/cpp/src/crypto.cpp clients/cpp/test/client_test.cpp $$(pkg-config --cflags --libs libcurl openssl) -o /tmp/custodia-cpp-client-test
	/tmp/custodia-cpp-client-test

.PHONY: test-rust-client
test-rust-client:
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "cargo not found; skipping Rust client tests. Run make test-rust-client where Rust is installed." >&2; \
	else \
		cargo test --manifest-path clients/rust/Cargo.toml; \
	fi

.PHONY: test-bash-client
test-bash-client:
	bash clients/bash/tests/test_custodia_bash.sh

.PHONY: run-dev
run-dev:
	CUSTODIA_DEV_INSECURE_HTTP=true \
	CUSTODIA_HEALTH_ADDR=:8080 \
	CUSTODIA_STORE_BACKEND=memory \
	CUSTODIA_BOOTSTRAP_CLIENTS=client_alice:client_alice,client_bob:client_bob,admin:admin \
	CUSTODIA_ADMIN_CLIENT_IDS=admin \
	$(GO) run ./cmd/custodia-server

.PHONY: build
build: build-server build-client

.PHONY: build-server
build-server: sqlite-driver-download
	$(GO) build $(SERVER_BUILD_TAGS_FLAG) -ldflags "$(LDFLAGS)" ./cmd/custodia-server
	$(GO) build $(SERVER_BUILD_TAGS_FLAG) -ldflags "$(LDFLAGS)" -o custodia-admin ./cmd/custodia-admin
	$(GO) build $(SERVER_BUILD_TAGS_FLAG) -ldflags "$(LDFLAGS)" ./cmd/custodia-signer

.PHONY: build-client
build-client:
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/custodia-client

.PHONY: build-sdk
build-sdk:
	./scripts/build-sdk-snapshot.sh build/sdk

.PHONY: man
man:
	VERSION="$(VERSION)" COMMIT="$(COMMIT)" DATE="$(DATE)" ./scripts/build-manpages.sh

.PHONY: install
install: install-server install-client install-sdk

.PHONY: install-smoke
install-smoke:
	./scripts/install-smoke.sh

.PHONY: operator-e2e-smoke
operator-e2e-smoke:
	./scripts/operator-e2e-smoke.sh check-only

.PHONY: kubernetes-runtime-smoke
kubernetes-runtime-smoke:
	./scripts/kubernetes-runtime-smoke.sh check-only

.PHONY: install-server
install-server: install-server-binaries install-server-man install-server-systemd install-server-backup install-server-docs

.PHONY: install-client
install-client: install-client-binaries install-client-man install-client-docs

.PHONY: install-sdk
install-sdk: install-sdk-tree install-sdk-docs

.PHONY: install-binaries
install-binaries: install-server-binaries install-client-binaries

.PHONY: install-server-binaries
install-server-binaries:
	@for binary in custodia-server custodia-admin custodia-signer; do \
		[ -x "$$binary" ] || { echo "missing built binary $$binary; run make as a normal user before sudo make install" >&2; exit 2; }; \
	done
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 0755 custodia-server "$(DESTDIR)$(BINDIR)/custodia-server"
	$(INSTALL) -m 0755 custodia-admin "$(DESTDIR)$(BINDIR)/custodia-admin"
	$(INSTALL) -m 0755 custodia-signer "$(DESTDIR)$(BINDIR)/custodia-signer"

.PHONY: install-server-systemd
install-server-systemd:
	$(INSTALL) -d "$(DESTDIR)$(SYSTEMDUNITDIR)"
	sed 's|/usr/local/bin|$(BINDIR)|g' deploy/examples/custodia-server.service > "$(DESTDIR)$(SYSTEMDUNITDIR)/custodia-server.service"
	sed 's|/usr/local/bin|$(BINDIR)|g' deploy/examples/custodia-signer.service > "$(DESTDIR)$(SYSTEMDUNITDIR)/custodia-signer.service"
	chmod 0644 "$(DESTDIR)$(SYSTEMDUNITDIR)/custodia-server.service" "$(DESTDIR)$(SYSTEMDUNITDIR)/custodia-signer.service"


.PHONY: install-server-backup
install-server-backup:
	$(INSTALL) -d "$(DESTDIR)$(SBINDIR)"
	$(INSTALL) -m 0755 scripts/sqlite-backup.sh "$(DESTDIR)$(SBINDIR)/custodia-sqlite-backup"

.PHONY: install-server-docs
install-server-docs:
	$(INSTALL) -d "$(DESTDIR)$(DOCDIR)/custodia"
	$(INSTALL) -m 0644 LICENSE README.md docs/QUICKSTART.md docs/DOCTOR.md docs/LITE_PROFILE.md docs/LITE_INSTALL.md docs/LITE_CONFIG.md docs/LITE_BACKUP_RESTORE.md docs/PRODUCTION_CHECKLIST.md docs/RELEASE_CHECK.md "$(DESTDIR)$(DOCDIR)/custodia/"
	$(INSTALL) -m 0644 deploy/examples/custodia-server.lite.yaml "$(DESTDIR)$(DOCDIR)/custodia/custodia-server.lite.yaml.example"
	$(INSTALL) -m 0644 deploy/examples/custodia-server.full.yaml "$(DESTDIR)$(DOCDIR)/custodia/custodia-server.full.yaml.example"
	$(INSTALL) -m 0644 deploy/examples/custodia-signer.yaml "$(DESTDIR)$(DOCDIR)/custodia/custodia-signer.yaml.example"

.PHONY: install-client-binaries
install-client-binaries:
	@[ -x custodia-client ] || { echo "missing built binary custodia-client; run make build-client as a normal user before sudo make install-client" >&2; exit 2; }
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 0755 custodia-client "$(DESTDIR)$(BINDIR)/custodia-client"

.PHONY: install-man
install-man: install-server-man install-client-man

.PHONY: install-server-man
install-server-man:
	@for page in custodia-admin custodia-server custodia-signer; do \
		[ -f "build/man/man1/$$page.1" ] || { echo "missing manpage build/man/man1/$$page.1; run make man before sudo make install-server" >&2; exit 2; }; \
	done
	$(INSTALL) -d "$(DESTDIR)$(MANDIR)/man1"
	for page in custodia-admin custodia-server custodia-signer; do \
		$(INSTALL) -m 0644 "build/man/man1/$$page.1" "$(DESTDIR)$(MANDIR)/man1/$$page.1"; \
	done

.PHONY: install-client-man
install-client-man:
	@[ -f build/man/man1/custodia-client.1 ] || { echo "missing manpage build/man/man1/custodia-client.1; run make man before sudo make install-client" >&2; exit 2; }
	$(INSTALL) -d "$(DESTDIR)$(MANDIR)/man1"
	$(INSTALL) -m 0644 build/man/man1/custodia-client.1 "$(DESTDIR)$(MANDIR)/man1/custodia-client.1"

.PHONY: install-client-docs
install-client-docs:
	$(INSTALL) -d "$(DESTDIR)$(DOCDIR)/custodia-client"
	$(INSTALL) -m 0644 LICENSE README.md docs/CUSTODIA_CLIENT_CLI.md docs/DOCTOR.md "$(DESTDIR)$(DOCDIR)/custodia-client/"

.PHONY: install-sdk-tree
install-sdk-tree:
	@[ -d build/sdk/clients/go/pkg/client ] || { echo "missing SDK snapshot build/sdk; run make build-sdk before sudo make install-sdk" >&2; exit 2; }
	rm -rf "$(DESTDIR)$(SHAREDIR)/sdk"
	$(INSTALL) -d "$(DESTDIR)$(SHAREDIR)/sdk"
	cp -R build/sdk/. "$(DESTDIR)$(SHAREDIR)/sdk/"

.PHONY: install-sdk-docs
install-sdk-docs:
	$(INSTALL) -d "$(DESTDIR)$(DOCDIR)/custodia-sdk"
	$(INSTALL) -m 0644 LICENSE README.md docs/CLIENT_LIBRARIES.md docs/CLIENT_CRYPTO_SPEC.md docs/SDK_RELEASE_POLICY.md docs/GO_CLIENT_SDK.md docs/PYTHON_CLIENT_SDK.md docs/NODE_CLIENT_SDK.md docs/JAVA_CLIENT_SDK.md docs/CPP_CLIENT_SDK.md docs/RUST_CLIENT_SDK.md "$(DESTDIR)$(DOCDIR)/custodia-sdk/"

.PHONY: build-postgres
build-postgres:
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" ./cmd/custodia-server
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" -o custodia-admin ./cmd/custodia-admin
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" ./cmd/custodia-signer
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/custodia-client

.PHONY: test-postgres
test-postgres:
	@if [ -z "$(TEST_CUSTODIA_POSTGRES_URL)" ]; then 		echo "TEST_CUSTODIA_POSTGRES_URL is required" >&2; 		exit 2; 	fi
	$(GO) test -tags postgres ./internal/store

.PHONY: run-signer-dev
run-signer-dev:
	CUSTODIA_SIGNER_DEV_INSECURE_HTTP=true \
	CUSTODIA_SIGNER_ADMIN_SUBJECTS=signer_admin \
	CUSTODIA_SIGNER_CA_CERT_FILE=./certs/custodia-ca.pem \
	CUSTODIA_SIGNER_CA_KEY_FILE=./certs/custodia-ca-key.pem \
	$(GO) run ./cmd/custodia-signer

.PHONY: formal-check
formal-check:
	./scripts/check-formal.sh

.PHONY: production-check
production-check:
	@if [ -z "$(CUSTODIA_PRODUCTION_ENV_FILE)" ]; then \
		echo "CUSTODIA_PRODUCTION_ENV_FILE is required" >&2; \
		exit 2; \
	fi
	$(GO) run ./cmd/custodia-admin production check --env-file "$(CUSTODIA_PRODUCTION_ENV_FILE)"

.PHONY: production-evidence-check
production-evidence-check:
	@if [ -z "$(CUSTODIA_PRODUCTION_ENV_FILE)" ]; then 		echo "CUSTODIA_PRODUCTION_ENV_FILE is required" >&2; 		exit 2; 	fi
	$(GO) run ./cmd/custodia-admin production evidence-check --env-file "$(CUSTODIA_PRODUCTION_ENV_FILE)"

.PHONY: release-check
release-check:
	./scripts/release-check.sh

.PHONY: package-deb
package-deb:
	PACKAGE_FORMATS=deb ./scripts/package-linux.sh

.PHONY: package-rpm
package-rpm:
	PACKAGE_FORMATS=rpm ./scripts/package-linux.sh

.PHONY: package-linux
package-linux:
	PACKAGE_FORMATS="deb rpm" ./scripts/package-linux.sh

.PHONY: package-checksums
package-checksums:
	./scripts/package-checksums.sh

.PHONY: package-smoke
package-smoke:
	./scripts/package-smoke.sh

.PHONY: sbom
sbom:
	./scripts/generate-sbom.sh

.PHONY: softhsm-dev-token
softhsm-dev-token:
	./scripts/softhsm-dev-token.sh

.PHONY: pkcs11-bridge-check
pkcs11-bridge-check:
	bash -n scripts/pkcs11-sign-command.sh scripts/softhsm-dev-token.sh

.PHONY: minio-object-lock-smoke
minio-object-lock-smoke:
	./scripts/minio-object-lock-smoke.sh

.PHONY: k3s-cockroachdb-apply
k3s-cockroachdb-apply:
	kubectl apply -f deploy/k3s/cockroachdb/namespace.yaml
	kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-services.yaml
	kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-statefulset.yaml
	kubectl rollout status statefulset/cockroachdb -n custodia-db --timeout=180s
	kubectl apply -f deploy/k3s/cockroachdb/cockroachdb-init-job.yaml

.PHONY: k3s-cockroachdb-smoke
k3s-cockroachdb-smoke:
	./scripts/k3s-cockroachdb-smoke.sh

.PHONY: passkey-assertion-verifier-template-check
passkey-assertion-verifier-template-check:
	@printf '{"credential_id":"fixture"}' | ./scripts/passkey-assertion-verify-command.sh | grep '"valid":false' >/dev/null

.PHONY: sqlite-driver-download
sqlite-driver-download:
	$(GO) mod download

.PHONY: build-sqlite
build-sqlite: sqlite-driver-download
	$(GO) build -tags sqlite -ldflags "$(LDFLAGS)" ./cmd/custodia-server
	$(GO) build -tags sqlite -ldflags "$(LDFLAGS)" -o custodia-admin ./cmd/custodia-admin
	$(GO) build -tags sqlite -ldflags "$(LDFLAGS)" ./cmd/custodia-signer
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/custodia-client

.PHONY: test-sqlite
test-sqlite: sqlite-driver-download
	$(GO) test -tags sqlite -p=1 -timeout 60s ./internal/store ./cmd/custodia-server

.PHONY: sqlite-backup
sqlite-backup:
	./scripts/sqlite-backup.sh

.PHONY: lite-upgrade-check
lite-upgrade-check:
	./scripts/lite-upgrade-check.sh
