# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

GO ?= go
VERSION ?= dev
COMMIT ?= unknown
DATE ?= unknown
LDFLAGS := -X custodia/internal/build.Version=$(VERSION) -X custodia/internal/build.Commit=$(COMMIT) -X custodia/internal/build.Date=$(DATE)

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
	rm -rf bin dist custodia-server custodia-admin custodia-signer clients/rust/target
	rm -f ./*.test coverage.out

.PHONY: license-check
license-check:
	./scripts/check-license-headers.sh

.PHONY: check
check: license-check test build test-python-client test-node-client test-java-client test-cpp-client test-rust-client test-bash-client
	python3 -m py_compile clients/python/custodia_client/__init__.py clients/python/custodia_client/types.py clients/python/custodia_client/crypto.py
	node --check clients/node/src/index.js
	node --check clients/node/src/crypto.js
	bash -n clients/bash/custodia.sh

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
	bash clients/bash/tests/test_custodia_sh.sh

.PHONY: run-dev
run-dev:
	CUSTODIA_DEV_INSECURE_HTTP=true \
	CUSTODIA_HEALTH_ADDR=:8080 \
	CUSTODIA_STORE_BACKEND=memory \
	CUSTODIA_BOOTSTRAP_CLIENTS=client_alice:client_alice,client_bob:client_bob,admin:admin \
	CUSTODIA_ADMIN_CLIENT_IDS=admin \
	$(GO) run ./cmd/custodia-server

.PHONY: build
build:
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/custodia-server
	$(GO) build -ldflags "$(LDFLAGS)" -o custodia-admin ./cmd/custodia-admin
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/custodia-signer

.PHONY: build-postgres
build-postgres:
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" ./cmd/custodia-server
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" -o custodia-admin ./cmd/custodia-admin
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" ./cmd/custodia-signer

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

.PHONY: test-sqlite
test-sqlite: sqlite-driver-download
	$(GO) test -tags sqlite -p=1 -timeout 60s ./internal/store ./cmd/custodia-server

.PHONY: sqlite-backup
sqlite-backup:
	./scripts/sqlite-backup.sh

.PHONY: lite-upgrade-check
lite-upgrade-check:
	./scripts/lite-upgrade-check.sh
