GO ?= go
VERSION ?= dev
COMMIT ?= unknown
DATE ?= unknown
LDFLAGS := -X custodia/internal/build.Version=$(VERSION) -X custodia/internal/build.Commit=$(COMMIT) -X custodia/internal/build.Date=$(DATE)

.PHONY: test
test:
	$(GO) test -p=1 -timeout 60s ./...

.PHONY: fmt
fmt:
	gofmt -w $$(find . -name '*.go')


.PHONY: check
check: test build
	python3 -m py_compile clients/python/custodia_client/__init__.py

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
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/vault-admin
	$(GO) build -ldflags "$(LDFLAGS)" ./cmd/custodia-signer

.PHONY: build-postgres
build-postgres:
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" ./cmd/custodia-server
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" ./cmd/vault-admin
	$(GO) build -tags postgres -ldflags "$(LDFLAGS)" ./cmd/custodia-signer

.PHONY: test-postgres
test-postgres:
	@if [ -z "$(TEST_CUSTODIA_POSTGRES_URL)" ]; then 		echo "TEST_CUSTODIA_POSTGRES_URL is required" >&2; 		exit 2; 	fi
	$(GO) test -tags postgres ./internal/store

.PHONY: run-signer-dev
run-signer-dev:
	CUSTODIA_SIGNER_DEV_INSECURE_HTTP=true \
	CUSTODIA_SIGNER_ADMIN_SUBJECTS=signer_admin \
	CUSTODIA_SIGNER_CA_CERT_FILE=./certs/vault-ca.pem \
	CUSTODIA_SIGNER_CA_KEY_FILE=./certs/vault-ca-key.pem \
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
	$(GO) run ./cmd/vault-admin production check --env-file "$(CUSTODIA_PRODUCTION_ENV_FILE)"

.PHONY: production-evidence-check
production-evidence-check:
	@if [ -z "$(CUSTODIA_PRODUCTION_ENV_FILE)" ]; then 		echo "CUSTODIA_PRODUCTION_ENV_FILE is required" >&2; 		exit 2; 	fi
	$(GO) run ./cmd/vault-admin production evidence-check --env-file "$(CUSTODIA_PRODUCTION_ENV_FILE)"

.PHONY: release-check
release-check:
	./scripts/release-check.sh
