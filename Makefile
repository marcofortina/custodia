GO ?= go

.PHONY: test
test:
	$(GO) test ./...

.PHONY: fmt
fmt:
	gofmt -w $$(find . -name '*.go')

.PHONY: run-dev
run-dev:
	CUSTODIA_DEV_INSECURE_HTTP=true \
	CUSTODIA_STORE_BACKEND=memory \
	CUSTODIA_BOOTSTRAP_CLIENTS=client_alice:client_alice,client_bob:client_bob,admin:admin \
	CUSTODIA_ADMIN_CLIENT_IDS=admin \
	$(GO) run ./cmd/custodia-server

.PHONY: build
build:
	$(GO) build ./cmd/custodia-server
	$(GO) build ./cmd/vault-admin

.PHONY: build-postgres
build-postgres:
	$(GO) build -tags postgres ./cmd/custodia-server
	$(GO) build -tags postgres ./cmd/vault-admin
