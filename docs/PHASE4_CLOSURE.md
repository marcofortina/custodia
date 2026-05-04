# Custodia Phase 4 closure

Phase 4 closes the Custodia Lite profile at repository level.

## Closed in the repository

- `CUSTODIA_PROFILE=lite|full|custom` profile defaults.
- `custodia-server --config PATH` flat YAML loading.
- Environment overrides after YAML.
- SQLite Lite store contract and build-tagged implementation.
- Fail-closed SQLite standard build guard.
- Lite installation, configuration, backup and restore documentation.
- Lite systemd and Docker Compose examples.
- SQLite online backup helper.
- Local CA bootstrap command and file-backed CA passphrase support.
- Lite to Full upgrade readiness checks.
- Full target environment example.

## Intentional boundaries

- SQLite is Lite/custom single-node only, not a Full/HA database target.
- Lite keeps API mTLS, Web MFA, audit integrity, authorization and the opaque crypto boundary.
- Lite does not require Valkey, PKCS#11/HSM, WORM/SIEM, k3s or MinIO at runtime.
- Full production still requires production readiness and external evidence gates.
- Lite to Full readiness checks do not perform data migration.

## Final verification

Run:

```bash
go test -p=1 -timeout 60s ./...
go build ./cmd/custodia-server ./cmd/vault-admin ./cmd/custodia-signer
python3 -m py_compile clients/python/custodia_client/__init__.py
bash -n scripts/release-check.sh scripts/check-formal.sh scripts/pkcs11-sign-command.sh scripts/softhsm-dev-token.sh scripts/minio-object-lock-smoke.sh scripts/k3s-cockroachdb-smoke.sh scripts/passkey-assertion-verify-command.sh scripts/sqlite-backup.sh scripts/lite-upgrade-check.sh
```

Optional Lite artifact checks require the SQLite build tag and driver dependency:

```bash
make build-sqlite
make test-sqlite
```

## Closure statement

Phase 4 is closed when the standard checks pass, Lite artifacts are built with
the SQLite tag for Lite deployments, and operators understand that Full
production still requires external infrastructure evidence.
