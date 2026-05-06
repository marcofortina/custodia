# Custodia Lite configuration

Custodia Lite is a profile of the same Custodia codebase. It uses the same
configuration vocabulary as Full deployments and avoids parallel names such as
`CUSTODIA_DB_TYPE` or `CUSTODIA_LISTEN_API`.

## Config precedence

`custodia-server` loads configuration in this order:

1. defaults derived from `CUSTODIA_PROFILE` or `profile` in the YAML file;
2. YAML from `--config PATH` when provided;
3. environment variable overrides.

Example:

```bash
custodia-server --config /etc/custodia/config.yaml
```

The YAML format is intentionally flat and maps directly to the existing config
fields. Nested YAML is rejected so the file cannot drift into a second config
schema.

## Lite profile

```yaml
profile: lite
store_backend: sqlite
database_url: file:/var/lib/custodia/custodia.db
rate_limit_backend: memory
deployment_mode: lite-single-node
database_ha_target: none
web_mfa_required: true
web_passkey_enabled: false
signer_key_provider: file
```

See `deploy/examples/config.lite.yaml` for a complete example.

## Full profile

```yaml
profile: full
store_backend: postgres
rate_limit_backend: valkey
deployment_mode: production
signer_key_provider: pkcs11
```

See `deploy/examples/config.full.yaml` for a complete example.

## Security note

Lite reduces external runtime dependencies, not security boundaries. API mTLS,
Web MFA, opaque ciphertext handling, authorization grants and audit integrity
remain part of the same server model.


## SQLite Lite store build note

The `sqlite` store is scoped to the Lite/custom single-node profile. The default build is universal and includes the SQLite store used by Lite/custom single-node deployments. Keep `make build-sqlite` and `make test-sqlite` for focused diagnostics, but normal installs should use `make` or release packages.


## Operational guides

After choosing the Lite profile, use the dedicated operational guides:

- `docs/LITE_INSTALL.md` for secure single-node installation;
- `docs/LITE_CA_BOOTSTRAP.md` for local CA and certificate handling;
- `docs/LITE_BACKUP_RESTORE.md` for SQLite backup and restore;
- `docs/LITE_TO_FULL_UPGRADE.md` for the path toward Full deployments.

Lite keeps the same security model as Full. These guides only reduce external dependencies; they do not remove mTLS, Web MFA, audit integrity or the opaque crypto boundary.
