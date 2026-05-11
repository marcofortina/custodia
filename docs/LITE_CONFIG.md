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
custodia-server --config /etc/custodia/custodia-server.yaml
```

Runtime YAML groups settings into explicit sections such as `server`, `storage`, `rate_limit`, `web`, `tls`, `deployment` and `signer`. Flat top-level runtime scalar keys are rejected; unknown sections and unknown keys fail closed.

## Lite profile

```yaml
profile: lite

server:
  url: "https://custodia.example.internal:8443"

storage:
  backend: sqlite
  database_url: "file:/var/lib/custodia/custodia.db"

rate_limit:
  backend: memory

web:
  mfa_required: true
  passkey_enabled: false

deployment:
  mode: lite-single-node
  database_ha_target: none

signer:
  key_provider: file
```

See `deploy/examples/custodia-server.lite.yaml` for a complete example and `docs/CONFIG_REFERENCE.md` for the full structured YAML reference. The `server.url` value is the externally reachable API URL printed by `custodia-admin client enrollment create` and used by remote clients during enrollment.

## Full profile

```yaml
profile: full

storage:
  backend: postgres

rate_limit:
  backend: valkey

deployment:
  mode: production

signer:
  key_provider: pkcs11
```

See `deploy/examples/custodia-server.full.yaml` for a complete example.

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
