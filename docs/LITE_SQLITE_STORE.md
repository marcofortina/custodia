# Custodia Lite SQLite store

Custodia Lite uses `CUSTODIA_STORE_BACKEND=sqlite` for single-node persistence.
The SQLite backend is deliberately scoped to the Lite/custom single-node profile and is not a FULL/HA target.

## Build

The standard build includes the SQLite backend through the universal store build. Focused diagnostics can still exercise the SQLite-only tag path:

```bash
make build-sqlite
make test-sqlite
```

The SQLite store uses the `modernc.org/sqlite` driver dependency and the `database/sql` driver name `sqlite`.

## Configuration

```bash
CUSTODIA_PROFILE=lite
CUSTODIA_STORE_BACKEND=sqlite
CUSTODIA_DATABASE_URL=file:/var/lib/custodia/custodia.db
```

## Safety properties

The SQLite Lite store preserves the same logical model as the FULL store. It does not introduce a reduced Lite schema, does not remove versioning and does not weaken the audit or crypto boundary.

The store enables:

- WAL mode;
- busy timeout;
- foreign keys;
- a single persisted state snapshot that mirrors the in-process logical model.

## Backup

Use the installed `custodia-sqlite-backup` helper for online SQLite backups:

```bash
if [ -x /usr/local/sbin/custodia-sqlite-backup ]; then
  CUSTODIA_SQLITE_BACKUP=/usr/local/sbin/custodia-sqlite-backup
else
  CUSTODIA_SQLITE_BACKUP=/usr/sbin/custodia-sqlite-backup
fi

sudo -u custodia env \
  CUSTODIA_SQLITE_DB=/var/lib/custodia/custodia.db \
  CUSTODIA_SQLITE_BACKUP_DIR=/var/lib/custodia/backups \
  "$CUSTODIA_SQLITE_BACKUP"
```

The helper requires the `sqlite3` CLI and uses SQLite `.backup` rather than raw file copies. Stop Custodia before restoring a backup.
