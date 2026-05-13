# Custodia Lite backup/restore smoke

This smoke validates the Lite SQLite backup/restore procedure without touching a
live Custodia service or `/var/lib/custodia`.

It creates a disposable SQLite database from the committed Lite schema, writes a
small metadata-only state row, runs the same `scripts/sqlite-backup.sh` helper used
by source installs and packages, then restores the backup into another disposable
database and verifies SQLite integrity plus payload continuity.

## Runbook metadata

| Field | Value |
| --- | --- |
| Audience | Release engineers validating the Lite SQLite backup/restore helper on disposable data. |
| Prerequisites | Repository checkout, sqlite3 and no dependency on live `/var/lib/custodia` state. |
| Outcome | A temporary SQLite backup/restore proof with integrity and payload continuity checks. |
| Do not continue if | You intend to restore a live production database; use the stopped-service restore runbook instead. |

## Scope

This smoke proves that:

- the committed SQLite Lite schema can initialize a fresh database;
- the backup helper can produce a usable SQLite `.backup` copy;
- the copied backup can be restored into a fresh database file;
- the restored database passes `PRAGMA integrity_check`;
- server-side metadata continuity is preserved.

It does not prove a production backup schedule, off-host retention, encrypted
backup storage or Kubernetes PVC snapshot correctness. Those remain operator
controls and must be evidenced separately.

## Safe wiring check

`make release-check` runs a syntax check only. The safe local wiring check is:

```bash
make lite-backup-restore-smoke
```

That calls:

```bash
./scripts/lite-backup-restore-smoke.sh check-only
```

## Disposable smoke

Run the full disposable smoke with:

```bash
./scripts/lite-backup-restore-smoke.sh smoke
```

Expected result:

```text
lite-backup-restore-smoke: OK
```

To inspect the temporary files, keep the work directory:

```bash
CUSTODIA_LITE_BACKUP_RESTORE_KEEP=true ./scripts/lite-backup-restore-smoke.sh smoke
```

## Live Lite restore remains manual

Live restore remains the operator procedure in
[`LITE_BACKUP_RESTORE.md`](LITE_BACKUP_RESTORE.md): stop the service, copy the
selected backup over the database, restore ownership and permissions, restart the
service and run status plus audit verification.

Never restore over a live SQLite database while `custodia-server` is running.
