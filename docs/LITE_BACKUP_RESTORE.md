# Custodia Lite backup and restore

Lite uses a single-node SQLite database, so backup and restore must be explicit
operator procedures.

## Online backup

Use the helper script to call SQLite online backup mode. Run it as the `custodia` service user so backup ownership and read boundaries match the running service:

```bash
sudo install -d -m 0750 -o custodia -g custodia /var/lib/custodia/backups
sudo -u custodia env \
  CUSTODIA_SQLITE_DB=/var/lib/custodia/custodia.db \
  CUSTODIA_SQLITE_BACKUP_DIR=/var/lib/custodia/backups \
  ./scripts/sqlite-backup.sh
```

This produces a timestamped `.db` copy using `sqlite3 .backup`.

## Restore

1. Stop Custodia.
2. Copy the selected backup over the database file.
3. Restore ownership and permissions.
4. Start Custodia.
5. Run a status read and audit verification.

Example:

```bash
sudo systemctl stop custodia-server
sudo cp /var/lib/custodia/backups/custodia-YYYYMMDD-HHMMSS.db /var/lib/custodia/custodia.db
sudo chown custodia:custodia /var/lib/custodia/custodia.db
sudo chmod 0640 /var/lib/custodia/custodia.db
sudo systemctl start custodia-server
```

## Audit artifacts

Back up audit exports and verification artifacts together with the database.
Lite does not enable WORM/SIEM by default, so the operator is responsible for
off-host or offline retention.

## Disaster recovery boundary

SQLite Lite is not HA. If the node is lost and no backup exists, Custodia cannot
recover local state. Move to FULL when automated failover or PITR is required.
