# Custodia audit archive runbook

Custodia can verify an audit export artifact and write an immutable-friendly archive bundle for downstream WORM/SIEM ingestion.

## Inputs

Generate export artifacts first:

```bash
vault-admin audit export \
  --out-file custodia-audit.jsonl \
  --sha256-out custodia-audit.jsonl.sha256 \
  --events-out custodia-audit.jsonl.events
```

Archive them locally after verification:

```bash
vault-admin audit archive-export \
  --file custodia-audit.jsonl \
  --sha256-file custodia-audit.jsonl.sha256 \
  --events-file custodia-audit.jsonl.events \
  --archive-dir /var/lib/custodia/audit-archive
```

The command refuses to archive artifacts when the body digest or event count does not match the sidecars.

## Output bundle

Each archive bundle contains:

- `custodia-audit.jsonl`
- `custodia-audit.jsonl.sha256`
- `custodia-audit.jsonl.events`
- `manifest.json`

The manifest records the archive timestamp and verification result. Copy the entire bundle to WORM object storage or forward it to a SIEM collector.

## Boundary

This tool does not make local disks WORM. It creates a verified bundle suitable for a WORM/SIEM pipeline.
