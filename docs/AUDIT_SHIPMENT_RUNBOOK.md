# Custodia audit shipment runbook

Custodia can verify an audit archive bundle and copy it into a sink directory with a shipment manifest.

## Inputs

Create a verified archive bundle first:

```bash
custodia-admin audit archive-export \
  --file custodia-audit.jsonl \
  --sha256-file custodia-audit.jsonl.sha256 \
  --events-file custodia-audit.jsonl.events \
  --archive-dir /var/lib/custodia/audit-archive
```

Ship the verified bundle:

```bash
custodia-admin audit ship-archive \
  --archive-dir /var/lib/custodia/audit-archive/20260102T030405Z \
  --sink-dir /mnt/worm/custodia-audit
```

## Output

The sink receives the original archive files plus `shipment.json` containing:

- source archive directory;
- destination sink directory;
- SHA-256 of each shipped file;
- artifact verification metadata.

## Boundary

This command verifies and copies artifacts. It does not make a normal filesystem immutable. Real WORM guarantees must come from the destination storage layer or SIEM/WORM platform policy.
