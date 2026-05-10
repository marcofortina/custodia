# Custodia doctor diagnostics

Custodia doctor commands are read-only diagnostics. They inspect local configuration,
file permissions, runtime directories and, when explicitly requested, systemd and
network reachability. They do not create files, modify permissions, start services
or repair configuration.

Use them when an installation does not start cleanly, when a signer cannot issue a
client certificate, or when a client profile fails before encrypted secret
operations.

## Admin doctor

Run the offline admin doctor first:

```bash
sudo -u custodia custodia-admin doctor \
  --server-config /etc/custodia/custodia-server.yaml \
  --signer-config /etc/custodia/custodia-signer.yaml
```

The offline check validates:

- server YAML parse and signer YAML parse;
- profile/backend coherence, for example Lite with SQLite and Full with PostgreSQL;
- required TLS, client CA, CRL, signer CA, signer key and passphrase files;
- private key and passphrase file modes;
- SQLite database directory and configured log directories;
- whether Web MFA is required for the operator console.

A typical failure includes a hint:

```text
[FAIL] signer CA key permissions: /etc/custodia/ca.key mode 0644 is too open
       Hint: use mode 0600 for private key/passphrase files
```

Exit codes:

```text
0  all checks passed
1  at least one check failed
2  command-line usage error
```

## systemd and network checks

Systemd and network checks are opt-in so the offline doctor stays safe in build,
container and CI environments:

```bash
sudo -u custodia custodia-admin doctor \
  --server-config /etc/custodia/custodia-server.yaml \
  --signer-config /etc/custodia/custodia-signer.yaml \
  --systemd \
  --network
```

`--systemd` checks:

- `custodia-server.service` active/enabled state;
- `custodia-signer.service` active/enabled state;
- whether `systemctl` is available.

`--network` checks local TCP reachability for the configured server and signer
listen addresses. It does not perform secret operations.

Custom unit names are supported for staging tests:

```bash
custodia-admin doctor \
  --server-config ./custodia-server.yaml \
  --signer-config ./custodia-signer.yaml \
  --systemd \
  --server-unit custodia-server.service \
  --signer-unit custodia-signer.service
```

## Client doctor

The client doctor validates a reusable local client profile:

```bash
custodia-client doctor --client-id client_alice
```

The default client doctor is offline. It validates:

- JSON profile parse;
- HTTPS server URL shape;
- mTLS certificate/key pair;
- CA bundle parse;
- local application crypto key parse;
- derived public-key fingerprint.

Use `--online` only when you want to test the configured server with mTLS:

```bash
custodia-client doctor --client-id client_alice --online
```

The online check performs a lightweight authenticated current-client request (`/v1/me`) with the configured non-admin mTLS identity. It should not be used as a secret read/write smoke test; use the Alice/Bob smoke runbook for that workflow.

## Related commands

Configuration validation checks only one daemon config file and does not inspect
the rest of the installation:

```bash
custodia-server config validate --config /etc/custodia/custodia-server.yaml
custodia-signer config validate --config /etc/custodia/custodia-signer.yaml
```

For a complete encrypted client workflow, see
[`CUSTODIA_ALICE_BOB_SMOKE.md`](CUSTODIA_ALICE_BOB_SMOKE.md).
