# End-to-end operator smoke

This runbook validates the public Custodia first-run workflow on disposable
release-candidate hosts. It is intentionally explicit: operators run each role on
the matching host and stop on the first mismatch between documentation, binaries
and runtime behavior.

The smoke is not part of `make release-check` because it installs binaries,
creates real runtime state, starts systemd units, creates client profiles and
writes Lite backup artifacts. Use disposable hosts or snapshots.

## Scope

Roles:

- `server`: bare-metal source install, Lite bootstrap, Web MFA, systemd and admin checks.
- `alice`: client-only source install, token enrollment, key publish, put/get and share source.
- `bob`: client-only source install, token enrollment, key publish and share target.
- `check-only`: local wiring check for the helper script.

The Kubernetes equivalent uses the Web Console to create enrollment tokens and
runs the Alice/Bob client roles from external client hosts. Do not `kubectl exec`
into application pods for normal onboarding.

## Safety guard

Destructive roles require:

```bash
export CUSTODIA_E2E_CONFIRM=YES
```

The helper refuses to run `server`, `alice` or `bob` without that variable.

## Server/admin host

Follow the source-install path from [`QUICKSTART.md`](QUICKSTART.md):

```bash
git clone https://github.com/marcofortina/custodia.git
cd custodia
make build-server man
sudo make install-server PREFIX=/usr/local
```

Prepare runtime directories exactly as documented in the Quickstart, then choose
a reachable server name. Do not use `localhost` for remote clients:

```bash
CUSTODIA_SERVER_NAME="$(hostname -f)"
```

Bootstrap Lite:

```bash
sudo -u custodia custodia-admin ca bootstrap-local \
  --out-dir /etc/custodia \
  --admin-client-id admin \
  --server-name "$CUSTODIA_SERVER_NAME" \
  --generate-ca-passphrase
```

Configure the first Web TOTP account:

```bash
sudo custodia-admin web totp configure --account admin
```

Start services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now custodia-server custodia-signer
sudo systemctl status custodia-server --no-pager
sudo systemctl status custodia-signer --no-pager
```

Admin checks:

```bash
sudo -u custodia custodia-admin doctor
sudo -u custodia custodia-admin status read
sudo -u custodia custodia-admin diagnostics read
```

Web Console checkpoint:

```text
https://SERVER_IP_OR_HOSTNAME:9443/web/login
```

Use the Web Console to create one enrollment token for Alice and one enrollment
token for Bob. In bare-metal CLI-only drills, the equivalent command is:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m
```

## Client host Alice

Install the client from source:

```bash
git clone https://github.com/marcofortina/custodia.git
cd custodia
make build-client man
sudo make install-client PREFIX=/usr/local
```

Enroll Alice. Use `--insecure` only for disposable lab runs where the local CA is
not trusted by the client host:

```bash
export ALICE_ID=client_alice
export CUSTODIA_SERVER_URL=https://SERVER_IP_OR_HOSTNAME:8443
export ALICE_ENROLLMENT_TOKEN=PASTE_TOKEN_HERE

custodia-client mtls enroll \
  --client-id "$ALICE_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$ALICE_ENROLLMENT_TOKEN" \
  --insecure
```

Generate and publish Alice's application public key metadata:

```bash
custodia-client key generate --client-id "$ALICE_ID"
custodia-client config write --client-id "$ALICE_ID"
custodia-client config check --client-id "$ALICE_ID"
custodia-client doctor --client-id "$ALICE_ID" --online
custodia-client key publish --client-id "$ALICE_ID"
```

Create and read a smoke secret:

```bash
export SMOKE_NAMESPACE=default
export SMOKE_KEY=alice-bob-demo
export ALICE_SECRET="$HOME/custodia-alice-secret.txt"
export ALICE_READBACK="$HOME/custodia-alice-readback.txt"

printf 'super secret demo value' > "$ALICE_SECRET"
chmod 600 "$ALICE_SECRET"

custodia-client secret put \
  --client-id "$ALICE_ID" \
  --namespace "$SMOKE_NAMESPACE" \
  --key "$SMOKE_KEY" \
  --value-file "$ALICE_SECRET"

custodia-client secret get \
  --client-id "$ALICE_ID" \
  --namespace "$SMOKE_NAMESPACE" \
  --key "$SMOKE_KEY" \
  --out "$ALICE_READBACK"

cat "$ALICE_READBACK"
```

## Client host Bob

Install the client from source, then enroll Bob with a separate token:

```bash
export BOB_ID=client_bob
export CUSTODIA_SERVER_URL=https://SERVER_IP_OR_HOSTNAME:8443
export BOB_ENROLLMENT_TOKEN=PASTE_TOKEN_HERE

custodia-client mtls enroll \
  --client-id "$BOB_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$BOB_ENROLLMENT_TOKEN" \
  --insecure

custodia-client key generate --client-id "$BOB_ID"
custodia-client config write --client-id "$BOB_ID"
custodia-client config check --client-id "$BOB_ID"
custodia-client doctor --client-id "$BOB_ID" --online
custodia-client key publish --client-id "$BOB_ID"
```

Set the shared logical identifiers on Bob explicitly. They do not magically cross
host boundaries:

```bash
export SMOKE_NAMESPACE=default
export SMOKE_KEY=alice-bob-demo
```

Before sharing, Bob must not be able to read Alice's secret:

```bash
if custodia-client secret get --client-id "$BOB_ID" --namespace "$SMOKE_NAMESPACE" --key "$SMOKE_KEY" --out "$HOME/custodia-bob-before-share.txt"; then
  echo "unexpected Bob access before share" >&2
  exit 1
fi
```

## Alice shares with Bob

Back on Alice, set Bob's client id explicitly:

```bash
export BOB_ID=client_bob
```

Share using Bob's server-published public key metadata:

```bash
custodia-client secret share \
  --client-id "$ALICE_ID" \
  --namespace "$SMOKE_NAMESPACE" \
  --key "$SMOKE_KEY" \
  --target-client-id "$BOB_ID" \
  --permissions read
```

## Bob reads the shared secret

```bash
export BOB_READBACK="$HOME/custodia-bob-readback.txt"

custodia-client secret get \
  --client-id "$BOB_ID" \
  --namespace "$SMOKE_NAMESPACE" \
  --key "$SMOKE_KEY" \
  --out "$BOB_READBACK"

cat "$BOB_READBACK"
```

Expected output:

```text
super secret demo value
```

## Revoke, deny and delete

Use the Web Console Secret Metadata page or CLI to revoke Bob's future access.
Then verify Bob is denied:

```bash
if custodia-client secret get --client-id "$BOB_ID" --namespace "$SMOKE_NAMESPACE" --key "$SMOKE_KEY" --out "$HOME/custodia-bob-after-revoke.txt"; then
  echo "unexpected Bob access after revoke" >&2
  exit 1
fi
```

Back on Alice, delete the smoke secret:

```bash
custodia-client secret delete \
  --client-id "$ALICE_ID" \
  --namespace "$SMOKE_NAMESPACE" \
  --key "$SMOKE_KEY"
```

## Lite backup checkpoint

For bare-metal Lite, run the SQLite backup workflow documented by the Quickstart
and [`LITE_PROFILE.md`](LITE_PROFILE.md). For Kubernetes Lite, use
[`KUBERNETES_LITE_BACKUP_RESTORE.md`](KUBERNETES_LITE_BACKUP_RESTORE.md): PVC
persistence is mandatory, but it is not a backup.

## Local wiring check

The repository helper provides a safe check-only target:

```bash
make operator-e2e-smoke
```

It validates that the helper wiring is present. It does not run the destructive
server/Alice/Bob roles.
