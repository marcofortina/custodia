# Operational readiness smoke

The operational readiness smoke is a read-only release-candidate check for a
running Custodia deployment. It verifies that the operator-facing visibility
surface works before a system is considered ready for production rehearsal.

It is intentionally separate from `make release-check`: the real endpoint check
contacts a live server, requires admin mTLS material and writes normal audit
entries for status and diagnostics reads.

## Scope

The smoke checks:

- public liveness endpoint (`/live`);
- public readiness endpoint (`/ready`);
- admin mTLS operational status (`/v1/status`);
- admin mTLS runtime diagnostics (`/v1/diagnostics`);
- admin mTLS client revocation status (`/v1/revocation/status`);
- optional Web Console login page reachability (`/web/login`).

It does not:

- create clients;
- create enrollment tokens;
- read or write secrets;
- revoke clients or access grants;
- read Kubernetes Secrets;
- execute commands inside pods;
- validate database HA, HSM or WORM evidence by itself.

## Safe wiring check

Run this in the repository on any developer machine:

```bash
make operational-readiness-smoke
```

It only verifies that the helper and runbook exist.

## Bare-metal release-candidate check

Run after the server and signer are installed, bootstrapped and running:

```bash
export CUSTODIA_OPERATIONAL_CONFIRM=YES
export CUSTODIA_SERVER_URL=https://SERVER_IP_OR_HOSTNAME:8443
export CUSTODIA_WEB_URL=https://SERVER_IP_OR_HOSTNAME:9443
export CUSTODIA_ADMIN_CERT=/etc/custodia/admin.crt
export CUSTODIA_ADMIN_KEY=/etc/custodia/admin.key
export CUSTODIA_CA_CERT=/etc/custodia/ca.crt
```

From a source checkout, run:

```bash
sudo -E ./scripts/operational-readiness-smoke.sh endpoint-check
```

After `sudo make install-server`, the same helper is installed as:

```bash
sudo -E /usr/local/sbin/custodia-operational-readiness-smoke endpoint-check
```

After a DEB/RPM package install, run:

```bash
sudo -E /usr/sbin/custodia-operational-readiness-smoke endpoint-check
```

Bare-metal bootstrap intentionally restricts `/etc/custodia` and the admin
private key. Running the helper as an unprivileged user with the default
`/etc/custodia/...` paths will fail because the operator cannot read or even
traverse that directory. Use `sudo -E` for this local server smoke, or copy
`admin.crt`, `admin.key` and `ca.crt` into an operator-only temporary directory
with restrictive permissions and point the environment variables there.

The URL host must match a DNS name or IP address present in the server
certificate SANs. Do not use `localhost` when validating remote operators or
remote clients.

For a disposable lab with an untrusted local CA only, `--insecure`-equivalent
TLS behavior can be enabled explicitly:

```bash
export CUSTODIA_OPERATIONAL_INSECURE=YES
```

Do not use that setting for production rehearsal or real remote operators.

## Kubernetes release-candidate check

First validate the release with the Kubernetes runtime smoke:

```bash
export CUSTODIA_K8S_NAMESPACE=custodia
export CUSTODIA_HELM_RELEASE=custodia
export CUSTODIA_K8S_PROFILE=full
export CUSTODIA_K8S_CONFIRM=YES
./scripts/kubernetes-runtime-smoke.sh cluster-check
```

Then expose the API and Web Console through the intended ingress, load balancer
or temporary port-forward and run the same endpoint check from an operator
workstation:

```bash
export CUSTODIA_OPERATIONAL_CONFIRM=YES
export CUSTODIA_SERVER_URL=https://custodia-api.example.internal
export CUSTODIA_WEB_URL=https://custodia-web.example.internal
export CUSTODIA_ADMIN_CERT=$HOME/custodia-admin.crt
export CUSTODIA_ADMIN_KEY=$HOME/custodia-admin.key
export CUSTODIA_CA_CERT=$HOME/custodia-ca.crt

./scripts/operational-readiness-smoke.sh endpoint-check
```

The helper does not call `kubectl exec`, does not read Kubernetes Secrets and
does not install the Helm chart.

## Expected result

A successful run ends with:

```text
operational-readiness-smoke: OK
```

Failures should be treated as operator-visible release blockers. Typical causes
are:

- wrong DNS name or certificate SAN mismatch;
- missing admin mTLS certificate/key on the operator workstation;
- CA bundle not trusted by the workstation;
- server not ready because the store is unavailable;
- CRL file configured but unreadable or invalid;
- Web Console not exposed on the expected URL.

## Relationship with other checks

Use this smoke after repository and packaging checks pass:

```bash
go test ./...
make helm-check
make package-install-smoke
make lite-backup-restore-smoke
make operator-e2e-smoke
make kubernetes-runtime-smoke
make operational-readiness-smoke
```

For encrypted client workflows, use
[`END_TO_END_OPERATOR_SMOKE.md`](END_TO_END_OPERATOR_SMOKE.md). For cluster object
readiness, use [`KUBERNETES_RUNTIME_SMOKE.md`](KUBERNETES_RUNTIME_SMOKE.md). For
Lite backup/restore integrity, use
[`LITE_BACKUP_RESTORE_SMOKE.md`](LITE_BACKUP_RESTORE_SMOKE.md).
