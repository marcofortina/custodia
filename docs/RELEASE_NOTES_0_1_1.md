# Custodia 0.1.1 release notes

Custodia 0.1.1 is a post-release stabilization update for the 0.1.x line.

This release is intentionally small: it keeps the 0.1.0 product surface and focuses on package smoke evidence, Kubernetes Lite smoke feedback, release runbook clarity and targeted runtime hardening found while validating the published 0.1.0 assets.

## Highlights

- DEB/RPM package smoke was run from published release assets on clean VMs.
- Kubernetes Lite smoke was run on a real single-node Kubernetes cluster.
- Kubernetes image build documentation now explicitly uses the SQLite/PostgreSQL build tags required by the universal server binary.
- Helm rendering now avoids invalid `rollingUpdate` fields when the deployment strategy is `Recreate`.
- Kubernetes containers now use a numeric non-root UID/GID that satisfies `runAsNonRoot` checks.
- Kubernetes server logging now uses stdout/stderr instead of file logging under `/var/log/custodia`.
- Empty `CUSTODIA_LOG_FILE` now explicitly disables file logging instead of falling back to the default log file path.
- Signer health probes no longer create repeated TLS handshake EOF noise in signer logs.
- Kubernetes Lite bootstraps the configured admin client mapping correctly for operational readiness checks.
- Kubernetes server resources are named explicitly as `custodia-custodia-server`, while signer resources remain `custodia-custodia-signer`.

## Package smoke evidence

The 0.1.1 stabilization work was driven by clean-machine package smoke checks against the published 0.1.0 release assets:

- Ubuntu noble DEB smoke passed.
- Fedora 44 RPM smoke passed.
- `SHA256SUMS` verification passed for downloaded release assets.
- `artifacts-manifest.json` validated as JSON.
- Package installation did not enable or start services automatically.

## Kubernetes Lite smoke evidence

Kubernetes Lite smoke passed on a real single-node Kubernetes cluster with a default `local-path` StorageClass:

- `make helm-check` passed.
- Helm fail-closed validations passed for unsafe Lite/Full combinations.
- Helm install completed successfully.
- Server and signer Deployments rolled out successfully.
- The Lite PVC was Bound and survived a server pod restart/reschedule.
- `kubernetes-runtime-smoke.sh cluster-check` passed.
- `operational-readiness-smoke.sh endpoint-check` passed for `/live`, `/ready`, admin status, diagnostics, revocation status and Web login reachability.

## Kubernetes naming

The server Deployment, Service and Pod names now include the server component explicitly:

```text
custodia-custodia-server
custodia-custodia-signer
```

The Lite PVC name remains unchanged as `custodia-custodia-data` to avoid unnecessary data-path churn.

## Upgrade notes

For Kubernetes Lite deployments created from earlier 0.1.0 chart renders, review the renamed server Service before reusing local port-forward or operational scripts:

```bash
kubectl -n custodia port-forward svc/custodia-custodia-server 18443:8443 19443:9443
```

The signer Service remains:

```text
custodia-custodia-signer:9444
```

If you are validating Kubernetes Lite from source, build the image with the universal store tags:

```bash
--build-arg GO_BUILD_TAGS="sqlite postgres"
```

## Release checks

Before publishing 0.1.1 artifacts, the following checks were run successfully on `master` after merging the stabilization branch:

```bash
git diff --check
make test
make helm-check
./scripts/release-check.sh
```

Additional targeted checks included:

```bash
go test ./internal/config ./cmd/custodia-server
go test ./internal/httpapi ./internal/webauth ./cmd/custodia-server
```

## Known scope limits

0.1.1 does not add a major product workflow. It is a stabilization release for 0.1.0 package, release and Kubernetes Lite readiness.

Production deployments still require operator-provided evidence for profile-specific dependencies such as HSM/PKCS#11, WORM/SIEM shipment, HA database topology, backup/restore drills, penetration testing and external revocation distribution where required by the deployment profile.
