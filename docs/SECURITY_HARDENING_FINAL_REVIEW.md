# Security hardening final review

This checklist is the final human security review for a Custodia release
candidate. It complements automated tests, package smoke checks and production
evidence gates. It must be completed for the exact commit, packages, image and
Helm chart being promoted.

Custodia's core boundary remains unchanged: the server is metadata-only. A
review finding must never be closed by moving plaintext, DEKs, application
private keys, ciphertext rendering or server-side recipient-envelope generation
into the server or Web Console.

## When to run it

Run this review after the release-candidate gates in
[`RELEASE_READINESS_MATRIX.md`](RELEASE_READINESS_MATRIX.md) have passed and
before declaring a production-ready build.

Minimum evidence to attach:

- release commit SHA;
- package/image/Helm chart identifiers;
- `make release-check` output;
- `make helm-check` output when Kubernetes artifacts are published;
- DEB/RPM clean-install smoke output for published package formats;
- Lite backup/restore smoke output when Lite is supported;
- operator end-to-end smoke output;
- Kubernetes runtime smoke output when Kubernetes is supported;
- operational readiness smoke output against a bootstrapped endpoint;
- production check and production evidence-check output when making a
  production claim.

## Web Console and browser boundary

Verify:

- Web Console access requires admin mTLS.
- Web MFA is enabled before production exposure.
- Session cookies use secure attributes appropriate for HTTPS-only operation.
- Browser mutations are protected by same-origin `Origin`/`Referer` checks.
- Authenticated POST actions fail closed for cross-origin requests.
- `POST /web/login` is treated as a pre-session handoff: it may bypass the same-origin guard, but still requires admin mTLS and valid Web MFA before issuing a session.
- Logout invalidates the Web session.
- Web pages remain metadata-only.
- Secret metadata pages do not render plaintext, ciphertext, DEKs, recipient
  envelopes or private keys.
- Audit export downloads include SHA-256 and event-count evidence that is stored
  with the exported body.
- Client enrollment, client revoke, access revoke, CRL download and serial-check
  actions are audited.

Stop promotion when a Web page exposes secret material, bypasses admin mTLS/MFA,
or accepts cross-origin browser mutations.

## API, mTLS and revocation boundary

Verify:

- API clients require verified mTLS identities.
- Admin APIs require configured admin client identities.
- Revoked client certificate serials are rejected after CRL update.
- `custodia-admin revocation status` and the Web revocation page agree on CRL
  freshness and revoked serial counts.
- CRL serial-check drills include one good serial and one revoked serial.
- Public-key metadata remains discovery-only; operators do not treat server-held
  public keys as an implicit trust decision.
- Rate limiting uses a shared backend for production Full deployments.

Stop promotion when revoked clients can still use the API after CRL publication,
or when any API path returns plaintext, DEKs, application private keys or
server-generated recipient envelopes.

## Audit and evidence boundary

Verify:

- Every admin mutation has an audit event.
- Audit event metadata does not contain plaintext secrets, DEKs or private keys.
- Exported JSONL evidence verifies with the expected SHA-256 and event count.
- Archive/export/shipping jobs preserve audit integrity evidence.
- WORM/SIEM/Object Lock retention evidence is attached for production claims.
- Time synchronization and log retention responsibilities are documented for the
  target environment.

Stop promotion when an admin mutation is unaudited or audit evidence cannot be
verified end-to-end.

## Bare-metal and package hardening

Verify:

- Packaged systemd units match the hardened directives checked by
  `make systemd-hardening-check`.
- Server runtime directories are owned by the `custodia` service user and are not
  world-readable.
- CA keys, server keys and admin client keys are not group/world-readable.
- Package install smoke passes on full clean Debian/Ubuntu and Fedora/RHEL-like
  machines for every published package format.
- Minimized Debian images with `dpkg path-exclude` filters are not used as the
  final package documentation/manpage validation environment.
- Manpages and operator docs are installed by packages.

Stop promotion when installed package payload differs from the release manifest,
when systemd hardening regresses, or when key files are readable by unintended
users.

## Kubernetes and container hardening

Verify:

- Helm unsafe combinations fail closed before render.
- Lite Kubernetes uses one server replica and a PVC-backed SQLite database.
- Full Kubernetes uses external PostgreSQL/CockroachDB and shared Valkey.
- Server and signer run as separate deployments and services.
- Application pods do not require `kubectl exec` for normal admin workflows.
- Kubernetes Secrets, HSM/PKCS#11 integration and signer material are managed by
  the platform, not by ad-hoc Web Console actions.
- NetworkPolicy, ingress, service exposure and certificate SANs match the
  intended deployment boundary.
- Container images are scanned and pinned before production promotion.

Stop promotion when Lite data can live only on pod-local ephemeral storage, when
Full uses SQLite/memory backends, or when normal operations require shell access
inside application pods.

## External dependency evidence

Verify production evidence for:

- HSM/PKCS#11 or equivalent signer custody;
- WORM/SIEM/Object Lock retention;
- PostgreSQL/CockroachDB HA and restore drills;
- Valkey HA and failover drills;
- TLS certificate lifecycle and renewal process;
- off-host backup retention and restore rehearsal;
- disaster recovery RPO/RTO rehearsal;
- penetration testing or an explicit compensating risk decision.

SoftHSM and MinIO are acceptable for lab/smoke profiles only unless the operator
provides independent production governance evidence for that environment.

## Sign-off template

```text
Release candidate: <commit/package/image/chart identifiers>
Deployment target: bare-metal source | bare-metal package | Kubernetes
Runtime profile: lite | full | custom
Reviewer:
Date:

Automated gates attached: yes/no
Operator smoke attached: yes/no
Kubernetes runtime smoke attached: yes/no/not applicable
Package install smoke attached: yes/no/not applicable
Operational readiness smoke attached: yes/no
Production evidence attached: yes/no/not applicable

Findings:
- <finding id> <severity> <status> <owner> <decision>

Promotion decision: promote | block | promote with documented risk
```

Do not use this checklist to waive critical findings silently. Critical findings
block promotion unless the release scope is explicitly reduced so the affected
feature, package format or deployment target is not shipped.
