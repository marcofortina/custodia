# Security Policy

Custodia is designed around a strict boundary: the server authenticates and authorizes access to opaque ciphertext and envelope material, while plaintext, DEKs, private keys and recipient key trust remain client-side.

## Supported versions

Until the first stable release, security fixes target the default development branch and the latest tagged pre-release, if any.

After a stable release, supported versions will be documented here with explicit maintenance windows.

## Reporting a vulnerability

Do not open a public GitHub issue for vulnerabilities, suspected key leaks, bypasses, exploit details or sensitive configuration material.

Preferred reporting path:

1. Use GitHub private vulnerability reporting if it is enabled for this repository.
2. If private reporting is not available, contact the maintainer through the repository profile or GitHub account contact methods and ask for a private security coordination channel.

When reporting, include:

- affected commit, tag or package version;
- affected component, for example server, signer, admin CLI, SDK, packaging or deployment chart;
- minimal reproduction steps;
- expected impact;
- whether any secrets, certificates, keys or production data are involved.

Do not include real private keys, DEKs, plaintext secrets, production certificates, customer data or access tokens in reports.

## Security model reminders

Reports are especially important if they affect any of these boundaries:

- server-side plaintext handling;
- server-side DEK or private-key handling;
- public-key directory or key-substitution behavior;
- weakened mTLS authentication;
- authorization bypass for per-secret grants;
- audit chain integrity bypass;
- Web MFA/passkey bypass;
- package, CI or release artifact integrity.

## Disclosure process

The maintainer will acknowledge valid private reports, investigate impact and coordinate a fix. Public disclosure should wait until a fix or mitigation is available, unless there is active exploitation or another compelling safety reason.
