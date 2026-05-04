# Contributing to Custodia

Thank you for considering a contribution to Custodia.

Custodia is a privacy-first, metadata-only vault for opaque ciphertext and envelope material. Contributions must preserve the security boundaries documented in `README.md` and `docs/SECURITY_MODEL.md`.

## License for contributions

Unless a separate written agreement says otherwise, contributions are accepted under the same license as the project:

```text
AGPL-3.0-only
```

By submitting a pull request, patch or other contribution, you confirm that you have the right to submit it and that you license it to the project under `AGPL-3.0-only`.

## Commercial licensing note

Custodia may offer commercial licensing, enterprise support or integration services separately from the public AGPL repository.

Substantial contributions that are intended to be included in commercial dual-licensed distributions may require a separate Contributor License Agreement or written permission. Do not submit code you are not willing to license under the public AGPL terms.

## Security expectations

Contributions must not add:

- plaintext secret handling on the server;
- server-side decrypt/unwrap capability;
- public-key directory behavior;
- DEK/wrapped-DEK handling;
- weakened mTLS, Web MFA, audit integrity or authorization checks.

Prefer small, reviewable patches with tests and documentation updates.
