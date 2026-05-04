## Summary

<!-- Describe the change and why it is needed. -->

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Security hardening
- [ ] Documentation
- [ ] Packaging / release
- [ ] Test-only change
- [ ] Refactor with no behavior change

## Security boundary checklist

- [ ] This change does not introduce server-side plaintext handling.
- [ ] This change does not introduce server-side DEK/private-key handling.
- [ ] This change does not turn Custodia into a public-key directory or key-trust source.
- [ ] This change preserves mTLS authentication, authorization checks and audit integrity.
- [ ] Sensitive values are not logged, printed, added to fixtures or stored in generated artifacts.

## Tests

<!-- List commands run locally or explain why a test is not applicable. -->

```text

```

## Documentation

- [ ] README/docs updated where needed.
- [ ] SDK docs updated where needed.
- [ ] Packaging/deployment docs updated where needed.
- [ ] Not applicable.

## Release impact

- [ ] No package/API/schema compatibility impact.
- [ ] Package layout changed.
- [ ] Public SDK API changed.
- [ ] Database schema/migration changed.
- [ ] Operator action required.
