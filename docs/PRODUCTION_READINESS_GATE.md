# Custodia production readiness gate

`custodia-admin production check` validates a production environment file before a deployment is promoted.

The gate is intentionally conservative: it rejects unsafe development defaults and requires the external dependencies expected by the Fort Knox roadmap.

## Usage

```bash
custodia-admin production check --env-file .env.production
```

or through Make:

```bash
CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-check
```

## Critical checks

The command fails on critical findings, including:

- insecure HTTP enabled for the API or signer;
- memory store instead of PostgreSQL/CockroachDB-compatible storage;
- memory rate limiter instead of Valkey;
- missing API mTLS material or client CRL;
- missing admin client IDs;
- web MFA disabled;
- missing TOTP/session secrets;
- missing audit shipment sink;
- signer key provider not set to `pkcs11`;
- missing signer mTLS, audit log or CRL distribution configuration.

## Warnings

Warnings currently cover HA metadata that cannot be proven locally, such as the named deployment topology and database HA target.

## Boundary

The readiness gate does not prove that a cloud bucket is WORM, that an HSM exists, or that a database is actually multi-region. It enforces the local deployment contract and makes unsafe defaults explicit before rollout.


## Example environment template

A production-readiness template is available at:

```bash
deploy/examples/production.env.example
```

Copy it to a private environment file, replace every placeholder, then run:

```bash
CUSTODIA_PRODUCTION_ENV_FILE=.env.production make production-check
```

The template intentionally includes external controls such as the WORM sink URI, HA database target and PKCS#11 signer provider. The readiness gate validates that these controls are declared; infrastructure evidence must still prove they exist.
