# Secret keyspace model

This document defines the Custodia namespace/key secret-addressing model.
User workflows address secrets by `namespace/key`; generated server identifiers are
internal storage, FK and audit details.


## Implementation status

Custodia treats `namespace/key` as the normal user-facing
addressing model across the client CLI, admin CLI, REST by-key routes, high-level
crypto SDKs and public transport SDK helpers. Generated `secret_id` values remain
internal storage, foreign-key and audit identifiers; normal client and operator
workflows should not require users to copy or pass them.

The metadata-only web console intentionally omits secret-id filtering from the access
request page. Operators can still filter by status, target client and requester without
exposing an internal identifier as a primary workflow concept.

The access-request workflow also exposes and filters by `namespace/key`, so web/API/SDK
operators can inspect pending/activated grants without using internal identifiers.

## Regression guardrails

The repository includes public SDK surface tests that reject reintroducing high-level
or public transport helpers whose normal workflow accepts `secret_id` instead of
`namespace/key`. This keeps unsupported `secret_id` and `name` aliases from leaking back into the
documented SDK surface.

## User-facing identity

Custodia user workflows address secrets by:

```text
namespace + key
```

The server authenticates the caller through mTLS and resolves `namespace/key` inside the
caller's visible keyspace. Users must not need to pass an owner client id for normal
read, update, share, revoke or delete flows.

Rules:

- `namespace` is a generic client-provided string.
- `namespace=default` is used when the caller omits a namespace.
- `key` is the exact logical key chosen by the client.
- The encrypted value remains opaque to the server.
- `put` creates a new key and never overwrites an existing visible key.
- `update` creates a new encrypted version of the resolved secret.
- `secret_id`, when retained, is an internal storage/FK/audit implementation detail.

Example:

```text
owner  namespace  key       value
alice  db01       user:sys  opaque client ciphertext
alice  db02       user:sys  opaque client ciphertext
bob    default    api-token opaque client ciphertext
```

## Visible keyspace

Every client has a visible keyspace keyed by `namespace/key`. A client cannot see two
secrets with the same `namespace/key`, even if they have different owners.

Recommended logical table:

```text
secret_visibility (
  client_id,
  namespace,
  key,
  secret_id,
  visibility_type, -- owner|shared
  granted_by,
  created_at,

  primary key(client_id, namespace, key),
  unique(client_id, secret_id)
)
```

This table is what allows Bob to read Alice's shared secret without passing Alice as the
owner:

```bash
custodia-client secret get --namespace db01 --key user:sys --out sys-db01.txt
```

Lookup:

```text
bob + db01 + user:sys -> Alice-owned secret visible to Bob
```

## Ownership and uniqueness

Secrets are owned by exactly one client. The owner key tuple must be unique:

```text
unique(owner_client_id, namespace, key)
```

The visible keyspace adds a second, user-facing uniqueness rule:

```text
unique(client_id, namespace, key)
```

Consequences:

- Alice may own `db01/user:sys` and `db02/user:sys`.
- Bob may own his own `db01/user:sys` only if Bob does not already see a shared
  `db01/user:sys`.
- Alice cannot share `db01/user:sys` to Bob if Bob already owns or sees
  `db01/user:sys`.
- Charlie cannot share another `db01/user:sys` to Bob while Bob already sees Alice's
  `db01/user:sys`.

Conflict error text should be explicit:

```text
409 Conflict: namespace/key already exists in your accessible keyspace
409 Conflict: target client already has namespace/key in its accessible keyspace
```

## Create, read and update

Create:

```bash
custodia-client secret put --namespace db01 --key user:sys --value-file sys-db01.txt
```

`put` succeeds only when the caller does not already see `db01/user:sys`. The caller is
added to `secret_visibility` as `owner` and receives the first encrypted version.

Read:

```bash
custodia-client secret get --namespace db01 --key user:sys --out sys-db01.txt
```

The server resolves the secret through the caller's visible keyspace, checks read access
and returns only ciphertext, crypto metadata and the caller's opaque envelope.

Update:

```bash
custodia-client secret update --namespace db01 --key user:sys --value-file sys-db01-v2.txt
```

`update` always creates a new version for the resolved owner secret. If Bob updates a
secret owned by Alice, ownership stays with Alice. Bob must have an explicit update grant
and must provide the recipient envelopes required for the new version.

## Share and revoke

Default share grants read access only:

```bash
custodia-client secret share --namespace db01 --key user:sys --to-client-id bob
```

Share must fail before changing ACLs when the target client already has the same
`namespace/key` in its visible keyspace.

Explicit update access is separate:

```bash
custodia-client secret share \
  --namespace db01 \
  --key user:sys \
  --to-client-id bob \
  --permissions read,update
```

`revoke` is owner/admin controlled. A shared recipient cannot revoke other recipients:

```bash
custodia-client secret revoke --namespace db01 --key user:sys --from-client-id bob
```

Revocation removes the target client's visibility and active grants. It does not make
already downloaded ciphertext/envelope material undecryptable. Strong revocation still
requires a new encrypted version excluding the revoked recipient.

## Delete semantics

`delete` depends on ownership:

- Owner + no active shares: delete the owner secret.
- Owner + active shares: fail with conflict unless `--cascade` is supplied.
- Non-owner shared recipient: remove only the caller's visibility/access to that secret.

Examples:

```bash
custodia-client secret delete --namespace db01 --key user:sys
custodia-client secret delete --namespace db01 --key user:sys --cascade
```

Recommended conflict for owner delete while shared:

```text
409 Conflict: secret is still shared; revoke recipients first or use --cascade
```

For a non-owner recipient, delete is a self-removal from the caller's keyspace. The owner
secret and other recipients remain unchanged.

## Database shape

Recommended internal shape:

```text
clients
  client_id primary key

secrets
  secret_id primary key          -- internal only
  owner_client_id references clients(client_id)
  namespace not null default 'default'
  key not null
  current_version_id
  deleted_at
  unique(owner_client_id, namespace, key)

secret_versions
  version_id primary key
  secret_id references secrets(secret_id)
  version_number
  ciphertext
  crypto_metadata
  created_by references clients(client_id)
  unique(secret_id, version_number)

secret_visibility
  client_id references clients(client_id)
  namespace not null
  key not null
  secret_id references secrets(secret_id)
  visibility_type not null       -- owner|shared
  granted_by references clients(client_id)
  primary key(client_id, namespace, key)
  unique(client_id, secret_id)

secret_grants
  secret_id references secrets(secret_id)
  grantee_client_id references clients(client_id)
  granted_by references clients(client_id)
  permission not null            -- read|update|share|admin
  revoked_at
  primary key(secret_id, grantee_client_id, permission)

secret_recipient_envelopes
  version_id references secret_versions(version_id)
  recipient_client_id references clients(client_id)
  envelope not null
  primary key(version_id, recipient_client_id)
```

`secret_recipient_envelopes` stores only the per-recipient encrypted DEK envelope for a
specific version. The server never sees the DEK in plaintext. When Bob reads a shared
secret, the server returns the ciphertext plus Bob's envelope for the active version;
Bob decrypts locally with his application private key.

## Crypto and AAD

Client crypto must bind metadata to the logical address, not to a user-visible UUID.
Current v1 AAD fields:

```text
crypto version
content cipher
envelope scheme
namespace
key
secret_version
```

The server still stores and returns opaque ciphertext, metadata and envelopes only. It
must not validate, decrypt or interpret the encrypted value.

## Audit vocabulary

Recommended event names:

```text
secret.put
secret.get
secret.update
secret.share
secret.revoke
secret.delete
secret.delete.cascade
secret.unmount
```

Audit records should include actor, owner, namespace, key, target client when present,
result and reason. They may include internal `secret_id` and `version_id` for operator
correlation, but those ids are not required in normal client workflows.
