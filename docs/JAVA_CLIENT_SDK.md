# Custodia Java SDK

`clients/java` contains the Java SDK. It includes a raw REST/mTLS transport client for opaque Custodia payloads and a high-level client-side crypto wrapper.

The high-level wrapper uses the shared v1 crypto contract: canonical AAD, AES-256-GCM content encryption and HPKE-v1 recipient envelopes. Plaintext, DEKs and private keys remain local to the caller.

## TLS configuration

The default client uses Java `SSLContext` through `java.net.http.HttpClient`.

Use either:

- an application-provided `SSLContext`; or
- a client identity keystore plus a Custodia CA trust store.

```java
var client = CustodiaClient.newClient(
    CustodiaClientConfig.builder()
        .serverUrl(URI.create("https://vault:8443"))
        .keyStorePath(Path.of("client.p12"))
        .keyStorePassword("changeit".toCharArray())
        .trustStorePath(Path.of("ca.p12"))
        .trustStorePassword("changeit".toCharArray())
        .build()
);
```

## Opaque secret payloads

```java
String response = client.createSecretPayload("""
    {"name":"db","ciphertext":"base64cipher","envelopes":[{"client_id":"self","envelope":"base64env"}]}
    """);

String secret = client.getSecretPayload("550e8400-e29b-41d4-a716-446655440000");
```

The client exposes transport methods for:

- client metadata;
- secret create/read/list/version/share flows;
- pending access grants;
- operational status/version/diagnostics;
- revocation status;
- audit event metadata and export artifacts.

## Security boundary

The Java SDK must not log plaintext, ciphertext, envelopes, DEKs, private keys, keystore passwords or passphrases.

It does not contact Custodia for recipient public keys and does not treat the server as a key directory.

## Verification

```bash
make test-java-client
```


## High-level crypto flow

```java
var privateKey = new CustodiaCrypto.X25519PrivateKeyHandle("client_alice", alicePrivateKeyBytes);
var crypto = client.withCrypto(new CustodiaCrypto.CryptoOptions(
    recipientId -> resolveRecipientPublicKeyOutOfBand(recipientId),
    new CustodiaCrypto.StaticPrivateKeyProvider(privateKey),
    null
));

crypto.createEncryptedSecret("db", plaintextBytes, List.of("client_bob"), CustodiaClient.PERMISSION_ALL);
var decrypted = crypto.readDecryptedSecret(secretId);
crypto.shareEncryptedSecret(secretId, "client_charlie", CustodiaClient.PERMISSION_READ);
```

The application must provide recipient public keys through `PublicKeyResolver`; Custodia is not a key directory.
