# Custodia Java client

This package contains the Java client for Custodia. It includes the raw REST/mTLS transport client and a high-level client-side crypto wrapper for AES-256-GCM content encryption plus HPKE-v1 recipient envelopes.

The crypto wrapper encrypts/decrypts locally and must not log plaintext, ciphertext, envelopes, DEKs, private keys or passphrases.

## TLS model

The Java standard library does not load a PEM client private key directly through `java.net.http.HttpClient`, so the default client configuration uses Java keystore material:

- `keyStorePath`: PKCS#12/JKS client identity containing the mTLS certificate and private key.
- `keyStorePassword`: password for the identity keystore.
- `trustStorePath`: PKCS#12/JKS trust store containing the Custodia CA.
- `trustStorePassword`: password for the trust store.

Applications that already own an `SSLContext` can pass it directly through `CustodiaClientConfig.builder().sslContext(...)`.

## Example

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

String response = client.createSecretPayload("""
    {"namespace":"default","key":"db","ciphertext":"base64cipher","envelopes":[{"client_id":"self","envelope":"base64env"}]}
    """);
String payload = client.getSecretPayloadByKey("default", "db");
```

## Boundary

Transport methods are opaque and do not inspect ciphertext, envelopes or `crypto_metadata`. High-level crypto methods encrypt/decrypt locally, use application-provided recipient public keys and never contact Custodia for key material.


## High-level crypto example

```java
var privateKey = new CustodiaCrypto.X25519PrivateKeyHandle("client_alice", alicePrivateKeyBytes);
var options = new CustodiaCrypto.CryptoOptions(
    recipientId -> resolveRecipientPublicKeyOutOfBand(recipientId),
    new CustodiaCrypto.StaticPrivateKeyProvider(privateKey),
    null
);
var crypto = client.withCrypto(options);

crypto.createEncryptedSecret(
    "db",
    "already local plaintext".getBytes(StandardCharsets.UTF_8),
    List.of("client_bob"),
    CustodiaClient.PERMISSION_ALL
);

var decrypted = crypto.readDecryptedSecret(secretId); // Legacy secret_id compatibility remains available.
```

Recipient public keys are still resolved by the application, not by Custodia.
