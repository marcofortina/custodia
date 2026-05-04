# Custodia Java transport client

This package contains the initial Java transport client for Custodia. It is a raw REST/mTLS client: callers send and receive opaque JSON payloads that already contain ciphertext, envelopes and crypto metadata produced by application-side crypto code.

The client intentionally does not implement high-level encryption yet and must not log plaintext, ciphertext, envelopes, DEKs, private keys or passphrases.

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
    {"name":"db","ciphertext":"base64cipher","envelopes":[{"client_id":"self","envelope":"base64env"}]}
    """);
```

## Boundary

This package is transport-only. It does not resolve recipient public keys, decrypt envelopes, decrypt ciphertext or contact the server for key material.
