/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

package dev.custodia.client;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import javax.net.ssl.SSLContext;

public final class CustodiaCryptoClientTest {
    private static final byte[] ALICE_PRIVATE = b64("MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=");
    private static final byte[] ALICE_PUBLIC = b64("BPXykWLDGo3voY5udCIk7oBvwXGKJ4voWbpWIEArjzo=");
    private static final byte[] DEK_SINGLE = b64("UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=");
    private static final byte[] NONCE_SINGLE = b64("YWFhYWFhYWFhYWFh");
    private static final byte[] EPHEMERAL_SINGLE = b64("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=");

    public static void main(String[] args) throws Exception {
        validatesSharedCryptoVectors();
        createsEncryptedSecretWithDeterministicVectorPayload();
        readsDecryptedSecretWithPersistedAADMetadata();
    }

    private static void validatesSharedCryptoVectors() {
        CustodiaCrypto.CryptoMetadata metadata = new CustodiaCrypto.CryptoMetadata(
            CustodiaCrypto.CRYPTO_VERSION_V1,
            CustodiaCrypto.CONTENT_CIPHER_V1,
            CustodiaCrypto.ENVELOPE_SCHEME_HPKE_V1,
            "",
            null
        );
        byte[] aad = CustodiaCrypto.buildCanonicalAAD(metadata, new CustodiaCrypto.AADInputs("", "database-password", ""));
        assertEquals(
            "{\"version\":\"custodia.client-crypto.v1\",\"content_cipher\":\"aes-256-gcm\",\"envelope_scheme\":\"hpke-v1\",\"secret_name\":\"database-password\"}",
            new String(aad, StandardCharsets.UTF_8),
            "canonical aad"
        );
        assertEquals("32f7c1471093f0a85a963d5cfeaf3aeec8edcd52577175c6b4a826c5063144bf", CustodiaCrypto.canonicalAADSHA256(aad), "aad sha");
        assertBytes(ALICE_PUBLIC, CustodiaCrypto.deriveX25519PublicKey(ALICE_PRIVATE), "alice public key");

        byte[] plaintext = b64("ZGF0YWJhc2UgcGFzc3dvcmQ6IGNvcnJlY3QgaG9yc2UgYmF0dGVyeSBzdGFwbGU=");
        byte[] ciphertext = CustodiaCrypto.sealContentAES256GCM(DEK_SINGLE, NONCE_SINGLE, plaintext, aad);
        assertEquals(
            "94P22VzLbeb3J+osVz4T/Pr3Qx0LBv8TbYL/BKfId08ZJV6XCPThpSrEt2h4N+zSXBrZBDJM6o0a8r/q1gqj",
            CustodiaCrypto.encodeBase64(ciphertext),
            "ciphertext"
        );
        assertBytes(plaintext, CustodiaCrypto.openContentAES256GCM(DEK_SINGLE, NONCE_SINGLE, ciphertext, aad), "plaintext roundtrip");

        byte[] envelope = CustodiaCrypto.sealHPKEV1Envelope(ALICE_PUBLIC, EPHEMERAL_SINGLE, DEK_SINGLE, aad);
        assertEquals(
            "ehpOcJvwhaxJSroEabmx7aCrH3ixaqu3n/7akGI+hSIIS8IcAryGTNuiRs8bUbEeIim/t9y6DjZ/88RjRh0q2dWBY0/F6EA3484TSix3NNA=",
            CustodiaCrypto.encodeBase64(envelope),
            "envelope"
        );
        assertBytes(DEK_SINGLE, CustodiaCrypto.openHPKEV1Envelope(ALICE_PRIVATE, envelope, aad), "opened envelope");
    }

    private static void createsEncryptedSecretWithDeterministicVectorPayload() throws Exception {
        QueueTransport transport = new QueueTransport();
        transport.enqueue(200, "{\"secret_id\":\"s1\"}");
        CustodiaClient client = CustodiaClient.withTransport(testConfig(), transport);
        CryptoCustodiaClient crypto = client.withCrypto(testOptions(DEK_SINGLE, NONCE_SINGLE, EPHEMERAL_SINGLE));

        String response = crypto.createEncryptedSecret(
            "database-password",
            b64("ZGF0YWJhc2UgcGFzc3dvcmQ6IGNvcnJlY3QgaG9yc2UgYmF0dGVyeSBzdGFwbGU="),
            List.of(),
            CustodiaClient.PERMISSION_ALL
        );

        assertEquals("{\"secret_id\":\"s1\"}", response, "create response");
        String body = new String(transport.lastRequest.body(), StandardCharsets.UTF_8);
        assertContains(body, "\"name\":\"database-password\"", "create name");
        assertContains(body, "\"content_nonce_b64\":\"YWFhYWFhYWFhYWFh\"", "create nonce");
        assertContains(body, "\"ciphertext\":\"94P22VzLbeb3J+osVz4T/Pr3Qx0LBv8TbYL/BKfId08ZJV6XCPThpSrEt2h4N+zSXBrZBDJM6o0a8r/q1gqj\"", "create ciphertext");
        assertContains(body, "\"envelope\":\"ehpOcJvwhaxJSroEabmx7aCrH3ixaqu3n/7akGI+hSIIS8IcAryGTNuiRs8bUbEeIim/t9y6DjZ/88RjRh0q2dWBY0/F6EA3484TSix3NNA=\"", "create envelope");
    }

    private static void readsDecryptedSecretWithPersistedAADMetadata() throws Exception {
        QueueTransport transport = new QueueTransport();
        transport.enqueue(200, """
            {"secret_id":"550e8400-e29b-41d4-a716-446655440000","version_id":"660e8400-e29b-41d4-a716-446655440000","ciphertext":"d+Ub720HWc3YmYcZyQPyyd3EK2QHKMg7iaKMgGg6Ir5RRRmfzoUe","crypto_metadata":{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","content_nonce_b64":"Y2NjY2NjY2NjY2Nj","aad":{"secret_id":"550e8400-e29b-41d4-a716-446655440000","version_id":"660e8400-e29b-41d4-a716-446655440000"}},"envelope":"ze/YeDqRtEZkDi4flVmds15ISgBxvSGCs7YNCBLBDHDZczDrK3IdDIfEWJA8JD3ERLLFg1eklPtBfJ2tbctFNV8yFiD0BrjltlAaV/RogLk=","permissions":7}
            """.trim());
        CustodiaClient client = CustodiaClient.withTransport(testConfig(), transport);
        CryptoCustodiaClient crypto = client.withCrypto(testOptions());

        CryptoCustodiaClient.DecryptedSecret secret = crypto.readDecryptedSecret("550e8400-e29b-41d4-a716-446655440000");

        assertEquals("existing secret payload", secret.plaintextUtf8(), "decrypted plaintext");
        assertEquals("550e8400-e29b-41d4-a716-446655440000", secret.secretId(), "secret id");
        assertEquals(7, secret.permissions(), "permissions");
    }

    private static CustodiaCrypto.CryptoOptions testOptions(byte[]... randomValues) {
        CustodiaCrypto.X25519PrivateKeyHandle handle = new CustodiaCrypto.X25519PrivateKeyHandle("client_alice", ALICE_PRIVATE);
        Map<String, CustodiaCrypto.RecipientPublicKey> recipients = Map.of(
            "client_alice",
            CustodiaCrypto.deriveX25519RecipientPublicKey("client_alice", ALICE_PRIVATE)
        );
        return new CustodiaCrypto.CryptoOptions(
            new CustodiaCrypto.StaticPublicKeyResolver(recipients),
            new CustodiaCrypto.StaticPrivateKeyProvider(handle),
            new QueueRandomSource(randomValues)
        );
    }

    private static CustodiaClientConfig testConfig() throws Exception {
        return CustodiaClientConfig.builder()
            .serverUrl(URI.create("https://vault.test/"))
            .sslContext(SSLContext.getDefault())
            .userAgent("test-agent")
            .build();
    }

    private static byte[] b64(String value) {
        return Base64.getDecoder().decode(value);
    }

    private static void assertContains(String haystack, String needle, String label) {
        if (!haystack.contains(needle)) {
            throw new AssertionError(label + ": missing <" + needle + "> in <" + haystack + ">");
        }
    }

    private static void assertBytes(byte[] expected, byte[] actual, String label) {
        if (!java.util.Arrays.equals(expected, actual)) {
            throw new AssertionError(label + ": bytes differ");
        }
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (!expected.equals(actual)) {
            throw new AssertionError(label + ": expected <" + expected + "> but got <" + actual + ">");
        }
    }

    private static final class QueueRandomSource implements CustodiaCrypto.RandomSource {
        private final Queue<byte[]> values = new ArrayDeque<>();

        QueueRandomSource(byte[]... values) {
            for (byte[] value : values) {
                this.values.add(value);
            }
        }

        @Override
        public byte[] randomBytes(int length) {
            byte[] value = values.poll();
            if (value == null || value.length != length) {
                throw new IllegalArgumentException("missing deterministic random value");
            }
            return value;
        }
    }

    private static final class QueueTransport implements CustodiaClient.Transport {
        private final Queue<CustodiaClient.TransportResponse> responses = new ArrayDeque<>();
        private CustodiaClient.TransportRequest lastRequest;

        void enqueue(int statusCode, String body) {
            responses.add(new CustodiaClient.TransportResponse(
                statusCode,
                body.getBytes(StandardCharsets.UTF_8),
                HttpHeaders.of(Map.of(), (key, value) -> true)
            ));
        }

        @Override
        public CustodiaClient.TransportResponse send(CustodiaClient.TransportRequest request) {
            this.lastRequest = request;
            CustodiaClient.TransportResponse response = responses.poll();
            if (response == null) {
                throw new IllegalStateException("missing response");
            }
            return response;
        }
    }
}
