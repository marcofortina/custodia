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
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;

public final class CustodiaClientTest {
    public static void main(String[] args) throws Exception {
        routesOpaqueSecretPayloads();
        routesHighLevelCryptoByKey();
        validatesHttpErrors();
        exportsAuditMetadataHeaders();
        rejectsInvalidFilterLimit();
        validatesRequiredConfig();
    }

    private static void routesOpaqueSecretPayloads() throws Exception {
        CapturingTransport transport = new CapturingTransport(200, "{\"secret_id\":\"s1\"}");
        CustodiaClient client = CustodiaClient.withTransport(testConfig(), transport);

        String response = client.createSecretPayload("{\"ciphertext\":\"opaque\"}");

        assertEquals("POST", transport.lastRequest.method(), "method");
        assertEquals("https://vault.test/v1/secrets", transport.lastRequest.uri().toString(), "uri");
        assertEquals("application/json", transport.lastRequest.headers().get("Content-Type"), "content-type");
        assertEquals("{\"ciphertext\":\"opaque\"}", new String(transport.lastRequest.body(), StandardCharsets.UTF_8), "body");
        assertEquals("{\"secret_id\":\"s1\"}", response, "response");

        client.activateAccessGrantPayload("secret/one", "client one", "{\"envelope\":\"opaque\"}");
        assertEquals(
            "https://vault.test/v1/secrets/secret%2Fone/access-requests/client%20one/activate",
            transport.lastRequest.uri().toString(),
            "encoded activate path"
        );

        client.getSecretPayloadByKey("db01", "user:sys");
        assertEquals("https://vault.test/v1/secrets/by-key?namespace=db01&key=user%3Asys", transport.lastRequest.uri().toString(), "read by key path");

        client.shareSecretPayloadByKey("db01", "user:sys", "{\"target_client_id\":\"client_bob\"}");
        assertEquals("https://vault.test/v1/secrets/by-key/share?namespace=db01&key=user%3Asys", transport.lastRequest.uri().toString(), "share by key path");

        client.createSecretVersionPayloadByKey("db01", "user:sys", "{\"ciphertext\":\"opaque\"}");
        assertEquals("https://vault.test/v1/secrets/by-key/versions?namespace=db01&key=user%3Asys", transport.lastRequest.uri().toString(), "version by key path");

        client.revokeAccessByKey("db01", "user:sys", "client bob");
        assertEquals("https://vault.test/v1/secrets/by-key/access/client%20bob?namespace=db01&key=user%3Asys", transport.lastRequest.uri().toString(), "revoke by key path");

        client.deleteSecretByKey("db01", "user:sys", true);
        assertEquals("https://vault.test/v1/secrets/by-key?namespace=db01&key=user%3Asys&cascade=true", transport.lastRequest.uri().toString(), "delete by key path");
    }


    private static void routesHighLevelCryptoByKey() throws Exception {
        CapturingTransport transport = new CapturingTransport(200, "{\"secret_id\":\"s1\",\"version_id\":\"v1\"}");
        CustodiaClient client = CustodiaClient.withTransport(testConfig(), transport);
        var alicePrivate = filledBytes(CustodiaCrypto.X25519_KEY_BYTES, 1);
        var aliceKey = new CustodiaCrypto.X25519PrivateKeyHandle("client_alice", alicePrivate);
        Map<String, CustodiaCrypto.RecipientPublicKey> recipients = new LinkedHashMap<>();
        recipients.put("client_alice", CustodiaCrypto.deriveX25519RecipientPublicKey("client_alice", alicePrivate));
        var crypto = client.withCrypto(new CustodiaCrypto.CryptoOptions(
            new CustodiaCrypto.StaticPublicKeyResolver(recipients),
            new CustodiaCrypto.StaticPrivateKeyProvider(aliceKey),
            new FixedRandomSource()
        ));

        crypto.createEncryptedSecretByKey(
            "db01",
            "user:sys",
            "local plaintext".getBytes(StandardCharsets.UTF_8),
            List.of(),
            CustodiaClient.PERMISSION_ALL
        );

        String body = new String(transport.lastRequest.body(), StandardCharsets.UTF_8);
        assertEquals("POST", transport.lastRequest.method(), "crypto by-key method");
        assertEquals("https://vault.test/v1/secrets", transport.lastRequest.uri().toString(), "crypto by-key uri");
        assertContains(body, "\"namespace\":\"db01\"", "namespace payload");
        assertContains(body, "\"key\":\"user:sys\"", "key payload");
        assertContains(body, "\"secret_name\":\"db01/user:sys\"", "keyspace AAD payload");
        assertContains(body, "\"client_id\":\"client_alice\"", "owner envelope payload");
    }

    private static void validatesHttpErrors() throws Exception {
        CapturingTransport transport = new CapturingTransport(403, "{\"error\":\"forbidden\"}");
        CustodiaClient client = CustodiaClient.withTransport(testConfig(), transport);

        try {
            client.statusInfo();
            throw new AssertionError("expected CustodiaHttpError");
        } catch (CustodiaHttpError err) {
            assertEquals(403, err.statusCode(), "status");
            assertEquals("{\"error\":\"forbidden\"}", err.body(), "error body");
        }
    }

    private static void exportsAuditMetadataHeaders() throws Exception {
        CapturingTransport transport = new CapturingTransport(
            200,
            "event_id,action\n1,read\n",
            HttpHeaders.of(
                Map.of(
                    "X-Custodia-Audit-Export-SHA256", List.of("abc123"),
                    "X-Custodia-Audit-Export-Events", List.of("1")
                ),
                (key, value) -> true
            )
        );
        CustodiaClient client = CustodiaClient.withTransport(testConfig(), transport);

        Map<String, String> filters = new LinkedHashMap<>();
        filters.put("limit", "1");
        filters.put("outcome", "ok");
        CustodiaAuditExport export = client.exportAuditEventArtifact(filters);

        assertEquals("https://vault.test/v1/audit-events/export?limit=1&outcome=ok", transport.lastRequest.uri().toString(), "export uri");
        assertEquals("abc123", export.sha256(), "sha256");
        assertEquals("1", export.eventCount(), "event count");
        assertEquals("event_id,action\n1,read\n", new String(export.body(), StandardCharsets.UTF_8), "export body");
    }

    private static void rejectsInvalidFilterLimit() throws Exception {
        CustodiaClient client = CustodiaClient.withTransport(testConfig(), new CapturingTransport(200, "{}"));
        Map<String, String> filters = new LinkedHashMap<>();
        filters.put("limit", "not-a-number");
        try {
            client.exportAuditEventArtifact(filters);
            throw new AssertionError("expected invalid limit error");
        } catch (IllegalArgumentException err) {
            assertEquals("limit must be an integer", err.getMessage(), "limit error");
        }
    }

    private static void validatesRequiredConfig() {
        try {
            CustodiaClientConfig.builder().serverUrl(URI.create("https://vault.test")).build();
            throw new AssertionError("expected config validation error");
        } catch (IllegalArgumentException expected) {
            assertEquals(
                "keyStorePath is required when sslContext is not set",
                expected.getMessage(),
                "config validation"
            );
        }
    }

    private static CustodiaClientConfig testConfig() throws Exception {
        return CustodiaClientConfig.builder()
            .serverUrl(URI.create("https://vault.test/"))
            .sslContext(SSLContext.getDefault())
            .userAgent("test-agent")
            .build();
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (!expected.equals(actual)) {
            throw new AssertionError(label + ": expected <" + expected + "> but got <" + actual + ">");
        }
    }

    private static void assertContains(String haystack, String needle, String label) {
        if (!haystack.contains(needle)) {
            throw new AssertionError(label + ": expected body to contain <" + needle + "> but got <" + haystack + ">");
        }
    }

    private static byte[] filledBytes(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    private static final class FixedRandomSource implements CustodiaCrypto.RandomSource {
        private int value = 10;

        @Override
        public byte[] randomBytes(int length) {
            return filledBytes(length, value++);
        }
    }

    private static final class CapturingTransport implements CustodiaClient.Transport {
        private final int statusCode;
        private final byte[] body;
        private final HttpHeaders headers;
        private CustodiaClient.TransportRequest lastRequest;

        private CapturingTransport(int statusCode, String body) {
            this(statusCode, body, HttpHeaders.of(Map.of(), (key, value) -> true));
        }

        private CapturingTransport(int statusCode, String body, HttpHeaders headers) {
            this.statusCode = statusCode;
            this.body = body.getBytes(StandardCharsets.UTF_8);
            this.headers = headers;
        }

        @Override
        public CustodiaClient.TransportResponse send(CustodiaClient.TransportRequest request) {
            this.lastRequest = request;
            return new CustodiaClient.TransportResponse(statusCode, body, headers);
        }
    }
}
