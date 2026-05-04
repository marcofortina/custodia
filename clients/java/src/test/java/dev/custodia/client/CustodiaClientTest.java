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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;

public final class CustodiaClientTest {
    public static void main(String[] args) throws Exception {
        routesOpaqueSecretPayloads();
        validatesHttpErrors();
        exportsAuditMetadataHeaders();
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
