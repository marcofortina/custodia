/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

package dev.custodia.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class CustodiaClient {
    public static final int PERMISSION_SHARE = 1;
    public static final int PERMISSION_WRITE = 2;
    public static final int PERMISSION_READ = 4;
    public static final int PERMISSION_ALL = PERMISSION_SHARE | PERMISSION_WRITE | PERMISSION_READ;

    private final CustodiaClientConfig config;
    private final Transport transport;

    private CustodiaClient(CustodiaClientConfig config, Transport transport) {
        this.config = Objects.requireNonNull(config, "config");
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    public static CustodiaClient newClient(CustodiaClientConfig config) throws IOException, GeneralSecurityException {
        return new CustodiaClient(config, defaultTransport(config));
    }

    static CustodiaClient withTransport(CustodiaClientConfig config, Transport transport) {
        return new CustodiaClient(config, transport);
    }

    public CryptoCustodiaClient withCrypto(CustodiaCrypto.CryptoOptions options) {
        return new CryptoCustodiaClient(this, options);
    }

    public String currentClientInfo() throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("GET", "/v1/me", null);
    }

    public String listClientInfos(int limit, Boolean active) throws IOException, InterruptedException, CustodiaHttpError {
        validateOptionalLimit(limit);
        Map<String, String> filters = new LinkedHashMap<>();
        if (limit > 0) {
            filters.put("limit", Integer.toString(limit));
        }
        if (active != null) {
            filters.put("active", Boolean.toString(active));
        }
        return requestJson("GET", withQuery("/v1/clients", filters), null);
    }

    public String getClientInfo(String clientId) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("GET", "/v1/clients/" + pathEscape(clientId), null);
    }

    public String createClientInfo(String payloadJson) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("POST", "/v1/clients", payloadJson);
    }

    public String revokeClientInfo(String payloadJson) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("POST", "/v1/clients/revoke", payloadJson);
    }

    public String createSecretPayload(String payloadJson) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("POST", "/v1/secrets", payloadJson);
    }

    public String getSecretPayload(String secretId) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("GET", "/v1/secrets/" + pathEscape(secretId), null);
    }

    public String listSecretMetadata(int limit) throws IOException, InterruptedException, CustodiaHttpError {
        validateOptionalLimit(limit);
        Map<String, String> filters = new LinkedHashMap<>();
        if (limit > 0) {
            filters.put("limit", Integer.toString(limit));
        }
        return requestJson("GET", withQuery("/v1/secrets", filters), null);
    }

    public String listSecretVersionMetadata(String secretId, int limit) throws IOException, InterruptedException, CustodiaHttpError {
        validateOptionalLimit(limit);
        Map<String, String> filters = new LinkedHashMap<>();
        if (limit > 0) {
            filters.put("limit", Integer.toString(limit));
        }
        return requestJson("GET", withQuery("/v1/secrets/" + pathEscape(secretId) + "/versions", filters), null);
    }

    public String listSecretAccessMetadata(String secretId, int limit) throws IOException, InterruptedException, CustodiaHttpError {
        validateOptionalLimit(limit);
        Map<String, String> filters = new LinkedHashMap<>();
        if (limit > 0) {
            filters.put("limit", Integer.toString(limit));
        }
        return requestJson("GET", withQuery("/v1/secrets/" + pathEscape(secretId) + "/access", filters), null);
    }

    public String shareSecretPayload(String secretId, String payloadJson) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("POST", "/v1/secrets/" + pathEscape(secretId) + "/share", payloadJson);
    }

    public String createAccessGrant(String secretId, String payloadJson) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("POST", "/v1/secrets/" + pathEscape(secretId) + "/access-requests", payloadJson);
    }

    public String activateAccessGrantPayload(String secretId, String targetClientId, String payloadJson)
        throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson(
            "POST",
            "/v1/secrets/" + pathEscape(secretId) + "/access-requests/" + pathEscape(targetClientId) + "/activate",
            payloadJson
        );
    }

    public String revokeAccess(String secretId, String clientId) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("DELETE", "/v1/secrets/" + pathEscape(secretId) + "/access/" + pathEscape(clientId), null);
    }

    public String createSecretVersionPayload(String secretId, String payloadJson) throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("POST", "/v1/secrets/" + pathEscape(secretId) + "/versions", payloadJson);
    }

    public String listAccessGrantMetadata(Map<String, String> filters) throws IOException, InterruptedException, CustodiaHttpError {
        validateFilters(filters);
        return requestJson("GET", withQuery("/v1/access-requests", filters), null);
    }

    public String statusInfo() throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("GET", "/v1/status", null);
    }

    public String versionInfo() throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("GET", "/v1/version", null);
    }

    public String diagnosticsInfo() throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("GET", "/v1/diagnostics", null);
    }

    public String revocationStatusInfo() throws IOException, InterruptedException, CustodiaHttpError {
        return requestJson("GET", "/v1/revocation/status", null);
    }

    public String revocationSerialStatusInfo(String serialHex) throws IOException, InterruptedException, CustodiaHttpError {
        String trimmed = requireText(serialHex, "serialHex");
        Map<String, String> filters = new LinkedHashMap<>();
        filters.put("serial_hex", trimmed);
        return requestJson("GET", withQuery("/v1/revocation/serial", filters), null);
    }

    public String listAuditEventMetadata(Map<String, String> filters) throws IOException, InterruptedException, CustodiaHttpError {
        validateFilters(filters);
        return requestJson("GET", withQuery("/v1/audit-events", filters), null);
    }

    public CustodiaAuditExport exportAuditEventArtifact(Map<String, String> filters)
        throws IOException, InterruptedException, CustodiaHttpError {
        validateFilters(filters);
        TransportResponse response = requestRaw("GET", withQuery("/v1/audit-events/export", filters), null);
        return CustodiaAuditExport.from(response.body(), response.headers());
    }

    public String requestJson(String method, String path, String payloadJson)
        throws IOException, InterruptedException, CustodiaHttpError {
        return new String(requestRaw(method, path, payloadJson).body(), StandardCharsets.UTF_8);
    }

    public TransportResponse requestRaw(String method, String path, String payloadJson)
        throws IOException, InterruptedException, CustodiaHttpError {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", "application/json");
        headers.put("User-Agent", config.userAgent());
        byte[] body = new byte[0];
        if (payloadJson != null) {
            headers.put("Content-Type", "application/json");
            body = payloadJson.getBytes(StandardCharsets.UTF_8);
            headers.put("Content-Length", Integer.toString(body.length));
        }
        TransportResponse response = transport.send(new TransportRequest(method, config.serverUrl().resolve(path), headers, body));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new CustodiaHttpError(response.statusCode(), new String(response.body(), StandardCharsets.UTF_8), response.headers());
        }
        return response;
    }

    private static Transport defaultTransport(CustodiaClientConfig config) throws IOException, GeneralSecurityException {
        SSLContext sslContext = config.sslContext() == null ? loadSSLContext(config) : config.sslContext();
        HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(config.timeout())
            .sslContext(sslContext)
            .build();
        return request -> {
            HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri()).timeout(config.timeout());
            request.headers().forEach(builder::header);
            HttpRequest.BodyPublisher publisher = request.body().length == 0
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(request.body());
            HttpResponse<byte[]> response = httpClient.send(
                builder.method(request.method(), publisher).build(),
                HttpResponse.BodyHandlers.ofByteArray()
            );
            return new TransportResponse(response.statusCode(), response.body(), response.headers());
        };
    }

    private static SSLContext loadSSLContext(CustodiaClientConfig config) throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream input = Files.newInputStream(config.keyStorePath())) {
            keyStore.load(input, config.keyStorePassword());
        }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, config.keyStorePassword());

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream input = Files.newInputStream(config.trustStorePath())) {
            trustStore.load(input, config.trustStorePassword());
        }
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
        return sslContext;
    }

    private static String withQuery(String path, Map<String, String> filters) {
        if (filters == null || filters.isEmpty()) {
            return path;
        }
        StringJoiner query = new StringJoiner("&");
        filters.forEach((key, value) -> {
            if (value != null && !value.isBlank()) {
                query.add(queryEscape(key) + "=" + queryEscape(value));
            }
        });
        String encoded = query.toString();
        return encoded.isEmpty() ? path : path + "?" + encoded;
    }

    private static void validateOptionalLimit(int limit) {
        if (limit < 0) {
            throw new IllegalArgumentException("limit must be non-negative");
        }
    }

    private static void validateFilters(Map<String, String> filters) {
        if (filters == null) {
            return;
        }
        if (filters.containsKey("limit")) {
            int limit = Integer.parseInt(filters.get("limit"));
            validateOptionalLimit(limit);
        }
    }

    private static String pathEscape(String value) {
        return queryEscape(requireText(value, "path segment"));
    }

    private static String queryEscape(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value.trim();
    }

    @FunctionalInterface
    interface Transport {
        TransportResponse send(TransportRequest request) throws IOException, InterruptedException;
    }

    record TransportRequest(String method, URI uri, Map<String, String> headers, byte[] body) {
        TransportRequest {
            body = body == null ? new byte[0] : body.clone();
        }
    }

    record TransportResponse(int statusCode, byte[] body, HttpHeaders headers) {
        TransportResponse {
            body = body == null ? new byte[0] : body.clone();
            headers = headers == null ? HttpHeaders.of(Map.of(), (key, value) -> true) : headers;
        }
    }
}
