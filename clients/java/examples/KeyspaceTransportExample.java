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
import java.util.Map;
import javax.net.ssl.SSLContext;

/** Minimal namespace/key transport example using opaque payloads. */
public final class KeyspaceTransportExample {
    private KeyspaceTransportExample() {}

    public static void main(String[] args) throws Exception {
        CustodiaClient client = CustodiaClient.withTransport(config(), new ExampleTransport());

        client.createSecretPayload("""
            {"namespace":"default","key":"db","ciphertext":"base64cipher","envelopes":[{"client_id":"self","envelope":"base64env"}]}
            """);
        client.getSecretPayloadByKey("default", "db");
        client.shareSecretPayloadByKey("default", "db", "{\"target_client_id\":\"client_bob\",\"permissions\":4}");
    }

    private static CustodiaClientConfig config() throws Exception {
        return CustodiaClientConfig.builder()
            .serverUrl(URI.create("https://vault.example"))
            .sslContext(SSLContext.getDefault())
            .build();
    }

    private static final class ExampleTransport implements CustodiaClient.Transport {
        @Override
        public CustodiaClient.TransportResponse send(CustodiaClient.TransportRequest request) {
            return new CustodiaClient.TransportResponse(
                200,
                "{}".getBytes(StandardCharsets.UTF_8),
                HttpHeaders.of(Map.of(), (key, value) -> true)
            );
        }
    }
}
