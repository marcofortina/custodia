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
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;

/** Minimal high-level local-crypto example. */
public final class HighLevelCryptoExample {
    private HighLevelCryptoExample() {}

    public static void main(String[] args) throws Exception {
        byte[] alicePrivateKey = filledBytes(CustodiaCrypto.X25519_KEY_BYTES, 1);
        CustodiaCrypto.X25519PrivateKeyHandle aliceKey = new CustodiaCrypto.X25519PrivateKeyHandle("client_alice", alicePrivateKey);
        Map<String, CustodiaCrypto.RecipientPublicKey> recipients = Map.of(
            "client_alice",
            CustodiaCrypto.deriveX25519RecipientPublicKey("client_alice", alicePrivateKey)
        );

        CustodiaClient client = CustodiaClient.withTransport(config(), new ExampleTransport());
        CryptoCustodiaClient crypto = client.withCrypto(new CustodiaCrypto.CryptoOptions(
            new CustodiaCrypto.StaticPublicKeyResolver(recipients),
            new CustodiaCrypto.StaticPrivateKeyProvider(aliceKey),
            null
        ));

        crypto.createEncryptedSecretByKey(
            "default",
            "db",
            "local plaintext only".getBytes(StandardCharsets.UTF_8),
            List.of("client_alice"),
            CustodiaClient.PERMISSION_ALL
        );
    }

    private static CustodiaClientConfig config() throws Exception {
        return CustodiaClientConfig.builder()
            .serverUrl(URI.create("https://vault.example"))
            .sslContext(SSLContext.getDefault())
            .build();
    }

    private static byte[] filledBytes(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    private static final class ExampleTransport implements CustodiaClient.Transport {
        @Override
        public CustodiaClient.TransportResponse send(CustodiaClient.TransportRequest request) {
            return new CustodiaClient.TransportResponse(
                200,
                "{\"secret_id\":\"example\"}".getBytes(StandardCharsets.UTF_8),
                HttpHeaders.of(Map.of(), (key, value) -> true)
            );
        }
    }
}
