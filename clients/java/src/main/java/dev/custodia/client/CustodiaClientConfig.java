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
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import javax.net.ssl.SSLContext;

/** Public Java transport configuration for REST/mTLS calls. */
public final class CustodiaClientConfig {
    private final URI serverUrl;
    private final Path keyStorePath;
    private final char[] keyStorePassword;
    private final Path trustStorePath;
    private final char[] trustStorePassword;
    private final SSLContext sslContext;
    private final Duration timeout;
    private final String userAgent;

    private CustodiaClientConfig(Builder builder) {
        this.serverUrl = normalizeServerUrl(builder.serverUrl);
        this.keyStorePath = builder.keyStorePath;
        this.keyStorePassword = copy(builder.keyStorePassword);
        this.trustStorePath = builder.trustStorePath;
        this.trustStorePassword = copy(builder.trustStorePassword);
        this.sslContext = builder.sslContext;
        this.timeout = builder.timeout == null ? Duration.ofSeconds(15) : builder.timeout;
        this.userAgent = builder.userAgent == null || builder.userAgent.isBlank()
            ? "custodia-java-transport/0.0.0"
            : builder.userAgent;
        validate();
    }

    public static Builder builder() {
        return new Builder();
    }

    public URI serverUrl() {
        return serverUrl;
    }

    public Path keyStorePath() {
        return keyStorePath;
    }

    public char[] keyStorePassword() {
        return copy(keyStorePassword);
    }

    public Path trustStorePath() {
        return trustStorePath;
    }

    public char[] trustStorePassword() {
        return copy(trustStorePassword);
    }

    public SSLContext sslContext() {
        return sslContext;
    }

    public Duration timeout() {
        return timeout;
    }

    public String userAgent() {
        return userAgent;
    }

    private void validate() {
        if (serverUrl == null) {
            throw new IllegalArgumentException("serverUrl is required");
        }
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        if (sslContext == null) {
            if (keyStorePath == null) {
                throw new IllegalArgumentException("keyStorePath is required when sslContext is not set");
            }
            if (trustStorePath == null) {
                throw new IllegalArgumentException("trustStorePath is required when sslContext is not set");
            }
        }
    }

    private static URI normalizeServerUrl(URI value) {
        if (value == null) {
            return null;
        }
        String raw = value.toString();
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        return URI.create(raw);
    }

    private static char[] copy(char[] value) {
        return value == null ? null : Arrays.copyOf(value, value.length);
    }

    public static final class Builder {
        private URI serverUrl;
        private Path keyStorePath;
        private char[] keyStorePassword;
        private Path trustStorePath;
        private char[] trustStorePassword;
        private SSLContext sslContext;
        private Duration timeout;
        private String userAgent;

        private Builder() {}

        public Builder serverUrl(URI serverUrl) {
            this.serverUrl = serverUrl;
            return this;
        }

        public Builder keyStorePath(Path keyStorePath) {
            this.keyStorePath = keyStorePath;
            return this;
        }

        public Builder keyStorePassword(char[] keyStorePassword) {
            this.keyStorePassword = copy(keyStorePassword);
            return this;
        }

        public Builder trustStorePath(Path trustStorePath) {
            this.trustStorePath = trustStorePath;
            return this;
        }

        public Builder trustStorePassword(char[] trustStorePassword) {
            this.trustStorePassword = copy(trustStorePassword);
            return this;
        }

        public Builder sslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        public CustodiaClientConfig build() {
            return new CustodiaClientConfig(this);
        }
    }
}
