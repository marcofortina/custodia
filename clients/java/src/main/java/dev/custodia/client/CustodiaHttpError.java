/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

package dev.custodia.client;

import java.net.http.HttpHeaders;

public final class CustodiaHttpError extends Exception {
    private final int statusCode;
    private final String body;
    private final HttpHeaders headers;

    public CustodiaHttpError(int statusCode, String body, HttpHeaders headers) {
        super("Custodia request failed with HTTP " + statusCode);
        this.statusCode = statusCode;
        this.body = body;
        this.headers = headers;
    }

    public int statusCode() {
        return statusCode;
    }

    public String body() {
        return body;
    }

    public HttpHeaders headers() {
        return headers;
    }
}
