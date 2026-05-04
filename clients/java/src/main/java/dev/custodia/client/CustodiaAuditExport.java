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
import java.util.Arrays;

public final class CustodiaAuditExport {
    private final byte[] body;
    private final String sha256;
    private final String eventCount;

    public CustodiaAuditExport(byte[] body, String sha256, String eventCount) {
        this.body = body == null ? new byte[0] : Arrays.copyOf(body, body.length);
        this.sha256 = sha256 == null ? "" : sha256;
        this.eventCount = eventCount == null ? "" : eventCount;
    }

    public static CustodiaAuditExport from(byte[] body, HttpHeaders headers) {
        return new CustodiaAuditExport(
            body,
            headers.firstValue("X-Custodia-Audit-Export-SHA256").orElse(""),
            headers.firstValue("X-Custodia-Audit-Export-Events").orElse("")
        );
    }

    public byte[] body() {
        return Arrays.copyOf(body, body.length);
    }

    public String sha256() {
        return sha256;
    }

    public String eventCount() {
        return eventCount;
    }
}
