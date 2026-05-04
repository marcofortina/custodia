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
