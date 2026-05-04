/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

import { readFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { URL, URLSearchParams } from "node:url";
import { CryptoCustodiaClient } from "./crypto.js";

export const PermissionShare = 1;
export const PermissionWrite = 2;
export const PermissionRead = 4;
export const PermissionAll = PermissionShare | PermissionWrite | PermissionRead;

const CLIENT_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const AUDIT_TOKEN_RE = /^[A-Za-z0-9._:-]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class CustodiaHttpError extends Error {
  constructor(message, { status, body, headers }) {
    super(message);
    this.name = "CustodiaHttpError";
    this.status = status;
    this.body = body;
    this.headers = headers;
  }
}

export class CustodiaClient {
  constructor({
    serverUrl,
    certFile,
    keyFile,
    caFile,
    timeoutMs = 15000,
    userAgent = "custodia-node-transport/0.0.0",
    transport = defaultTransport,
  }) {
    if (!serverUrl) {
      throw new TypeError("serverUrl is required");
    }
    if (!certFile) {
      throw new TypeError("certFile is required");
    }
    if (!keyFile) {
      throw new TypeError("keyFile is required");
    }
    if (!caFile) {
      throw new TypeError("caFile is required");
    }
    this.serverUrl = normalizeServerUrl(serverUrl);
    this.certFile = certFile;
    this.keyFile = keyFile;
    this.caFile = caFile;
    this.timeoutMs = timeoutMs;
    this.userAgent = userAgent;
    this.transport = transport;
  }

  currentClientInfo() {
    return this.requestJSON("GET", "/v1/me");
  }

  listClientInfos({ limit, active } = {}) {
    validateOptionalLimit(limit);
    const query = queryParams({
      limit: limit == null ? undefined : String(limit),
      active: active == null ? undefined : String(Boolean(active)),
    });
    return this.requestJSON("GET", withQuery("/v1/clients", query));
  }

  getClientInfo(clientID) {
    return this.requestJSON("GET", `/v1/clients/${pathEscape(clientID)}`);
  }

  createClientInfo(payload) {
    return this.requestJSON("POST", "/v1/clients", payload);
  }

  revokeClientInfo(payload) {
    return this.requestJSON("POST", "/v1/clients/revoke", payload);
  }

  createSecretPayload(payload) {
    return this.requestJSON("POST", "/v1/secrets", payload);
  }

  getSecretPayload(secretID) {
    return this.requestJSON("GET", `/v1/secrets/${pathEscape(secretID)}`);
  }

  listSecretMetadata(limit) {
    validateOptionalLimit(limit);
    const query = queryParams({ limit: limit == null ? undefined : String(limit) });
    return this.requestJSON("GET", withQuery("/v1/secrets", query));
  }

  listSecretVersionMetadata(secretID, limit) {
    validateOptionalLimit(limit);
    const query = queryParams({ limit: limit == null ? undefined : String(limit) });
    return this.requestJSON("GET", withQuery(`/v1/secrets/${pathEscape(secretID)}/versions`, query));
  }

  listSecretAccessMetadata(secretID, limit) {
    validateOptionalLimit(limit);
    const query = queryParams({ limit: limit == null ? undefined : String(limit) });
    return this.requestJSON("GET", withQuery(`/v1/secrets/${pathEscape(secretID)}/access`, query));
  }

  shareSecretPayload(secretID, payload) {
    return this.requestJSON("POST", `/v1/secrets/${pathEscape(secretID)}/share`, payload);
  }

  createAccessGrant(secretID, payload) {
    return this.requestJSON("POST", `/v1/secrets/${pathEscape(secretID)}/access-requests`, payload);
  }

  activateAccessGrantPayload(secretID, targetClientID, payload) {
    return this.requestJSON(
      "POST",
      `/v1/secrets/${pathEscape(secretID)}/access-requests/${pathEscape(targetClientID)}/activate`,
      payload,
    );
  }

  revokeAccess(secretID, clientID) {
    return this.requestJSON("DELETE", `/v1/secrets/${pathEscape(secretID)}/access/${pathEscape(clientID)}`);
  }

  createSecretVersionPayload(secretID, payload) {
    return this.requestJSON("POST", `/v1/secrets/${pathEscape(secretID)}/versions`, payload);
  }

  listAccessGrantMetadata(filters = {}) {
    validateAccessGrantRequestFilters(filters);
    const query = queryParams({
      limit: filters.limit == null ? undefined : String(filters.limit),
      secret_id: filters.secret_id,
      status: filters.status,
      client_id: filters.client_id,
      requested_by_client_id: filters.requested_by_client_id,
    });
    return this.requestJSON("GET", withQuery("/v1/access-requests", query));
  }

  statusInfo() {
    return this.requestJSON("GET", "/v1/status");
  }

  versionInfo() {
    return this.requestJSON("GET", "/v1/version");
  }

  diagnosticsInfo() {
    return this.requestJSON("GET", "/v1/diagnostics");
  }

  revocationStatusInfo() {
    return this.requestJSON("GET", "/v1/revocation/status");
  }

  revocationSerialStatusInfo(serialHex) {
    if (!String(serialHex ?? "").trim()) {
      throw new TypeError("serialHex is required");
    }
    const query = queryParams({ serial_hex: String(serialHex).trim() });
    return this.requestJSON("GET", `/v1/revocation/serial?${query}`);
  }

  listAuditEventMetadata(filters = {}) {
    validateAuditEventFilters(filters);
    const query = queryParams({
      limit: filters.limit == null ? undefined : String(filters.limit),
      outcome: filters.outcome,
      action: filters.action,
      actor_client_id: filters.actor_client_id,
      resource_type: filters.resource_type,
      resource_id: filters.resource_id,
    });
    return this.requestJSON("GET", withQuery("/v1/audit-events", query));
  }

  async exportAuditEventArtifact(filters = {}) {
    validateAuditEventFilters(filters);
    const query = queryParams({
      limit: filters.limit == null ? undefined : String(filters.limit),
      outcome: filters.outcome,
      action: filters.action,
      actor_client_id: filters.actor_client_id,
      resource_type: filters.resource_type,
      resource_id: filters.resource_id,
    });
    const response = await this.requestRaw("GET", withQuery("/v1/audit-events/export", query));
    return {
      body: response.body,
      sha256: response.headers["x-custodia-audit-export-sha256"] ?? "",
      eventCount: response.headers["x-custodia-audit-export-events"] ?? "",
    };
  }


  withCrypto(options) {
    return new CryptoCustodiaClient(this, options);
  }

  async requestJSON(method, path, payload) {
    const response = await this.requestRaw(method, path, payload);
    if (!response.body) {
      return {};
    }
    return JSON.parse(response.body);
  }

  async requestRaw(method, path, payload) {
    const body = payload == null ? undefined : JSON.stringify(payload);
    const headers = {
      Accept: "application/json",
      "User-Agent": this.userAgent,
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(body).toString();
    }
    const response = await this.transport({
      method,
      url: new URL(path, this.serverUrl).toString(),
      headers,
      body,
      timeoutMs: this.timeoutMs,
      certFile: this.certFile,
      keyFile: this.keyFile,
      caFile: this.caFile,
    });
    if (response.status < 200 || response.status >= 300) {
      throw new CustodiaHttpError(`Custodia request failed with HTTP ${response.status}`, response);
    }
    return response;
  }
}

async function defaultTransport({ method, url, headers, body, timeoutMs, certFile, keyFile, caFile }) {
  const [cert, key, ca] = await Promise.all([readFile(certFile), readFile(keyFile), readFile(caFile)]);
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = httpsRequest(
      {
        method,
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port,
        path: `${parsed.pathname}${parsed.search}`,
        headers,
        cert,
        key,
        ca,
        minVersion: "TLSv1.2",
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: normalizeHeaders(res.headers),
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("Custodia request timed out")));
    req.on("error", reject);
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      normalized[key.toLowerCase()] = value.join(", ");
    } else if (value !== undefined) {
      normalized[key.toLowerCase()] = String(value);
    }
  }
  return normalized;
}

function normalizeServerUrl(serverUrl) {
  const parsed = new URL(serverUrl);
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString();
}

function pathEscape(value) {
  return encodeURIComponent(String(value));
}

function queryParams(params) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      query.set(key, value);
    }
  }
  return query.toString();
}

function withQuery(path, query) {
  return query ? `${path}?${query}` : path;
}

function validateAuditEventFilters(filters) {
  validateOptionalLimit(filters.limit);
  if (filters.outcome !== undefined && !["success", "failure", "degraded"].includes(filters.outcome)) {
    throw new TypeError("outcome must be success, failure or degraded when set");
  }
  if (filters.action !== undefined && !boundedToken(filters.action, 128)) {
    throw new TypeError("action filter is invalid");
  }
  if (filters.actor_client_id !== undefined && !CLIENT_ID_RE.test(filters.actor_client_id)) {
    throw new TypeError("actor client id filter is invalid");
  }
  if (filters.resource_type !== undefined && !boundedToken(filters.resource_type, 64)) {
    throw new TypeError("resource type filter is invalid");
  }
  if (filters.resource_id !== undefined) {
    const resourceID = String(filters.resource_id);
    if (!resourceID || resourceID.length > 256 || [...resourceID].some((ch) => ch.charCodeAt(0) < 32)) {
      throw new TypeError("resource id filter is invalid");
    }
  }
}

function validateAccessGrantRequestFilters(filters) {
  validateOptionalLimit(filters.limit);
  if (filters.secret_id !== undefined && !UUID_RE.test(String(filters.secret_id).toLowerCase())) {
    throw new TypeError("secret id filter is invalid");
  }
  if (filters.status !== undefined && !["pending", "activated", "revoked", "expired"].includes(filters.status)) {
    throw new TypeError("status filter is invalid");
  }
  if (filters.client_id !== undefined && !CLIENT_ID_RE.test(filters.client_id)) {
    throw new TypeError("client id filter is invalid");
  }
  if (filters.requested_by_client_id !== undefined && !CLIENT_ID_RE.test(filters.requested_by_client_id)) {
    throw new TypeError("requested by client id filter is invalid");
  }
}

function validateOptionalLimit(limit) {
  if (limit !== undefined && (limit <= 0 || limit > 500)) {
    throw new TypeError("limit must be between 1 and 500 when set");
  }
}

function boundedToken(value, maxLength) {
  return Boolean(value) && String(value).length <= maxLength && AUDIT_TOKEN_RE.test(value);
}

export * from "./crypto.js";
