export const PermissionShare: 1;
export const PermissionWrite: 2;
export const PermissionRead: 4;
export const PermissionAll: 7;

export type JsonObject = Record<string, unknown>;

export interface RecipientEnvelope {
  client_id: string;
  envelope: string;
}

export interface CustodiaClientOptions {
  serverUrl: string;
  certFile: string;
  keyFile: string;
  caFile: string;
  timeoutMs?: number;
  userAgent?: string;
  transport?: Transport;
}

export interface TransportRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs: number;
  certFile: string;
  keyFile: string;
  caFile: string;
}

export interface TransportResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export type Transport = (request: TransportRequest) => Promise<TransportResponse>;

export interface CreateSecretPayload {
  name: string;
  ciphertext: string;
  envelopes: RecipientEnvelope[];
  permissions?: number;
  crypto_metadata?: JsonObject;
  expires_at?: string;
}

export interface CreateSecretVersionPayload {
  ciphertext: string;
  envelopes: RecipientEnvelope[];
  permissions?: number;
  crypto_metadata?: JsonObject;
  expires_at?: string;
}

export interface ShareSecretPayload {
  version_id: string;
  target_client_id: string;
  envelope: string;
  permissions?: number;
  expires_at?: string;
}

export interface AccessGrantPayload {
  target_client_id: string;
  permissions?: number;
  version_id?: string;
  expires_at?: string;
}

export interface ActivateAccessPayload {
  envelope: string;
}

export interface ClientListFilters {
  limit?: number;
  active?: boolean;
}

export interface AuditEventFilters {
  limit?: number;
  outcome?: "success" | "failure" | "degraded";
  action?: string;
  actor_client_id?: string;
  resource_type?: string;
  resource_id?: string;
}

export interface AccessGrantRequestFilters {
  limit?: number;
  secret_id?: string;
  status?: "pending" | "activated" | "revoked" | "expired";
  client_id?: string;
  requested_by_client_id?: string;
}

export interface AuditExportArtifact {
  body: string;
  sha256: string;
  eventCount: string;
}

export class CustodiaHttpError extends Error {
  status: number;
  body: string;
  headers: Record<string, string>;
}

export class CustodiaClient {
  constructor(options: CustodiaClientOptions);
  currentClientInfo(): Promise<JsonObject>;
  listClientInfos(filters?: ClientListFilters): Promise<JsonObject>;
  getClientInfo(clientID: string): Promise<JsonObject>;
  createClientInfo(payload: JsonObject): Promise<JsonObject>;
  revokeClientInfo(payload: JsonObject): Promise<JsonObject>;
  createSecretPayload(payload: CreateSecretPayload): Promise<JsonObject>;
  getSecretPayload(secretID: string): Promise<JsonObject>;
  listSecretMetadata(limit?: number): Promise<JsonObject>;
  listSecretVersionMetadata(secretID: string, limit?: number): Promise<JsonObject>;
  listSecretAccessMetadata(secretID: string, limit?: number): Promise<JsonObject>;
  shareSecretPayload(secretID: string, payload: ShareSecretPayload): Promise<JsonObject>;
  createAccessGrant(secretID: string, payload: AccessGrantPayload): Promise<JsonObject>;
  activateAccessGrantPayload(secretID: string, targetClientID: string, payload: ActivateAccessPayload): Promise<JsonObject>;
  revokeAccess(secretID: string, clientID: string): Promise<JsonObject>;
  createSecretVersionPayload(secretID: string, payload: CreateSecretVersionPayload): Promise<JsonObject>;
  listAccessGrantMetadata(filters?: AccessGrantRequestFilters): Promise<JsonObject>;
  statusInfo(): Promise<JsonObject>;
  versionInfo(): Promise<JsonObject>;
  diagnosticsInfo(): Promise<JsonObject>;
  revocationStatusInfo(): Promise<JsonObject>;
  revocationSerialStatusInfo(serialHex: string): Promise<JsonObject>;
  listAuditEventMetadata(filters?: AuditEventFilters): Promise<JsonObject>;
  exportAuditEventArtifact(filters?: AuditEventFilters): Promise<AuditExportArtifact>;
}
