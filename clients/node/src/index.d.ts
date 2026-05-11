/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

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
  namespace?: string;
  key?: string;
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
  getSecretPayloadByKey(namespace: string, key: string): Promise<JsonObject>;
  listSecretMetadata(limit?: number): Promise<JsonObject>;
  shareSecretPayloadByKey(namespace: string, key: string, payload: ShareSecretPayload): Promise<JsonObject>;
  createAccessGrant(secretID: string, payload: AccessGrantPayload): Promise<JsonObject>;
  activateAccessGrantPayload(secretID: string, targetClientID: string, payload: ActivateAccessPayload): Promise<JsonObject>;
  createSecretVersionPayloadByKey(namespace: string, key: string, payload: CreateSecretVersionPayload): Promise<JsonObject>;
  deleteSecretPayloadByKey(namespace: string, key: string, options?: { cascade?: boolean }): Promise<JsonObject>;
  listAccessGrantMetadata(filters?: AccessGrantRequestFilters): Promise<JsonObject>;
  statusInfo(): Promise<JsonObject>;
  versionInfo(): Promise<JsonObject>;
  diagnosticsInfo(): Promise<JsonObject>;
  revocationStatusInfo(): Promise<JsonObject>;
  revocationSerialStatusInfo(serialHex: string): Promise<JsonObject>;
  listAuditEventMetadata(filters?: AuditEventFilters): Promise<JsonObject>;
  exportAuditEventArtifact(filters?: AuditEventFilters): Promise<AuditExportArtifact>;
  withCrypto(options: CryptoOptions): CryptoCustodiaClient;
}

export const CryptoVersionV1: "custodia.client-crypto.v1";
export const ContentCipherV1: "aes-256-gcm";
export const EnvelopeSchemeHPKEV1: "hpke-v1";
export const AES256GCMKeyBytes: 32;
export const AESGCMNonceBytes: 12;
export const AESGCMTagBytes: 16;
export const X25519KeyBytes: 32;

export class CryptoError extends Error {}
export class UnsupportedCryptoVersion extends CryptoError {}
export class UnsupportedContentCipher extends CryptoError {}
export class UnsupportedEnvelopeScheme extends CryptoError {}
export class MalformedCryptoMetadata extends CryptoError {}
export class MalformedAAD extends CryptoError {}
export class CiphertextAuthenticationFailed extends CryptoError {}
export class WrongRecipient extends CryptoError {}

export interface CanonicalAADInputOptions {
  namespace?: string;
  key?: string;
  secretVersion?: number;
  secret_version?: number;
}

export class CanonicalAADInputs {
  constructor(options?: CanonicalAADInputOptions);
  namespace: string;
  key: string;
  secretVersion: number;
  static fromMapping(value?: JsonObject | null): CanonicalAADInputs;
  toMetadataObject(): JsonObject;
}

export interface CryptoMetadataOptions {
  version?: string;
  contentCipher?: string;
  envelopeScheme?: string;
  contentNonceB64?: string;
  aad?: CanonicalAADInputs | null;
}

export class CryptoMetadata {
  constructor(options?: CryptoMetadataOptions);
  version: string;
  contentCipher: string;
  envelopeScheme: string;
  contentNonceB64: string;
  aad: CanonicalAADInputs | null;
  static fromMapping(payload: JsonObject): CryptoMetadata;
  toJSON(): JsonObject;
  canonicalAADInputs(fallback: CanonicalAADInputs): CanonicalAADInputs;
}

export function metadataV1(aad: CanonicalAADInputs, contentNonce: Uint8Array): CryptoMetadata;
export function parseMetadata(payload: JsonObject | string | Uint8Array): CryptoMetadata;
export function validateMetadata(metadata: CryptoMetadata): void;
export function buildCanonicalAAD(metadata: CryptoMetadata | JsonObject, inputs: CanonicalAADInputs): Buffer;
export function canonicalAADSHA256(aad: Uint8Array): string;
export function sealContentAES256GCM(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Buffer;
export function openContentAES256GCM(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Buffer;
export function deriveX25519PublicKey(privateKey: Uint8Array): Buffer;
export function sealHPKEV1Envelope(recipientPublicKey: Uint8Array, senderEphemeralPrivateKey: Uint8Array, dek: Uint8Array, aad: Uint8Array): Buffer;
export function openHPKEV1Envelope(recipientPrivateKey: Uint8Array, envelope: Uint8Array, aad: Uint8Array): Buffer;
export function encodeEnvelope(envelope: Uint8Array): string;
export function decodeEnvelope(value: string): Buffer;

export interface RecipientPublicKeyOptions {
  clientID: string;
  scheme?: string;
  publicKey: Uint8Array;
  fingerprint?: string;
}

export class RecipientPublicKey {
  constructor(options: RecipientPublicKeyOptions);
  clientID: string;
  scheme: string;
  publicKey: Buffer;
  fingerprint: string;
}

export class X25519PrivateKeyHandle {
  constructor(options: { clientID: string; privateKey: Uint8Array });
  clientID: string;
  privateKey: Buffer;
  readonly scheme: string;
  openEnvelope(envelope: Uint8Array, aad: Uint8Array): Buffer;
}

export function deriveX25519RecipientPublicKey(clientID: string, privateKey: Uint8Array): RecipientPublicKey;

export interface PrivateKeyProvider {
  currentPrivateKey(): X25519PrivateKeyHandle;
}

export interface PublicKeyResolver {
  resolveRecipientPublicKey(clientID: string): RecipientPublicKey;
}

export class StaticPrivateKeyProvider implements PrivateKeyProvider {
  constructor(privateKey: X25519PrivateKeyHandle);
  privateKey: X25519PrivateKeyHandle;
  currentPrivateKey(): X25519PrivateKeyHandle;
}

export class StaticPublicKeyResolver implements PublicKeyResolver {
  constructor(publicKeys: Record<string, RecipientPublicKey>);
  resolveRecipientPublicKey(clientID: string): RecipientPublicKey;
}

export interface CryptoOptionsConfig {
  publicKeyResolver: PublicKeyResolver;
  privateKeyProvider: PrivateKeyProvider;
  randomSource?: (length: number) => Uint8Array;
}

export class CryptoOptions {
  constructor(config: CryptoOptionsConfig);
  publicKeyResolver: PublicKeyResolver;
  privateKeyProvider: PrivateKeyProvider;
  randomSource: (length: number) => Uint8Array;
  validate(): void;
}

export class DecryptedSecret {
  constructor(payload: {
    secretID: string;
    versionID: string;
    plaintext: Uint8Array;
    cryptoMetadata: JsonObject;
    permissions: number;
    grantedAt?: string;
    accessExpiresAt?: string | null;
  });
  secretID: string;
  versionID: string;
  plaintext: Buffer;
  cryptoMetadata: JsonObject;
  permissions: number;
  grantedAt: string;
  accessExpiresAt: string | null;
}

export class CryptoCustodiaClient {
  constructor(transport: CustodiaClient, options: CryptoOptions);
  createEncryptedSecretByKey(payload: {
    namespace?: string;
    key: string;
    plaintext: Uint8Array;
    recipients?: string[];
    permissions?: number;
    expiresAt?: string;
  }): Promise<JsonObject>;
  createEncryptedSecretVersionByKey(payload: {
    namespace?: string;
    key: string;
    plaintext: Uint8Array;
    recipients?: string[];
    permissions?: number;
    expiresAt?: string;
  }): Promise<JsonObject>;
  readDecryptedSecretByKey(namespace: string, key: string): Promise<DecryptedSecret>;
  shareEncryptedSecretByKey(payload: {
    namespace?: string;
    key: string;
    targetClientID: string;
    permissions?: number;
    expiresAt?: string;
  }): Promise<JsonObject>;
}

export function withCrypto(client: CustodiaClient, options: CryptoOptions): CryptoCustodiaClient;
