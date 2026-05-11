/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

//! Custodia Rust client for opaque REST/mTLS payloads and local client-side crypto.
//!
//! Transport methods keep payloads opaque. High-level crypto methods encrypt,
//! decrypt and create HPKE-v1 recipient envelopes locally using application
//! provided key resolvers; Custodia never becomes a public-key directory.

pub mod crypto;
pub use crypto::*;

use serde_json::{json, Value};
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub const PERMISSION_SHARE: u8 = 1;
pub const PERMISSION_WRITE: u8 = 2;
pub const PERMISSION_READ: u8 = 4;
pub const PERMISSION_ALL: u8 = PERMISSION_SHARE | PERMISSION_WRITE | PERMISSION_READ;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodiaClientConfig {
    pub server_url: String,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ca_file: PathBuf,
    pub timeout: Duration,
    pub user_agent: String,
}

impl CustodiaClientConfig {
    pub fn new(
        server_url: impl Into<String>,
        cert_file: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
        ca_file: impl Into<PathBuf>,
    ) -> Self {
        Self {
            server_url: server_url.into(),
            cert_file: cert_file.into(),
            key_file: key_file.into(),
            ca_file: ca_file.into(),
            timeout: Duration::from_secs(15),
            user_agent: "custodia-rust-transport/0.0.0".to_string(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessGrantFilters {
    pub limit: Option<u32>,
    pub secret_id: Option<String>,
    pub status: Option<String>,
    pub client_id: Option<String>,
    pub requested_by_client_id: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditEventFilters {
    pub limit: Option<u32>,
    pub outcome: Option<String>,
    pub action: Option<String>,
    pub actor_client_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExportArtifact {
    pub body: String,
    pub sha256: String,
    pub event_count: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// HTTP transport abstraction used by tests and by callers that need custom I/O.
/// Implementations must not log request bodies because they may contain opaque
/// ciphertext and recipient envelopes.
pub trait HttpTransport: Send + Sync {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse>;
}

#[derive(Debug)]
pub enum CustodiaError {
    InvalidConfig(String),
    Http {
        status: u16,
        body: String,
        headers: Vec<(String, String)>,
    },
    Transport(String),
    Json(serde_json::Error),
    Io(std::io::Error),
    Crypto(CryptoError),
}

impl fmt::Display for CustodiaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid Custodia client config: {message}"),
            Self::Http { status, .. } => write!(f, "Custodia request failed with HTTP {status}"),
            Self::Transport(message) => write!(f, "Custodia transport error: {message}"),
            Self::Json(err) => write!(f, "Custodia JSON error: {err}"),
            Self::Io(err) => write!(f, "Custodia IO error: {err}"),
            Self::Crypto(err) => write!(f, "Custodia crypto error: {err}"),
        }
    }
}

impl std::error::Error for CustodiaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for CustodiaError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl From<std::io::Error> for CustodiaError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<CryptoError> for CustodiaError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

pub type Result<T> = std::result::Result<T, CustodiaError>;

pub struct CustodiaClient {
    config: CustodiaClientConfig,
    transport: Arc<dyn HttpTransport>,
}

impl CustodiaClient {
    pub fn new(config: CustodiaClientConfig) -> Result<Self> {
        let transport = Arc::new(ReqwestTransport::new(&config)?);
        Self::with_transport(config, transport)
    }

    pub fn with_transport(config: CustodiaClientConfig, transport: Arc<dyn HttpTransport>) -> Result<Self> {
        validate_config(&config)?;
        Ok(Self { config, transport })
    }

    pub fn current_client_info(&self) -> Result<Value> {
        self.request_json("GET", "/v1/me", None)
    }

    pub fn list_client_infos(&self, limit: Option<u32>, active: Option<bool>) -> Result<Value> {
        let mut query = Vec::new();
        push_optional(&mut query, "limit", limit.map(|value| value.to_string()));
        push_optional(&mut query, "active", active.map(|value| value.to_string()));
        self.request_json("GET", &with_query("/v1/clients", &query), None)
    }

    pub fn get_client_info(&self, client_id: &str) -> Result<Value> {
        self.request_json("GET", &format!("/v1/clients/{}", path_escape(client_id)), None)
    }

    pub fn create_client_info(&self, payload: &Value) -> Result<Value> {
        self.request_json("POST", "/v1/clients", Some(payload))
    }

    pub fn revoke_client_info(&self, payload: &Value) -> Result<Value> {
        self.request_json("POST", "/v1/clients/revoke", Some(payload))
    }

    pub fn create_secret_payload(&self, payload: &Value) -> Result<Value> {
        self.request_json("POST", "/v1/secrets", Some(payload))
    }

    pub fn get_secret_payload(&self, secret_id: &str) -> Result<Value> {
        self.request_json("GET", &format!("/v1/secrets/{}", path_escape(secret_id)), None)
    }

    pub fn get_secret_payload_by_key(&self, namespace: &str, key: &str) -> Result<Value> {
        self.request_json(
            "GET",
            &with_query(
                "/v1/secrets/by-key",
                &[
                    ("namespace".to_string(), namespace.to_string()),
                    ("key".to_string(), key.to_string()),
                ],
            ),
            None,
        )
    }

    pub fn list_secret_metadata(&self, limit: Option<u32>) -> Result<Value> {
        let mut query = Vec::new();
        push_optional(&mut query, "limit", limit.map(|value| value.to_string()));
        self.request_json("GET", &with_query("/v1/secrets", &query), None)
    }

    pub fn list_secret_version_metadata(&self, secret_id: &str, limit: Option<u32>) -> Result<Value> {
        let mut query = Vec::new();
        push_optional(&mut query, "limit", limit.map(|value| value.to_string()));
        self.request_json(
            "GET",
            &with_query(&format!("/v1/secrets/{}/versions", path_escape(secret_id)), &query),
            None,
        )
    }

    pub fn list_secret_version_metadata_by_key(&self, namespace: &str, key: &str, limit: Option<u32>) -> Result<Value> {
        let mut query = vec![
            ("namespace".to_string(), namespace.to_string()),
            ("key".to_string(), key.to_string()),
        ];
        push_optional(&mut query, "limit", limit.map(|value| value.to_string()));
        self.request_json("GET", &with_query("/v1/secrets/by-key/versions", &query), None)
    }

    pub fn list_secret_access_metadata(&self, secret_id: &str, limit: Option<u32>) -> Result<Value> {
        let mut query = Vec::new();
        push_optional(&mut query, "limit", limit.map(|value| value.to_string()));
        self.request_json(
            "GET",
            &with_query(&format!("/v1/secrets/{}/access", path_escape(secret_id)), &query),
            None,
        )
    }

    pub fn list_secret_access_metadata_by_key(&self, namespace: &str, key: &str, limit: Option<u32>) -> Result<Value> {
        let mut query = vec![
            ("namespace".to_string(), namespace.to_string()),
            ("key".to_string(), key.to_string()),
        ];
        push_optional(&mut query, "limit", limit.map(|value| value.to_string()));
        self.request_json("GET", &with_query("/v1/secrets/by-key/access", &query), None)
    }

    pub fn share_secret_payload(&self, secret_id: &str, payload: &Value) -> Result<Value> {
        self.request_json(
            "POST",
            &format!("/v1/secrets/{}/share", path_escape(secret_id)),
            Some(payload),
        )
    }

    pub fn share_secret_payload_by_key(&self, namespace: &str, key: &str, payload: &Value) -> Result<Value> {
        self.request_json(
            "POST",
            &with_query(
                "/v1/secrets/by-key/share",
                &[
                    ("namespace".to_string(), namespace.to_string()),
                    ("key".to_string(), key.to_string()),
                ],
            ),
            Some(payload),
        )
    }

    pub fn create_access_grant(&self, secret_id: &str, payload: &Value) -> Result<Value> {
        self.request_json(
            "POST",
            &format!("/v1/secrets/{}/access-requests", path_escape(secret_id)),
            Some(payload),
        )
    }

    pub fn activate_access_grant_payload(
        &self,
        secret_id: &str,
        target_client_id: &str,
        payload: &Value,
    ) -> Result<Value> {
        self.request_json(
            "POST",
            &format!(
                "/v1/secrets/{}/access-requests/{}/activate",
                path_escape(secret_id),
                path_escape(target_client_id)
            ),
            Some(payload),
        )
    }

    pub fn revoke_access(&self, secret_id: &str, client_id: &str) -> Result<Value> {
        self.request_json(
            "DELETE",
            &format!("/v1/secrets/{}/access/{}", path_escape(secret_id), path_escape(client_id)),
            None,
        )
    }

    pub fn revoke_access_by_key(&self, namespace: &str, key: &str, client_id: &str) -> Result<Value> {
        self.request_json(
            "DELETE",
            &with_query(
                &format!("/v1/secrets/by-key/access/{}", path_escape(client_id)),
                &[
                    ("namespace".to_string(), namespace.to_string()),
                    ("key".to_string(), key.to_string()),
                ],
            ),
            None,
        )
    }

    pub fn create_secret_version_payload(&self, secret_id: &str, payload: &Value) -> Result<Value> {
        self.request_json(
            "POST",
            &format!("/v1/secrets/{}/versions", path_escape(secret_id)),
            Some(payload),
        )
    }

    pub fn create_secret_version_payload_by_key(&self, namespace: &str, key: &str, payload: &Value) -> Result<Value> {
        self.request_json(
            "POST",
            &with_query(
                "/v1/secrets/by-key/versions",
                &[
                    ("namespace".to_string(), namespace.to_string()),
                    ("key".to_string(), key.to_string()),
                ],
            ),
            Some(payload),
        )
    }

    pub fn delete_secret_by_key(&self, namespace: &str, key: &str, cascade: bool) -> Result<Value> {
        let mut query = vec![
            ("namespace".to_string(), namespace.to_string()),
            ("key".to_string(), key.to_string()),
        ];
        if cascade {
            query.push(("cascade".to_string(), "true".to_string()));
        }
        self.request_json("DELETE", &with_query("/v1/secrets/by-key", &query), None)
    }

    pub fn list_access_grant_metadata(&self, filters: &AccessGrantFilters) -> Result<Value> {
        let query = access_grant_query(filters);
        self.request_json("GET", &with_query("/v1/access-requests", &query), None)
    }

    pub fn status_info(&self) -> Result<Value> {
        self.request_json("GET", "/v1/status", None)
    }

    pub fn version_info(&self) -> Result<Value> {
        self.request_json("GET", "/v1/version", None)
    }

    pub fn diagnostics_info(&self) -> Result<Value> {
        self.request_json("GET", "/v1/diagnostics", None)
    }

    pub fn revocation_status_info(&self) -> Result<Value> {
        self.request_json("GET", "/v1/revocation/status", None)
    }

    pub fn revocation_serial_status_info(&self, serial_hex: &str) -> Result<Value> {
        let trimmed = serial_hex.trim();
        if trimmed.is_empty() {
            return Err(CustodiaError::InvalidConfig("serial_hex is required".to_string()));
        }
        let query = vec![("serial_hex".to_string(), trimmed.to_string())];
        self.request_json("GET", &with_query("/v1/revocation/serial", &query), None)
    }

    pub fn list_audit_event_metadata(&self, filters: &AuditEventFilters) -> Result<Value> {
        let query = audit_event_query(filters);
        self.request_json("GET", &with_query("/v1/audit-events", &query), None)
    }

    pub fn export_audit_event_artifact(&self, filters: &AuditEventFilters) -> Result<AuditExportArtifact> {
        let query = audit_event_query(filters);
        let response = self.request_raw("GET", &with_query("/v1/audit-events/export", &query), None)?;
        Ok(AuditExportArtifact {
            body: response.body,
            sha256: header_value(&response.headers, "x-custodia-audit-export-sha256").unwrap_or_default(),
            event_count: header_value(&response.headers, "x-custodia-audit-export-events").unwrap_or_default(),
        })
    }

    pub fn with_crypto(self, options: CryptoOptions) -> CryptoCustodiaClient {
        CryptoCustodiaClient::new(self, options)
    }

    pub fn request_json(&self, method: &str, path: &str, payload: Option<&Value>) -> Result<Value> {
        let response = self.request_raw(method, path, payload)?;
        if response.body.trim().is_empty() {
            return Ok(Value::Object(Default::default()));
        }
        Ok(serde_json::from_str(&response.body)?)
    }

    pub fn request_raw(&self, method: &str, path: &str, payload: Option<&Value>) -> Result<TransportResponse> {
        let body = match payload {
            Some(value) => Some(serde_json::to_string(value)?),
            None => None,
        };
        let mut headers = vec![
            ("Accept".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), self.config.user_agent.clone()),
        ];
        if let Some(body) = &body {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
            headers.push(("Content-Length".to_string(), body.len().to_string()));
        }
        let response = self.transport.send(TransportRequest {
            method: method.to_string(),
            url: self.build_url(path),
            headers,
            body,
        })?;
        if response.status < 200 || response.status >= 300 {
            return Err(CustodiaError::Http {
                status: response.status,
                body: response.body,
                headers: response.headers,
            });
        }
        Ok(response)
    }

    fn build_url(&self, path: &str) -> String {
        format!("{}{}", self.config.server_url.trim_end_matches('/'), path)
    }
}

struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    fn new(config: &CustodiaClientConfig) -> Result<Self> {
        validate_config(config)?;
        let ca = reqwest::Certificate::from_pem(&fs::read(&config.ca_file)?)
            .map_err(|err| CustodiaError::Transport(err.to_string()))?;
        let mut identity_pem = fs::read(&config.cert_file)?;
        identity_pem.push(b'\n');
        identity_pem.extend(fs::read(&config.key_file)?);
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|err| CustodiaError::Transport(err.to_string()))?;
        let client = reqwest::blocking::Client::builder()
            .add_root_certificate(ca)
            .identity(identity)
            .timeout(config.timeout)
            .user_agent(config.user_agent.clone())
            .build()
            .map_err(|err| CustodiaError::Transport(err.to_string()))?;
        Ok(Self { client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse> {
        let method = reqwest::Method::from_str(&request.method)
            .map_err(|err| CustodiaError::Transport(err.to_string()))?;
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let response = builder.send().map_err(|err| CustodiaError::Transport(err.to_string()))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.to_string(), v.to_string())))
            .collect();
        let body = response.text().map_err(|err| CustodiaError::Transport(err.to_string()))?;
        Ok(TransportResponse { status, headers, body })
    }
}

fn validate_config(config: &CustodiaClientConfig) -> Result<()> {
    if config.server_url.trim().is_empty() {
        return Err(CustodiaError::InvalidConfig("server_url is required".to_string()));
    }
    if config.cert_file.as_os_str().is_empty() {
        return Err(CustodiaError::InvalidConfig("cert_file is required".to_string()));
    }
    if config.key_file.as_os_str().is_empty() {
        return Err(CustodiaError::InvalidConfig("key_file is required".to_string()));
    }
    if config.ca_file.as_os_str().is_empty() {
        return Err(CustodiaError::InvalidConfig("ca_file is required".to_string()));
    }
    Ok(())
}

fn require_text<'a>(value: &'a str, label: &str) -> Result<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CustodiaError::InvalidConfig(format!("{label} is required")));
    }
    Ok(trimmed)
}

fn access_grant_query(filters: &AccessGrantFilters) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_optional(&mut query, "limit", filters.limit.map(|value| value.to_string()));
    push_optional(&mut query, "secret_id", filters.secret_id.clone());
    push_optional(&mut query, "status", filters.status.clone());
    push_optional(&mut query, "client_id", filters.client_id.clone());
    push_optional(
        &mut query,
        "requested_by_client_id",
        filters.requested_by_client_id.clone(),
    );
    query
}

fn audit_event_query(filters: &AuditEventFilters) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_optional(&mut query, "limit", filters.limit.map(|value| value.to_string()));
    push_optional(&mut query, "outcome", filters.outcome.clone());
    push_optional(&mut query, "action", filters.action.clone());
    push_optional(&mut query, "actor_client_id", filters.actor_client_id.clone());
    push_optional(&mut query, "resource_type", filters.resource_type.clone());
    push_optional(&mut query, "resource_id", filters.resource_id.clone());
    query
}

fn push_optional(query: &mut Vec<(String, String)>, name: &str, value: Option<String>) {
    if let Some(value) = value {
        query.push((name.to_string(), value));
    }
}

fn with_query(path: &str, query: &[(String, String)]) -> String {
    if query.is_empty() {
        return path.to_string();
    }
    let encoded = query
        .iter()
        .map(|(name, value)| format!("{}={}", urlencoding::encode(name), urlencoding::encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{encoded}")
}

fn path_escape(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptedSecret {
    pub secret_id: String,
    pub version_id: String,
    pub plaintext: Vec<u8>,
    pub crypto_metadata: Value,
    pub permissions: u8,
    pub granted_at: String,
    pub access_expires_at: Option<String>,
}

pub struct CryptoCustodiaClient {
    transport: CustodiaClient,
    options: CryptoOptions,
}

impl CryptoCustodiaClient {
    pub fn new(transport: CustodiaClient, options: CryptoOptions) -> Self {
        Self { transport, options }
    }

    pub fn create_encrypted_secret_by_key(
        &self,
        namespace: &str,
        key: &str,
        plaintext: &[u8],
        recipients: &[String],
        permissions: u8,
        expires_at: Option<&str>,
    ) -> Result<Value> {
        let normalized_namespace = require_text(namespace, "namespace")?;
        let normalized_key = require_text(key, "secret key")?;
        let dek = self.random(AES_256_GCM_KEY_BYTES)?;
        let nonce = self.random(AES_GCM_NONCE_BYTES)?;
        let aad_inputs = CanonicalAADInputs {
            namespace: normalized_namespace.to_string(),
            key: normalized_key.to_string(),
            secret_version: 1,
        };
        let metadata = metadata_v1(aad_inputs.clone(), &nonce);
        let aad = build_canonical_aad(&metadata, &aad_inputs)?;
        let ciphertext = seal_content_aes_256_gcm(&dek, &nonce, plaintext, &aad)?;
        let mut payload = json!({
            "namespace": normalized_namespace,
            "key": normalized_key,
            "ciphertext": encode_base64(&ciphertext),
            "crypto_metadata": metadata.to_value(),
            "envelopes": self.seal_recipient_envelopes(&self.normalized_recipients(recipients)?, &dek, &aad)?,
            "permissions": permissions,
        });
        if let Some(expires_at) = expires_at {
            payload["expires_at"] = Value::String(expires_at.to_string());
        }
        self.transport.create_secret_payload(&payload)
    }

    pub fn create_encrypted_secret_version(
        &self,
        secret_id: &str,
        plaintext: &[u8],
        recipients: &[String],
        permissions: u8,
        expires_at: Option<&str>,
    ) -> Result<Value> {
        if secret_id.trim().is_empty() {
            return Err(CustodiaError::InvalidConfig("secret id is required".to_string()));
        }
        let current_secret = self.transport.get_secret_payload(secret_id)?;
        let empty_metadata = Value::Object(Default::default());
        let current_metadata = parse_metadata(current_secret.get("crypto_metadata").unwrap_or(&empty_metadata))?;
        let current_aad_inputs = current_metadata.canonical_aad_inputs(CanonicalAADInputs {
            namespace: value_string(current_secret.get("namespace")),
            key: value_string(current_secret.get("key")),
            secret_version: 1,
        });
        let aad_inputs = CanonicalAADInputs {
            namespace: current_aad_inputs.namespace,
            key: current_aad_inputs.key,
            secret_version: current_aad_inputs.secret_version + 1,
        };
        let dek = self.random(AES_256_GCM_KEY_BYTES)?;
        let nonce = self.random(AES_GCM_NONCE_BYTES)?;
        let metadata = metadata_v1(aad_inputs.clone(), &nonce);
        let aad = build_canonical_aad(&metadata, &aad_inputs)?;
        let ciphertext = seal_content_aes_256_gcm(&dek, &nonce, plaintext, &aad)?;
        let mut payload = json!({
            "ciphertext": encode_base64(&ciphertext),
            "crypto_metadata": metadata.to_value(),
            "envelopes": self.seal_recipient_envelopes(&self.normalized_recipients(recipients)?, &dek, &aad)?,
            "permissions": permissions,
        });
        if let Some(expires_at) = expires_at {
            payload["expires_at"] = Value::String(expires_at.to_string());
        }
        self.transport.create_secret_version_payload(secret_id, &payload)
    }

    pub fn create_encrypted_secret_version_by_key(
        &self,
        namespace: &str,
        key: &str,
        plaintext: &[u8],
        recipients: &[String],
        permissions: u8,
        expires_at: Option<&str>,
    ) -> Result<Value> {
        let normalized_namespace = require_text(namespace, "namespace")?;
        let normalized_key = require_text(key, "secret key")?;
        let current_secret = self.transport.get_secret_payload_by_key(normalized_namespace, normalized_key)?;
        let empty_metadata = Value::Object(Default::default());
        let current_metadata = parse_metadata(current_secret.get("crypto_metadata").unwrap_or(&empty_metadata))?;
        let current_aad_inputs = current_metadata.canonical_aad_inputs(CanonicalAADInputs {
            namespace: normalized_namespace.to_string(),
            key: normalized_key.to_string(),
            secret_version: 1,
        });
        let aad_inputs = CanonicalAADInputs {
            namespace: current_aad_inputs.namespace,
            key: current_aad_inputs.key,
            secret_version: current_aad_inputs.secret_version + 1,
        };
        let dek = self.random(AES_256_GCM_KEY_BYTES)?;
        let nonce = self.random(AES_GCM_NONCE_BYTES)?;
        let metadata = metadata_v1(aad_inputs.clone(), &nonce);
        let aad = build_canonical_aad(&metadata, &aad_inputs)?;
        let ciphertext = seal_content_aes_256_gcm(&dek, &nonce, plaintext, &aad)?;
        let mut payload = json!({
            "ciphertext": encode_base64(&ciphertext),
            "crypto_metadata": metadata.to_value(),
            "envelopes": self.seal_recipient_envelopes(&self.normalized_recipients(recipients)?, &dek, &aad)?,
            "permissions": permissions,
        });
        if let Some(expires_at) = expires_at {
            payload["expires_at"] = Value::String(expires_at.to_string());
        }
        self.transport.create_secret_version_payload_by_key(normalized_namespace, normalized_key, &payload)
    }

    pub fn read_decrypted_secret(&self, secret_id: &str) -> Result<DecryptedSecret> {
        let secret = self.transport.get_secret_payload(secret_id)?;
        let empty_metadata = Value::Object(Default::default());
        let metadata = parse_metadata(secret.get("crypto_metadata").unwrap_or(&empty_metadata))?;
        let fallback = CanonicalAADInputs {
            namespace: value_string(secret.get("namespace")),
            key: value_string(secret.get("key")),
            secret_version: 1,
        };
        let aad_inputs = metadata.canonical_aad_inputs(fallback);
        let aad = build_canonical_aad(&metadata, &aad_inputs)?;
        if metadata.content_nonce_b64.is_empty() {
            return Err(CryptoError::MalformedCryptoMetadata("missing content nonce".to_string()).into());
        }
        let nonce = decode_base64(&metadata.content_nonce_b64)?;
        let dek = self.open_secret_envelope(&value_string(secret.get("envelope")), &aad)?;
        let ciphertext = decode_base64(&value_string(secret.get("ciphertext")))?;
        let plaintext = open_content_aes_256_gcm(&dek, &nonce, &ciphertext, &aad)?;
        Ok(DecryptedSecret {
            secret_id: value_string(secret.get("secret_id")),
            version_id: value_string(secret.get("version_id")),
            plaintext,
            crypto_metadata: metadata.to_value(),
            permissions: value_u8(secret.get("permissions")),
            granted_at: value_string(secret.get("granted_at")),
            access_expires_at: value_optional_string(secret.get("access_expires_at")),
        })
    }

    pub fn read_decrypted_secret_by_key(&self, namespace: &str, key: &str) -> Result<DecryptedSecret> {
        let secret = self.transport.get_secret_payload_by_key(namespace, key)?;
        let empty_metadata = Value::Object(Default::default());
        let metadata = parse_metadata(secret.get("crypto_metadata").unwrap_or(&empty_metadata))?;
        let fallback = CanonicalAADInputs {
            namespace: value_string(secret.get("namespace")),
            key: value_string(secret.get("key")),
            secret_version: 1,
        };
        let aad_inputs = metadata.canonical_aad_inputs(fallback);
        let aad = build_canonical_aad(&metadata, &aad_inputs)?;
        if metadata.content_nonce_b64.is_empty() {
            return Err(CryptoError::MalformedCryptoMetadata("missing content nonce".to_string()).into());
        }
        let nonce = decode_base64(&metadata.content_nonce_b64)?;
        let dek = self.open_secret_envelope(&value_string(secret.get("envelope")), &aad)?;
        let ciphertext = decode_base64(&value_string(secret.get("ciphertext")))?;
        let plaintext = open_content_aes_256_gcm(&dek, &nonce, &ciphertext, &aad)?;
        Ok(DecryptedSecret {
            secret_id: value_string(secret.get("secret_id")),
            version_id: value_string(secret.get("version_id")),
            plaintext,
            crypto_metadata: metadata.to_value(),
            permissions: value_u8(secret.get("permissions")),
            granted_at: value_string(secret.get("granted_at")),
            access_expires_at: value_optional_string(secret.get("access_expires_at")),
        })
    }

    pub fn share_encrypted_secret(
        &self,
        secret_id: &str,
        target_client_id: &str,
        permissions: u8,
        expires_at: Option<&str>,
    ) -> Result<Value> {
        if target_client_id.trim().is_empty() {
            return Err(CustodiaError::InvalidConfig("target client id is required".to_string()));
        }
        let secret = self.transport.get_secret_payload(secret_id)?;
        let empty_metadata = Value::Object(Default::default());
        let metadata = parse_metadata(secret.get("crypto_metadata").unwrap_or(&empty_metadata))?;
        let fallback = CanonicalAADInputs {
            namespace: value_string(secret.get("namespace")),
            key: value_string(secret.get("key")),
            secret_version: 1,
        };
        let aad_inputs = metadata.canonical_aad_inputs(fallback);
        let aad = build_canonical_aad(&metadata, &aad_inputs)?;
        let dek = self.open_secret_envelope(&value_string(secret.get("envelope")), &aad)?;
        let envelope = self.seal_recipient_envelopes(&[target_client_id.to_string()], &dek, &aad)?
            .into_iter()
            .next()
            .ok_or_else(|| CustodiaError::InvalidConfig("missing recipient envelope".to_string()))?;
        let mut payload = json!({
            "version_id": value_string(secret.get("version_id")),
            "target_client_id": target_client_id,
            "envelope": envelope["envelope"].clone(),
            "permissions": permissions,
        });
        if let Some(expires_at) = expires_at {
            payload["expires_at"] = Value::String(expires_at.to_string());
        }
        self.transport.share_secret_payload(secret_id, &payload)
    }

    pub fn share_encrypted_secret_by_key(
        &self,
        namespace: &str,
        key: &str,
        target_client_id: &str,
        permissions: u8,
        expires_at: Option<&str>,
    ) -> Result<Value> {
        let normalized_namespace = require_text(namespace, "namespace")?;
        let normalized_key = require_text(key, "secret key")?;
        let target = require_text(target_client_id, "target client id")?;
        let secret = self.transport.get_secret_payload_by_key(normalized_namespace, normalized_key)?;
        let empty_metadata = Value::Object(Default::default());
        let metadata = parse_metadata(secret.get("crypto_metadata").unwrap_or(&empty_metadata))?;
        let fallback = CanonicalAADInputs {
            namespace: value_string(secret.get("namespace")),
            key: value_string(secret.get("key")),
            secret_version: 1,
        };
        let aad_inputs = metadata.canonical_aad_inputs(fallback);
        let aad = build_canonical_aad(&metadata, &aad_inputs)?;
        let dek = self.open_secret_envelope(&value_string(secret.get("envelope")), &aad)?;
        let envelope = self.seal_recipient_envelopes(&[target.to_string()], &dek, &aad)?
            .into_iter()
            .next()
            .ok_or_else(|| CustodiaError::InvalidConfig("missing recipient envelope".to_string()))?;
        let mut payload = json!({
            "version_id": value_string(secret.get("version_id")),
            "target_client_id": target,
            "envelope": envelope["envelope"].clone(),
            "permissions": permissions,
        });
        if let Some(expires_at) = expires_at {
            payload["expires_at"] = Value::String(expires_at.to_string());
        }
        self.transport.share_secret_payload_by_key(normalized_namespace, normalized_key, &payload)
    }

    fn normalized_recipients(&self, recipients: &[String]) -> Result<Vec<String>> {
        let current = self.options.private_key_provider.current_private_key()?;
        let mut values = Vec::new();
        if !current.client_id().is_empty() {
            values.push(current.client_id().to_string());
        }
        for recipient in recipients {
            let value = recipient.trim();
            if !value.is_empty() && !values.iter().any(|existing| existing == value) {
                values.push(value.to_string());
            }
        }
        if values.is_empty() {
            return Err(CustodiaError::InvalidConfig("missing recipient envelope".to_string()));
        }
        Ok(values)
    }

    fn seal_recipient_envelopes(&self, recipients: &[String], dek: &[u8], aad: &[u8]) -> Result<Vec<Value>> {
        let mut envelopes = Vec::new();
        for recipient in recipients {
            let public_key = self.options.public_key_resolver.resolve_recipient_public_key(recipient)?;
            if public_key.scheme != ENVELOPE_SCHEME_HPKE_V1 {
                return Err(CryptoError::UnsupportedEnvelopeScheme.into());
            }
            let ephemeral_private_key = self.random(X25519_KEY_BYTES)?;
            let envelope = seal_hpke_v1_envelope(&public_key.public_key, &ephemeral_private_key, dek, aad)?;
            envelopes.push(json!({
                "client_id": recipient,
                "envelope": encode_envelope(&envelope),
            }));
        }
        Ok(envelopes)
    }

    fn open_secret_envelope(&self, encoded_envelope: &str, aad: &[u8]) -> Result<Vec<u8>> {
        let private_key = self.options.private_key_provider.current_private_key()?;
        if private_key.scheme() != ENVELOPE_SCHEME_HPKE_V1 {
            return Err(CryptoError::UnsupportedEnvelopeScheme.into());
        }
        Ok(private_key.open_envelope(&decode_envelope(encoded_envelope)?, aad)?)
    }

    fn random(&self, length: usize) -> Result<Vec<u8>> {
        let value = self.options.random_source.random(length)?;
        if value.len() != length {
            return Err(CryptoError::RandomSource("invalid random byte length".to_string()).into());
        }
        Ok(value)
    }
}

fn value_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(value) if !value.is_null() => value.to_string(),
        _ => String::new(),
    }
}

fn value_optional_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(value) if !value.is_null() => Some(value.to_string()),
        _ => None,
    }
}

fn value_u8(value: Option<&Value>) -> u8 {
    value.and_then(Value::as_u64).unwrap_or_default() as u8
}
