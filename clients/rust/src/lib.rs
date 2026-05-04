//! Custodia Rust transport client for opaque REST/mTLS payloads.
//!
//! The Phase 5 Rust client is transport-only. It does not encrypt, decrypt,
//! resolve public keys or inspect ciphertext/envelopes.

use serde_json::Value;
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
}

impl fmt::Display for CustodiaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid Custodia client config: {message}"),
            Self::Http { status, .. } => write!(f, "Custodia request failed with HTTP {status}"),
            Self::Transport(message) => write!(f, "Custodia transport error: {message}"),
            Self::Json(err) => write!(f, "Custodia JSON error: {err}"),
            Self::Io(err) => write!(f, "Custodia IO error: {err}"),
        }
    }
}

impl std::error::Error for CustodiaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
            Self::Io(err) => Some(err),
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

    pub fn list_secret_access_metadata(&self, secret_id: &str, limit: Option<u32>) -> Result<Value> {
        let mut query = Vec::new();
        push_optional(&mut query, "limit", limit.map(|value| value.to_string()));
        self.request_json(
            "GET",
            &with_query(&format!("/v1/secrets/{}/access", path_escape(secret_id)), &query),
            None,
        )
    }

    pub fn share_secret_payload(&self, secret_id: &str, payload: &Value) -> Result<Value> {
        self.request_json(
            "POST",
            &format!("/v1/secrets/{}/share", path_escape(secret_id)),
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

    pub fn create_secret_version_payload(&self, secret_id: &str, payload: &Value) -> Result<Value> {
        self.request_json(
            "POST",
            &format!("/v1/secrets/{}/versions", path_escape(secret_id)),
            Some(payload),
        )
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
