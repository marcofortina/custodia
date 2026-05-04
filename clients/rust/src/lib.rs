//! Custodia Rust transport client for opaque REST/mTLS payloads.
//!
//! The Phase 5 Rust client is transport-only. It does not encrypt, decrypt,
//! resolve public keys or inspect ciphertext/envelopes.

use std::fmt;
use std::path::PathBuf;
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
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, CustodiaError>;
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
