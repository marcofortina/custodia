use custodia_client::{
    AccessGrantFilters, AuditEventFilters, CustodiaClient, CustodiaClientConfig, CustodiaError,
    HttpTransport, TransportRequest, TransportResponse, PERMISSION_ALL,
};
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct FakeTransport {
    requests: Mutex<Vec<TransportRequest>>,
    responses: Mutex<Vec<TransportResponse>>,
}

impl FakeTransport {
    fn push_response(&self, response: TransportResponse) {
        self.responses.lock().unwrap().push(response);
    }

    fn requests(&self) -> Vec<TransportRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl HttpTransport for FakeTransport {
    fn send(&self, request: TransportRequest) -> custodia_client::Result<TransportResponse> {
        self.requests.lock().unwrap().push(request);
        let mut responses = self.responses.lock().unwrap();
        if responses.is_empty() {
            return Err(CustodiaError::Transport("missing fake response".to_string()));
        }
        Ok(responses.remove(0))
    }
}

fn config() -> CustodiaClientConfig {
    CustodiaClientConfig::new(
        "https://vault.example.test:8443/",
        PathBuf::from("client.crt"),
        PathBuf::from("client.key"),
        PathBuf::from("ca.crt"),
    )
    .with_timeout(Duration::from_secs(3))
    .with_user_agent("custodia-rust-test/0.0.0")
}

fn json_response(body: serde_json::Value) -> TransportResponse {
    TransportResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: body.to_string(),
    }
}

#[test]
fn sends_opaque_secret_payload_without_interpreting_crypto_fields() {
    let fake = Arc::new(FakeTransport::default());
    fake.push_response(json_response(json!({
        "secret_id": "550e8400-e29b-41d4-a716-446655440000",
        "version_id": "11111111-1111-4111-8111-111111111111"
    })));
    let client = CustodiaClient::with_transport(config(), fake.clone()).unwrap();

    let payload = json!({
        "name": "db/password",
        "ciphertext": "opaque-ciphertext",
        "crypto_metadata": { "format": "client-defined" },
        "envelopes": [{ "client_id": "client_alice", "envelope": "opaque-envelope" }],
        "permissions": PERMISSION_ALL
    });
    let response = client.create_secret_payload(&payload).unwrap();

    assert_eq!(response["secret_id"], "550e8400-e29b-41d4-a716-446655440000");
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].url, "https://vault.example.test:8443/v1/secrets");
    assert!(requests[0].body.as_ref().unwrap().contains("opaque-ciphertext"));
    assert!(requests[0].body.as_ref().unwrap().contains("opaque-envelope"));
}

#[test]
fn builds_metadata_and_operational_paths() {
    let fake = Arc::new(FakeTransport::default());
    for body in [
        json!({"clients": []}),
        json!({"secrets": []}),
        json!({"versions": []}),
        json!({"access": []}),
        json!({"access_requests": []}),
        json!({"status": "ok"}),
        json!({"version": "dev"}),
        json!({"diagnostics": {}}),
        json!({"revocation": "ok"}),
        json!({"serial_hex": "01"}),
        json!({"events": []}),
    ] {
        fake.push_response(json_response(body));
    }
    let client = CustodiaClient::with_transport(config(), fake.clone()).unwrap();

    client.list_client_infos(Some(10), Some(true)).unwrap();
    client.list_secret_metadata(Some(5)).unwrap();
    client
        .list_secret_version_metadata("550e8400-e29b-41d4-a716-446655440000", Some(2))
        .unwrap();
    client
        .list_secret_access_metadata("550e8400-e29b-41d4-a716-446655440000", Some(3))
        .unwrap();
    client
        .list_access_grant_metadata(&AccessGrantFilters {
            limit: Some(7),
            status: Some("pending".to_string()),
            client_id: Some("client_alice".to_string()),
            ..Default::default()
        })
        .unwrap();
    client.status_info().unwrap();
    client.version_info().unwrap();
    client.diagnostics_info().unwrap();
    client.revocation_status_info().unwrap();
    client.revocation_serial_status_info("01").unwrap();
    client
        .list_audit_event_metadata(&AuditEventFilters {
            limit: Some(9),
            outcome: Some("success".to_string()),
            action: Some("secret.read".to_string()),
            ..Default::default()
        })
        .unwrap();

    let urls = fake.requests().into_iter().map(|request| request.url).collect::<Vec<_>>();
    assert_eq!(urls[0], "https://vault.example.test:8443/v1/clients?limit=10&active=true");
    assert_eq!(urls[1], "https://vault.example.test:8443/v1/secrets?limit=5");
    assert!(urls[2].contains("/v1/secrets/550e8400-e29b-41d4-a716-446655440000/versions?limit=2"));
    assert!(urls[4].contains("/v1/access-requests?"));
    assert!(urls[4].contains("status=pending"));
    assert!(urls[10].contains("/v1/audit-events?"));
}

#[test]
fn exposes_audit_export_headers() {
    let fake = Arc::new(FakeTransport::default());
    fake.push_response(TransportResponse {
        status: 200,
        headers: vec![
            ("x-custodia-audit-export-sha256".to_string(), "abc123".to_string()),
            ("x-custodia-audit-export-events".to_string(), "2".to_string()),
        ],
        body: "event_id,action\n1,secret.read\n".to_string(),
    });
    let client = CustodiaClient::with_transport(config(), fake.clone()).unwrap();

    let artifact = client
        .export_audit_event_artifact(&AuditEventFilters {
            limit: Some(2),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(artifact.sha256, "abc123");
    assert_eq!(artifact.event_count, "2");
    assert!(artifact.body.contains("secret.read"));
    assert_eq!(fake.requests()[0].url, "https://vault.example.test:8443/v1/audit-events/export?limit=2");
}

#[test]
fn maps_http_errors_without_leaking_request_payload() {
    let fake = Arc::new(FakeTransport::default());
    fake.push_response(TransportResponse {
        status: 403,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: "{\"error\":\"forbidden\"}".to_string(),
    });
    let client = CustodiaClient::with_transport(config(), fake).unwrap();

    let err = client.get_secret_payload("secret-a").unwrap_err();
    match err {
        CustodiaError::Http { status, body, .. } => {
            assert_eq!(status, 403);
            assert!(body.contains("forbidden"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
