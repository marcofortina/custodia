/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

use custodia_client::{
    AccessGrantFilters, AuditEventFilters, CustodiaClient, CustodiaClientConfig, CustodiaError,
    HttpTransport, TransportRequest, TransportResponse, PERMISSION_ALL,
};
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
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

fn assert_url_seen(urls: &[String], expected_suffix: &str) {
    assert!(
        urls.iter().any(|url| url.ends_with(expected_suffix)),
        "expected to see URL ending with {expected_suffix}, got {urls:?}"
    );
}

fn random_test_bytes(length: usize) -> Vec<u8> {
    use custodia_client::{OsRandomSource, RandomSource};

    OsRandomSource.random(length).unwrap()
}

fn alice_private_key() -> Vec<u8> {
    static ALICE_PRIVATE_KEY: OnceLock<Vec<u8>> = OnceLock::new();
    ALICE_PRIVATE_KEY.get_or_init(|| random_test_bytes(custodia_client::X25519_KEY_BYTES)).clone()
}

fn bob_private_key() -> Vec<u8> {
    static BOB_PRIVATE_KEY: OnceLock<Vec<u8>> = OnceLock::new();
    BOB_PRIVATE_KEY.get_or_init(|| random_test_bytes(custodia_client::X25519_KEY_BYTES)).clone()
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
        json!({"versions": []}),
        json!({"access": []}),
        json!({"access_requests": []}),
        json!({"secret_id": "s1"}),
        json!({"status": "shared"}),
        json!({"version_id": "v2"}),
        json!({"status": "revoked"}),
        json!({"status": "deleted"}),
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
    client.list_secret_version_metadata_by_key("db01", "user:sys", Some(10)).unwrap();
    client.list_secret_access_metadata_by_key("db01", "user:sys", Some(10)).unwrap();
    client
        .list_access_grant_metadata(&AccessGrantFilters {
            limit: Some(7),
            status: Some("pending".to_string()),
            client_id: Some("client_alice".to_string()),
            ..Default::default()
        })
        .unwrap();
    client.get_secret_payload_by_key("db01", "user:sys").unwrap();
    client
        .share_secret_payload_by_key("db01", "user:sys", &json!({"target_client_id":"client_bob"}))
        .unwrap();
    client
        .create_secret_version_payload_by_key("db01", "user:sys", &json!({"ciphertext":"opaque"}))
        .unwrap();
    client.revoke_access_by_key("db01", "user:sys", "client_bob").unwrap();
    client.delete_secret_by_key("db01", "user:sys", true).unwrap();
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
    assert!(urls[3].contains("/v1/secrets/550e8400-e29b-41d4-a716-446655440000/access?limit=3"));

    assert_url_seen(&urls, "/v1/secrets/by-key/versions?namespace=db01&key=user%3Asys&limit=10");
    assert_url_seen(&urls, "/v1/secrets/by-key/access?namespace=db01&key=user%3Asys&limit=10");
    assert_url_seen(&urls, "/v1/access-requests?limit=7&status=pending&client_id=client_alice");
    assert_url_seen(&urls, "/v1/secrets/by-key?namespace=db01&key=user%3Asys");
    assert_url_seen(&urls, "/v1/secrets/by-key/share?namespace=db01&key=user%3Asys");
    assert_url_seen(&urls, "/v1/secrets/by-key/versions?namespace=db01&key=user%3Asys");
    assert_url_seen(&urls, "/v1/secrets/by-key/access/client_bob?namespace=db01&key=user%3Asys");
    assert_url_seen(&urls, "/v1/secrets/by-key?namespace=db01&key=user%3Asys&cascade=true");
    assert_url_seen(&urls, "/v1/audit-events?limit=9&outcome=success&action=secret.read");
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

#[derive(Default)]
struct FixedRandomSource {
    chunks: Mutex<Vec<Vec<u8>>>,
}

impl FixedRandomSource {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self { chunks: Mutex::new(chunks) }
    }
}

impl custodia_client::RandomSource for FixedRandomSource {
    fn random(&self, length: usize) -> custodia_client::CryptoResult<Vec<u8>> {
        let mut chunks = self.chunks.lock().unwrap();
        if chunks.is_empty() {
            return Err(custodia_client::CryptoError::RandomSource("missing deterministic bytes".to_string()));
        }
        let chunk = chunks.remove(0);
        assert_eq!(chunk.len(), length);
        Ok(chunk)
    }
}

fn crypto_options(random_chunks: Vec<Vec<u8>>) -> custodia_client::CryptoOptions {
    use custodia_client::{
        derive_x25519_recipient_public_key, StaticPrivateKeyProvider, StaticPublicKeyResolver,
        X25519PrivateKeyHandle,
    };
    use std::collections::BTreeMap;

    let alice_private = alice_private_key();
    let bob_private = bob_private_key();
    let alice_key = Arc::new(X25519PrivateKeyHandle::new("client_alice", &alice_private).unwrap());
    let mut public_keys = BTreeMap::new();
    public_keys.insert(
        "client_alice".to_string(),
        derive_x25519_recipient_public_key("client_alice", &alice_private).unwrap(),
    );
    public_keys.insert(
        "client_bob".to_string(),
        derive_x25519_recipient_public_key("client_bob", &bob_private).unwrap(),
    );
    custodia_client::CryptoOptions::new(
        Arc::new(StaticPublicKeyResolver::new(public_keys)),
        Arc::new(StaticPrivateKeyProvider::new(alice_key)),
    )
    .with_random_source(Arc::new(FixedRandomSource::new(random_chunks)))
}

#[test]
fn high_level_crypto_client_creates_keyspace_payload() {
    let fake = Arc::new(FakeTransport::default());
    fake.push_response(json_response(json!({
        "secret_id": "550e8400-e29b-41d4-a716-446655440000",
        "version_id": "11111111-1111-4111-8111-111111111111"
    })));
    let client = CustodiaClient::with_transport(config(), fake.clone()).unwrap();
    let crypto = client.with_crypto(crypto_options(vec![
        random_test_bytes(custodia_client::AES_256_GCM_KEY_BYTES),
        random_test_bytes(custodia_client::AES_GCM_NONCE_BYTES),
        random_test_bytes(custodia_client::X25519_KEY_BYTES),
        random_test_bytes(custodia_client::X25519_KEY_BYTES),
    ]));

    crypto
        .create_encrypted_secret_by_key(
            "db01",
            "user:sys",
            b"local plaintext",
            &["client_bob".to_string()],
            PERMISSION_ALL,
            None,
        )
        .unwrap();

    let create_body: serde_json::Value = serde_json::from_str(fake.requests()[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(create_body["namespace"], "db01");
    assert_eq!(create_body["key"], "user:sys");
    assert_eq!(create_body["crypto_metadata"]["aad"]["namespace"], "db01");
    assert_eq!(create_body["crypto_metadata"]["aad"]["key"], "user:sys");
    assert_eq!(create_body["crypto_metadata"]["aad"]["secret_version"], 1);
    assert_eq!(create_body["envelopes"].as_array().unwrap().len(), 2);
}

#[test]
fn high_level_crypto_client_creates_and_reads_local_plaintext() {
    let fake = Arc::new(FakeTransport::default());
    fake.push_response(json_response(json!({
        "secret_id": "550e8400-e29b-41d4-a716-446655440000",
        "version_id": "11111111-1111-4111-8111-111111111111"
    })));
    let client = CustodiaClient::with_transport(config(), fake.clone()).unwrap();
    let crypto = client.with_crypto(crypto_options(vec![
        random_test_bytes(custodia_client::AES_256_GCM_KEY_BYTES),
        random_test_bytes(custodia_client::AES_GCM_NONCE_BYTES),
        random_test_bytes(custodia_client::X25519_KEY_BYTES),
        random_test_bytes(custodia_client::X25519_KEY_BYTES),
    ]));

    crypto
        .create_encrypted_secret_by_key(
            "default",
            "db/password",
            b"local plaintext",
            &["client_bob".to_string()],
            PERMISSION_ALL,
            None,
        )
        .unwrap();

    let create_body: serde_json::Value = serde_json::from_str(fake.requests()[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(create_body["namespace"], "default");
    assert_eq!(create_body["key"], "db/password");
    assert_ne!(create_body["ciphertext"], "local plaintext");
    assert_eq!(create_body["crypto_metadata"]["version"], custodia_client::CRYPTO_VERSION_V1);
    assert_eq!(create_body["crypto_metadata"]["aad"]["namespace"], "default");
    assert_eq!(create_body["crypto_metadata"]["aad"]["key"], "db/password");
    assert_eq!(create_body["crypto_metadata"]["aad"]["secret_version"], 1);
    assert_eq!(create_body["envelopes"].as_array().unwrap().len(), 2);

    let alice_envelope = create_body["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["client_id"] == "client_alice")
        .unwrap()["envelope"]
        .clone();
    fake.push_response(json_response(json!({
        "secret_id": "550e8400-e29b-41d4-a716-446655440000",
        "namespace": "default",
        "key": "db/password",
        "version_id": "11111111-1111-4111-8111-111111111111",
        "ciphertext": create_body["ciphertext"],
        "crypto_metadata": create_body["crypto_metadata"],
        "envelope": alice_envelope,
        "permissions": PERMISSION_ALL
    })));

    let decrypted = crypto.read_decrypted_secret_by_key("default", "db/password").unwrap();
    assert_eq!(decrypted.plaintext, b"local plaintext");
}

#[test]
fn high_level_crypto_client_shares_existing_dek_without_plaintext_server_side() {
    let fake = Arc::new(FakeTransport::default());
    let client = CustodiaClient::with_transport(config(), fake.clone()).unwrap();
    let crypto = client.with_crypto(crypto_options(vec![random_test_bytes(
        custodia_client::X25519_KEY_BYTES,
    )]));

    let nonce = random_test_bytes(custodia_client::AES_GCM_NONCE_BYTES);
    let aad_inputs = custodia_client::CanonicalAADInputs {
        namespace: "db01".to_string(),
        key: "user:sys".to_string(),
        secret_version: 1,
    };
    let metadata = custodia_client::metadata_v1(aad_inputs.clone(), &nonce);
    let aad = custodia_client::build_canonical_aad(&metadata, &aad_inputs).unwrap();
    let dek = random_test_bytes(custodia_client::AES_256_GCM_KEY_BYTES);
    let alice_private = alice_private_key();
    let envelope_ephemeral = random_test_bytes(custodia_client::X25519_KEY_BYTES);
    let alice_public = custodia_client::derive_x25519_public_key(&alice_private).unwrap();
    let envelope = custodia_client::seal_hpke_v1_envelope(&alice_public, &envelope_ephemeral, &dek, &aad).unwrap();

    fake.push_response(json_response(json!({
        "secret_id": "550e8400-e29b-41d4-a716-446655440000",
        "namespace": "db01",
        "key": "user:sys",
        "version_id": "11111111-1111-4111-8111-111111111111",
        "ciphertext": custodia_client::encode_base64(&custodia_client::seal_content_aes_256_gcm(&dek, &nonce, b"secret", &aad).unwrap()),
        "crypto_metadata": metadata.to_value(),
        "envelope": custodia_client::encode_envelope(&envelope),
        "permissions": PERMISSION_ALL
    })));
    fake.push_response(json_response(json!({"status": "shared"})));

    crypto
        .share_encrypted_secret_by_key(
            "db01",
            "user:sys",
            "client_bob",
            custodia_client::PERMISSION_READ,
            None,
        )
        .unwrap();

    let requests = fake.requests();
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[1].method, "POST");
    let share_body: serde_json::Value = serde_json::from_str(requests[1].body.as_ref().unwrap()).unwrap();
    assert_eq!(share_body["target_client_id"], "client_bob");
    assert_eq!(share_body["permissions"], custodia_client::PERMISSION_READ);
    assert!(share_body["envelope"].as_str().unwrap().len() > 20);
}
