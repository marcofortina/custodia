/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

#include "custodia/client.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <queue>
#include <string>
#include <vector>

namespace {

class FakeTransport final : public custodia::Transport {
 public:
  custodia::Response response;
  custodia::Request last_request;

  custodia::Response send(const custodia::Request& request) override {
    last_request = request;
    return response;
  }
};

void expect_eq(const std::string& expected, const std::string& actual, const std::string& label) {
  if (expected != actual) {
    std::cerr << label << ": expected <" << expected << "> but got <" << actual << ">\n";
    std::exit(1);
  }
}

void expect_eq(int expected, int actual, const std::string& label) {
  if (expected != actual) {
    std::cerr << label << ": expected <" << expected << "> but got <" << actual << ">\n";
    std::exit(1);
  }
}


std::vector<std::uint8_t> b64(const std::string& value) {
  return custodia::base64_decode(value);
}

void expect_contains(const std::string& haystack, const std::string& needle, const std::string& label) {
  if (haystack.find(needle) == std::string::npos) {
    std::cerr << label << ": missing <" << needle << "> in <" << haystack << ">\n";
    std::exit(1);
  }
}

void expect_bytes(const std::vector<std::uint8_t>& expected, const std::vector<std::uint8_t>& actual, const std::string& label) {
  if (expected != actual) {
    std::cerr << label << ": bytes differ\n";
    std::exit(1);
  }
}

custodia::CryptoOptions crypto_options(std::queue<std::vector<std::uint8_t>> random_values = {}) {
  auto alice_private = b64("MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=");
  return custodia::CryptoOptions{
      .public_key_resolver = [alice_private](const std::string& client_id) {
        if (client_id != "client_alice") {
          throw custodia::CryptoError("recipient public key not found");
        }
        return custodia::derive_x25519_recipient_public_key(client_id, alice_private);
      },
      .private_key = custodia::X25519PrivateKeyHandle("client_alice", alice_private),
      .random_source = [values = std::move(random_values)](std::size_t length) mutable {
        if (values.empty() || values.front().size() != length) {
          throw std::invalid_argument("missing deterministic random value");
        }
        auto value = values.front();
        values.pop();
        return value;
      }};
}

custodia::Client test_client(std::shared_ptr<FakeTransport> transport) {
  return custodia::Client(custodia::Config{.server_url = "https://vault.test/", .cert_file = "client.crt", .key_file = "client.key", .ca_file = "ca.crt"}, std::move(transport));
}

void routes_opaque_secret_payloads() {
  auto transport = std::make_shared<FakeTransport>();
  transport->response = custodia::Response{.status = 200, .body = R"({"secret_id":"s1"})", .headers = {}};
  auto client = test_client(transport);

  std::string response = client.create_secret_payload(R"({"ciphertext":"opaque"})");

  expect_eq("POST", transport->last_request.method, "method");
  expect_eq("https://vault.test/v1/secrets", transport->last_request.url, "url");
  expect_eq("application/json", transport->last_request.headers.at("Content-Type"), "content-type");
  expect_eq(R"({"ciphertext":"opaque"})", *transport->last_request.body, "body");
  expect_eq(R"({"secret_id":"s1"})", response, "response");

  client.activate_access_grant_payload("secret/one", "client one", R"({"envelope":"opaque"})");
  expect_eq(
      "https://vault.test/v1/secrets/secret%2Fone/access-requests/client%20one/activate",
      transport->last_request.url,
      "encoded activate path");
}

void validates_http_errors() {
  auto transport = std::make_shared<FakeTransport>();
  transport->response = custodia::Response{.status = 403, .body = R"({"error":"forbidden"})", .headers = {}};
  auto client = test_client(transport);

  try {
    client.status_info();
    std::cerr << "expected HttpError\n";
    std::exit(1);
  } catch (const custodia::HttpError& err) {
    expect_eq(403, err.status(), "status");
    expect_eq(R"({"error":"forbidden"})", err.body(), "error body");
  }
}

void exports_audit_metadata_headers() {
  auto transport = std::make_shared<FakeTransport>();
  transport->response = custodia::Response{
      .status = 200,
      .body = "event_id,action\n1,read\n",
      .headers = {{"X-Custodia-Audit-Export-SHA256", "abc123"}, {"X-Custodia-Audit-Export-Events", "1"}}};
  auto client = test_client(transport);

  auto artifact = client.export_audit_event_artifact({{"limit", "1"}, {"outcome", "ok"}});

  expect_eq("https://vault.test/v1/audit-events/export?limit=1&outcome=ok", transport->last_request.url, "export url");
  expect_eq("abc123", artifact.sha256, "sha256");
  expect_eq("1", artifact.event_count, "event count");
  expect_eq("event_id,action\n1,read\n", artifact.body, "export body");
}


void validates_shared_crypto_vectors() {
  custodia::CryptoMetadata metadata{};
  auto aad = custodia::build_canonical_aad(metadata, custodia::AADInputs{"", "database-password", ""});
  expect_eq(
      R"({"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","secret_name":"database-password"})",
      std::string(aad.begin(), aad.end()),
      "canonical aad");
  expect_eq("32f7c1471093f0a85a963d5cfeaf3aeec8edcd52577175c6b4a826c5063144bf", custodia::canonical_aad_sha256(aad), "aad sha");

  auto alice_private = b64("MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=");
  expect_eq("BPXykWLDGo3voY5udCIk7oBvwXGKJ4voWbpWIEArjzo=", custodia::base64_encode(custodia::derive_x25519_public_key(alice_private)), "alice public key");

  auto dek = b64("UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=");
  auto nonce = b64("YWFhYWFhYWFhYWFh");
  auto plaintext = b64("ZGF0YWJhc2UgcGFzc3dvcmQ6IGNvcnJlY3QgaG9yc2UgYmF0dGVyeSBzdGFwbGU=");
  auto ciphertext = custodia::seal_content_aes_256_gcm(dek, nonce, plaintext, aad);
  expect_eq(
      "94P22VzLbeb3J+osVz4T/Pr3Qx0LBv8TbYL/BKfId08ZJV6XCPThpSrEt2h4N+zSXBrZBDJM6o0a8r/q1gqj",
      custodia::base64_encode(ciphertext),
      "ciphertext");
  expect_bytes(plaintext, custodia::open_content_aes_256_gcm(dek, nonce, ciphertext, aad), "plaintext roundtrip");

  auto envelope = custodia::seal_hpke_v1_envelope(
      custodia::derive_x25519_public_key(alice_private),
      b64("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="),
      dek,
      aad);
  expect_eq(
      "ehpOcJvwhaxJSroEabmx7aCrH3ixaqu3n/7akGI+hSIIS8IcAryGTNuiRs8bUbEeIim/t9y6DjZ/88RjRh0q2dWBY0/F6EA3484TSix3NNA=",
      custodia::base64_encode(envelope),
      "envelope");
  expect_bytes(dek, custodia::open_hpke_v1_envelope(alice_private, envelope, aad), "opened envelope");
}

void creates_encrypted_secret_with_deterministic_vector_payload() {
  auto transport = std::make_shared<FakeTransport>();
  transport->response = custodia::Response{.status = 200, .body = R"({"secret_id":"s1"})", .headers = {}};
  auto client = test_client(transport);
  std::queue<std::vector<std::uint8_t>> random_values;
  random_values.push(b64("UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE="));
  random_values.push(b64("YWFhYWFhYWFhYWFh"));
  random_values.push(b64("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="));
  auto crypto = client.with_crypto(crypto_options(std::move(random_values)));

  auto response = crypto.create_encrypted_secret(
      "database-password",
      b64("ZGF0YWJhc2UgcGFzc3dvcmQ6IGNvcnJlY3QgaG9yc2UgYmF0dGVyeSBzdGFwbGU="));

  expect_eq(R"({"secret_id":"s1"})", response, "create response");
  expect_contains(*transport->last_request.body, R"("name":"database-password")", "create name");
  expect_contains(*transport->last_request.body, R"("content_nonce_b64":"YWFhYWFhYWFhYWFh")", "create nonce");
  expect_contains(
      *transport->last_request.body,
      R"("ciphertext":"94P22VzLbeb3J+osVz4T/Pr3Qx0LBv8TbYL/BKfId08ZJV6XCPThpSrEt2h4N+zSXBrZBDJM6o0a8r/q1gqj")",
      "create ciphertext");
  expect_contains(
      *transport->last_request.body,
      R"("envelope":"ehpOcJvwhaxJSroEabmx7aCrH3ixaqu3n/7akGI+hSIIS8IcAryGTNuiRs8bUbEeIim/t9y6DjZ/88RjRh0q2dWBY0/F6EA3484TSix3NNA=")",
      "create envelope");
}

void reads_decrypted_secret_with_persisted_aad_metadata() {
  auto transport = std::make_shared<FakeTransport>();
  transport->response = custodia::Response{
      .status = 200,
      .body = R"({"secret_id":"550e8400-e29b-41d4-a716-446655440000","version_id":"660e8400-e29b-41d4-a716-446655440000","ciphertext":"d+Ub720HWc3YmYcZyQPyyd3EK2QHKMg7iaKMgGg6Ir5RRRmfzoUe","crypto_metadata":{"version":"custodia.client-crypto.v1","content_cipher":"aes-256-gcm","envelope_scheme":"hpke-v1","content_nonce_b64":"Y2NjY2NjY2NjY2Nj","aad":{"secret_id":"550e8400-e29b-41d4-a716-446655440000","version_id":"660e8400-e29b-41d4-a716-446655440000"}},"envelope":"ze/YeDqRtEZkDi4flVmds15ISgBxvSGCs7YNCBLBDHDZczDrK3IdDIfEWJA8JD3ERLLFg1eklPtBfJ2tbctFNV8yFiD0BrjltlAaV/RogLk=","permissions":7})",
      .headers = {}};
  auto client = test_client(transport);
  auto crypto = client.with_crypto(crypto_options());

  auto secret = crypto.read_decrypted_secret("550e8400-e29b-41d4-a716-446655440000");

  expect_eq("existing secret payload", std::string(secret.plaintext.begin(), secret.plaintext.end()), "decrypted plaintext");
  expect_eq("550e8400-e29b-41d4-a716-446655440000", secret.secret_id, "secret id");
  expect_eq(7, secret.permissions, "permissions");
}

void validates_config() {
  try {
    custodia::Client client(custodia::Config{});
    (void)client;
    std::cerr << "expected config validation error\n";
    std::exit(1);
  } catch (const std::invalid_argument& err) {
    expect_eq("server_url is required", err.what(), "config validation");
  }
}

}  // namespace

int main() {
  routes_opaque_secret_payloads();
  validates_http_errors();
  exports_audit_metadata_headers();
  validates_config();
  validates_shared_crypto_vectors();
  creates_encrypted_secret_with_deterministic_vector_payload();
  reads_decrypted_secret_with_persisted_aad_metadata();
  return 0;
}
