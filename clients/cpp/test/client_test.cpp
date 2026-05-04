#include "custodia/client.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

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
  return 0;
}
