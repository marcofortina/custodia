#include "custodia/client.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace custodia {
namespace {

class CurlTransport final : public Transport {
 public:
  explicit CurlTransport(Config config) : config_(std::move(config)) {}

  Response send(const Request& request) override {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
      throw std::runtime_error("failed to initialize libcurl");
    }

    Response response;
    curl_slist* header_list = nullptr;
    for (const auto& [key, value] : request.headers) {
      std::string header = key + ": " + value;
      header_list = curl_slist_append(header_list, header.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.method.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, config_.cert_file.c_str());
    curl_easy_setopt(curl, CURLOPT_SSLKEY, config_.key_file.c_str());
    curl_easy_setopt(curl, CURLOPT_CAINFO, config_.ca_file.c_str());
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(config_.timeout.count()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &CurlTransport::write_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &CurlTransport::write_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);

    if (request.body.has_value()) {
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body->data());
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body->size()));
    }

    CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
      std::string message = curl_easy_strerror(code);
      curl_slist_free_all(header_list);
      curl_easy_cleanup(curl);
      throw std::runtime_error("Custodia request failed: " + message);
    }

    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    response.status = static_cast<int>(status);

    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);
    return response;
  }

 private:
  static size_t write_body(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* body = static_cast<std::string*>(userdata);
    body->append(ptr, size * nmemb);
    return size * nmemb;
  }

  static size_t write_header(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* headers = static_cast<Headers*>(userdata);
    std::string line(ptr, size * nmemb);
    auto separator = line.find(':');
    if (separator == std::string::npos) {
      return size * nmemb;
    }
    std::string key = trim(line.substr(0, separator));
    std::string value = trim(line.substr(separator + 1));
    if (!key.empty()) {
      (*headers)[key] = value;
    }
    return size * nmemb;
  }

  static std::string trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
      value.erase(value.begin());
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
      value.pop_back();
    }
    return value;
  }

  Config config_;
};

std::string normalize_server_url(std::string value) {
  while (!value.empty() && value.back() == '/') {
    value.pop_back();
  }
  return value;
}

void validate_config(const Config& config) {
  if (config.server_url.empty()) {
    throw std::invalid_argument("server_url is required");
  }
  if (config.cert_file.empty()) {
    throw std::invalid_argument("cert_file is required");
  }
  if (config.key_file.empty()) {
    throw std::invalid_argument("key_file is required");
  }
  if (config.ca_file.empty()) {
    throw std::invalid_argument("ca_file is required");
  }
  if (config.timeout.count() <= 0) {
    throw std::invalid_argument("timeout must be positive");
  }
}

void validate_optional_limit(int limit) {
  if (limit < 0) {
    throw std::invalid_argument("limit must be non-negative");
  }
}

std::string require_text(const std::string& value, const std::string& name) {
  auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch); });
  auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch); }).base();
  if (first >= last) {
    throw std::invalid_argument(name + " is required");
  }
  return std::string(first, last);
}

std::string bool_string(bool value) {
  return value ? "true" : "false";
}

std::string header_value_case_insensitive(const Headers& headers, const std::string& wanted) {
  auto lower = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
  };
  const std::string wanted_lower = lower(wanted);
  for (const auto& [key, value] : headers) {
    if (lower(key) == wanted_lower) {
      return value;
    }
  }
  return "";
}

}  // namespace

HttpError::HttpError(Response response)
    : std::runtime_error("Custodia request failed with HTTP " + std::to_string(response.status)),
      response_(std::move(response)) {}

int HttpError::status() const noexcept { return response_.status; }
const std::string& HttpError::body() const noexcept { return response_.body; }
const Headers& HttpError::headers() const noexcept { return response_.headers; }

Client::Client(Config config, std::shared_ptr<Transport> transport) : config_(std::move(config)) {
  config_.server_url = normalize_server_url(config_.server_url);
  if (config_.user_agent.empty()) {
    config_.user_agent = "custodia-cpp-transport/0.0.0";
  }
  if (transport == nullptr) {
    validate_config(config_);
    transport_ = std::make_shared<CurlTransport>(config_);
  } else {
    if (config_.server_url.empty()) {
      throw std::invalid_argument("server_url is required");
    }
    transport_ = std::move(transport);
  }
}

std::string Client::current_client_info() { return request_json("GET", "/v1/me"); }

std::string Client::list_client_infos(int limit, std::optional<bool> active) {
  validate_optional_limit(limit);
  Filters filters;
  if (limit > 0) {
    filters.emplace_back("limit", std::to_string(limit));
  }
  if (active.has_value()) {
    filters.emplace_back("active", bool_string(*active));
  }
  return request_json("GET", with_query("/v1/clients", filters));
}

std::string Client::get_client_info(const std::string& client_id) {
  return request_json("GET", "/v1/clients/" + path_escape(client_id));
}

std::string Client::create_client_info(const std::string& payload_json) {
  return request_json("POST", "/v1/clients", payload_json);
}

std::string Client::revoke_client_info(const std::string& payload_json) {
  return request_json("POST", "/v1/clients/revoke", payload_json);
}

std::string Client::create_secret_payload(const std::string& payload_json) {
  return request_json("POST", "/v1/secrets", payload_json);
}

std::string Client::get_secret_payload(const std::string& secret_id) {
  return request_json("GET", "/v1/secrets/" + path_escape(secret_id));
}

std::string Client::list_secret_metadata(int limit) {
  validate_optional_limit(limit);
  Filters filters;
  if (limit > 0) {
    filters.emplace_back("limit", std::to_string(limit));
  }
  return request_json("GET", with_query("/v1/secrets", filters));
}

std::string Client::list_secret_version_metadata(const std::string& secret_id, int limit) {
  validate_optional_limit(limit);
  Filters filters;
  if (limit > 0) {
    filters.emplace_back("limit", std::to_string(limit));
  }
  return request_json("GET", with_query("/v1/secrets/" + path_escape(secret_id) + "/versions", filters));
}

std::string Client::list_secret_access_metadata(const std::string& secret_id, int limit) {
  validate_optional_limit(limit);
  Filters filters;
  if (limit > 0) {
    filters.emplace_back("limit", std::to_string(limit));
  }
  return request_json("GET", with_query("/v1/secrets/" + path_escape(secret_id) + "/access", filters));
}

std::string Client::share_secret_payload(const std::string& secret_id, const std::string& payload_json) {
  return request_json("POST", "/v1/secrets/" + path_escape(secret_id) + "/share", payload_json);
}

std::string Client::create_access_grant(const std::string& secret_id, const std::string& payload_json) {
  return request_json("POST", "/v1/secrets/" + path_escape(secret_id) + "/access-requests", payload_json);
}

std::string Client::activate_access_grant_payload(
    const std::string& secret_id,
    const std::string& target_client_id,
    const std::string& payload_json) {
  return request_json(
      "POST",
      "/v1/secrets/" + path_escape(secret_id) + "/access-requests/" + path_escape(target_client_id) + "/activate",
      payload_json);
}

std::string Client::revoke_access(const std::string& secret_id, const std::string& client_id) {
  return request_json("DELETE", "/v1/secrets/" + path_escape(secret_id) + "/access/" + path_escape(client_id));
}

std::string Client::create_secret_version_payload(const std::string& secret_id, const std::string& payload_json) {
  return request_json("POST", "/v1/secrets/" + path_escape(secret_id) + "/versions", payload_json);
}

std::string Client::list_access_grant_metadata(const Filters& filters) {
  return request_json("GET", with_query("/v1/access-requests", filters));
}

std::string Client::status_info() { return request_json("GET", "/v1/status"); }
std::string Client::version_info() { return request_json("GET", "/v1/version"); }
std::string Client::diagnostics_info() { return request_json("GET", "/v1/diagnostics"); }
std::string Client::revocation_status_info() { return request_json("GET", "/v1/revocation/status"); }

std::string Client::revocation_serial_status_info(const std::string& serial_hex) {
  return request_json("GET", with_query("/v1/revocation/serial", {{"serial_hex", require_text(serial_hex, "serial_hex")}}));
}

std::string Client::list_audit_event_metadata(const Filters& filters) {
  return request_json("GET", with_query("/v1/audit-events", filters));
}

AuditExportArtifact Client::export_audit_event_artifact(const Filters& filters) {
  Response response = request_raw("GET", with_query("/v1/audit-events/export", filters));
  return AuditExportArtifact{
      response.body,
      header_value_case_insensitive(response.headers, "X-Custodia-Audit-Export-SHA256"),
      header_value_case_insensitive(response.headers, "X-Custodia-Audit-Export-Events")};
}

Response Client::request_raw(const std::string& method, const std::string& path, std::optional<std::string> payload_json) {
  Request request;
  request.method = method;
  request.url = config_.server_url + path;
  request.headers.emplace("Accept", "application/json");
  request.headers.emplace("User-Agent", config_.user_agent);
  if (payload_json.has_value()) {
    request.headers.emplace("Content-Type", "application/json");
    request.headers.emplace("Content-Length", std::to_string(payload_json->size()));
    request.body = std::move(payload_json);
  }
  Response response = transport_->send(request);
  if (response.status < 200 || response.status >= 300) {
    throw HttpError(std::move(response));
  }
  return response;
}

std::string Client::request_json(const std::string& method, const std::string& path, std::optional<std::string> payload_json) {
  return request_raw(method, path, std::move(payload_json)).body;
}

std::string path_escape(const std::string& value) {
  const std::string text = require_text(value, "path segment");
  std::ostringstream out;
  out << std::uppercase << std::hex;
  for (unsigned char ch : text) {
    const bool unreserved = std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~';
    if (unreserved) {
      out << static_cast<char>(ch);
    } else {
      out << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(ch);
    }
  }
  return out.str();
}

std::string with_query(const std::string& path, const Filters& filters) {
  if (filters.empty()) {
    return path;
  }
  std::ostringstream query;
  bool first = true;
  for (const auto& [key, value] : filters) {
    if (key.empty() || value.empty()) {
      continue;
    }
    if (!first) {
      query << '&';
    }
    query << path_escape(key) << '=' << path_escape(value);
    first = false;
  }
  const std::string encoded = query.str();
  return encoded.empty() ? path : path + "?" + encoded;
}

}  // namespace custodia
