#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace custodia {

inline constexpr int permission_share = 1;
inline constexpr int permission_write = 2;
inline constexpr int permission_read = 4;
inline constexpr int permission_all = permission_share | permission_write | permission_read;

using Headers = std::map<std::string, std::string>;
using Filters = std::vector<std::pair<std::string, std::string>>;

struct Config {
  std::string server_url;
  std::string cert_file;
  std::string key_file;
  std::string ca_file;
  std::chrono::milliseconds timeout{15000};
  std::string user_agent{"custodia-cpp-transport/0.0.0"};
};

struct Request {
  std::string method;
  std::string url;
  Headers headers;
  std::optional<std::string> body;
};

struct Response {
  int status{0};
  std::string body;
  Headers headers;
};

struct AuditExportArtifact {
  std::string body;
  std::string sha256;
  std::string event_count;
};

class HttpError final : public std::runtime_error {
 public:
  explicit HttpError(Response response);

  int status() const noexcept;
  const std::string& body() const noexcept;
  const Headers& headers() const noexcept;

 private:
  Response response_;
};

class Transport {
 public:
  virtual ~Transport() = default;
  virtual Response send(const Request& request) = 0;
};

class Client final {
 public:
  explicit Client(Config config, std::shared_ptr<Transport> transport = {});

  std::string current_client_info();
  std::string list_client_infos(int limit = 0, std::optional<bool> active = std::nullopt);
  std::string get_client_info(const std::string& client_id);
  std::string create_client_info(const std::string& payload_json);
  std::string revoke_client_info(const std::string& payload_json);

  std::string create_secret_payload(const std::string& payload_json);
  std::string get_secret_payload(const std::string& secret_id);
  std::string list_secret_metadata(int limit = 0);
  std::string list_secret_version_metadata(const std::string& secret_id, int limit = 0);
  std::string list_secret_access_metadata(const std::string& secret_id, int limit = 0);
  std::string share_secret_payload(const std::string& secret_id, const std::string& payload_json);
  std::string create_access_grant(const std::string& secret_id, const std::string& payload_json);
  std::string activate_access_grant_payload(
      const std::string& secret_id,
      const std::string& target_client_id,
      const std::string& payload_json);
  std::string revoke_access(const std::string& secret_id, const std::string& client_id);
  std::string create_secret_version_payload(const std::string& secret_id, const std::string& payload_json);
  std::string list_access_grant_metadata(const Filters& filters = {});

  std::string status_info();
  std::string version_info();
  std::string diagnostics_info();
  std::string revocation_status_info();
  std::string revocation_serial_status_info(const std::string& serial_hex);
  std::string list_audit_event_metadata(const Filters& filters = {});
  AuditExportArtifact export_audit_event_artifact(const Filters& filters = {});

  Response request_raw(const std::string& method, const std::string& path, std::optional<std::string> payload_json = std::nullopt);
  std::string request_json(const std::string& method, const std::string& path, std::optional<std::string> payload_json = std::nullopt);

 private:
  Config config_;
  std::shared_ptr<Transport> transport_;
};

std::string path_escape(const std::string& value);
std::string with_query(const std::string& path, const Filters& filters);

}  // namespace custodia
