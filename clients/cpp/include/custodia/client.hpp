/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
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

// Public C++ transport configuration. The SDK uses mTLS for every request and
// keeps payload encryption/decryption in the optional CryptoClient layer.
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

// Transport is injectable so tests and applications can exercise SDK behavior
// without logging or replaying real ciphertext/envelope payloads.
class Transport {
 public:
  virtual ~Transport() = default;
  virtual Response send(const Request& request) = 0;
};

struct AADInputs {
  std::string namespace_name;
  std::string key;
  int secret_version{0};
};

struct CryptoMetadata {
  std::string version{"custodia.client-crypto.v1"};
  std::string content_cipher{"aes-256-gcm"};
  std::string envelope_scheme{"hpke-v1"};
  std::string content_nonce_b64;
  std::optional<AADInputs> aad;

  AADInputs canonical_aad_inputs(const AADInputs& fallback) const;
};

struct RecipientPublicKey {
  std::string client_id;
  std::string scheme{"hpke-v1"};
  std::vector<std::uint8_t> public_key;
  std::string fingerprint;
};

class CryptoError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class X25519PrivateKeyHandle final {
 public:
  X25519PrivateKeyHandle(std::string client_id, std::vector<std::uint8_t> private_key);

  const std::string& client_id() const noexcept;
  std::string scheme() const;
  std::vector<std::uint8_t> open_envelope(const std::vector<std::uint8_t>& envelope, const std::vector<std::uint8_t>& aad) const;
  const std::vector<std::uint8_t>& private_key() const noexcept;

 private:
  std::string client_id_;
  std::vector<std::uint8_t> private_key_;
};

struct CryptoOptions {
  std::function<RecipientPublicKey(const std::string&)> public_key_resolver;
  X25519PrivateKeyHandle private_key;
  std::function<std::vector<std::uint8_t>(std::size_t)> random_source;
};

std::vector<std::uint8_t> build_canonical_aad(const CryptoMetadata& metadata, const AADInputs& inputs);
std::string canonical_aad_sha256(const std::vector<std::uint8_t>& aad);
CryptoMetadata metadata_v1(const AADInputs& aad, const std::vector<std::uint8_t>& content_nonce);
std::vector<std::uint8_t> seal_content_aes_256_gcm(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& nonce,
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::uint8_t>& aad);
std::vector<std::uint8_t> open_content_aes_256_gcm(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& nonce,
    const std::vector<std::uint8_t>& ciphertext,
    const std::vector<std::uint8_t>& aad);
std::vector<std::uint8_t> derive_x25519_public_key(const std::vector<std::uint8_t>& private_key);
std::vector<std::uint8_t> seal_hpke_v1_envelope(
    const std::vector<std::uint8_t>& recipient_public_key,
    const std::vector<std::uint8_t>& sender_ephemeral_private_key,
    const std::vector<std::uint8_t>& dek,
    const std::vector<std::uint8_t>& aad);
std::vector<std::uint8_t> open_hpke_v1_envelope(
    const std::vector<std::uint8_t>& recipient_private_key,
    const std::vector<std::uint8_t>& envelope,
    const std::vector<std::uint8_t>& aad);
RecipientPublicKey derive_x25519_recipient_public_key(const std::string& client_id, const std::vector<std::uint8_t>& private_key);
std::string base64_encode(const std::vector<std::uint8_t>& value);
std::vector<std::uint8_t> base64_decode(const std::string& value);
std::string metadata_json(const CryptoMetadata& metadata);

class CryptoClient;

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
  std::string get_secret_payload_by_key(const std::string& namespace_name, const std::string& key);
  std::string list_secret_metadata(int limit = 0);
  std::string list_secret_version_metadata(const std::string& secret_id, int limit = 0);
  std::string list_secret_access_metadata(const std::string& secret_id, int limit = 0);
  std::string share_secret_payload(const std::string& secret_id, const std::string& payload_json);
  std::string share_secret_payload_by_key(const std::string& namespace_name, const std::string& key, const std::string& payload_json);
  std::string revoke_access_by_key(const std::string& namespace_name, const std::string& key, const std::string& client_id);
  std::string create_access_grant(const std::string& secret_id, const std::string& payload_json);
  std::string activate_access_grant_payload(
      const std::string& secret_id,
      const std::string& target_client_id,
      const std::string& payload_json);
  std::string revoke_access(const std::string& secret_id, const std::string& client_id);
  std::string create_secret_version_payload(const std::string& secret_id, const std::string& payload_json);
  std::string create_secret_version_payload_by_key(const std::string& namespace_name, const std::string& key, const std::string& payload_json);
  std::string delete_secret_by_key(const std::string& namespace_name, const std::string& key, bool cascade = false);
  std::string list_access_grant_metadata(const Filters& filters = {});

  std::string status_info();
  std::string version_info();
  std::string diagnostics_info();
  std::string revocation_status_info();
  std::string revocation_serial_status_info(const std::string& serial_hex);
  std::string list_audit_event_metadata(const Filters& filters = {});
  AuditExportArtifact export_audit_event_artifact(const Filters& filters = {});
  CryptoClient with_crypto(CryptoOptions options);

  Response request_raw(const std::string& method, const std::string& path, std::optional<std::string> payload_json = std::nullopt);
  std::string request_json(const std::string& method, const std::string& path, std::optional<std::string> payload_json = std::nullopt);

 private:
  Config config_;
  std::shared_ptr<Transport> transport_;
};

struct DecryptedSecret {
  std::string secret_id;
  std::string version_id;
  std::vector<std::uint8_t> plaintext;
  CryptoMetadata crypto_metadata;
  int permissions{0};
  std::string granted_at;
  std::string access_expires_at;
};

class CryptoClient final {
 public:
  CryptoClient(Client& transport, CryptoOptions options);

  std::string create_encrypted_secret(
      const std::string& name,
      const std::vector<std::uint8_t>& plaintext,
      const std::vector<std::string>& recipients = {},
      int permissions = permission_all,
      const std::string& expires_at = "");
  std::string create_encrypted_secret_by_key(
      const std::string& namespace_name,
      const std::string& key,
      const std::vector<std::uint8_t>& plaintext,
      const std::vector<std::string>& recipients = {},
      int permissions = permission_all,
      const std::string& expires_at = "");
  std::string create_encrypted_secret_version(
      const std::string& secret_id,
      const std::vector<std::uint8_t>& plaintext,
      const std::vector<std::string>& recipients = {},
      int permissions = permission_all,
      const std::string& expires_at = "");
  std::string create_encrypted_secret_version_by_key(
      const std::string& namespace_name,
      const std::string& key,
      const std::vector<std::uint8_t>& plaintext,
      const std::vector<std::string>& recipients = {},
      int permissions = permission_all,
      const std::string& expires_at = "");
  DecryptedSecret read_decrypted_secret(const std::string& secret_id);
  DecryptedSecret read_decrypted_secret_by_key(const std::string& namespace_name, const std::string& key);
  std::string share_encrypted_secret(
      const std::string& secret_id,
      const std::string& target_client_id,
      int permissions = permission_read,
      const std::string& expires_at = "");
  std::string share_encrypted_secret_by_key(
      const std::string& namespace_name,
      const std::string& key,
      const std::string& target_client_id,
      int permissions = permission_read,
      const std::string& expires_at = "");

 private:
  std::vector<std::string> normalized_recipients(const std::vector<std::string>& recipients) const;
  std::string seal_recipient_envelopes(const std::vector<std::string>& recipients, const std::vector<std::uint8_t>& dek, const std::vector<std::uint8_t>& aad);
  std::vector<std::uint8_t> open_secret_envelope(const std::string& encoded_envelope, const std::vector<std::uint8_t>& aad) const;
  std::vector<std::uint8_t> random(std::size_t length) const;

  Client* transport_;
  CryptoOptions options_;
};

std::string path_escape(const std::string& value);
std::string with_query(const std::string& path, const Filters& filters);

}  // namespace custodia
