#include "custodia/client.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

namespace custodia {
namespace {

constexpr const char* kCryptoVersionV1 = "custodia.client-crypto.v1";
constexpr const char* kContentCipherV1 = "aes-256-gcm";
constexpr const char* kEnvelopeSchemeHPKEV1 = "hpke-v1";
constexpr std::size_t kAES256GCMKeyBytes = 32;
constexpr std::size_t kAESGCMNonceBytes = 12;
constexpr std::size_t kAESGCMTagBytes = 16;
constexpr std::size_t kX25519KeyBytes = 32;

const std::vector<std::uint8_t> kHPKEEnvelopeInfo{'c','u','s','t','o','d','i','a','.','c','l','i','e','n','t','-','c','r','y','p','t','o','.','v','1',' ','e','n','v','e','l','o','p','e'};
const std::vector<std::uint8_t> kHPKEKEMID{0x00, 0x20};
const std::vector<std::uint8_t> kHPKEKDFID{0x00, 0x01};
const std::vector<std::uint8_t> kHPKEAEADID{0x00, 0x02};
const std::vector<std::uint8_t> kHPKEVersionLabel{'H','P','K','E','-','v','1'};

std::vector<std::uint8_t> bytes(const std::string& value) {
  return {value.begin(), value.end()};
}

std::vector<std::uint8_t> concat(std::initializer_list<std::vector<std::uint8_t>> values) {
  std::size_t size = 0;
  for (const auto& value : values) {
    size += value.size();
  }
  std::vector<std::uint8_t> out;
  out.reserve(size);
  for (const auto& value : values) {
    out.insert(out.end(), value.begin(), value.end());
  }
  return out;
}

std::vector<std::uint8_t> hpke_kem_suite_id() { return concat({bytes("KEM"), kHPKEKEMID}); }
std::vector<std::uint8_t> hpke_suite_id() { return concat({bytes("HPKE"), kHPKEKEMID, kHPKEKDFID, kHPKEAEADID}); }

void require_size(const std::vector<std::uint8_t>& value, std::size_t size, const std::string& message) {
  if (value.size() != size) {
    throw CryptoError(message);
  }
}

std::string json_quote(const std::string& value) {
  std::ostringstream out;
  out << '"';
  for (unsigned char ch : value) {
    switch (ch) {
      case '"': out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      default:
        if (ch < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch);
        } else {
          out << ch;
        }
    }
  }
  out << '"';
  return out.str();
}

void append_json_field(std::ostringstream& json, const std::string& key, const std::string& value) {
  json << json_quote(key) << ':' << json_quote(value);
}

std::vector<std::uint8_t> hmac_sha256(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& data) {
  unsigned int length = SHA256_DIGEST_LENGTH;
  std::vector<std::uint8_t> out(length);
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &length);
  out.resize(length);
  return out;
}

std::vector<std::uint8_t> hkdf_extract(const std::optional<std::vector<std::uint8_t>>& salt, const std::vector<std::uint8_t>& ikm) {
  return hmac_sha256(salt.value_or(std::vector<std::uint8_t>(32, 0)), ikm);
}

std::vector<std::uint8_t> hkdf_expand(const std::vector<std::uint8_t>& prk, const std::vector<std::uint8_t>& info, std::size_t length) {
  std::vector<std::uint8_t> result;
  std::vector<std::uint8_t> previous;
  std::uint8_t counter = 1;
  while (result.size() < length) {
    auto block_input = concat({previous, info, std::vector<std::uint8_t>{counter}});
    previous = hmac_sha256(prk, block_input);
    result.insert(result.end(), previous.begin(), previous.end());
    counter++;
  }
  result.resize(length);
  return result;
}

std::vector<std::uint8_t> hpke_labeled_extract(
    const std::vector<std::uint8_t>& suite_id,
    const std::optional<std::vector<std::uint8_t>>& salt,
    const std::vector<std::uint8_t>& label,
    const std::vector<std::uint8_t>& ikm) {
  return hkdf_extract(salt, concat({kHPKEVersionLabel, suite_id, label, ikm}));
}

std::vector<std::uint8_t> hpke_labeled_expand(
    const std::vector<std::uint8_t>& prk,
    const std::vector<std::uint8_t>& suite_id,
    const std::vector<std::uint8_t>& label,
    const std::vector<std::uint8_t>& info,
    std::size_t length) {
  std::vector<std::uint8_t> length_prefix{static_cast<std::uint8_t>((length >> 8) & 0xff), static_cast<std::uint8_t>(length & 0xff)};
  auto labeled_info = concat({length_prefix, kHPKEVersionLabel, suite_id, label, info});
  return hkdf_expand(prk, labeled_info, length);
}

std::vector<std::uint8_t> hpke_kem_extract_and_expand(const std::vector<std::uint8_t>& dh, const std::vector<std::uint8_t>& kem_context) {
  auto suite = hpke_kem_suite_id();
  auto eae_prk = hpke_labeled_extract(suite, std::nullopt, bytes("eae_prk"), dh);
  return hpke_labeled_expand(eae_prk, suite, bytes("shared_secret"), kem_context, 32);
}

struct HPKEKeySchedule {
  std::vector<std::uint8_t> key;
  std::vector<std::uint8_t> nonce;
};

HPKEKeySchedule hpke_key_schedule(const std::vector<std::uint8_t>& shared_secret, const std::vector<std::uint8_t>& info) {
  auto suite = hpke_suite_id();
  auto psk_id_hash = hpke_labeled_extract(suite, std::nullopt, bytes("psk_id_hash"), {});
  auto info_hash = hpke_labeled_extract(suite, std::nullopt, bytes("info_hash"), info);
  auto context = concat({std::vector<std::uint8_t>{0x00}, psk_id_hash, info_hash});
  auto secret = hpke_labeled_extract(suite, shared_secret, bytes("secret"), {});
  return {
      hpke_labeled_expand(secret, suite, bytes("key"), context, kAES256GCMKeyBytes),
      hpke_labeled_expand(secret, suite, bytes("base_nonce"), context, kAESGCMNonceBytes)};
}

std::vector<std::uint8_t> x25519(const std::vector<std::uint8_t>& private_key, const std::vector<std::uint8_t>& public_key) {
  require_size(private_key, kX25519KeyBytes, "invalid x25519 private key");
  require_size(public_key, kX25519KeyBytes, "invalid x25519 public key");
  EVP_PKEY* sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
  EVP_PKEY* pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, public_key.data(), public_key.size());
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(sk, nullptr);
  if (sk == nullptr || pk == nullptr || ctx == nullptr || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, pk) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(sk);
    throw CryptoError("x25519 operation failed");
  }
  std::size_t length = 0;
  EVP_PKEY_derive(ctx, nullptr, &length);
  std::vector<std::uint8_t> shared(length);
  if (EVP_PKEY_derive(ctx, shared.data(), &length) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(sk);
    throw CryptoError("x25519 operation failed");
  }
  shared.resize(length);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pk);
  EVP_PKEY_free(sk);
  return shared;
}

std::vector<std::uint8_t> hpke_seal(
    const std::vector<std::uint8_t>& shared_secret,
    const std::vector<std::uint8_t>& info,
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::uint8_t>& aad) {
  auto schedule = hpke_key_schedule(shared_secret, info);
  return seal_content_aes_256_gcm(schedule.key, schedule.nonce, plaintext, aad);
}

std::vector<std::uint8_t> hpke_open(
    const std::vector<std::uint8_t>& shared_secret,
    const std::vector<std::uint8_t>& info,
    const std::vector<std::uint8_t>& ciphertext,
    const std::vector<std::uint8_t>& aad) {
  auto schedule = hpke_key_schedule(shared_secret, info);
  return open_content_aes_256_gcm(schedule.key, schedule.nonce, ciphertext, aad);
}

}  // namespace

AADInputs CryptoMetadata::canonical_aad_inputs(const AADInputs& fallback) const { return aad.value_or(fallback); }

X25519PrivateKeyHandle::X25519PrivateKeyHandle(std::string client_id, std::vector<std::uint8_t> private_key)
    : client_id_(std::move(client_id)), private_key_(std::move(private_key)) {
  derive_x25519_public_key(private_key_);
}

const std::string& X25519PrivateKeyHandle::client_id() const noexcept { return client_id_; }
std::string X25519PrivateKeyHandle::scheme() const { return kEnvelopeSchemeHPKEV1; }
std::vector<std::uint8_t> X25519PrivateKeyHandle::open_envelope(const std::vector<std::uint8_t>& envelope, const std::vector<std::uint8_t>& aad) const {
  return open_hpke_v1_envelope(private_key_, envelope, aad);
}
const std::vector<std::uint8_t>& X25519PrivateKeyHandle::private_key() const noexcept { return private_key_; }

std::vector<std::uint8_t> build_canonical_aad(const CryptoMetadata& metadata, const AADInputs& inputs) {
  if (metadata.version != kCryptoVersionV1) {
    throw CryptoError("unsupported crypto metadata version");
  }
  if (metadata.content_cipher != kContentCipherV1) {
    throw CryptoError("unsupported content cipher");
  }
  if (metadata.envelope_scheme != kEnvelopeSchemeHPKEV1) {
    throw CryptoError("unsupported envelope scheme");
  }
  if (inputs.secret_id.empty() && inputs.secret_name.empty()) {
    throw CryptoError("secret_id or secret_name is required");
  }
  std::ostringstream json;
  json << '{';
  append_json_field(json, "version", metadata.version);
  json << ',';
  append_json_field(json, "content_cipher", metadata.content_cipher);
  json << ',';
  append_json_field(json, "envelope_scheme", metadata.envelope_scheme);
  if (!inputs.secret_id.empty()) {
    json << ',';
    append_json_field(json, "secret_id", inputs.secret_id);
  }
  if (!inputs.secret_name.empty()) {
    json << ',';
    append_json_field(json, "secret_name", inputs.secret_name);
  }
  if (!inputs.version_id.empty()) {
    json << ',';
    append_json_field(json, "version_id", inputs.version_id);
  }
  json << '}';
  return bytes(json.str());
}

std::string canonical_aad_sha256(const std::vector<std::uint8_t>& aad) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
  SHA256(aad.data(), aad.size(), digest.data());
  std::ostringstream out;
  for (unsigned char value : digest) {
    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value);
  }
  return out.str();
}

CryptoMetadata metadata_v1(const AADInputs& aad, const std::vector<std::uint8_t>& content_nonce) {
  return CryptoMetadata{kCryptoVersionV1, kContentCipherV1, kEnvelopeSchemeHPKEV1, base64_encode(content_nonce), aad};
}

std::vector<std::uint8_t> seal_content_aes_256_gcm(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& nonce,
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::uint8_t>& aad) {
  require_size(key, kAES256GCMKeyBytes, "invalid content key");
  require_size(nonce, kAESGCMNonceBytes, "invalid content nonce");
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  std::vector<std::uint8_t> ciphertext(plaintext.size() + kAESGCMTagBytes);
  int out_len = 0;
  int total = 0;
  if (ctx == nullptr || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1 ||
      EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1 ||
      EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw CryptoError("content encryption failed");
  }
  total += out_len;
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &out_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw CryptoError("content encryption failed");
  }
  total += out_len;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kAESGCMTagBytes, ciphertext.data() + total) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw CryptoError("content encryption failed");
  }
  ciphertext.resize(total + kAESGCMTagBytes);
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext;
}

std::vector<std::uint8_t> open_content_aes_256_gcm(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& nonce,
    const std::vector<std::uint8_t>& ciphertext,
    const std::vector<std::uint8_t>& aad) {
  require_size(key, kAES256GCMKeyBytes, "invalid content key");
  require_size(nonce, kAESGCMNonceBytes, "invalid content nonce");
  if (ciphertext.size() <= kAESGCMTagBytes) {
    throw CryptoError("ciphertext authentication failed");
  }
  std::size_t encrypted_size = ciphertext.size() - kAESGCMTagBytes;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  std::vector<std::uint8_t> plaintext(encrypted_size);
  int out_len = 0;
  int total = 0;
  if (ctx == nullptr || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1 ||
      EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1 ||
      EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(), static_cast<int>(encrypted_size)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw CryptoError("ciphertext authentication failed");
  }
  total += out_len;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kAESGCMTagBytes, const_cast<std::uint8_t*>(ciphertext.data() + encrypted_size)) != 1 ||
      EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &out_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw CryptoError("ciphertext authentication failed");
  }
  total += out_len;
  plaintext.resize(total);
  EVP_CIPHER_CTX_free(ctx);
  return plaintext;
}

std::vector<std::uint8_t> derive_x25519_public_key(const std::vector<std::uint8_t>& private_key) {
  require_size(private_key, kX25519KeyBytes, "invalid x25519 private key");
  EVP_PKEY* sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
  if (sk == nullptr) {
    throw CryptoError("x25519 operation failed");
  }
  std::vector<std::uint8_t> out(kX25519KeyBytes);
  std::size_t length = out.size();
  if (EVP_PKEY_get_raw_public_key(sk, out.data(), &length) != 1) {
    EVP_PKEY_free(sk);
    throw CryptoError("x25519 operation failed");
  }
  out.resize(length);
  EVP_PKEY_free(sk);
  return out;
}

std::vector<std::uint8_t> seal_hpke_v1_envelope(
    const std::vector<std::uint8_t>& recipient_public_key,
    const std::vector<std::uint8_t>& sender_ephemeral_private_key,
    const std::vector<std::uint8_t>& dek,
    const std::vector<std::uint8_t>& aad) {
  require_size(recipient_public_key, kX25519KeyBytes, "invalid envelope key");
  require_size(sender_ephemeral_private_key, kX25519KeyBytes, "invalid envelope key");
  auto enc = derive_x25519_public_key(sender_ephemeral_private_key);
  auto dh = x25519(sender_ephemeral_private_key, recipient_public_key);
  auto shared_secret = hpke_kem_extract_and_expand(dh, concat({enc, recipient_public_key}));
  auto sealed = hpke_seal(shared_secret, kHPKEEnvelopeInfo, dek, aad);
  return concat({enc, sealed});
}

std::vector<std::uint8_t> open_hpke_v1_envelope(
    const std::vector<std::uint8_t>& recipient_private_key,
    const std::vector<std::uint8_t>& envelope,
    const std::vector<std::uint8_t>& aad) {
  require_size(recipient_private_key, kX25519KeyBytes, "invalid envelope key");
  if (envelope.size() <= kX25519KeyBytes + kAESGCMTagBytes) {
    throw CryptoError("malformed envelope");
  }
  std::vector<std::uint8_t> enc(envelope.begin(), envelope.begin() + kX25519KeyBytes);
  std::vector<std::uint8_t> sealed(envelope.begin() + kX25519KeyBytes, envelope.end());
  auto recipient_public_key = derive_x25519_public_key(recipient_private_key);
  auto dh = x25519(recipient_private_key, enc);
  auto shared_secret = hpke_kem_extract_and_expand(dh, concat({enc, recipient_public_key}));
  try {
    return hpke_open(shared_secret, kHPKEEnvelopeInfo, sealed, aad);
  } catch (const CryptoError&) {
    throw CryptoError("wrong recipient");
  }
}

RecipientPublicKey derive_x25519_recipient_public_key(const std::string& client_id, const std::vector<std::uint8_t>& private_key) {
  return RecipientPublicKey{client_id, kEnvelopeSchemeHPKEV1, derive_x25519_public_key(private_key), ""};
}

std::string base64_encode(const std::vector<std::uint8_t>& value) {
  if (value.empty()) {
    return "";
  }
  std::string out(((value.size() + 2) / 3) * 4, '\0');
  int length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), value.data(), static_cast<int>(value.size()));
  out.resize(length);
  return out;
}

std::vector<std::uint8_t> base64_decode(const std::string& value) {
  if (value.empty()) {
    return {};
  }
  std::vector<std::uint8_t> out((value.size() / 4) * 3 + 3);
  int length = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(value.data()), static_cast<int>(value.size()));
  if (length < 0) {
    throw CryptoError("invalid base64");
  }
  std::size_t padding = 0;
  if (!value.empty() && value.back() == '=') padding++;
  if (value.size() > 1 && value[value.size() - 2] == '=') padding++;
  out.resize(static_cast<std::size_t>(length) - padding);
  return out;
}

std::string metadata_json(const CryptoMetadata& metadata) {
  std::ostringstream json;
  json << '{';
  append_json_field(json, "version", metadata.version);
  json << ',';
  append_json_field(json, "content_cipher", metadata.content_cipher);
  json << ',';
  append_json_field(json, "envelope_scheme", metadata.envelope_scheme);
  if (!metadata.content_nonce_b64.empty()) {
    json << ',';
    append_json_field(json, "content_nonce_b64", metadata.content_nonce_b64);
  }
  if (metadata.aad.has_value()) {
    json << ',' << json_quote("aad") << ':' << '{';
    bool wrote = false;
    if (!metadata.aad->secret_id.empty()) {
      append_json_field(json, "secret_id", metadata.aad->secret_id);
      wrote = true;
    }
    if (!metadata.aad->secret_name.empty()) {
      if (wrote) json << ',';
      append_json_field(json, "secret_name", metadata.aad->secret_name);
      wrote = true;
    }
    if (!metadata.aad->version_id.empty()) {
      if (wrote) json << ',';
      append_json_field(json, "version_id", metadata.aad->version_id);
    }
    json << '}';
  }
  json << '}';
  return json.str();
}

}  // namespace custodia

namespace custodia {
namespace {

std::string require_text(std::string value, const std::string& label) {
  auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch); });
  auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch); }).base();
  if (first >= last) {
    throw std::invalid_argument(label + " is required");
  }
  return std::string(first, last);
}

void append_json_int(std::ostringstream& json, const std::string& key, int value) {
  json << json_quote(key) << ':' << value;
}

std::string json_string_field(const std::string& json, const std::string& field) {
  std::string needle = json_quote(field) + ":";
  auto index = json.find(needle);
  if (index == std::string::npos) {
    return "";
  }
  auto start = json.find('"', index + needle.size());
  if (start == std::string::npos) {
    return "";
  }
  std::string out;
  bool escaped = false;
  for (std::size_t i = start + 1; i < json.size(); i++) {
    char ch = json[i];
    if (escaped) {
      switch (ch) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        default: out.push_back(ch); break;
      }
      escaped = false;
    } else if (ch == '\\') {
      escaped = true;
    } else if (ch == '"') {
      return out;
    } else {
      out.push_back(ch);
    }
  }
  return "";
}

int json_int_field(const std::string& json, const std::string& field) {
  std::string needle = json_quote(field) + ":";
  auto index = json.find(needle);
  if (index == std::string::npos) {
    return 0;
  }
  auto start = index + needle.size();
  while (start < json.size() && std::isspace(static_cast<unsigned char>(json[start]))) {
    start++;
  }
  auto end = start;
  while (end < json.size() && std::isdigit(static_cast<unsigned char>(json[end]))) {
    end++;
  }
  return end == start ? 0 : std::stoi(json.substr(start, end - start));
}

std::string json_object_field(const std::string& json, const std::string& field) {
  std::string needle = json_quote(field) + ":";
  auto index = json.find(needle);
  if (index == std::string::npos) {
    return "";
  }
  auto start = json.find('{', index + needle.size());
  if (start == std::string::npos) {
    return "";
  }
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (std::size_t i = start; i < json.size(); i++) {
    char ch = json[i];
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        in_string = false;
      }
      continue;
    }
    if (ch == '"') {
      in_string = true;
    } else if (ch == '{') {
      depth++;
    } else if (ch == '}') {
      depth--;
      if (depth == 0) {
        return json.substr(start, i - start + 1);
      }
    }
  }
  return "";
}

struct ParsedSecret {
  std::string secret_id;
  std::string version_id;
  std::string ciphertext;
  CryptoMetadata metadata;
  std::string envelope;
  int permissions{0};
  std::string granted_at;
  std::string access_expires_at;
};

ParsedSecret parse_secret(const std::string& json) {
  auto metadata_object = json_object_field(json, "crypto_metadata");
  auto aad_object = json_object_field(metadata_object, "aad");
  std::optional<AADInputs> aad;
  if (!aad_object.empty()) {
    aad = AADInputs{
        json_string_field(aad_object, "secret_id"),
        json_string_field(aad_object, "secret_name"),
        json_string_field(aad_object, "version_id")};
  }
  CryptoMetadata metadata{
      json_string_field(metadata_object, "version"),
      json_string_field(metadata_object, "content_cipher"),
      json_string_field(metadata_object, "envelope_scheme"),
      json_string_field(metadata_object, "content_nonce_b64"),
      aad};
  (void)build_canonical_aad(metadata, metadata.canonical_aad_inputs(AADInputs{"probe", "", ""}));
  return ParsedSecret{
      json_string_field(json, "secret_id"),
      json_string_field(json, "version_id"),
      json_string_field(json, "ciphertext"),
      metadata,
      json_string_field(json, "envelope"),
      json_int_field(json, "permissions"),
      json_string_field(json, "granted_at"),
      json_string_field(json, "access_expires_at")};
}

std::string envelope_object_without_client_id(std::string envelope_json) {
  if (envelope_json.size() >= 2 && envelope_json.front() == '[' && envelope_json.back() == ']') {
    envelope_json = envelope_json.substr(1, envelope_json.size() - 2);
  }
  auto envelope_field = json_quote("envelope") + ":";
  auto pos = envelope_json.find(envelope_field);
  if (pos == std::string::npos) {
    return envelope_json;
  }
  return envelope_json.substr(pos);
}

}  // namespace

CryptoClient Client::with_crypto(CryptoOptions options) { return CryptoClient(*this, std::move(options)); }

CryptoClient::CryptoClient(Client& transport, CryptoOptions options) : transport_(&transport), options_(std::move(options)) {
  if (!options_.public_key_resolver) {
    throw std::invalid_argument("public key resolver is required");
  }
}

std::string CryptoClient::create_encrypted_secret(
    const std::string& name,
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::string>& recipients,
    int permissions,
    const std::string& expires_at) {
  auto normalized_name = require_text(name, "secret name");
  auto dek = random(kAES256GCMKeyBytes);
  auto nonce = random(kAESGCMNonceBytes);
  AADInputs aad_inputs{"", normalized_name, ""};
  auto metadata = metadata_v1(aad_inputs, nonce);
  auto aad = build_canonical_aad(metadata, aad_inputs);
  auto ciphertext = seal_content_aes_256_gcm(dek, nonce, plaintext, aad);

  std::ostringstream payload;
  payload << '{';
  append_json_field(payload, "name", normalized_name);
  payload << ',';
  append_json_field(payload, "ciphertext", base64_encode(ciphertext));
  payload << ',' << json_quote("crypto_metadata") << ':' << metadata_json(metadata);
  payload << ',' << json_quote("envelopes") << ':' << seal_recipient_envelopes(normalized_recipients(recipients), dek, aad);
  payload << ',';
  append_json_int(payload, "permissions", permissions);
  if (!expires_at.empty()) {
    payload << ',';
    append_json_field(payload, "expires_at", expires_at);
  }
  payload << '}';
  return transport_->create_secret_payload(payload.str());
}

std::string CryptoClient::create_encrypted_secret_version(
    const std::string& secret_id,
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::string>& recipients,
    int permissions,
    const std::string& expires_at) {
  auto normalized_secret_id = require_text(secret_id, "secret id");
  auto dek = random(kAES256GCMKeyBytes);
  auto nonce = random(kAESGCMNonceBytes);
  AADInputs aad_inputs{normalized_secret_id, "", ""};
  auto metadata = metadata_v1(aad_inputs, nonce);
  auto aad = build_canonical_aad(metadata, aad_inputs);
  auto ciphertext = seal_content_aes_256_gcm(dek, nonce, plaintext, aad);

  std::ostringstream payload;
  payload << '{';
  append_json_field(payload, "ciphertext", base64_encode(ciphertext));
  payload << ',' << json_quote("crypto_metadata") << ':' << metadata_json(metadata);
  payload << ',' << json_quote("envelopes") << ':' << seal_recipient_envelopes(normalized_recipients(recipients), dek, aad);
  payload << ',';
  append_json_int(payload, "permissions", permissions);
  if (!expires_at.empty()) {
    payload << ',';
    append_json_field(payload, "expires_at", expires_at);
  }
  payload << '}';
  return transport_->create_secret_version_payload(normalized_secret_id, payload.str());
}

DecryptedSecret CryptoClient::read_decrypted_secret(const std::string& secret_id) {
  auto secret = parse_secret(transport_->get_secret_payload(secret_id));
  auto aad_inputs = secret.metadata.canonical_aad_inputs(AADInputs{secret.secret_id, "", secret.version_id});
  auto aad = build_canonical_aad(secret.metadata, aad_inputs);
  if (secret.metadata.content_nonce_b64.empty()) {
    throw CryptoError("missing content nonce");
  }
  auto dek = open_secret_envelope(secret.envelope, aad);
  auto plaintext = open_content_aes_256_gcm(dek, base64_decode(secret.metadata.content_nonce_b64), base64_decode(secret.ciphertext), aad);
  return DecryptedSecret{secret.secret_id, secret.version_id, plaintext, secret.metadata, secret.permissions, secret.granted_at, secret.access_expires_at};
}

std::string CryptoClient::share_encrypted_secret(
    const std::string& secret_id,
    const std::string& target_client_id,
    int permissions,
    const std::string& expires_at) {
  auto target = require_text(target_client_id, "target client id");
  auto secret = parse_secret(transport_->get_secret_payload(secret_id));
  auto aad_inputs = secret.metadata.canonical_aad_inputs(AADInputs{secret.secret_id, "", secret.version_id});
  auto aad = build_canonical_aad(secret.metadata, aad_inputs);
  auto dek = open_secret_envelope(secret.envelope, aad);
  auto envelope_json = envelope_object_without_client_id(seal_recipient_envelopes({target}, dek, aad));

  std::ostringstream payload;
  payload << '{';
  append_json_field(payload, "version_id", secret.version_id);
  payload << ',';
  append_json_field(payload, "target_client_id", target);
  payload << ',' << envelope_json;
  payload << ',';
  append_json_int(payload, "permissions", permissions);
  if (!expires_at.empty()) {
    payload << ',';
    append_json_field(payload, "expires_at", expires_at);
  }
  payload << '}';
  return transport_->share_secret_payload(secret_id, payload.str());
}

std::vector<std::string> CryptoClient::normalized_recipients(const std::vector<std::string>& recipients) const {
  std::vector<std::string> normalized;
  auto add = [&normalized](const std::string& value) {
    auto trimmed = require_text(value, "recipient id");
    if (std::find(normalized.begin(), normalized.end(), trimmed) == normalized.end()) {
      normalized.push_back(trimmed);
    }
  };
  if (!options_.private_key.client_id().empty()) {
    add(options_.private_key.client_id());
  }
  for (const auto& recipient : recipients) {
    if (!recipient.empty()) {
      add(recipient);
    }
  }
  if (normalized.empty()) {
    throw std::invalid_argument("missing recipient envelope");
  }
  return normalized;
}

std::string CryptoClient::seal_recipient_envelopes(const std::vector<std::string>& recipients, const std::vector<std::uint8_t>& dek, const std::vector<std::uint8_t>& aad) {
  std::ostringstream envelopes;
  envelopes << '[';
  for (std::size_t i = 0; i < recipients.size(); i++) {
    if (i > 0) {
      envelopes << ',';
    }
    auto recipient = options_.public_key_resolver(recipients[i]);
    if (recipient.scheme != kEnvelopeSchemeHPKEV1) {
      throw CryptoError("unsupported envelope scheme");
    }
    auto envelope = seal_hpke_v1_envelope(recipient.public_key, random(kX25519KeyBytes), dek, aad);
    envelopes << '{';
    append_json_field(envelopes, "client_id", recipients[i]);
    envelopes << ',';
    append_json_field(envelopes, "envelope", base64_encode(envelope));
    envelopes << '}';
  }
  envelopes << ']';
  return envelopes.str();
}

std::vector<std::uint8_t> CryptoClient::open_secret_envelope(const std::string& encoded_envelope, const std::vector<std::uint8_t>& aad) const {
  if (options_.private_key.scheme() != kEnvelopeSchemeHPKEV1) {
    throw CryptoError("unsupported envelope scheme");
  }
  return options_.private_key.open_envelope(base64_decode(encoded_envelope), aad);
}

std::vector<std::uint8_t> CryptoClient::random(std::size_t length) const {
  if (options_.random_source) {
    auto out = options_.random_source(length);
    if (out.size() != length) {
      throw std::invalid_argument("random source returned invalid length");
    }
    return out;
  }
  std::vector<std::uint8_t> out(length);
  std::random_device rd;
  std::generate(out.begin(), out.end(), [&rd]() { return static_cast<std::uint8_t>(rd()); });
  return out;
}

}  // namespace custodia
