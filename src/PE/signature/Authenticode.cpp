/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <limits>

#include <mbedtls/pk.h>

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/signature/Authenticode.hpp"
#include "LIEF/PE/signature/PKCS9TSTInfo.hpp"
#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/PE/signature/SpcIndirectData.hpp"
#include "LIEF/PE/signature/attributes/MsCounterSign.hpp"
#include "LIEF/PE/signature/attributes/PKCS9SigningTime.hpp"

#include "hash_stream.hpp"
#include "logging.hpp"
#include "mbedtls_init.hpp"
#include "mbedtls_wraps.h"

namespace LIEF::PE {

namespace {

using bytes_t = std::vector<uint8_t>;

constexpr auto OID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2";
constexpr auto OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4";
constexpr auto OID_SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15";
constexpr auto OID_SPC_STATEMENT_TYPE = "1.3.6.1.4.1.311.2.1.11";
constexpr auto OID_SPC_INDIVIDUAL_PURPOSE = "1.3.6.1.4.1.311.2.1.21";
constexpr auto OID_SPC_COMMERCIAL_PURPOSE = "1.3.6.1.4.1.311.2.1.22";
constexpr auto OID_SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12";
constexpr auto OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
constexpr auto OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
constexpr auto OID_SIGNING_TIME = "1.2.840.113549.1.9.5";
constexpr auto OID_MS_COUNTER_SIGN = "1.3.6.1.4.1.311.3.3.1";
constexpr auto OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
constexpr auto OID_ECDSA_SHA1 = "1.2.840.10045.4.1";
constexpr auto OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
constexpr auto OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
constexpr auto OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4";
constexpr auto OID_SHA1 = "1.3.14.3.2.26";
constexpr auto OID_SHA256 = "2.16.840.1.101.3.4.2.1";
constexpr auto OID_SHA384 = "2.16.840.1.101.3.4.2.2";
constexpr auto OID_SHA512 = "2.16.840.1.101.3.4.2.3";

struct digest_t {
  ALGORITHMS algo = ALGORITHMS::UNKNOWN;
  const char* oid = nullptr;
  hashstream::HASH hash = hashstream::HASH::SHA256;
  mbedtls_md_type_t md = MBEDTLS_MD_SHA256;
};

const digest_t* digest_info(ALGORITHMS algo) {
  static const digest_t SHA1{ALGORITHMS::SHA_1, OID_SHA1, hashstream::HASH::SHA1,
                             MBEDTLS_MD_SHA1};
  static const digest_t SHA256{ALGORITHMS::SHA_256, OID_SHA256,
                               hashstream::HASH::SHA256, MBEDTLS_MD_SHA256};
  static const digest_t SHA384{ALGORITHMS::SHA_384, OID_SHA384,
                               hashstream::HASH::SHA384, MBEDTLS_MD_SHA384};
  static const digest_t SHA512{ALGORITHMS::SHA_512, OID_SHA512,
                               hashstream::HASH::SHA512, MBEDTLS_MD_SHA512};
  switch (algo) {
    case ALGORITHMS::SHA_1: return &SHA1;
    case ALGORITHMS::SHA_256: return &SHA256;
    case ALGORITHMS::SHA_384: return &SHA384;
    case ALGORITHMS::SHA_512: return &SHA512;
    default: return nullptr;
  }
}

uint16_t read_u16(const bytes_t& data, size_t off) {
  if (off + sizeof(uint16_t) > data.size()) {
    return 0;
  }
  uint16_t value = 0;
  std::memcpy(&value, data.data() + off, sizeof(value));
  return value;
}

uint32_t read_u32(const bytes_t& data, size_t off) {
  if (off + sizeof(uint32_t) > data.size()) {
    return 0;
  }
  uint32_t value = 0;
  std::memcpy(&value, data.data() + off, sizeof(value));
  return value;
}

void write_u16(bytes_t& data, uint16_t value) {
  data.push_back(uint8_t(value & 0xff));
  data.push_back(uint8_t((value >> 8) & 0xff));
}

void write_u32(bytes_t& data, uint32_t value) {
  data.push_back(uint8_t(value & 0xff));
  data.push_back(uint8_t((value >> 8) & 0xff));
  data.push_back(uint8_t((value >> 16) & 0xff));
  data.push_back(uint8_t((value >> 24) & 0xff));
}

bytes_t der_length(size_t size) {
  if (size < 0x80) {
    return {uint8_t(size)};
  }
  std::array<uint8_t, sizeof(size_t)> encoded{};
  size_t count = 0;
  while (size > 0) {
    encoded[encoded.size() - 1 - count] = uint8_t(size & 0xff);
    size >>= 8;
    ++count;
  }
  bytes_t out{uint8_t(0x80 | count)};
  out.insert(out.end(), encoded.end() - count, encoded.end());
  return out;
}

bytes_t der_wrap(uint8_t tag, const bytes_t& content) {
  bytes_t out{tag};
  const bytes_t len = der_length(content.size());
  out.insert(out.end(), len.begin(), len.end());
  out.insert(out.end(), content.begin(), content.end());
  return out;
}

bytes_t der_cat(std::initializer_list<bytes_t> parts) {
  bytes_t out;
  size_t size = 0;
  for (const bytes_t& part : parts) {
    size += part.size();
  }
  out.reserve(size);
  for (const bytes_t& part : parts) {
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

bytes_t der_cat(const std::vector<bytes_t>& parts) {
  bytes_t out;
  size_t size = 0;
  for (const bytes_t& part : parts) {
    size += part.size();
  }
  out.reserve(size);
  for (const bytes_t& part : parts) {
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

bytes_t der_sequence(const bytes_t& content) {
  return der_wrap(0x30, content);
}

bytes_t der_sequence(std::initializer_list<bytes_t> parts) {
  return der_sequence(der_cat(parts));
}

bytes_t der_set(const bytes_t& content) {
  return der_wrap(0x31, content);
}

bytes_t der_integer(uint64_t value) {
  bytes_t content;
  do {
    content.push_back(uint8_t(value & 0xff));
    value >>= 8;
  } while (value > 0);
  std::reverse(content.begin(), content.end());
  if (content.empty() || (content[0] & 0x80) != 0) {
    content.insert(content.begin(), 0);
  }
  return der_wrap(0x02, content);
}

bytes_t der_octet_string(const bytes_t& value) {
  return der_wrap(0x04, value);
}

bytes_t der_octet_string(span<const uint8_t> value) {
  return der_octet_string(bytes_t(value.begin(), value.end()));
}

bytes_t der_bit_string(const bytes_t& content) {
  return der_wrap(0x03, content);
}

bytes_t der_null() {
  return {0x05, 0x00};
}

bytes_t der_oid(std::string_view value) {
  std::vector<uint64_t> arcs;
  uint64_t current = 0;
  for (char c : value) {
    if (c == '.') {
      arcs.push_back(current);
      current = 0;
    } else if (c >= '0' && c <= '9') {
      current = current * 10 + uint64_t(c - '0');
    }
  }
  arcs.push_back(current);

  bytes_t encoded;
  auto append_base128 = [&encoded](uint64_t v) {
    std::array<uint8_t, 10> tmp{};
    size_t count = 0;
    do {
      tmp[count++] = uint8_t(v & 0x7f);
      v >>= 7;
    } while (v > 0);
    for (size_t i = count; i > 0; --i) {
      uint8_t byte = tmp[i - 1];
      if (i != 1) {
        byte |= 0x80;
      }
      encoded.push_back(byte);
    }
  };

  if (arcs.size() < 2) {
    return {};
  }
  append_base128(arcs[0] * 40 + arcs[1]);
  for (size_t i = 2; i < arcs.size(); ++i) {
    append_base128(arcs[i]);
  }
  return der_wrap(0x06, encoded);
}

bytes_t der_algorithm_identifier(std::string_view oid) {
  return der_sequence({der_oid(oid), der_null()});
}

bytes_t der_attribute(std::string_view oid, const bytes_t& value) {
  return der_sequence({der_oid(oid), der_set(value)});
}

bytes_t der_utc_or_generalized_time(const std::array<int32_t, 6>& time) {
  char buffer[32] = {0};
  if (time[0] >= 1950 && time[0] <= 2049) {
    std::snprintf(buffer, sizeof(buffer), "%02d%02d%02d%02d%02d%02dZ",
                  time[0] % 100, time[1], time[2], time[3], time[4], time[5]);
    return der_wrap(0x17, bytes_t(buffer, buffer + std::strlen(buffer)));
  }
  std::snprintf(buffer, sizeof(buffer), "%04d%02d%02d%02d%02d%02dZ", time[0],
                time[1], time[2], time[3], time[4], time[5]);
  return der_wrap(0x18, bytes_t(buffer, buffer + std::strlen(buffer)));
}

std::array<int32_t, 6> current_utc_time() {
  const std::time_t now = std::time(nullptr);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &now);
#else
  gmtime_r(&now, &tm);
#endif
  return {
      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
      tm.tm_hour,        tm.tm_min,     tm.tm_sec,
  };
}

bool read_file(std::string_view path, bytes_t& out) {
  std::ifstream input(std::string(path), std::ios::in | std::ios::binary);
  if (!input) {
    return false;
  }
  input.unsetf(std::ios::skipws);
  out.assign(std::istreambuf_iterator<char>(input),
             std::istreambuf_iterator<char>());
  return input.good() || input.eof();
}

int base64_value(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

bytes_t base64_decode(std::string_view value) {
  bytes_t out;
  uint32_t accumulator = 0;
  int bits = 0;
  for (char c : value) {
    if (std::isspace(static_cast<unsigned char>(c))) {
      continue;
    }
    if (c == '=') {
      break;
    }
    const int v = base64_value(c);
    if (v < 0) {
      return {};
    }
    accumulator = (accumulator << 6) | uint32_t(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(uint8_t((accumulator >> bits) & 0xff));
    }
  }
  return out;
}

struct tlv_t {
  size_t start = 0;
  size_t content = 0;
  size_t end = 0;
  uint8_t tag = 0;

  bytes_t bytes(const bytes_t& data) const {
    return bytes_t(data.begin() + start, data.begin() + end);
  }
};

bool read_tlv(const bytes_t& data, size_t& pos, tlv_t& out) {
  if (pos >= data.size()) {
    return false;
  }
  const size_t start = pos;
  const uint8_t tag = data[pos++];
  if (pos >= data.size()) {
    return false;
  }
  size_t length = data[pos++];
  if ((length & 0x80) != 0) {
    const size_t count = length & 0x7f;
    if (count == 0 || count > sizeof(size_t) || pos + count > data.size()) {
      return false;
    }
    length = 0;
    for (size_t i = 0; i < count; ++i) {
      length = (length << 8) | data[pos++];
    }
  }
  if (length > data.size() - pos) {
    return false;
  }
  out = {start, pos, pos + length, tag};
  pos += length;
  return true;
}

std::vector<bytes_t> load_certificates(const bytes_t& data) {
  std::vector<bytes_t> certs;
  std::string_view view(reinterpret_cast<const char*>(data.data()), data.size());
  constexpr std::string_view BEGIN = "-----BEGIN CERTIFICATE-----";
  constexpr std::string_view END = "-----END CERTIFICATE-----";

  size_t pos = view.find(BEGIN);
  if (pos == std::string_view::npos) {
    size_t offset = 0;
    while (offset < data.size()) {
      tlv_t cert;
      if (!read_tlv(data, offset, cert) || cert.tag != 0x30) {
        certs.clear();
        break;
      }
      certs.push_back(cert.bytes(data));
    }
    if (certs.empty() && !data.empty()) {
      certs.push_back(data);
    }
    return certs;
  }

  while (pos != std::string_view::npos) {
    const size_t begin = pos + BEGIN.size();
    const size_t end = view.find(END, begin);
    if (end == std::string_view::npos) {
      break;
    }
    bytes_t cert = base64_decode(view.substr(begin, end - begin));
    if (!cert.empty()) {
      certs.push_back(std::move(cert));
    }
    pos = view.find(BEGIN, end + END.size());
  }
  return certs;
}

struct certificate_info_t {
  bytes_t der;
  bytes_t issuer;
  bytes_t serial;
};

bool parse_certificate(const bytes_t& der, certificate_info_t& info) {
  size_t pos = 0;
  tlv_t cert;
  if (!read_tlv(der, pos, cert) || cert.tag != 0x30 || cert.end != der.size()) {
    return false;
  }
  info.der = der;

  pos = cert.content;
  tlv_t tbs;
  if (!read_tlv(der, pos, tbs) || tbs.tag != 0x30) {
    return false;
  }

  pos = tbs.content;
  tlv_t field;
  if (!read_tlv(der, pos, field)) {
    return false;
  }
  if (field.tag == 0xa0) {
    if (!read_tlv(der, pos, field)) {
      return false;
    }
  }
  if (field.tag != 0x02) {
    return false;
  }
  info.serial = field.bytes(der);

  if (!read_tlv(der, pos, field) || field.tag != 0x30) {
    return false;
  }
  if (!read_tlv(der, pos, field) || field.tag != 0x30) {
    return false;
  }
  info.issuer = field.bytes(der);
  return true;
}

struct layout_t {
  uint64_t checksum_offset = 0;
  uint64_t cert_entry_offset = 0;
  uint64_t headers_end = 0;
  uint64_t file_end = 0;
  uint64_t cert_offset = 0;
  uint64_t cert_size = 0;
  std::vector<std::pair<uint64_t, uint64_t>> sections;
};

layout_t parse_layout(const bytes_t& data) {
  layout_t layout;
  layout.file_end = data.size();
  if (data.size() < 0x40) {
    return layout;
  }

  const uint64_t pe_offset = read_u32(data, 0x3c);
  if (pe_offset + 24 > data.size()) {
    return layout;
  }

  const uint64_t opt_offset = pe_offset + 24;
  const uint16_t magic = read_u16(data, opt_offset);
  const uint64_t data_dir_offset = opt_offset + (magic == 0x20b ? 112 : 96);
  layout.checksum_offset = opt_offset + 64;
  layout.cert_entry_offset = data_dir_offset + 4 * 8;
  layout.headers_end = read_u32(data, opt_offset + 60);
  layout.cert_offset = read_u32(data, layout.cert_entry_offset);
  layout.cert_size = read_u32(data, layout.cert_entry_offset + 4);

  const uint16_t nb_sections = read_u16(data, pe_offset + 6);
  const uint16_t opt_size = read_u16(data, pe_offset + 20);
  uint64_t section_offset = opt_offset + opt_size;
  for (uint16_t i = 0; i < nb_sections; ++i) {
    if (section_offset + 40 > data.size()) {
      break;
    }
    const uint32_t raw_size = read_u32(data, section_offset + 16);
    const uint32_t raw_ptr = read_u32(data, section_offset + 20);
    if (raw_size > 0 && raw_ptr < data.size()) {
      const uint64_t end = std::min<uint64_t>(data.size(), raw_ptr + raw_size);
      layout.sections.emplace_back(raw_ptr, end);
    }
    section_offset += 40;
  }
  return layout;
}

void append_range(std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                  uint64_t start, uint64_t end, uint64_t file_end) {
  start = std::min(start, file_end);
  end = std::min(end, file_end);
  if (end > start) {
    ranges.emplace_back(start, end);
  }
}

std::vector<std::pair<uint64_t, uint64_t>> hash_ranges(const layout_t& layout) {
  std::vector<std::pair<uint64_t, uint64_t>> ranges;
  append_range(ranges, 0, layout.checksum_offset, layout.file_end);
  append_range(ranges, layout.checksum_offset + 4, layout.cert_entry_offset,
               layout.file_end);
  append_range(ranges, layout.cert_entry_offset + 8, layout.headers_end,
               layout.file_end);

  std::vector<std::pair<uint64_t, uint64_t>> sections = layout.sections;
  std::sort(sections.begin(), sections.end());
  uint64_t last_end = layout.headers_end;
  for (const auto& [start, end] : sections) {
    if (end <= last_end) {
      continue;
    }
    const uint64_t clipped_start = std::max(start, last_end);
    append_range(ranges, clipped_start, end, layout.file_end);
    last_end = end;
  }

  if (layout.file_end > last_end) {
    uint64_t extra_start = last_end;
    const uint64_t extra_end = layout.file_end;
    if (layout.cert_size > 0 && layout.cert_offset >= extra_start &&
        layout.cert_offset < extra_end)
    {
      append_range(ranges, extra_start, layout.cert_offset, extra_end);
      append_range(ranges, layout.cert_offset + layout.cert_size, extra_end,
                   extra_end);
    } else {
      append_range(ranges, extra_start, extra_end, extra_end);
    }
  }
  return ranges;
}

bytes_t compute_authentihash(const bytes_t& data, ALGORITHMS algo) {
  const digest_t* info = digest_info(algo);
  if (info == nullptr) {
    return {};
  }
  layout_t layout = parse_layout(data);
  hashstream stream(info->hash);
  for (const auto& [start, end] : hash_ranges(layout)) {
    stream.write(data.data() + start, end - start);
  }
  return stream.raw();
}

bytes_t make_spc_pe_image_data() {
  static constexpr uint16_t obsolete[] = {
      '<', '<', '<', 'O', 'b', 's', 'o', 'l', 'e', 't', 'e', '>', '>', '>',
  };
  bytes_t bmp;
  bmp.reserve(sizeof(obsolete));
  for (uint16_t c : obsolete) {
    bmp.push_back(uint8_t(c >> 8));
    bmp.push_back(uint8_t(c & 0xff));
  }
  const bytes_t spc_string = der_wrap(0x80, bmp);      // [0] IMPLICIT BMPString
  const bytes_t spc_link = der_wrap(0xa2, spc_string); // file [2] EXPLICIT
  return der_sequence({
      der_bit_string({0x07, 0x80}),
      der_wrap(0xa0, spc_link),
  });
}

bytes_t make_spc_indirect_data(ALGORITHMS algo, span<const uint8_t> digest) {
  const digest_t* info = digest_info(algo);
  if (info == nullptr) {
    return {};
  }
  const bytes_t spc_attr = der_sequence({
      der_oid(OID_SPC_PE_IMAGE_DATA),
      make_spc_pe_image_data(),
  });
  const bytes_t digest_info = der_sequence({
      der_algorithm_identifier(info->oid),
      der_octet_string(digest),
  });
  return der_sequence({spc_attr, digest_info});
}

bytes_t make_spc_sp_opus_info(const std::string& program_name,
                              const std::string& more_info) {
  std::vector<bytes_t> fields;
  if (!program_name.empty()) {
    const bytes_t ascii(program_name.begin(), program_name.end());
    fields.push_back(der_wrap(0xa0, der_wrap(0x81, ascii)));
  }
  if (!more_info.empty()) {
    const bytes_t url(more_info.begin(), more_info.end());
    fields.push_back(der_wrap(0xa1, der_wrap(0x80, url)));
  }
  if (fields.empty()) {
    return {};
  }
  return der_sequence(der_cat(fields));
}

bytes_t sign_data(const bytes_t& data, const digest_t& digest,
                  mbedtls_pk_context& key, bool& is_rsa) {
  const bytes_t hash = Signature::hash(data, digest.algo);
  if (hash.empty()) {
    return {};
  }

  std::vector<uint8_t> signature(MBEDTLS_PK_SIGNATURE_MAX_SIZE, 0);
  size_t signature_size = 0;
  const int ret =
      mbedtls_pk_sign(&key, digest.md, hash.data(), hash.size(), signature.data(),
                      signature.size(), &signature_size);
  if (ret != 0) {
    LIEF_ERR("mbedtls_pk_sign failed: {:#x}", ret);
    return {};
  }

  const mbedtls_pk_type_t type = mbedtls_pk_get_type(&key);
  is_rsa = type == MBEDTLS_PK_RSA || type == MBEDTLS_PK_RSASSA_PSS;
  signature.resize(signature_size);
  return signature;
}

bytes_t make_signer_info(const certificate_info_t& cert, ALGORITHMS algo,
                         bool is_rsa, const bytes_t& auth_attrs_content,
                         const bytes_t& signature, const bytes_t& token) {
  const digest_t* digest = digest_info(algo);
  if (digest == nullptr) {
    return {};
  }

  const bytes_t issuer_and_serial = der_sequence({cert.issuer, cert.serial});

  bytes_t signature_algorithm;
  if (is_rsa) {
    signature_algorithm = der_algorithm_identifier(OID_RSA_ENCRYPTION);
  } else if (algo == ALGORITHMS::SHA_1) {
    signature_algorithm = der_algorithm_identifier(OID_ECDSA_SHA1);
  } else if (algo == ALGORITHMS::SHA_384) {
    signature_algorithm = der_algorithm_identifier(OID_ECDSA_SHA384);
  } else if (algo == ALGORITHMS::SHA_512) {
    signature_algorithm = der_algorithm_identifier(OID_ECDSA_SHA512);
  } else {
    signature_algorithm = der_algorithm_identifier(OID_ECDSA_SHA256);
  }

  std::vector<bytes_t> fields = {
      der_integer(1),
      issuer_and_serial,
      der_algorithm_identifier(digest->oid),
      der_wrap(0xa0, auth_attrs_content),
      signature_algorithm,
      der_octet_string(signature),
  };

  if (!token.empty()) {
    const bytes_t unsigned_attr =
        der_sequence({der_oid(OID_MS_COUNTER_SIGN), der_set(token)});
    fields.push_back(der_wrap(0xa1, unsigned_attr));
  }
  return der_sequence(der_cat(fields));
}

bytes_t make_pkcs7(const certificate_info_t& cert,
                   const std::vector<bytes_t>& extra_certs, ALGORITHMS algo,
                   bool is_rsa, const bytes_t& auth_attrs_content,
                   const bytes_t& signature, const bytes_t& token,
                   span<const uint8_t> pe_digest) {
  const digest_t* digest = digest_info(algo);
  if (digest == nullptr) {
    return {};
  }

  const bytes_t spc_indirect = make_spc_indirect_data(algo, pe_digest);
  if (spc_indirect.empty()) {
    return {};
  }
  const bytes_t spc_content =
      der_sequence({der_oid(OID_SPC_INDIRECT_DATA), der_wrap(0xa0, spc_indirect)});

  std::vector<bytes_t> certs = {cert.der};
  certs.insert(certs.end(), extra_certs.begin(), extra_certs.end());
  const bytes_t certs_content = der_cat(certs);

  const bytes_t signer =
      make_signer_info(cert, algo, is_rsa, auth_attrs_content, signature, token);
  if (signer.empty()) {
    return {};
  }

  const bytes_t signed_data = der_sequence({
      der_integer(1),
      der_set(der_algorithm_identifier(digest->oid)),
      spc_content,
      der_wrap(0xa0, certs_content),
      der_set(signer),
  });

  return der_sequence({
      der_oid(OID_PKCS7_SIGNED_DATA),
      der_wrap(0xa0, signed_data),
  });
}

bytes_t make_win_certificate(const bytes_t& pkcs7) {
  const size_t padding = (8 - ((pkcs7.size() + 8) % 8)) % 8;
  bytes_t out;
  out.reserve(8 + pkcs7.size() + padding);
  write_u32(out, uint32_t(8 + pkcs7.size() + padding));
  write_u16(out, 0x0200);
  write_u16(out, 0x0002);
  out.insert(out.end(), pkcs7.begin(), pkcs7.end());
  out.insert(out.end(), padding, 0);
  return out;
}

} // namespace

Authenticode::ranges_t Authenticode::ranges(const Binary& binary) {
  ranges_t ranges;
  const uint64_t pe_offset = binary.dos_header().addressof_new_exeheader();
  const bool is64 = binary.type() == PE_TYPE::PE32_PLUS;
  const uint64_t checksum_offset = pe_offset + 88;
  const uint64_t cert_entry_offset = pe_offset + (is64 ? 168 : 152);
  const uint64_t headers_end = binary.optional_header().sizeof_headers();

  uint64_t file_end = headers_end;
  std::vector<std::pair<uint64_t, uint64_t>> sections;
  for (const Section& section : binary.sections()) {
    const uint64_t end = section.offset() + section.size();
    file_end = std::max(file_end, end);
    if (section.size() > 0) {
      sections.emplace_back(section.offset(), end);
    }
  }

  if (!binary.overlay().empty()) {
    file_end = std::max<uint64_t>(file_end, binary.overlay_offset() +
                                                binary.overlay().size());
  }

  const DataDirectory* cert_dir = binary.cert_dir();
  const uint64_t cert_offset = cert_dir != nullptr ? cert_dir->RVA() : 0;
  const uint64_t cert_size = cert_dir != nullptr ? cert_dir->size() : 0;
  if (cert_size > 0) {
    file_end = std::max(file_end, cert_offset + cert_size);
  }

  auto add = [&ranges, file_end](uint64_t start, uint64_t end) {
    start = std::min(start, file_end);
    end = std::min(end, file_end);
    if (end > start) {
      ranges.push_back({start, end});
    }
  };

  add(0, checksum_offset);
  add(checksum_offset + 4, cert_entry_offset);
  add(cert_entry_offset + 8, headers_end);

  std::sort(sections.begin(), sections.end());
  uint64_t last_end = headers_end;
  for (const auto& [start, end] : sections) {
    if (end <= last_end) {
      continue;
    }
    add(std::max(start, last_end), end);
    last_end = end;
  }

  if (file_end > last_end) {
    if (cert_size > 0 && cert_offset >= last_end && cert_offset < file_end) {
      add(last_end, cert_offset);
      add(cert_offset + cert_size, file_end);
    } else {
      add(last_end, file_end);
    }
  }

  return ranges;
}

result<Authenticode::extracted_t> Authenticode::extract(const Binary& binary) {
  extracted_t extracted;
  const DataDirectory* cert_dir = binary.cert_dir();
  if (cert_dir == nullptr) {
    return extracted;
  }

  extracted.present = cert_dir->RVA() != 0 || cert_dir->size() != 0;
  extracted.table_offset = cert_dir->RVA();
  extracted.table_size = cert_dir->size();
  extracted.corrupted = binary.signature_parse_error_;
  extracted.ranges = ranges(binary);

  for (const Signature& signature : binary.signatures()) {
    const bytes_t der(signature.raw_der().begin(), signature.raw_der().end());
    extracted.pkcs7_list.push_back(der);
    if (extracted.pkcs7.empty()) {
      extracted.pkcs7 = der;
    }
    extracted.signatures.push_back(signature);

    for (const x509& cert : signature.certificates()) {
      const bytes_t raw = cert.raw();
      const bool exists =
          std::any_of(extracted.certificates.begin(), extracted.certificates.end(),
                      [&raw](const x509& other) { return other.raw() == raw; });
      if (!exists) {
        extracted.certificates.push_back(cert);
      }
    }

    for (const SignerInfo& signer : signature.signers()) {
      const auto* attr = static_cast<const MsCounterSign*>(
          signer.get_unauth_attribute(Attribute::TYPE::MS_COUNTER_SIGN));
      if (attr == nullptr) {
        continue;
      }
      timestamp_t timestamp;
      timestamp.protocol = attr->content_info().content_type() ==
                                   PKCS9TSTInfo::PKCS9_TSTINFO_OBJID ?
                               "RFC3161" :
                               "Authenticode";
      timestamp.token =
          bytes_t(attr->raw_token().begin(), attr->raw_token().end());
      timestamp.certificates.assign(attr->certificates().begin(),
                                    attr->certificates().end());
      timestamp.signers.assign(attr->signers().begin(), attr->signers().end());
      extracted.timestamps.push_back(std::move(timestamp));
    }
  }

  if (extracted.present && extracted.signatures.empty()) {
    extracted.corrupted = true;
  }
  return extracted;
}

bool Authenticode::strip(Binary& binary) {
  DataDirectory* cert_dir = binary.cert_dir();
  const bool had_signature = binary.has_signature() ||
                             !binary.signatures_.empty() ||
                             !binary.authenticode_blob_.empty();
  if (!had_signature) {
    return false;
  }

  if (!binary.authenticode_blob_.empty()) {
    binary.authenticode_blob_.clear();
  } else if (cert_dir != nullptr && cert_dir->size() > 0 &&
             cert_dir->RVA() >= binary.overlay_offset_)
  {
    const uint64_t start = cert_dir->RVA() - binary.overlay_offset_;
    const uint64_t end = start + cert_dir->size();
    if (end <= binary.overlay_.size()) {
      binary.overlay_.erase(binary.overlay_.begin() + start,
                            binary.overlay_.begin() + end);
    }
  }

  if (cert_dir != nullptr) {
    cert_dir->RVA(0);
    cert_dir->size(0);
  }
  binary.signatures_.clear();
  binary.signature_parse_error_ = false;
  binary.update_checksum_ = true;
  binary.optional_header_.checksum(binary.compute_checksum());
  return true;
}

result<std::vector<uint8_t>>
    Authenticode::timestamp_token_from_response(std::vector<uint8_t> response) {
  size_t pos = 0;
  tlv_t outer;
  if (!read_tlv(response, pos, outer) || outer.tag != 0x30) {
    return make_error_code(lief_errors::read_error);
  }

  pos = outer.content;
  tlv_t first;
  if (!read_tlv(response, pos, first)) {
    return make_error_code(lief_errors::read_error);
  }
  if (first.tag == 0x06) {
    return response;
  }
  if (pos >= outer.end) {
    return make_error_code(lief_errors::not_found);
  }
  tlv_t token;
  if (!read_tlv(response, pos, token) || token.tag != 0x30 ||
      token.end > outer.end)
  {
    return make_error_code(lief_errors::read_error);
  }
  return bytes_t(response.begin() + token.start, response.begin() + token.end);
}

ok_error_t Authenticode::sign(Binary& binary, const signing_config_t& config) {
  const digest_t* digest = digest_info(config.digest_algorithm);
  if (digest == nullptr) {
    LIEF_ERR("Unsupported Authenticode digest algorithm");
    return make_error_code(lief_errors::not_supported);
  }
  if (binary.cert_dir() == nullptr) {
    LIEF_ERR("The PE binary has no CERTIFICATE_TABLE data directory");
    return make_error_code(lief_errors::not_found);
  }

  bytes_t cert_file;
  bytes_t key_file;
  if (!read_file(config.certificate, cert_file)) {
    LIEF_ERR("Can't read certificate '{}'", config.certificate);
    return make_error_code(lief_errors::file_error);
  }
  if (!read_file(config.private_key, key_file)) {
    LIEF_ERR("Can't read private key '{}'", config.private_key);
    return make_error_code(lief_errors::file_error);
  }

  std::vector<bytes_t> certs = load_certificates(cert_file);
  if (certs.empty()) {
    LIEF_ERR("No certificate found in '{}'", config.certificate);
    return make_error_code(lief_errors::parsing_error);
  }

  certificate_info_t signer_cert;
  if (!parse_certificate(certs.front(), signer_cert)) {
    LIEF_ERR("Failed to parse the signer certificate");
    return make_error_code(lief_errors::parsing_error);
  }

  std::vector<bytes_t> chain;
  for (size_t i = 1; i < certs.size(); ++i) {
    chain.push_back(certs[i]);
  }
  for (const std::string& path : config.certificate_chain) {
    bytes_t data;
    if (!read_file(path, data)) {
      LIEF_ERR("Can't read certificate chain '{}'", path);
      return make_error_code(lief_errors::file_error);
    }
    for (bytes_t& cert : load_certificates(data)) {
      if (std::find(chain.begin(), chain.end(), cert) == chain.end() &&
          cert != signer_cert.der)
      {
        chain.push_back(std::move(cert));
      }
    }
  }

  mbedtls_init();
  mbedtls_pk_context key;
  mbedtls_pk_init(&key);
  bytes_t key_data = key_file;
  const bool key_is_pem =
      key_data.size() >= 10 &&
      std::string_view(reinterpret_cast<const char*>(key_data.data()), 10)
              .find("-----BEGIN") != std::string_view::npos;
  if (key_is_pem && (key_data.empty() || key_data.back() != 0)) {
    key_data.push_back(0);
  }

  const unsigned char* password = nullptr;
  size_t password_size = 0;
  if (!config.private_key_password.empty()) {
    password =
        reinterpret_cast<const unsigned char*>(config.private_key_password.data());
    password_size = config.private_key_password.size();
  }
  const int key_ret = mbedtls_pk_parse_key(&key, key_data.data(), key_data.size(),
                                           password, password_size);
  if (key_ret != 0) {
    LIEF_ERR("Failed to parse the private key: {:#x}", key_ret);
    mbedtls_pk_free(&key);
    return make_error_code(lief_errors::parsing_error);
  }

  strip(binary);

  Builder builder(binary, config.builder_config);
  if (auto res = builder.build(); !res) {
    mbedtls_pk_free(&key);
    return res;
  }
  const bytes_t unsigned_pe = builder.get_build();
  const bytes_t pe_digest = compute_authentihash(unsigned_pe, digest->algo);
  if (pe_digest.empty()) {
    mbedtls_pk_free(&key);
    return make_error_code(lief_errors::build_error);
  }

  const bytes_t spc_indirect = make_spc_indirect_data(digest->algo, pe_digest);
  if (spc_indirect.empty()) {
    mbedtls_pk_free(&key);
    return make_error_code(lief_errors::build_error);
  }
  size_t spc_header_size = 0;
  {
    size_t pos = 0;
    tlv_t spc;
    if (!read_tlv(spc_indirect, pos, spc)) {
      mbedtls_pk_free(&key);
      return make_error_code(lief_errors::build_error);
    }
    spc_header_size = spc.content;
  }
  const bytes_t spc_signed_content(spc_indirect.begin() + spc_header_size,
                                   spc_indirect.end());
  const bytes_t message_digest = Signature::hash(spc_signed_content, digest->algo);

  std::vector<bytes_t> attributes;
  attributes.push_back(
      der_attribute(OID_CONTENT_TYPE, der_oid(OID_SPC_INDIRECT_DATA)));
  if (config.include_signing_time) {
    std::array<int32_t, 6> signing_time = config.signing_time;
    if (std::all_of(signing_time.begin(), signing_time.end(),
                    [](int32_t v) { return v == 0; }))
    {
      signing_time = current_utc_time();
    }
    attributes.push_back(der_attribute(OID_SIGNING_TIME,
                                       der_utc_or_generalized_time(signing_time)));
  }
  attributes.push_back(der_attribute(
      OID_SPC_STATEMENT_TYPE,
      der_sequence({der_oid(config.commercial ? OID_SPC_COMMERCIAL_PURPOSE :
                                                OID_SPC_INDIVIDUAL_PURPOSE)})));
  if (const bytes_t opus =
          make_spc_sp_opus_info(config.program_name, config.more_info);
      !opus.empty())
  {
    attributes.push_back(der_attribute(OID_SPC_SP_OPUS_INFO, opus));
  }
  attributes.push_back(
      der_attribute(OID_MESSAGE_DIGEST, der_octet_string(message_digest)));

  const bytes_t auth_attrs_content = der_cat(attributes);
  const bytes_t auth_attrs_set = der_set(auth_attrs_content);
  bool is_rsa = false;
  const bytes_t signature = sign_data(auth_attrs_set, *digest, key, is_rsa);
  if (signature.empty()) {
    mbedtls_pk_free(&key);
    return make_error_code(lief_errors::build_error);
  }

  bytes_t timestamp_token = config.timestamp_token;
  if (config.timestamp_callback) {
    const digest_t* ts_digest = digest_info(config.timestamp_digest_algorithm);
    if (ts_digest == nullptr) {
      mbedtls_pk_free(&key);
      return make_error_code(lief_errors::not_supported);
    }
    const bytes_t ts_digest_value = Signature::hash(signature, ts_digest->algo);
    timestamp_token = config.timestamp_callback(ts_digest_value);
    if (timestamp_token.empty()) {
      LIEF_ERR("The RFC3161 timestamp callback returned an empty token");
      mbedtls_pk_free(&key);
      return make_error_code(lief_errors::build_error);
    }
  }

  const bytes_t pkcs7 =
      make_pkcs7(signer_cert, chain, digest->algo, is_rsa, auth_attrs_content,
                 signature, timestamp_token, pe_digest);
  mbedtls_pk_free(&key);
  if (pkcs7.empty()) {
    return make_error_code(lief_errors::build_error);
  }

  auto parsed = SignatureParser::parse(pkcs7);
  if (!parsed) {
    LIEF_ERR("The generated PKCS #7 signature cannot be parsed");
    return make_error_code(lief_errors::build_error);
  }

  binary.authenticode_blob_ = make_win_certificate(pkcs7);
  binary.cert_dir()->RVA(uint32_t(unsigned_pe.size()));
  binary.cert_dir()->size(uint32_t(binary.authenticode_blob_.size()));
  binary.signatures_.clear();
  binary.signatures_.push_back(std::move(*parsed));
  binary.signature_parse_error_ = false;
  binary.update_checksum_ = true;
  binary.optional_header_.checksum(binary.compute_checksum());
  return ok();
}

} // namespace LIEF::PE
