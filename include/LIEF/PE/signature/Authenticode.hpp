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
#ifndef LIEF_PE_AUTHENTICODE_H
#define LIEF_PE_AUTHENTICODE_H

#include <array>
#include <functional>
#include <string>
#include <vector>

#include "LIEF/errors.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Builder.hpp"
#include "LIEF/PE/enums.hpp"
#include "LIEF/PE/signature/Signature.hpp"
#include "LIEF/PE/signature/attributes/MsCounterSign.hpp"
#include "LIEF/PE/signature/x509.hpp"

namespace LIEF::PE {

class Binary;

/// High-level interface for extracting, removing, and creating Authenticode
/// signatures.
class LIEF_API Authenticode {
  public:
  /// A half-open interval ``[start, end)`` covered by the Authenticode hash.
  struct LIEF_API range_t {
    uint64_t start = 0;
    uint64_t end = 0;

    uint64_t size() const {
      return end > start ? end - start : 0;
    }
  };

  using ranges_t = std::vector<range_t>;
  using certificates_t = std::vector<x509>;

  /// Timestamp attached to a signer.
  struct LIEF_API timestamp_t {
    /// ``RFC3161`` or ``Authenticode``.
    std::string protocol;

    /// DER encoded TimeStampToken (a CMS ``ContentInfo``).
    std::vector<uint8_t> token;

    /// Certificates embedded in the timestamp token.
    certificates_t certificates;

    /// Signers of the timestamp token.
    std::vector<SignerInfo> signers;
  };

  using timestamps_t = std::vector<timestamp_t>;

  /// Result of Authenticode::extract.
  struct LIEF_API extracted_t {
    /// True when the PE has a non-empty certificate directory.
    bool present = false;

    /// The certificate directory cannot be parsed as a PKCS #7 signature.
    bool corrupted = false;

    /// File offset of the attribute certificate table.
    uint64_t table_offset = 0;

    /// Size of the attribute certificate table.
    uint64_t table_size = 0;

    /// Parsed signatures.
    std::vector<Signature> signatures;

    /// DER encoded PKCS #7 of the first signature (if any).
    std::vector<uint8_t> pkcs7;

    /// DER encoded PKCS #7 of every signature.
    std::vector<std::vector<uint8_t>> pkcs7_list;

    /// Certificates from every signature.
    certificates_t certificates;

    /// RFC3161 or legacy Authenticode timestamps.
    timestamps_t timestamps;

    /// Intervals hashed by the Authenticode digest.
    ranges_t ranges;

    explicit operator bool() const {
      return present;
    }
  };

  /// Callback used to request an RFC3161 timestamp.
  ///
  /// It receives SHA-256(encryptedDigest), as required by RFC3161, and must
  /// return a DER encoded TimeStampToken.
  using timestamp_callback_t =
      std::function<std::vector<uint8_t>(const std::vector<uint8_t>& digest)>;

  /// Configuration for Authenticode::sign.
  struct LIEF_API signing_config_t {
    /// Path to the signer certificate (PEM or DER).
    std::string certificate;

    /// Path to the signer private key (PEM or DER).
    std::string private_key;

    /// Optional private-key password.
    std::string private_key_password;

    /// Extra certificates appended to the PKCS #7 certificate set.
    std::vector<std::string> certificate_chain;

    /// Digest algorithm used for the Authenticode digest and SignerInfo.
    ALGORITHMS digest_algorithm = ALGORITHMS::SHA_256;

    /// Digest algorithm used for the RFC3161 message imprint.
    ALGORITHMS timestamp_digest_algorithm = ALGORITHMS::SHA_256;

    /// Pre-computed DER encoded RFC3161 TimeStampToken.
    std::vector<uint8_t> timestamp_token;

    /// Callback invoked after the signature value has been generated.
    timestamp_callback_t timestamp_callback;

    /// Optional program description (SpcSpOpusInfo).
    std::string program_name;

    /// Optional program URL (SpcSpOpusInfo).
    std::string more_info;

    /// Add the PKCS #9 signingTime attribute.
    bool include_signing_time = false;

    /// Signing time as ``[year, month, day, hour, minute, second]`` in UTC.
    ///
    /// A zero-filled array means "use the current time".
    std::array<int32_t, 6> signing_time = {};

    /// Use the "commercial" statement type instead of the individual one.
    bool commercial = false;

    /// Configuration forwarded to the PE Builder.
    Builder::config_t builder_config;
  };

  /// Extract signatures, certificates, timestamps, and hashed ranges.
  static result<extracted_t> extract(const Binary& binary);

  /// Return the intervals covered by the Authenticode hash.
  static ranges_t ranges(const Binary& binary);

  /// Remove the attribute certificate table and its parsed signatures.
  /// Returns ``true`` if a signature was effectively removed.
  static bool strip(Binary& binary);

  /// Remove the attribute certificate table and its parsed signatures.
  static void remove_signature(Binary& binary) {
    strip(binary);
  }

  /// Sign the binary in place.
  ///
  /// The PEM/DER certificate and private key are parsed with MbedTLS. SHA-256
  /// and RSA PKCS#1 v1.5 are supported, as well as RFC3161 timestamps through
  /// ``signing_config_t::timestamp_callback`` or ``timestamp_token``.
  static ok_error_t sign(Binary& binary, const signing_config_t& config);

  /// Extract the TimeStampToken from an RFC3161 TimeStampResp.
  ///
  /// A TimeStampToken ContentInfo is returned unchanged.
  static result<std::vector<uint8_t>>
      timestamp_token_from_response(std::vector<uint8_t> response);
};

}

#endif
