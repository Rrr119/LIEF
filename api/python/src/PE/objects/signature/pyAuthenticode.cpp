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
#include "PE/pyPE.hpp"

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/signature/Authenticode.hpp"

#include "PE/objects/signature/pyAuthenticode.hpp"
#include "pyErr.hpp"

#include <nanobind/stl/array.h>
#include <nanobind/stl/function.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

template<>
void create<Authenticode>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Authenticode> auth(m, "Authenticode",
                                "Authenticode signature extraction and signing "
                                "helpers"_doc);

  nb::class_<Authenticode::range_t>(auth, "range_t")
      .def(nb::init<>())
      .def_rw("start", &Authenticode::range_t::start)
      .def_rw("end", &Authenticode::range_t::end)
      .def_prop_ro("size", &Authenticode::range_t::size);

  nb::class_<Authenticode::timestamp_t>(auth, "timestamp_t")
      .def(nb::init<>())
      .def_rw("protocol", &Authenticode::timestamp_t::protocol)
      .def_rw("token", &Authenticode::timestamp_t::token)
      .def_rw("certificates", &Authenticode::timestamp_t::certificates)
      .def_rw("signers", &Authenticode::timestamp_t::signers);

  nb::class_<Authenticode::extracted_t>(auth, "extracted_t")
      .def(nb::init<>())
      .def_rw("present", &Authenticode::extracted_t::present)
      .def_rw("corrupted", &Authenticode::extracted_t::corrupted)
      .def_rw("table_offset", &Authenticode::extracted_t::table_offset)
      .def_rw("table_size", &Authenticode::extracted_t::table_size)
      .def_rw("signatures", &Authenticode::extracted_t::signatures)
      .def_rw("pkcs7", &Authenticode::extracted_t::pkcs7)
      .def_rw("pkcs7_list", &Authenticode::extracted_t::pkcs7_list)
      .def_rw("certificates", &Authenticode::extracted_t::certificates)
      .def_rw("timestamps", &Authenticode::extracted_t::timestamps)
      .def_rw("ranges", &Authenticode::extracted_t::ranges)
      .def("__bool__",
           [](const Authenticode::extracted_t& self) { return self.present; });

  nb::class_<Authenticode::signing_config_t>(auth, "signing_config_t")
      .def(nb::init<>())
      .def_rw("certificate", &Authenticode::signing_config_t::certificate)
      .def_rw("private_key", &Authenticode::signing_config_t::private_key)
      .def_rw("private_key_password",
              &Authenticode::signing_config_t::private_key_password)
      .def_rw("certificate_chain",
              &Authenticode::signing_config_t::certificate_chain)
      .def_rw("digest_algorithm",
              &Authenticode::signing_config_t::digest_algorithm)
      .def_rw("timestamp_digest_algorithm",
              &Authenticode::signing_config_t::timestamp_digest_algorithm)
      .def_prop_rw(
          "timestamp_token",
          [](const Authenticode::signing_config_t& self) {
            return self.timestamp_token;
          },
          [](Authenticode::signing_config_t& self, nb::object token) {
            if (nb::isinstance<nb::bytes>(token)) {
              const nb::bytes value = nb::cast<nb::bytes>(token);
              self.timestamp_token.assign(
                  reinterpret_cast<const uint8_t*>(value.data()),
                  reinterpret_cast<const uint8_t*>(value.data()) + value.size());
            } else {
              self.timestamp_token = nb::cast<std::vector<uint8_t>>(token);
            }
          })
      .def_prop_rw(
          "timestamp_callback",
          [](const Authenticode::signing_config_t&) { return nb::none(); },
          [](Authenticode::signing_config_t& self, nb::object callback) {
            self.timestamp_callback = to_timestamp_callback(callback);
          })
      .def_rw("program_name", &Authenticode::signing_config_t::program_name)
      .def_rw("more_info", &Authenticode::signing_config_t::more_info)
      .def_rw("include_signing_time",
              &Authenticode::signing_config_t::include_signing_time)
      .def_rw("signing_time", &Authenticode::signing_config_t::signing_time)
      .def_rw("commercial", &Authenticode::signing_config_t::commercial)
      .def_rw("builder_config", &Authenticode::signing_config_t::builder_config);

  auth.def_static(
          "extract",
          [](const Binary& binary) {
            return error_or(&Authenticode::extract, binary);
          },
          "Extract PKCS #7 signatures, certificates, timestamps and hashed "
          "ranges"_doc,
          "binary"_a)
      .def_static(
          "ranges",
          [](const Binary& binary) { return Authenticode::ranges(binary); },
          "Return the intervals covered by the Authenticode hash"_doc, "binary"_a)
      .def_static(
          "strip", [](Binary& binary) { return Authenticode::strip(binary); },
          "Remove the Authenticode signature and rebuild the certificate "
          "directory"_doc,
          "binary"_a)
      .def_static(
          "sign",
          [](Binary& binary, const Authenticode::signing_config_t& config) {
            return bool(Authenticode::sign(binary, config));
          },
          "Sign the binary in place"_doc, "binary"_a, "config"_a);

  auth.def_static(
      "timestamp_token_from_response",
      [](const std::vector<uint8_t>& response) -> nb::object {
        auto result = Authenticode::timestamp_token_from_response(
            std::vector<uint8_t>(response));
        if (!result) {
          return nb::cast(as_lief_err(result));
        }
        return nb::bytes(reinterpret_cast<const char*>(result->data()),
                         result->size());
      },
      "Extract a DER TimeStampToken from an RFC3161 TimeStampResp"_doc,
      "response"_a);
}

} // namespace LIEF::PE::py
