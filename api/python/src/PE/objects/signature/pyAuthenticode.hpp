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
#ifndef PY_LIEF_PE_AUTHENTICODE_H
#define PY_LIEF_PE_AUTHENTICODE_H

#include <cstring>
#include <vector>

#include "LIEF/PE/signature/Authenticode.hpp"

#include <nanobind/nanobind.h>
#include <nanobind/stl/function.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

/// Adapt a Python callback that accepts/returns ``bytes`` to the C++ vector
/// based callback used by Authenticode::sign.
inline Authenticode::timestamp_callback_t
    to_timestamp_callback(nb::object callback) {
  if (callback.is_none()) {
    return {};
  }

  nb::object adapter =
      nb::cpp_function([callback](const std::vector<uint8_t>& digest) {
        nb::object result = callback(nb::bytes(
            reinterpret_cast<const char*>(digest.data()), digest.size()));
        if (nb::isinstance<nb::bytes>(result)) {
          const nb::bytes value = nb::cast<nb::bytes>(result);
          std::vector<uint8_t> out(value.size());
          std::memcpy(out.data(), value.data(), value.size());
          return out;
        }
        return nb::cast<std::vector<uint8_t>>(result);
      });

  return nb::cast<Authenticode::timestamp_callback_t>(adapter);
}

}

#endif
