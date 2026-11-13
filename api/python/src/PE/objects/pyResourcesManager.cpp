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
#include "pyIterator.hpp"
#include "pySafeString.hpp"
#include "nanobind/utils.hpp"
#include <string_view>
#include <nanobind/stl/string_view.h>

#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/Binary.hpp"
#include "enums_wrapper.hpp"

#include "nanobind/extra/stl/u16string.h"
#include <nanobind/stl/set.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::PE::py {

static std::vector<uint8_t> to_byte_vector(nb::handle data) {
  if (nb::isinstance<nb::str>(data)) {
    const std::string str = nb::cast<std::string>(data);
    return {str.begin(), str.end()};
  }
  if (nb::isinstance<nb::bytes>(data)) {
    return nanobind::to_vector(nb::cast<nb::bytes>(data));
  }
  return nb::cast<std::vector<uint8_t>>(data);
}

template<>
void create<ResourcesManager>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<ResourcesManager, LIEF::Object> manager(
      m, "ResourcesManager",
      "The Resource Manager provides an enhanced API to manipulate the resource tree"_doc
  );

  init_ref_iterator<ResourcesManager::it_const_dialogs>(manager,
                                                        "it_const_dialogs");
  init_ref_iterator<ResourcesManager::it_const_icons>(manager, "it_const_icons");
  init_ref_iterator<ResourcesManager::it_const_accelerators>(
      manager, "it_const_accelerators"
  );

  nb::class_<ResourcesManager::string_entry_t>(manager, "string_entry_t")
      .def_rw("string", &ResourcesManager::string_entry_t::string)
      .def_rw("id", &ResourcesManager::string_entry_t::id)
      .LIEF_DEFAULT_STR(ResourcesManager::string_entry_t);
  ;

  nb::class_<ResourcesManager::entry_t>(manager, "entry_t",
      "Description of a resource data node"_doc)
      .def_rw("type", &ResourcesManager::entry_t::type,
              "Numeric resource type"_doc)
      .def_rw("type_name", &ResourcesManager::entry_t::type_name,
              "Human-readable resource type"_doc)
      .def_rw("name", &ResourcesManager::entry_t::name,
              "Resource name (empty if the node uses a numeric ID)"_doc)
      .def_rw("name_id", &ResourcesManager::entry_t::name_id,
              "Numeric ID of the resource name"_doc)
      .def_rw("language", &ResourcesManager::entry_t::language,
              "Language ID of the resource data"_doc)
      .def_rw("size", &ResourcesManager::entry_t::size,
              "Size of the resource data"_doc)
      .def_rw("rva", &ResourcesManager::entry_t::rva,
              "RVA of the resource data"_doc)
      .def_rw("code_page", &ResourcesManager::entry_t::code_page,
              "Code page associated with the resource data"_doc)
      .def_rw("path", &ResourcesManager::entry_t::path,
              "Path usable with export/replace/remove"_doc);

  // clang-format off
  #define ENTRY(X) .value(to_string(ResourcesManager::TYPE::X), ResourcesManager::TYPE::X)
  enum_<ResourcesManager::TYPE>(manager, "TYPE")
    ENTRY(CURSOR)
    ENTRY(BITMAP)
    ENTRY(ICON)
    ENTRY(MENU)
    ENTRY(DIALOG)
    ENTRY(STRING)
    ENTRY(FONTDIR)
    ENTRY(FONT)
    ENTRY(ACCELERATOR)
    ENTRY(RCDATA)
    ENTRY(MESSAGETABLE)
    ENTRY(GROUP_CURSOR)
    ENTRY(GROUP_ICON)
    ENTRY(VERSION)
    ENTRY(DLGINCLUDE)
    ENTRY(PLUGPLAY)
    ENTRY(VXD)
    ENTRY(ANICURSOR)
    ENTRY(ANIICON)
    ENTRY(HTML)
    ENTRY(MANIFEST)
  ;
  #undef ENTRY
  // clang-format on

  manager.def(nb::init<ResourceNode&>(), nb::keep_alive<0, 1>(), "node"_a)

      .def(nb::init<ResourceNode&, Binary&>(), nb::keep_alive<0, 1>(),
           nb::keep_alive<0, 2>(), "node"_a, "binary"_a)

      .def_prop_ro("has_signatures", &ResourcesManager::has_signatures,
                   "``True`` if the underlying binary is signed"_doc)

      .def_prop_ro(
          "original_signature_data",
          [](const ResourcesManager& self) {
            return nb::to_bytes(self.original_signature_data());
          },
          "Raw certificate table captured from the original binary"_doc)

      .def("has_path", &ResourcesManager::has_path,
           "Check if the given resource path exists"_doc, "path"_a)

      .def_prop_ro("entries", &ResourcesManager::entries,
                   "Description of every resource data node"_doc)

      .def("list", &ResourcesManager::list,
           "Return the description of every resource data node"_doc)

      .def(
          "export",
          [](const ResourcesManager& self, std::string_view path) {
            auto content = self.extract(path);
            if (!content) {
              throw nb::value_error(
                  ("Resource path not found: " + std::string(path)).c_str()
              );
            }
            return nb::to_bytes(*content);
          },
          "Export the content of the resource at the given path"_doc,
          "path"_a)

      .def(
          "replace",
          [](ResourcesManager& self, std::string_view path, nb::object data) {
            return self.replace(path, to_byte_vector(data));
          },
          R"doc(
          Replace the resource at the given ``path``.

          Missing intermediate directories and the final data node are created
          automatically, so this method can also be used to add a resource.
          )doc"_doc,
          "path"_a, "data"_a)

      .def(
          "add",
          [](ResourcesManager& self, std::string_view path, nb::object data) {
            return self.add(path, to_byte_vector(data));
          },
          "Add a new resource; fails if the path already exists"_doc,
          "path"_a, "data"_a)

      .def("remove", &ResourcesManager::remove,
           "Remove the resource or directory at the given path"_doc, "path"_a)

      .def_prop_ro("has_manifest", &ResourcesManager::has_manifest,
                   "``True`` if the resources contain a Manifest element"_doc)

      .def_prop_rw(
          "manifest",
          [](const ResourcesManager& obj) { return safe_string(obj.manifest()); },
          nb::overload_cast<std::string_view>(&ResourcesManager::manifest),
          "Manifest as a ``string``"_doc
      )


      .def_prop_ro(
          "has_version", &ResourcesManager::has_version,
          "``True`` if the resources contain a :class:`~lief.PE.ResourceVersion`"_doc
      )

      .def_prop_ro("version", &ResourcesManager::version,
                   "Return a list of version info (``VS_VERSIONINFO``)."_doc)

      .def_prop_ro(
          "has_icons", &ResourcesManager::has_icons,
          "``True`` if the resources contain :class:`~lief.PE.ResourceIcon`"_doc
      )

      .def_prop_ro(
          "icons", &ResourcesManager::icons,
          "Return the list of the :class:`~lief.PE.ResourceIcon` present in the resource"_doc,
          nb::keep_alive<0, 1>()
      )

      .def("change_icon", &ResourcesManager::change_icon,
           "Switch the given icons"_doc, "old_one"_a, "new_one"_a)

      .def_prop_ro(
          "has_dialogs", &ResourcesManager::has_dialogs,
          "``True`` if the resources contain :class:`~lief.PE.ResourceDialog`"_doc
      )

      .def_prop_ro(
          "dialogs", &ResourcesManager::dialogs,
          "Return the list of the :class:`~lief.PE.ResourceDialog` present in the resource"_doc,
          nb::keep_alive<0, 1>()
      )

      .def_prop_ro("types", &ResourcesManager::get_types,
                   "Return list of :class:`~.TYPE` present in the resources"_doc)

      .def("add_icon", &ResourcesManager::add_icon,
           "Add an icon to the resources"_doc, "icon"_a)

      .def("has_type", &ResourcesManager::has_type,
           "``True`` if the resource has the given :class:`~.TYPE`"_doc, "type"_a)

      .def_prop_ro(
          "has_string_table", &ResourcesManager::has_string_table,
          "``True`` if resources contain :class:`~lief.PE.ResourceStringTable`"_doc
      )

      .def_prop_ro(
          "string_table", &ResourcesManager::string_table,
          "Return the list of the strings embedded in the string table (``RT_STRING``)"_doc
      )

      .def_prop_ro("has_html", &ResourcesManager::has_html,
                   "``True`` if resources contain HTML resource"_doc)

      .def_prop_ro("html", &ResourcesManager::html,
                   "HTML resource as the list of ``string``"_doc)

      .def_prop_ro(
          "has_accelerator", &ResourcesManager::has_accelerator,
          "``True`` if resources contain :class:`~lief.PE.ResourceAccelerator`"_doc
      )

      .def_prop_ro(
          "accelerator", &ResourcesManager::accelerator,
          "Return list of :class:`~lief.PE.ResourceAccelerator` present in the resource"_doc,
          nb::keep_alive<1, 0>()
      )

      .def("get_node_type",
           nb::overload_cast<ResourcesManager::TYPE>(
               &ResourcesManager::get_node_type
           ),
           R"delim(
           Return :class:`~lief.PE.ResourceNode` with the given :class:`~.TYPE`
           or None if not found.
           )delim"_doc,
           "type"_a, nb::rv_policy::reference_internal)

      .def("print", &ResourcesManager::print, "Print the current resource tree",
           "max_depth"_a = 0)

      .LIEF_DEFAULT_STR(ResourcesManager);
}
}
