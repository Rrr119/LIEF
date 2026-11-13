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
#ifndef LIEF_PE_RESOURCES_MANAGER_H
#define LIEF_PE_RESOURCES_MANAGER_H
#include <cstdint>
#include <string_view>
#include <ostream>
#include <sstream>
#include <vector>

#include "LIEF/Object.hpp"
#include "LIEF/errors.hpp"
#include "LIEF/iterators.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/resources/ResourceAccelerator.hpp"
#include "LIEF/PE/resources/ResourceDialog.hpp"
#include "LIEF/PE/resources/ResourceIcon.hpp"
#include "LIEF/PE/resources/ResourceVersion.hpp"

namespace LIEF {
class VectorStream;

namespace PE {
class ResourceNode;
class ResourceData;
class Binary;

/// The Resource Manager provides an enhanced API to manipulate the resource tree.
class LIEF_API ResourcesManager : public Object {
  public:
  /// The different types of resources
  /// From https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types
  enum class TYPE {
    CURSOR = 1,
    BITMAP = 2,
    ICON = 3,
    MENU = 4,
    DIALOG = 5,
    STRING = 6,
    FONTDIR = 7,
    FONT = 8,
    ACCELERATOR = 9,
    RCDATA = 10,
    MESSAGETABLE = 11,
    GROUP_CURSOR = 12,
    GROUP_ICON = 14,
    VERSION = 16,
    DLGINCLUDE = 17,
    PLUGPLAY = 19,
    VXD = 20,
    ANICURSOR = 21,
    ANIICON = 22,
    HTML = 23,
    MANIFEST = 24,
  };

  public:
  using dialogs_t = ResourceDialog::dialogs_t;
  using it_const_dialogs =
      const_ref_iterator<const dialogs_t&, const ResourceDialog*>;

  using icons_t = std::vector<ResourceIcon>;
  using it_const_icons = const_ref_iterator<icons_t>;

  using accelerators_t = std::vector<ResourceAccelerator>;
  using it_const_accelerators = const_ref_iterator<accelerators_t>;

  /// This structure represent an entry in the string table (`RT_STRING`)
  struct LIEF_API string_entry_t {
    std::u16string string;
    uint32_t id = 0;

    std::string string_u8() const;

    bool is_defined() const {
      return !string.empty();
    }

    operator bool() const {
      return is_defined();
    }

    friend LIEF_API std::ostream& operator<<(std::ostream& os,
                                             const string_entry_t& str) {
      os << std::to_string(str.id) << ", " << str.string_u8();
      return os;
    }
  };

  using strings_table_t = std::vector<string_entry_t>;

  /// Description of a resource data node in the resource tree
  struct LIEF_API entry_t {
    /// Numeric resource type (e.g. ``3`` for ``RT_ICON``)
    uint32_t type = 0;

    /// Human-readable resource type (e.g. ``ICON``)
    std::string type_name;

    /// Name of the resource (empty if the node is identified by an ID)
    std::string name;

    /// Numeric ID of the resource name
    uint32_t name_id = 0;

    /// Language ID of the resource data
    uint32_t language = 0;

    /// Size of the resource data
    uint64_t size = 0;

    /// RVA of the resource data
    uint32_t rva = 0;

    /// Code page associated with the resource data
    uint32_t code_page = 0;

    /// Path that can be used with :meth:`export`, :meth:`replace` and
    /// :meth:`remove` (e.g. ``ICON/1/1033``)
    std::string path;
  };

  using entries_t = std::vector<entry_t>;

  ResourcesManager() = delete;
  ResourcesManager(ResourceNode& rsrc) :
    resources_{&rsrc} {}

  ResourcesManager(ResourceNode& rsrc, Binary& binary) :
    resources_{&rsrc},
    binary_{&binary} {}

  ResourcesManager(const ResourcesManager& other) :
    Object(other),
    resources_(other.resources_),
    binary_(other.binary_)
  // Skip (on purpose) the `dialogs_` cache
  {}

  ResourcesManager& operator=(const ResourcesManager& other) {
    if (&other != this) {
      Object::operator=(other);
      resources_ = other.resources_;
      binary_ = other.binary_;
      // Skip (on purpose) the `dialogs_` cache
    }
    return *this;
  }

  ResourcesManager(ResourcesManager&&) = default;
  ResourcesManager& operator=(ResourcesManager&&) = default;

  ~ResourcesManager() override = default;

  /// Return the ResourceNode associated with the given TYPE
  /// or a nullptr if not found;
  ResourceNode* get_node_type(TYPE type) LIEF_LIFETIMEBOUND {
    return const_cast<ResourceNode*>(
        static_cast<const ResourcesManager*>(this)->get_node_type(type)
    );
  }
  const ResourceNode* get_node_type(TYPE type) const LIEF_LIFETIMEBOUND;

  /// List of TYPE present in the resources
  std::vector<TYPE> get_types() const;

  /// `true` if the resource has the given TYPE node
  bool has_type(TYPE type) const {
    return get_node_type(type) != nullptr;
  }

  /// `true` if resources contain the Manifest element
  bool has_manifest() const {
    return get_node_type(TYPE::MANIFEST) != nullptr;
  }

  /// Return the manifest as a std::string or an empty string if not found
  /// or corrupted.
  std::string manifest() const;

  /// Change or set the manifest. If the manifest node path does not exist,
  /// all required nodes are created.
  void manifest(std::string_view manifest);

  /// `true` if resources contain a LIEF::PE::ResourceVersion
  bool has_version() const {
    return get_node_type(TYPE::VERSION) != nullptr;
  }

  /// Return a list of version info (`VS_VERSIONINFO`).
  std::vector<ResourceVersion> version() const;

  /// `true` if resources contain a LIEF::PE::ResourceIcon
  bool has_icons() const {
    return get_node_type(TYPE::ICON) != nullptr &&
           get_node_type(TYPE::GROUP_ICON) != nullptr;
  }

  /// Return the list of the icons present in the resources
  it_const_icons icons() const LIEF_LIFETIMEBOUND;

  /// Add an icon to the resources
  void add_icon(const ResourceIcon& icon);

  void change_icon(const ResourceIcon& original, const ResourceIcon& newone);

  /// `true` if resources contain dialogs
  bool has_dialogs() const {
    return get_node_type(TYPE::DIALOG) != nullptr;
  }

  /// Return the list of the dialogs present in the resource
  it_const_dialogs dialogs() const LIEF_LIFETIMEBOUND;

  /// `true` if the resources contain a string table
  bool has_string_table() const {
    return get_node_type(TYPE::STRING) != nullptr;
  }

  /// Return the list of the strings embedded in the string table (`RT_STRING`)
  strings_table_t string_table() const;

  /// `true` if the resources contain html
  bool has_html() const {
    return get_node_type(TYPE::HTML) != nullptr;
  }

  /// Return the list of the html resources
  std::vector<std::string> html() const;

  /// `true` if the resources contain accelerator info
  bool has_accelerator() const {
    return get_node_type(TYPE::ACCELERATOR) != nullptr;
  }

  /// Return the list of the accelerator in the resource
  it_const_accelerators accelerator() const;

  /// Print the resource tree to the given depth
  std::string print(uint32_t depth = 0) const;

  /// Describe every resource data node in depth-first order
  entries_t entries() const;

  /// Alias for :meth:`entries`
  entries_t list() const {
    return entries();
  }

  /// Export the content of the resource at the given path.
  ///
  /// The path is a ``/``-separated sequence of type, name and language
  /// identifiers. Each component can be a decimal/hexadecimal ID or the
  /// corresponding resource name. For example, the following paths identify
  /// the same icon:
  ///
  /// * ``3/1/1033``
  /// * ``ICON/1/1033``
  /// * ``RT_ICON/1/1033``
  result<std::vector<uint8_t>> extract(std::string_view path) const;

  /// Replace the resource at the given path.
  ///
  /// If the path does not exist, the intermediate directories and the final
  /// data node are created. This makes :meth:`replace` suitable for adding a
  /// new resource as well.
  bool replace(std::string_view path, std::vector<uint8_t> content);

  /// Add a new resource at the given path.
  ///
  /// Unlike :meth:`replace`, this method fails if the path already exists.
  bool add(std::string_view path, std::vector<uint8_t> content);

  /// Remove the resource or directory at the given path
  bool remove(std::string_view path);

  /// Check if the given resource path exists
  bool has_path(std::string_view path) const;

  /// ``True`` if the underlying binary is signed
  bool has_signatures() const;

  /// Raw certificate table of the original binary.
  ///
  /// The data remains available after the resource tree is modified so it can
  /// be compared with the original Authenticode signature.
  std::vector<uint8_t> original_signature_data() const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                           const ResourcesManager& m);

  private:
  void print_tree(const ResourceNode& node, std::ostringstream& stream,
                  uint32_t current_depth, uint32_t max_depth,
                  const ResourceNode* parent = nullptr, std::string header = "",
                  bool is_last = false) const;

  ResourceNode* find_node(std::string_view path) const;
  ResourceData* find_data(std::string_view path) const;
  ResourceNode* create_path(std::string_view path,
                            const std::vector<uint8_t>* content);
  void notify_signature_invalidated() const;
  void collect_entries(const ResourceNode& node, std::vector<uint32_t>& ids,
                       std::vector<std::string>& names, entries_t& out) const;

  ResourceNode* resources_ = nullptr;
  Binary* binary_ = nullptr;
  mutable bool signature_warned_ = false;
  mutable dialogs_t dialogs_;
};

LIEF_API const char* to_string(ResourcesManager::TYPE type);

}
}

#endif
