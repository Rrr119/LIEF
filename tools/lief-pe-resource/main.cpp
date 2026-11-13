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
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <LIEF/PE.hpp>
#include <LIEF/errors.hpp>

namespace {

struct options_t {
  std::vector<std::string> args;
  std::string output;
  std::string signature;
  bool json = false;
  bool recompute_checksum = true;
};

void usage() {
  std::cout <<
      "Usage:\n"
      "  lief-pe-resource list <pe> [--json]\n"
      "  lief-pe-resource export <pe> <resource-path> [-o <file>]\n"
      "  lief-pe-resource replace <pe> <resource-path> <data-file> -o <out>\n"
      "  lief-pe-resource add <pe> <resource-path> <data-file> -o <out>\n"
      "  lief-pe-resource remove <pe> <resource-path> -o <out>\n"
      "\n"
      "Resource paths use the type/name/language form, for example:\n"
      "  ICON/1/1033\n"
      "  3/1/1033\n"
      "  RT_MANIFEST/1/1033\n"
      "\n"
      "Options:\n"
      "  -o, --output <file>       Output file\n"
      "      --signature <file>    Save the original certificate table to <file>\n"
      "      --no-checksum         Do not recompute the PE checksum\n"
      "      --json                JSON output for the list command\n";
}

bool parse_options(int argc, char** argv, int start, options_t& opts) {
  for (int i = start; i < argc; ++i) {
    std::string_view arg = argv[i];
    if (arg == "-o" || arg == "--output") {
      if (++i >= argc) {
        std::cerr << "Missing value for " << arg << '\n';
        return false;
      }
      opts.output = argv[i];
    } else if (arg == "--signature") {
      if (++i >= argc) {
        std::cerr << "Missing value for --signature\n";
        return false;
      }
      opts.signature = argv[i];
    } else if (arg == "--json") {
      opts.json = true;
    } else if (arg == "--no-checksum") {
      opts.recompute_checksum = false;
    } else if (arg == "--help" || arg == "-h") {
      usage();
      std::exit(0);
    } else if (!arg.empty() && arg[0] == '-') {
      std::cerr << "Unknown option: " << arg << '\n';
      return false;
    } else {
      opts.args.emplace_back(arg);
    }
  }
  return true;
}

std::vector<uint8_t> read_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return {};
  }
  return {std::istreambuf_iterator<char>{input},
          std::istreambuf_iterator<char>{}};
}

bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    return false;
  }
  output.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
  return output.good();
}

std::string json_escape(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (char c : value) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out += c; break;
    }
  }
  return out;
}

void print_entries(const LIEF::PE::ResourcesManager& manager, bool json) {
  const auto entries = manager.entries();
  if (json) {
    std::cout << "[\n";
    for (size_t i = 0; i < entries.size(); ++i) {
      const auto& entry = entries[i];
      std::cout << "  {\"type\": \"" << json_escape(entry.type_name)
                << "\", \"type_id\": " << entry.type
                << ", \"name\": \"" << json_escape(entry.name)
                << "\", \"name_id\": " << entry.name_id
                << ", \"language\": " << entry.language
                << ", \"size\": " << entry.size
                << ", \"rva\": " << entry.rva
                << ", \"path\": \"" << json_escape(entry.path)
                << "\"}";
      if (i + 1 != entries.size()) {
        std::cout << ',';
      }
      std::cout << '\n';
    }
    std::cout << "]\n";
    return;
  }

  std::cout << std::left << std::setw(18) << "TYPE"
            << std::setw(20) << "NAME"
            << std::setw(18) << "LANGUAGE"
            << std::setw(12) << "SIZE"
            << std::setw(14) << "RVA"
            << "PATH\n";
  for (const auto& entry : entries) {
    std::ostringstream lang;
    lang << entry.language << " (0x" << std::hex << entry.language << ')';
    std::ostringstream rva;
    rva << "0x" << std::hex << entry.rva;
    std::cout << std::left << std::setw(18) << entry.type_name
              << std::setw(20)
              << (entry.name.empty() ? std::to_string(entry.name_id) : entry.name)
              << std::setw(18) << lang.str()
              << std::setw(12) << entry.size
              << std::setw(14) << rva.str()
              << entry.path << '\n';
  }
}

int apply_edit(const std::string& command, const std::string& input_path,
               const std::string& resource_path, const options_t& opts,
               const std::vector<uint8_t>* content) {
  auto binary = LIEF::PE::Parser::parse(input_path);
  if (binary == nullptr) {
    std::cerr << "Failed to parse " << input_path << '\n';
    return 1;
  }

  auto manager = binary->resources_manager();
  if (!manager) {
    std::cerr << "No resources in " << input_path << '\n';
    return 1;
  }

  const bool was_signed = binary->has_signatures();
  const std::vector<uint8_t> signature = binary->signature_data();

  bool ok = false;
  if (command == "replace") {
    ok = manager->replace(resource_path, *content);
  } else if (command == "add") {
    ok = manager->add(resource_path, *content);
  } else if (command == "remove") {
    ok = manager->remove(resource_path);
  }

  if (!ok) {
    std::cerr << "Failed to " << command << " resource '" << resource_path << "'\n";
    return 1;
  }

  if (was_signed) {
    std::cerr << "warning: the resource modification invalidates the "
                 "Authenticode signature\n";
    if (!signature.empty()) {
      const std::string sig_path =
          opts.signature.empty() ? opts.output + ".sig" : opts.signature;
      if (!write_file(sig_path, signature)) {
        std::cerr << "warning: failed to save the original certificate table "
                     "to "
                  << sig_path << '\n';
      } else {
        std::cerr << "warning: original certificate table saved to "
                  << sig_path << " (" << signature.size() << " bytes)\n";
      }
    }
    binary->remove_signatures();
  }

  LIEF::PE::Builder::config_t config;
  config.recompute_checksum = opts.recompute_checksum;
  binary->write(opts.output, config);

  auto rebuilt = LIEF::PE::Parser::parse(opts.output);
  if (rebuilt == nullptr) {
    std::cerr << "Failed to re-parse the rebuilt binary\n";
    return 1;
  }
  std::string error;
  if (!LIEF::PE::check_layout(*rebuilt, &error)) {
    std::cerr << "warning: rebuilt PE layout check failed: " << error << '\n';
  }

  std::cout << "Wrote " << opts.output << '\n';
  return 0;
}

}

int main(int argc, char** argv) {
  if (argc < 2 || std::string_view(argv[1]) == "--help" ||
      std::string_view(argv[1]) == "-h")
  {
    usage();
    return argc < 2 ? 1 : 0;
  }

  const std::string command = argv[1];
  options_t opts;
  if (!parse_options(argc, argv, 2, opts)) {
    usage();
    return 1;
  }

  if (command == "list") {
    if (opts.args.empty()) {
      usage();
      return 1;
    }
    auto binary = LIEF::PE::Parser::parse(opts.args[0]);
    if (binary == nullptr) {
      std::cerr << "Failed to parse " << opts.args[0] << '\n';
      return 1;
    }
    if (!binary->has_resources()) {
      std::cerr << "No resources in " << opts.args[0] << '\n';
      return 1;
    }
    auto manager = binary->resources_manager();
    if (!manager) {
      std::cerr << "Failed to access the resource tree\n";
      return 1;
    }
    print_entries(*manager, opts.json);
    return 0;
  }

  if (command == "export") {
    if (opts.args.size() < 2) {
      usage();
      return 1;
    }
    auto binary = LIEF::PE::Parser::parse(opts.args[0]);
    if (binary == nullptr) {
      std::cerr << "Failed to parse " << opts.args[0] << '\n';
      return 1;
    }
    auto manager = binary->resources_manager();
    if (!manager) {
      std::cerr << "No resources in " << opts.args[0] << '\n';
      return 1;
    }
    auto content = manager->extract(opts.args[1]);
    if (!content) {
      std::cerr << "Resource not found: " << opts.args[1] << '\n';
      return 1;
    }
    if (opts.output.empty()) {
      std::cout.write(reinterpret_cast<const char*>(content->data()),
                      static_cast<std::streamsize>(content->size()));
      return 0;
    }
    if (!write_file(opts.output, *content)) {
      std::cerr << "Failed to write " << opts.output << '\n';
      return 1;
    }
    std::cerr << "Exported " << content->size() << " bytes to "
              << opts.output << '\n';
    return 0;
  }

  if (command == "replace" || command == "add") {
    if (opts.args.size() < 3 || opts.output.empty()) {
      usage();
      return 1;
    }
    const auto content = read_file(opts.args[2]);
    if (content.empty()) {
      std::cerr << "Cannot read resource data from " << opts.args[2] << '\n';
      return 1;
    }
    return apply_edit(command, opts.args[0], opts.args[1], opts, &content);
  }

  if (command == "remove") {
    if (opts.args.size() < 2 || opts.output.empty()) {
      usage();
      return 1;
    }
    return apply_edit(command, opts.args[0], opts.args[1], opts, nullptr);
  }

  std::cerr << "Unknown command: " << command << '\n';
  usage();
  return 1;
}
