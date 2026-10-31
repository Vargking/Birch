#include "resource_obfuscator.h"
#include "rename_names.h"
#include "birch/dex/dex_file.h"
#include "birch/guard/arsc.h"
#include "birch/io/apk_entries.h"
#include "birch/utils/hash.h"
#include <algorithm>
#include <set>
#include <stdexcept>
#include <string_view>

namespace birch::guard::detail {
namespace {
bool Contains(std::span<const std::uint8_t> data, std::string_view value) {
    return std::search(data.begin(), data.end(), value.begin(), value.end()) != data.end();
}
bool DynamicNameApi(std::string_view name) {
    return name == "getIdentifier" || name == "getResourceName" ||
           name == "getResourceEntryName" || name == "getResourceTypeName" ||
           name == "getField" || name == "getDeclaredField";
}
bool DynamicPathApi(std::string_view name) {
    return name == "openNonAsset" || name == "openNonAssetFd" ||
           name == "list"; // AssetManager subclasses / reflective path enumeration.
}
}

ResourceObfuscator ResourceObfuscator::Plan(const ZipArchive& archive,
                                           const GuardConfig& config) {
    ResourceObfuscator plan;
    const bool rename_names = config.resources.rename_names ||
        config.passes.at("resources.name_rename").enabled;
    const bool rename_files = config.resources.rename_files ||
        config.passes.at("resources.file_rename").enabled;
    if (!rename_names && !rename_files) return plan;
    const auto* entry = archive.Find("resources.arsc");
    if (entry == nullptr) {
        plan.warnings_.push_back("Resource transforms requested, but APK has no resources.arsc.");
        return plan;
    }
    const auto table = ArscTable::Parse(entry->data);
    bool dynamic_names = false;
    bool dynamic_paths = false;
    bool native_code = false;
    bool overlay = false;
    std::set<std::string, std::less<>> literals;
    for (const auto& chunk : table.chunks()) {
        // Overlayable/policy/staged alias metadata may expose names externally.
        overlay = overlay || chunk.type == 0x0204U || chunk.type == 0x0205U ||
                             chunk.type == 0x0206U;
    }
    for (const auto& item : archive.entries()) {
        if (item.name.starts_with("lib/") && item.name.ends_with(".so")) native_code = true;
        if (!io::IsDexEntryName(item.name)) continue;
        const auto dex = dex::DexFile::Parse(item.data);
        for (const auto& string : dex.strings()) literals.insert(string.mutf8);
        for (const auto& method : dex.methods()) {
            const auto name = dex.string(method.name_idx);
            dynamic_names = dynamic_names || DynamicNameApi(name);
            dynamic_paths = dynamic_paths || (DynamicPathApi(name) &&
                (name != "list" || dex.descriptor(method.class_idx) == "Landroid/content/res/AssetManager;"));
        }
    }
    if (rename_names && (dynamic_names || native_code || overlay)) {
        plan.warnings_.push_back("ARSC key names preserved: dynamic resource-name/reflection APIs, native code, or overlay metadata make uniform BirchGuard keys unsafe to prove. IDs/values unchanged.");
    } else if (rename_names) {
        for (const auto& key : table.resource_names()) {
            if (key == "BirchGuard") continue;
            // Names mentioned in DEX or opaque assets can be external contracts.
            bool exposed = literals.contains(key);
            for (const auto& item : archive.entries()) {
                if (item.name.starts_with("assets/") && Contains(item.data, key)) exposed = true;
            }
            if (exposed) {
                plan.warnings_.push_back("ARSC key preserved (literal/asset contract): " + key);
                continue;
            }
            plan.names_.emplace(key, "BirchGuard");
            plan.mapping_.push_back("resource-key " + key + " -> BirchGuard");
        }
    }
    if (rename_files && dynamic_paths) {
        plan.warnings_.push_back("Resource file paths preserved: dynamic non-asset path access/enumeration cannot be safely rewritten.");
    } else if (rename_files) {
        const auto tokens = NameGenerator::DictionaryTokens(config.resources.dictionary.empty() ?
            DefaultRenameDictionary() : config.resources.dictionary);
        std::set<std::string, std::less<>> occupied;
        for (const auto& item : archive.entries()) occupied.insert(item.name);
        for (const auto& path : table.strings()) {
            if (!path.starts_with("res/") || archive.Find(path) == nullptr ||
                plan.paths_.contains(path)) continue;
            const auto slash = path.rfind('/');
            const auto suffix = path.ends_with(".9.png") ? path.size() - 6U : path.rfind('.');
            if (suffix == std::string::npos || suffix <= slash + 1U) continue;
            bool exposed = literals.contains(path);
            for (const auto& item : archive.entries()) {
                if ((item.name.starts_with("assets/") || item.name.ends_with(".so")) &&
                    Contains(item.data, path)) exposed = true;
            }
            // Raw filenames are commonly an implicit native/embedded-engine API.
            if (native_code && path.starts_with("res/raw")) exposed = true;
            if (exposed) {
                plan.warnings_.push_back("Resource path preserved (literal/native contract): " + path);
                continue;
            }
            std::string target;
            for (std::size_t attempt = 0U; attempt < 1024U; ++attempt) {
                auto state = utils::StableHash64(path, config.seed ^ attempt);
                std::string stem;
                for (unsigned i = 0; i < 16U; ++i) {
                    stem += tokens[state % tokens.size()];
                    state = utils::StableHash64(std::to_string(i), state);
                }
                target = path.substr(0, slash + 1U) + stem + path.substr(suffix);
                if (occupied.insert(target).second) break;
                target.clear();
            }
            if (target.empty()) throw std::runtime_error("resource filename namespace exhausted");
            plan.paths_.emplace(path, target);
            plan.mapping_.push_back("resource-file " + path + " -> " + target);
        }
    }
    return plan;
}

void ResourceObfuscator::Apply(ZipArchive& archive) const {
    if (names_.empty() && paths_.empty()) return;
    auto* arsc = archive.FindMutable("resources.arsc");
    if (arsc == nullptr) throw std::runtime_error("resources.arsc disappeared");
    arsc->data = ArscTable::Parse(arsc->data).RenameResources(names_, paths_);
    for (const auto& [old_path, new_path] : paths_) archive.RenameEntry(old_path, new_path);
    const auto strings = ArscTable::Parse(arsc->data).strings();
    for (const auto& [old_path, new_path] : paths_) {
        (void)old_path;
        if (archive.Find(new_path) == nullptr ||
            std::find(strings.begin(), strings.end(), new_path) == strings.end()) {
            throw std::runtime_error("ARSC/ZIP resource path rewrite incomplete: " + new_path);
        }
    }
}
} // namespace birch::guard::detail
