#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/config.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace birch::guard {

struct ModelLoweringResult {
    std::vector<std::uint8_t> bytes;
    std::size_t transformed_classes{};
    std::size_t outlined_methods{};
    std::size_t split_methods{};
    std::size_t split_classes{};
    std::size_t proxy_methods{};
    std::size_t inlined_calls{};
    std::size_t annotation_noise_items{};
    std::size_t debug_noise_methods{};
    std::size_t encrypted_strings{};
    std::size_t virtualized_arrays{};
    std::size_t split_arrays{};
    std::size_t lowered_enums{};
    std::size_t merged_classes{};
    std::size_t converted_classes{};
    std::size_t tail_recursive_methods{};
    std::size_t skipped_methods{};
    std::map<std::string, std::size_t, std::less<>> pass_applications;
};

// Final runtime names for strings consumed by Java reflection APIs.  Class,
// method and field namespaces are kept separate because the same source text
// may legitimately occur in more than one namespace.
struct ReflectionRenamePlan {
    std::map<std::string, std::string, std::less<>> classes;
    std::map<std::string, std::string, std::less<>> methods;
    std::map<std::string, std::string, std::less<>> fields;
};

class DexModelLowering final {
public:
    explicit DexModelLowering(
        const GuardConfig& config,
        const ReflectionRenamePlan* reflection_renames = nullptr)
        : config_(&config), reflection_renames_(reflection_renames) {}

    [[nodiscard]] static bool HasPasses(const GuardConfig& config);
    [[nodiscard]] static bool HasReflectionRenameSites(
        const dex::DexFile& source, const ReflectionRenamePlan& plan);
    [[nodiscard]] static ReflectionRenamePlan UsedReflectionRenames(
        const dex::DexFile& source, const ReflectionRenamePlan& plan);
    // The caller reserves all other DEX types, not only locally defined types.
    [[nodiscard]] ModelLoweringResult Apply(
        const dex::DexFile& source,
        const std::set<std::string, std::less<>>& reserved_descriptors = {}) const;

private:
    const GuardConfig* config_{};
    const ReflectionRenamePlan* reflection_renames_{};
};

} // namespace birch::guard
