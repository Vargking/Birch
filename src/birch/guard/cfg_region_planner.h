#pragma once

#include "birch/dex/liveness.h"
#include "birch/dex/type_analysis.h"
#include "birch/guard/config.h"

#include <optional>

namespace birch::guard::detail {
struct RegionValue {
    std::uint16_t reg{};
    std::string descriptor;
    std::optional<std::uint32_t> constant32;
    [[nodiscard]] std::uint16_t words() const { return descriptor == "J" || descriptor == "D" ? 2U : 1U; }
};
struct CfgRegion {
    std::size_t first{}, end{}; // ordinals in the analyzed source only
    std::uint32_t start_offset{}, end_offset{};
    std::vector<RegionValue> inputs;
    std::vector<RegionValue> constant_outputs;
    std::optional<RegionValue> output;
    std::uint16_t argument_words{};
    std::string helper;
};

// Plans only single-entry/single-continuation regions, including internal
// branches/loops. No serialized signature parsing or sequential type guessing.
class CfgRegionPlanner final {
public:
    // Profitability is proved from the actual typed call below. A 48-unit
    // source floor excluded short regions whose later protection expands
    // heavily (strings, constants and branches), leaving feedback no route.
    static constexpr std::size_t kMinimumRegionUnits = 16U;
    static constexpr std::size_t kMaximumRegionUnits = 192U;
    [[nodiscard]] static std::vector<CfgRegion> Plan(
        const dex::DexFile& file, const dex::DexEncodedMethod& method,
        const dex::CodeItem& code, const GuardConfig& config,
        std::size_t maximum_units = kMaximumRegionUnits);
};
}
