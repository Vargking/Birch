#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/config.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace birch::guard::detail {

struct LinearOutlineResult {
    std::vector<std::uint8_t> bytes;
    std::size_t methods{};
    std::size_t regions{};
    std::size_t moved_code_units{};
};

// Before instruction materialization, extract only straight-line void regions
// whose live outputs are unchanged. Original register operands and symbolic
// references are retained. All same-owner helpers still receive every lowering
// pass and the full per-method CFF/dead-state floor; this is not a budget bypass.
class LinearRegionOutliner final {
public:
    static constexpr std::size_t kCallerThreshold = 1536U;
    static constexpr std::size_t kMinimumRegionUnits = 128U;
    static constexpr std::size_t kMaximumRegionUnits = 256U;

    [[nodiscard]] static LinearOutlineResult Apply(
        const dex::DexFile& source, const GuardConfig& config);
};

} // namespace birch::guard::detail
