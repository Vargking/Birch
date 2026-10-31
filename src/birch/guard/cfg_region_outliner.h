#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/config.h"
#include <map>

namespace birch::guard::detail {
struct CfgOutlineResult {
    std::vector<std::uint8_t> bytes;
    std::size_t methods{}, regions{}, moved_code_units{};
};
class CfgRegionOutliner final {
public:
    using Targets = std::map<std::string, std::size_t, std::less<>>;
    // Explicit targets bypass only the size heuristic, never the safety proof.
    [[nodiscard]] static CfgOutlineResult Apply(const dex::DexFile& source, const GuardConfig& config,
                                               const Targets* targets = nullptr);
};
}
