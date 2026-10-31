#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/config.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace birch::guard {

struct DexLoweringResult {
    std::vector<std::uint8_t> bytes;
    bool debug_removed{};
    std::size_t cfg_methods{};
    std::size_t flattened_methods{};
    std::size_t cfg_blocks_added{};
    std::size_t data_methods{};
    std::size_t constants_rewritten{};
    std::size_t strings_rewritten{};
    std::map<std::string, std::size_t, std::less<>> pass_applications;
};

class DexCodeLowering final {
public:
    explicit DexCodeLowering(const GuardConfig& config) : config_(&config) {}

    [[nodiscard]] static bool HasControlFlowPasses(const GuardConfig& config);
    [[nodiscard]] static bool HasInstructionPasses(const GuardConfig& config);
    [[nodiscard]] DexLoweringResult Apply(const dex::DexFile& source) const;

private:
    const GuardConfig* config_{};
};

} // namespace birch::guard
