#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/config.h"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <set>
#include <string>

namespace birch::guard::detail {

struct ConstantOutlineResult {
    std::vector<std::uint8_t> bytes;
    std::size_t helpers{};
    std::size_t programs{};
    std::size_t arithmetic_steps{};
};

// Runs between materialization and CFF. Moves complete keyed programs, never
// folds their operations, and leaves the typed runtime barriers at the callsite.
// Generated private same-owner helpers subsequently receive the full dispatcher.
class ConstantProgramOutliner final {
public:
    // Typed/monitor-isolated dispatchers can exceed the ART budget even when
    // materialization is only ~1500 units. Bound their constant growth too.
    static constexpr std::size_t kCallerThreshold = 1024U;
    static constexpr std::size_t kHelperBudget = 1024U;

    [[nodiscard]] static ConstantOutlineResult Apply(
        const dex::DexFile& source, const GuardConfig& config,
        const std::set<std::string, std::less<>>* targets = nullptr);
};

} // namespace birch::guard::detail
