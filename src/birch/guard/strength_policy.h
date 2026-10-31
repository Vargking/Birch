#pragma once

#include "birch/guard/config.h"

#include <cstddef>

namespace birch::guard::detail {

// One policy for both prefix materialization and whole-method dispatch.
class StrengthPolicy final {
public:
    static constexpr std::size_t kMinimumFullStrengthCfgBlocks = 256U;
    static constexpr std::size_t kMaximumArtCompilerCodeUnits = 16000U;

    [[nodiscard]] static bool RequiresFullStrength(const GuardConfig& config);
    [[nodiscard]] static std::size_t TargetBlocks(const GuardConfig& config);
    [[nodiscard]] static std::size_t CodeUnitLimit(const GuardConfig& config);
    // Saturates before conversion: even a finite configured ratio can overflow.
    [[nodiscard]] static std::size_t GrowthLimit(std::size_t source_units, double ratio);
};

} // namespace birch::guard::detail
