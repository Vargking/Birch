#include "strength_policy.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <limits>

namespace birch::guard::detail {

std::size_t StrengthPolicy::CodeUnitLimit(const GuardConfig& config) {
    return RequiresFullStrength(config) ?
        std::min<std::size_t>(config.budget.max_code_units_per_method, kMaximumArtCompilerCodeUnits) :
        config.budget.max_code_units_per_method;
}

std::size_t StrengthPolicy::GrowthLimit(std::size_t source_units, double ratio) {
    if (!std::isfinite(ratio) || ratio < 0.0) throw std::invalid_argument("invalid growth ratio");
    const auto units = static_cast<long double>(source_units) * static_cast<long double>(ratio);
    const auto limit = std::numeric_limits<std::size_t>::max();
    if (units >= static_cast<long double>(limit)) return limit;
    return static_cast<std::size_t>(units);
}

bool StrengthPolicy::RequiresFullStrength(const GuardConfig& config) {
    const auto& automation = config.passes.at("strength.anti_automation_profile");
    const auto& analysis = config.passes.at("strength.analysis_cost_budget");
    return (config.strength.anti_automation_profile && automation.enabled &&
            automation.intensity >= 1.0) ||
           (analysis.enabled && analysis.intensity >= 1.0);
}

std::size_t StrengthPolicy::TargetBlocks(const GuardConfig& config) {
    const auto budget = config.budget.max_added_blocks_per_method;
    const auto& automation = config.passes.at("strength.anti_automation_profile");
    const auto& analysis = config.passes.at("strength.analysis_cost_budget");
    std::size_t target = 0U;
    const auto scaled = [&](double intensity) {
        return static_cast<std::size_t>(std::ceil(
            static_cast<double>(budget) * intensity));
    };
    if (config.strength.anti_automation_profile && automation.enabled) {
        target = scaled(automation.intensity);
    }
    if (analysis.enabled) {
        // This is a structural policy calibration, not a claim that a given
        // number of blocks guarantees a measured number of analyst-weeks.
        const auto calibrated = static_cast<std::uint64_t>(
            config.strength.target_analysis_cost_weeks) * 16U;
        if (calibrated > budget) {
            throw std::runtime_error(
                "analysis-cost target exceeds max_added_blocks_per_method");
        }
        target = std::max({target, scaled(analysis.intensity),
                           static_cast<std::size_t>(calibrated)});
    }
    if (RequiresFullStrength(config) &&
        target < kMinimumFullStrengthCfgBlocks) {
        throw std::runtime_error("full-strength CFG floor exceeds block budget");
    }
    return target;
}

} // namespace birch::guard::detail
