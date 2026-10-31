#include "cff_code_budget.h"
#include "strength_policy.h"
#include <limits>
#include <stdexcept>

namespace birch::guard::detail {
CffPartitionRequired::CffPartitionRequired(std::vector<CffPartitionFailure> failures)
    : std::length_error(failures.empty() ? "empty CFF partition request" :
          failures.front().diagnostic + " (over-budget methods=" + std::to_string(failures.size()) + ")"),
      failures_(std::move(failures)) {}

CffCodeBudget::CffCodeBudget(const GuardConfig& config, std::size_t source_units)
    : limit_(StrengthPolicy::CodeUnitLimit(config)),
      growth_limit_(StrengthPolicy::GrowthLimit(source_units, config.budget.max_method_growth_ratio)) {}

void CffCodeBudget::Reserve(std::string_view section, std::size_t units) {
    if (units > std::numeric_limits<std::size_t>::max() - total_)
        throw std::length_error("CFF layout size overflow");
    for (const auto& item : sections_) if (item.first == section)
        throw std::logic_error("duplicate CFF budget section");
    sections_.emplace_back(section, units);
    total_ += units;
}
bool CffCodeBudget::Fits() const noexcept { return total_ <= limit_ && total_ <= growth_limit_; }
void CffCodeBudget::Require(std::string_view method, std::size_t dead_states) const {
    if (Fits()) return;
    auto message = "CFF layout exceeds runtime code budget for " + std::string(method) +
        ": planned=" + std::to_string(total_) + ", maximum=" + std::to_string(limit_) +
        ", growth maximum=" + std::to_string(growth_limit_) + ", dead_states=" + std::to_string(dead_states);
    for (const auto& [name, units] : sections_) message += ", " + name + "=" + std::to_string(units);
    throw CffCodeBudgetExceeded(message);
}
void CffCodeBudget::Reconcile(std::size_t emitted_units) const {
    if (emitted_units != total_) throw std::logic_error("CFF planned/emitted code size mismatch");
}
}
