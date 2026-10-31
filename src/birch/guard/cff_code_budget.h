#pragma once

#include "birch/guard/config.h"
#include <cstddef>
#include <string>
#include <string_view>
#include <stdexcept>
#include <utility>
#include <vector>

namespace birch::guard::detail {

// A planning failure, distinct from malformed code or an emission bug. Only
// this failure may trigger safe repartitioning; never catch arbitrary errors
// and silently retry a weaker transform.
class CffCodeBudgetExceeded final : public std::length_error {
public:
    using std::length_error::length_error;
};

struct CffPartitionFailure {
    std::string method_key; // canonical DEX key, not the strategy/salt key
    std::string diagnostic;
};

class CffPartitionRequired final : public std::length_error {
public:
    explicit CffPartitionRequired(std::vector<CffPartitionFailure> failures);
    [[nodiscard]] const auto& failures() const noexcept { return failures_; }
private:
    std::vector<CffPartitionFailure> failures_;
};

// An exact, non-overlapping layout ledger, not a source-size heuristic.
// Callers reserve all fixed code and deferred payloads before materializing
// payload bytes, then reconcile the emitted size before committing a method.
class CffCodeBudget final {
public:
    CffCodeBudget(const GuardConfig& config, std::size_t source_units);
    void Reserve(std::string_view section, std::size_t units);
    [[nodiscard]] bool Fits() const noexcept;
    void Require(std::string_view method, std::size_t dead_states) const;
    void Reconcile(std::size_t emitted_units) const;
    [[nodiscard]] std::size_t planned_units() const noexcept { return total_; }
private:
    std::size_t limit_, growth_limit_, total_{};
    std::vector<std::pair<std::string, std::size_t>> sections_;
};
}
