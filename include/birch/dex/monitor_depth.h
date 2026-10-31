#pragma once

#include "birch/dex/ir.h"

#include <map>
#include <optional>

namespace birch::dex {

// Conservative explicit-monitor depth, not a lock-identity verifier. A merge
// of different depths becomes unknown; exceptional paths keep the held locks.
// Used only to prove that introducing a potentially throwing call needs no
// additional catch-all. It must NOT authorize sharing monitor type domains.
class MethodMonitorDepth final {
public:
    explicit MethodMonitorDepth(const MethodIr& ir);
    [[nodiscard]] bool DefinitelyEmpty(std::uint32_t offset) const;
private:
    std::map<std::uint32_t, std::optional<std::uint32_t>> before_;
};

} // namespace birch::dex
