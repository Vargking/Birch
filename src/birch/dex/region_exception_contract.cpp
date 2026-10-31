#include "birch/dex/region_exception_contract.h"

#include <algorithm>

namespace birch::dex {

std::optional<RegionExceptionContract> RegionExceptionContract::Prove(
    const CodeItem& code, std::uint32_t start, std::uint32_t end) {
    if (start >= end || end > code.insns.size()) return std::nullopt;
    RegionExceptionContract result;
    for (const auto& region : code.tries) {
        const auto region_end = static_cast<std::uint64_t>(region.start_address) +
            region.instruction_count;
        const bool intersects = start < region_end && end > region.start_address;
        if (intersects && (start < region.start_address || end > region_end))
            return std::nullopt;
        for (const auto& handler : region.handlers) {
            if (handler.address >= start && handler.address < end) return std::nullopt;
            if (intersects && !handler.type_idx) result.catches_all_ = true;
            if (intersects && std::find(result.handlers_.begin(), result.handlers_.end(),
                handler.address) == result.handlers_.end()) result.handlers_.push_back(handler.address);
        }
    }
    return result;
}

} // namespace birch::dex
