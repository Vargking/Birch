#pragma once

#include "birch/dex/ir.h"
#include "birch/dex/type_analysis.h"

#include <span>
#include <vector>

namespace birch::guard::detail {

// Exit states share only with identical verifier types and register sets.
// Optional liveness projection excludes words proven overwritten before use.
class CffTypeDomains final {
public:
    CffTypeDomains(const dex::DexFile& file, const dex::DexEncodedMethod& method,
                   const dex::MethodIr& ir,
                   std::span<const std::uint16_t> redefined_scratch,
                   bool share = true, bool project_live = false);

    [[nodiscard]] dex::BlockId Owner(dex::BlockId block) const { return owners_.at(block); }
    [[nodiscard]] std::size_t MemberCount(dex::BlockId owner) const { return counts_.at(owner); }

private:
    std::vector<dex::BlockId> owners_;
    std::vector<std::size_t> counts_;
};

} // namespace birch::guard::detail
