#pragma once

#include "cff_assembler.h"

#include <cstdint>
#include <optional>

namespace birch::guard::detail {

// A cached mask must be initialized before dispatch and remain unchanged on
// every live path. Dead-only registers may be reused after leaving that CFG.
class CffJointToken final {
public:
    CffJointToken(CffAssembler& assembler, std::uint32_t mask,
                  std::optional<std::uint16_t> cached_mask = std::nullopt);
    void Emit(std::uint16_t joint, std::uint16_t state, std::uint16_t selector) const;
    void Guard(std::uint16_t temporary, std::uint16_t joint, std::uint16_t state,
               std::uint16_t selector, CffAssembler::Label invalid) const;

private:
    CffAssembler* assembler_;
    std::uint32_t mask_;
    std::optional<std::uint16_t> cached_mask_;
};

} // namespace birch::guard::detail
