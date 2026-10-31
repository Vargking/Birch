#include "cff_joint_token.h"

#include <stdexcept>

namespace birch::guard::detail {

CffJointToken::CffJointToken(CffAssembler& assembler, std::uint32_t mask,
                           std::optional<std::uint16_t> cached_mask)
    : assembler_(&assembler), mask_(mask), cached_mask_(cached_mask) {
    if (cached_mask && *cached_mask > 255U)
        throw std::invalid_argument("CFF joint mask register exceeds encoding");
}

void CffJointToken::Emit(std::uint16_t joint, std::uint16_t state,
                         std::uint16_t selector) const {
    if (cached_mask_) {
        if (*cached_mask_ == joint || *cached_mask_ == state || *cached_mask_ == selector)
            throw std::invalid_argument("CFF joint mask aliases live token");
        assembler_->EmitXor(joint, state, selector);
        assembler_->EmitXor(joint, joint, *cached_mask_);
    } else {
        assembler_->EmitConst32(joint, mask_);
        assembler_->EmitXor(joint, joint, state);
        assembler_->EmitXor(joint, joint, selector);
    }
}

void CffJointToken::Guard(std::uint16_t temporary, std::uint16_t joint,
                          std::uint16_t state, std::uint16_t selector,
                          CffAssembler::Label invalid) const {
    if (temporary == joint || temporary == state || temporary == selector)
        throw std::invalid_argument("CFF joint guard aliases live token");
    if (cached_mask_ && *cached_mask_ == temporary)
        throw std::invalid_argument("CFF joint guard overwrites cached mask");
    Emit(temporary, state, selector);
    assembler_->EmitXor(temporary, temporary, joint);
    assembler_->EmitIf16(static_cast<std::uint16_t>(0x39U | (temporary << 8U)), invalid);
}

} // namespace birch::guard::detail
