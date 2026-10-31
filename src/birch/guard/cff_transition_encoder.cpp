#include "cff_transition_encoder.h"
#include "cff_joint_token.h"

#include <stdexcept>

namespace birch::guard::detail {

CffTransitionEncoder::CffTransitionEncoder(
    CffAssembler& assembler, Registers registers, std::uint32_t state_base,
    std::uint32_t bucket_base, std::uint8_t bucket_count, std::uint32_t joint_mask,
    bool multi_state, CffAssembler::Label dispatcher, CffAssembler::Label invalid,
    std::uint64_t salt, std::optional<std::uint16_t> barrier,
    std::optional<std::uint16_t> callback,
    std::optional<std::uint16_t> cached_joint_mask)
    : assembler_(&assembler), registers_(registers), state_base_(state_base),
      bucket_base_(bucket_base), joint_mask_(joint_mask), bucket_count_(bucket_count),
      xor_key_(static_cast<std::uint8_t>((salt >> 9U) | 1U)),
      add_key_(static_cast<std::uint8_t>((salt >> 33U) | 1U)),
      multi_state_(multi_state), tail_(assembler.NewLabel()),
      dispatcher_(dispatcher), invalid_(invalid), barrier_(barrier), callback_(callback),
      cached_joint_mask_(cached_joint_mask) {
    if (bucket_count == 0U || bucket_count > 16U || registers.state > 255U ||
        registers.selector > 255U || registers.joint > 255U || registers.temporary > 255U ||
        registers.state == registers.selector || registers.temporary == registers.state ||
        registers.temporary == registers.selector ||
        (multi_state && (registers.joint == registers.state ||
                         registers.joint == registers.selector ||
                         registers.joint == registers.temporary)))
        throw std::invalid_argument("invalid shared CFF transition layout");
}

void CffTransitionEncoder::Emit(std::uint32_t target) {
    positive_targets_ = positive_targets_ && target >= state_base_ && target <= 0x7fffffffU;
    const auto initial =
        (target - static_cast<std::uint32_t>(static_cast<std::int32_t>(
                      static_cast<std::int8_t>(add_key_)))) ^
        static_cast<std::uint32_t>(static_cast<std::int32_t>(
            static_cast<std::int8_t>(xor_key_)));
    assembler_->EmitConst32(registers_.state, initial);
    assembler_->EmitGoto32(tail_);
    used_ = true;
}

void CffTransitionEncoder::Bind(bool fallthrough_to_dispatcher) {
    assembler_->Bind(tail_);
    if (!used_) return;
    const auto [state, selector, joint, temporary] = registers_;
    if (callback_) {
        assembler_->Emit({0x0071U, *callback_, 0U,
            static_cast<std::uint16_t>(0x0aU | (selector << 8U))});
        assembler_->EmitIf16(static_cast<std::uint16_t>(0x38U | (selector << 8U)), invalid_);
    }
    assembler_->Emit({static_cast<std::uint16_t>(0xdfU | (state << 8U)),
        static_cast<std::uint16_t>(state | (static_cast<std::uint16_t>(xor_key_) << 8U)),
        static_cast<std::uint16_t>(0xd8U | (state << 8U)),
        static_cast<std::uint16_t>(state | (static_cast<std::uint16_t>(add_key_) << 8U))});
    if (barrier_) assembler_->Emit({0x0177U, *barrier_, state,
        static_cast<std::uint16_t>(0x0aU | (state << 8U))});

    // Dense states are assigned in the same order as round-robin buckets.
    // Derive the selector from the actual barrier result, not a foldable copy
    // of the expected token. Difference is nonnegative for every valid state.
    // Production dense states start on a bucket multiple and stay positive.
    // Thus state % count == (state - base) % count. Keep the general path
    // for callers with wrapping/unaligned domains (including oracle tests).
    if (positive_targets_ && state_base_ % bucket_count_ == 0U) {
        assembler_->Emit({static_cast<std::uint16_t>(0xdcU | (selector << 8U)),
            static_cast<std::uint16_t>(state | (static_cast<std::uint16_t>(bucket_count_) << 8U))});
    } else {
        assembler_->EmitConst32(selector, state_base_);
        assembler_->Emit({static_cast<std::uint16_t>(0x91U | (selector << 8U)),
            static_cast<std::uint16_t>(state | (selector << 8U)),
            static_cast<std::uint16_t>(0xdcU | (selector << 8U)),
            static_cast<std::uint16_t>(selector | (static_cast<std::uint16_t>(bucket_count_) << 8U))});
    }
    assembler_->EmitConst32(temporary, bucket_base_);
    assembler_->Emit({static_cast<std::uint16_t>(0x90U | (selector << 8U)),
        static_cast<std::uint16_t>(selector | (temporary << 8U))});
    if (multi_state_) {
        CffJointToken(*assembler_, joint_mask_, cached_joint_mask_).Emit(joint, state, selector);
    }
    if (!fallthrough_to_dispatcher) assembler_->EmitGoto32(dispatcher_);
}

} // namespace birch::guard::detail
