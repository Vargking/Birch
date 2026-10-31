#pragma once

#include "cff_assembler.h"

#include <cstdint>
#include <optional>

namespace birch::guard::detail {

// One keyed tail per exact verifier domain, never a method-wide merge hub.
// Every edge still passes through the callback, runtime barrier and joint
// token check. Only their identical instruction sequences are shared.
class CffTransitionEncoder final {
public:
    struct Registers {
        std::uint16_t state;
        std::uint16_t selector;
        std::uint16_t joint;
        std::uint16_t temporary;
    };
    CffTransitionEncoder(CffAssembler& assembler, Registers registers,
                         std::uint32_t state_base, std::uint32_t bucket_base,
                         std::uint8_t bucket_count, std::uint32_t joint_mask,
                         bool multi_state, CffAssembler::Label dispatcher,
                         CffAssembler::Label invalid, std::uint64_t salt,
                         std::optional<std::uint16_t> barrier,
                         std::optional<std::uint16_t> callback,
                         std::optional<std::uint16_t> cached_joint_mask = std::nullopt);

    void Emit(std::uint32_t target);
    void Bind(bool fallthrough_to_dispatcher = false);

private:
    CffAssembler* assembler_;
    Registers registers_;
    std::uint32_t state_base_;
    std::uint32_t bucket_base_;
    std::uint32_t joint_mask_;
    std::uint8_t bucket_count_;
    std::uint8_t xor_key_;
    std::uint8_t add_key_;
    bool multi_state_;
    bool used_{};
    bool positive_targets_{true};
    CffAssembler::Label tail_;
    CffAssembler::Label dispatcher_;
    CffAssembler::Label invalid_;
    std::optional<std::uint16_t> barrier_;
    std::optional<std::uint16_t> callback_;
    std::optional<std::uint16_t> cached_joint_mask_;
};

} // namespace birch::guard::detail
