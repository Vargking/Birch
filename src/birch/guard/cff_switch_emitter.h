#pragma once

#include "cff_assembler.h"

namespace birch::guard::detail {

// Owns dispatcher sorting, DEX payload encoding and relocation. The flattener
// only chooses control-flow policy; it does not patch switch words itself.
class CffSwitchEmitter final {
public:
    CffSwitchEmitter(CffAssembler& assembler, CffAssembler::Label invalid_target);
    void Emit(std::uint16_t reg, std::vector<std::uint32_t> keys,
              std::vector<CffAssembler::Label> targets, bool prefer_packed,
              std::optional<CffAssembler::Label> invalid_target = std::nullopt,
              bool inline_default = false);
    void EmitPayloads(std::uint16_t scratch_register);
    [[nodiscard]] std::size_t PlannedPayloadEnd(std::size_t start, std::uint16_t scratch_register) const;
    void PatchPayloads(std::vector<std::uint16_t>& units) const;
    [[nodiscard]] bool used_sparse() const noexcept { return used_sparse_; }
    [[nodiscard]] bool used_packed() const noexcept { return used_packed_; }

private:
    struct Payload {
        std::size_t instruction_offset;
        bool packed;
        std::vector<std::uint32_t> keys;
        std::vector<CffAssembler::Label> targets;
        std::optional<std::size_t> offset;
    };
    CffAssembler* assembler_;
    CffAssembler::Label invalid_target_;
    std::vector<Payload> payloads_;
    bool used_sparse_{};
    bool used_packed_{};
    bool payloads_emitted_{};
};

} // namespace birch::guard::detail
