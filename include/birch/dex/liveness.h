#pragma once

#include "birch/dex/ir.h"

#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>

namespace birch::dex {

struct InstructionRegisterEffects {
    std::vector<bool> reads;
    std::vector<bool> writes;
    bool complete{true};
};

// Shared operand decoder. Unknown instructions read every word and report an
// incomplete result, so transformation clients must not speculate about kills.
[[nodiscard]] InstructionRegisterEffects AnalyzeRegisterEffects(
    const IrInstruction& instruction, std::size_t register_count);

// Register words that can be read before being overwritten on a continuation
// from a block exit. Exceptional continuations use the pre-instruction state.
// Unrecognized opcodes conservatively read the entire register file.
class MethodLiveness final {
public:
    // Shared exits expose every normal successor of their owner group to the
    // verifier. Analyze that expanded graph, not just the original CFG.
    explicit MethodLiveness(const MethodIr& ir,
                            std::span<const BlockId> exit_owners = {});
    [[nodiscard]] const std::vector<std::uint16_t>& LiveOut(BlockId block) const {
        return live_out_.at(block);
    }
    [[nodiscard]] const std::vector<std::uint16_t>& LiveIn(BlockId block) const {
        return live_in_.at(block);
    }

private:
    std::vector<std::vector<std::uint16_t>> live_out_;
    std::vector<std::vector<std::uint16_t>> live_in_;
};

} // namespace birch::dex
