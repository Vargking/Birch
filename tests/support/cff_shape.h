#pragma once

#include "birch/dex/ir.h"

#include <algorithm>
#include <map>
#include <optional>

namespace birch::test {
struct CffShape {
    std::size_t empty_gotos{};
    std::size_t max_empty_fan_in{};
    std::size_t max_empty_run{};
    std::size_t switches{};
    std::size_t largest_switch{};
};

inline CffShape MeasureCffShape(const dex::MethodIr& ir) {
    CffShape shape;
    std::map<dex::BlockId, std::size_t> fan_in;
    std::optional<dex::BlockId> previous;
    std::size_t run = 0;
    for (const auto& block : ir.blocks()) {
        if (block.instructions.size() == 1U && block.successors.size() == 1U &&
            block.instructions.front().dex_opcode >= 0x28U &&
            block.instructions.front().dex_opcode <= 0x2aU) {
            const auto target = block.successors.front().target;
            ++shape.empty_gotos;
            shape.max_empty_fan_in = std::max(shape.max_empty_fan_in, ++fan_in[target]);
            run = previous == target ? run + 1U : 1U;
            previous = target;
            shape.max_empty_run = std::max(shape.max_empty_run, run);
        } else {
            previous.reset();
            run = 0;
        }
    }
    for (const auto& instruction : ir.code().instructions)
        if (instruction.kind == dex::InstructionKind::Switch) {
            ++shape.switches;
            shape.largest_switch = std::max(shape.largest_switch, instruction.targets.size());
        }
    return shape;
}
} // namespace birch::test
