#include "birch/dex/ir.h"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>

namespace birch::dex {
namespace {

bool IsTerminator(InstructionKind kind) {
    return kind == InstructionKind::ConditionalBranch ||
           kind == InstructionKind::UnconditionalBranch ||
           kind == InstructionKind::Switch || kind == InstructionKind::Return ||
           kind == InstructionKind::Throw;
}

void AddEdge(IrBasicBlock& block, BlockId target, IrEdgeKind kind,
             std::optional<std::uint32_t> catch_type = std::nullopt) {
    const auto duplicate = std::find_if(block.successors.begin(), block.successors.end(),
        [&](const IrEdge& edge) {
            return edge.target == target && edge.kind == kind &&
                   edge.catch_type_idx == catch_type;
        });
    if (duplicate == block.successors.end()) {
        block.successors.push_back({target, kind, catch_type});
    }
}

} // namespace

MethodIr BuildMethodIr(CodeItem code) {
    MethodIr result;
    result.code_ = std::move(code);
    if (result.code_.instructions.empty()) {
        return result;
    }

    std::map<std::uint32_t, const DecodedInstruction*> executable;
    for (const auto& instruction : result.code_.instructions) {
        if (instruction.kind != InstructionKind::Payload) {
            executable.emplace(instruction.offset, &instruction);
        }
    }
    if (executable.empty()) {
        throw DexParseError(DexErrorCode::InvalidClassData, result.code_.file_offset,
                            "code item has no executable instructions");
    }

    std::set<std::uint32_t> leaders{executable.begin()->first};
    for (const auto& [offset, instruction] : executable) {
        for (const auto target : instruction->targets) {
            leaders.insert(target);
        }
        if (IsTerminator(instruction->kind)) {
            const auto next = executable.upper_bound(offset);
            if (next != executable.end()) {
                leaders.insert(next->first);
            }
        }
    }
    for (const auto& region : result.code_.tries) {
        if (executable.contains(region.start_address)) {
            leaders.insert(region.start_address);
        }
        const auto end = region.start_address + region.instruction_count;
        if (executable.contains(end)) {
            leaders.insert(end);
        }
        for (const auto& handler : region.handlers) {
            leaders.insert(handler.address);
        }
    }
    for (auto it = result.code_.instructions.begin(); it != result.code_.instructions.end(); ++it) {
        if (it->kind != InstructionKind::Payload) {
            continue;
        }
        const auto after = it->offset + it->width;
        if (executable.contains(after)) {
            leaders.insert(after);
        }
    }

    std::map<std::uint32_t, BlockId> block_by_offset;
    for (const auto leader : leaders) {
        if (!executable.contains(leader)) {
            throw DexParseError(DexErrorCode::InvalidClassData, result.code_.file_offset,
                                "CFG leader is not executable");
        }
        const auto id = static_cast<BlockId>(result.blocks_.size());
        block_by_offset.emplace(leader, id);
        result.blocks_.push_back({id, leader, {}, {}});
    }
    result.entry_ = block_by_offset.at(executable.begin()->first);

    auto current = result.blocks_.begin();
    for (const auto& instruction : result.code_.instructions) {
        if (instruction.kind == InstructionKind::Payload) {
            continue;
        }
        while (std::next(current) != result.blocks_.end() &&
               instruction.offset >= std::next(current)->start_offset) {
            ++current;
        }
        current->instructions.push_back({instruction.offset, instruction.opcode,
                                         instruction.code_units, instruction.can_throw});
    }

    std::map<std::uint32_t, const DecodedInstruction*> decoded_by_offset;
    for (const auto& instruction : result.code_.instructions) {
        if (instruction.kind != InstructionKind::Payload) {
            decoded_by_offset.emplace(instruction.offset, &instruction);
        }
    }
    for (auto& block : result.blocks_) {
        if (block.instructions.empty()) {
            throw DexParseError(DexErrorCode::InvalidClassData, result.code_.file_offset,
                                "empty CFG block");
        }
        const auto& last_ir = block.instructions.back();
        const auto* last = decoded_by_offset.at(last_ir.dex_offset);
        for (const auto target : last->targets) {
            AddEdge(block, block_by_offset.at(target),
                    last->kind == InstructionKind::Switch ? IrEdgeKind::SwitchCase
                                                          : IrEdgeKind::Branch);
        }
        if (last->kind != InstructionKind::UnconditionalBranch &&
            last->kind != InstructionKind::Return && last->kind != InstructionKind::Throw) {
            const auto next_offset = last->offset + last->width;
            const auto next = block_by_offset.find(next_offset);
            if (next != block_by_offset.end()) {
                AddEdge(block, next->second, IrEdgeKind::Fallthrough);
            } else if (next_offset < result.code_.insns.size()) {
                const auto next_executable = executable.lower_bound(next_offset);
                if (next_executable != executable.end() && next_executable->first == next_offset) {
                    AddEdge(block, block_by_offset.at(next_executable->first),
                            IrEdgeKind::Fallthrough);
                }
            }
        }
        for (const auto& region : result.code_.tries) {
            const auto region_end = region.start_address + region.instruction_count;
            const bool has_throwing_instruction = std::any_of(
                block.instructions.begin(), block.instructions.end(),
                [&](const IrInstruction& instruction) {
                    return instruction.can_throw && instruction.dex_offset >= region.start_address &&
                           instruction.dex_offset < region_end;
                });
            if (!has_throwing_instruction) {
                continue;
            }
            for (const auto& handler : region.handlers) {
                AddEdge(block, block_by_offset.at(handler.address), IrEdgeKind::Exception,
                        handler.type_idx);
            }
        }
    }
    return result;
}

} // namespace birch::dex
