#include "region_replacement.h"
#include "birch/dex/region_exception_contract.h"

#include <algorithm>
#include <stdexcept>

namespace birch::dex::detail {
std::set<std::uint32_t> PrepareOutlineReplacements(const CodeItem& code, CodePrefix& prefix) {
    std::set<std::uint32_t> erased;
    if (prefix.outline_span_ends.empty()) return erased;
    if (prefix.reorder_blocks || prefix.replacement_code_units)
        throw std::invalid_argument("outline spans cannot be combined with a different layout");
    for (const auto& [start, end] : prefix.outline_span_ends)
        for (const auto& [other_start, other_end] : prefix.arithmetic_span_ends)
            if (start < other_end && other_start < end)
                throw std::invalid_argument("overlapping arithmetic and outline replacements");
    std::uint32_t previous_end{};
    for (const auto& [start, end] : prefix.outline_span_ends) {
        const auto at = [&](std::uint32_t offset) {
            return std::lower_bound(code.instructions.begin(), code.instructions.end(), offset,
                [](const auto& instruction, auto value) { return instruction.offset < value; });
        };
        const auto first = at(start), last = at(end);
        if (start < previous_end || end <= start || first == code.instructions.end() ||
            last == code.instructions.end() || first->offset != start || last->offset != end ||
            !prefix.linear_replacements.contains(start) || prefix.linear_replacements.at(start).empty() ||
            (first->opcode >= 0x0aU && first->opcode <= 0x0dU) ||
            (last->opcode >= 0x0aU && last->opcode <= 0x0cU))
            throw std::invalid_argument("invalid outline replacement boundary");
        previous_end = end;
        if (!RegionExceptionContract::Prove(code, start, end))
            throw std::invalid_argument("outline replacement crosses an exception boundary or handler");
        for (const auto& instruction : code.instructions) {
            const bool inside = instruction.offset >= start && instruction.offset < end;
            if (inside && (instruction.opcode == 0x1dU || instruction.opcode == 0x1eU ||
                instruction.opcode == 0x0dU))
                throw std::invalid_argument("outline replacement contains a monitor or exception entry");
            if (inside && instruction.kind != InstructionKind::Normal &&
                instruction.kind != InstructionKind::ConditionalBranch &&
                instruction.kind != InstructionKind::UnconditionalBranch)
                throw std::invalid_argument("unsupported instruction in outline replacement");
            for (auto target : instruction.targets) {
                if ((!inside && target > start && target < end) ||
                    (inside && (target < start || target > end)))
                    throw std::invalid_argument("outline replacement crosses a CFG boundary");
            }
        }
        for (auto instruction = std::next(first); instruction != last; ++instruction) {
            if (prefix.linear_replacements.contains(instruction->offset) ||
                prefix.arithmetic_span_ends.contains(instruction->offset))
                throw std::invalid_argument("overlapping outline replacement");
            erased.insert(instruction->offset);
            prefix.linear_replacements.emplace(instruction->offset, std::vector<std::uint16_t>{});
        }
    }
    return erased;
}
}
