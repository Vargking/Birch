#include "birch/dex/monitor_depth.h"

#include <deque>
#include <limits>

namespace birch::dex {

MethodMonitorDepth::MethodMonitorDepth(const MethodIr& ir) {
    if (ir.blocks().empty()) return;
    struct State {
        bool reached{};
        std::optional<std::uint32_t> depth;
    };
    std::vector<State> incoming(ir.blocks().size());
    std::vector<bool> queued(ir.blocks().size());
    std::deque<BlockId> pending;
    std::map<std::uint32_t, BlockId> blocks;
    for (const auto& block : ir.blocks()) blocks.emplace(block.start_offset, block.id);
    const auto merge = [&](BlockId target, std::optional<std::uint32_t> depth) {
        auto& state = incoming.at(target);
        if (state.reached && state.depth == depth) return;
        if (state.reached) {
            if (!state.depth) return; // unknown is the lattice top
            state.depth.reset();
        } else state = {true, depth};
        if (!queued.at(target)) {
            pending.push_back(target);
            queued[target] = true;
        }
    };
    merge(ir.entry(), 0U);
    while (!pending.empty()) {
        const auto id = pending.front();
        pending.pop_front();
        queued[id] = false;
        auto depth = incoming[id].depth;
        const auto& block = ir.blocks().at(id);
        for (const auto& ins : block.instructions) {
            before_[ins.dex_offset] = depth;
            const auto prior = depth;
            if (ins.dex_opcode == 0x1dU && depth) {
                if (*depth == std::numeric_limits<std::uint32_t>::max()) depth.reset();
                else ++*depth;
            } else if (ins.dex_opcode == 0x1eU && depth) {
                if (*depth == 0U) depth.reset();
                else --*depth;
            }
            if (ins.can_throw) for (const auto& region : ir.code().tries) {
                if (ins.dex_offset < region.start_address ||
                    ins.dex_offset - region.start_address >= region.instruction_count) continue;
                for (const auto& handler : region.handlers) {
                    merge(blocks.at(handler.address), prior);
                    // A failed monitor-exit cannot prove the lock was released.
                    // Include both interpretations instead of assuming balance.
                    if (ins.dex_opcode == 0x1eU) merge(blocks.at(handler.address), depth);
                }
            }
        }
        for (const auto& edge : block.successors)
            if (edge.kind != IrEdgeKind::Exception) merge(edge.target, depth);
    }
}

bool MethodMonitorDepth::DefinitelyEmpty(std::uint32_t offset) const {
    const auto found = before_.find(offset);
    return found != before_.end() && found->second && *found->second == 0U;
}

} // namespace birch::dex
