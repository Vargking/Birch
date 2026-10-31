#include "birch/dex/liveness.h"

#include <algorithm>
#include <array>
#include <map>
#include <stdexcept>

namespace birch::dex {
namespace {
using Bits = std::vector<bool>;
using Effects = InstructionRegisterEffects;

Effects DecodeEffects(const IrInstruction& ins, std::size_t count) {
    Effects e{Bits(count), Bits(count)};
    const auto mark = [count](Bits& bits, std::size_t reg, bool wide = false) {
        if (reg >= count || (wide && reg + 1U >= count))
            throw std::runtime_error("liveness operand outside register file");
        bits[reg] = true;
        if (wide) bits[reg + 1U] = true;
    };
    const auto read = [&](std::size_t reg, bool wide = false) { mark(e.reads, reg, wide); };
    const auto write = [&](std::size_t reg, bool wide = false) { mark(e.writes, reg, wide); };
    const auto op = ins.dex_opcode;
    const auto first = ins.encoded.at(0U);
    const auto a8 = static_cast<unsigned>(first >> 8U);
    const auto a4 = a8 & 15U;
    const auto b4 = static_cast<unsigned>(first >> 12U);
    const auto pair = ins.encoded.size() > 1U ? ins.encoded[1U] : 0U;
    const auto b8 = pair & 255U;
    const auto c8 = pair >> 8U;
    if (op == 0U || op == 0x0eU || (op >= 0x28U && op <= 0x2aU)) return e;
    if (op >= 1U && op <= 9U) {
        auto dst = static_cast<unsigned>(a4), src = static_cast<unsigned>(b4);
        const auto form = (op - 1U) % 3U;
        if (form == 1U) { dst = a8; src = ins.encoded.at(1U); }
        if (form == 2U) { dst = ins.encoded.at(1U); src = ins.encoded.at(2U); }
        const bool wide = op >= 4U && op <= 6U;
        read(src, wide); write(dst, wide); return e;
    }
    if (op >= 0x0aU && op <= 0x0dU) { write(a8, op == 0x0bU); return e; }
    if (op >= 0x0fU && op <= 0x11U) { read(a8, op == 0x10U); return e; }
    if (op >= 0x12U && op <= 0x1cU) {
        write(op == 0x12U ? a4 : a8, op >= 0x16U && op <= 0x19U); return e;
    }
    if (op == 0x1dU || op == 0x1eU || op == 0x26U || op == 0x27U ||
        op == 0x2bU || op == 0x2cU || (op >= 0x38U && op <= 0x3dU)) {
        read(a8); return e;
    }
    if (op == 0x1fU) { read(a8); write(a8); return e; }
    if (op == 0x20U || op == 0x21U || op == 0x23U) { read(b4); write(a4); return e; }
    if (op == 0x22U || op == 0xfeU || op == 0xffU) { write(a8); return e; }
    if (op == 0x24U || (op >= 0x6eU && op <= 0x72U) || op == 0xfaU || op == 0xfcU) {
        const auto size = b4;
        // 35c/45cc register words are in the third code unit, not the index.
        const auto packed = ins.encoded.at(2U);
        const std::array<unsigned, 5U> args{static_cast<unsigned>(packed & 15U),
            static_cast<unsigned>((packed >> 4U) & 15U),
            static_cast<unsigned>((packed >> 8U) & 15U),
            static_cast<unsigned>(packed >> 12U), static_cast<unsigned>(a4)};
        if (size > args.size()) throw std::runtime_error("invalid invoke word count");
        for (unsigned i = 0; i < size; ++i) read(args[i]);
        return e;
    }
    if (op == 0x25U || (op >= 0x74U && op <= 0x78U) || op == 0xfbU || op == 0xfdU) {
        for (unsigned i = 0; i < a8; ++i) read(ins.encoded.at(2U) + i);
        return e;
    }
    if (op >= 0x2dU && op <= 0x31U) {
        read(b8, op >= 0x2fU); read(c8, op >= 0x2fU); write(a8); return e;
    }
    if (op >= 0x32U && op <= 0x37U) { read(a4); read(b4); return e; }
    if (op >= 0x44U && op <= 0x51U) {
        read(b8); read(c8);
        if (op <= 0x4aU) write(a8, op == 0x45U);
        else read(a8, op == 0x4cU);
        return e;
    }
    if (op >= 0x52U && op <= 0x6dU) {
        const bool instance = op <= 0x5fU;
        const bool put = (op >= 0x59U && op <= 0x5fU) || op >= 0x67U;
        const bool wide = op == 0x53U || op == 0x5aU || op == 0x61U || op == 0x68U;
        if (instance) read(b4);
        if (put) read(instance ? a4 : a8, wide); else write(instance ? a4 : a8, wide);
        return e;
    }
    if (op >= 0x7bU && op <= 0x8fU) {
        const bool wide_in = op == 0x7dU || op == 0x7eU || op == 0x80U ||
            (op >= 0x84U && op <= 0x86U) || (op >= 0x8aU && op <= 0x8cU);
        const bool wide_out = op == 0x7dU || op == 0x7eU || op == 0x80U ||
            op == 0x81U || op == 0x83U || op == 0x86U || op == 0x88U ||
            op == 0x89U || op == 0x8bU;
        read(b4, wide_in); write(a4, wide_out); return e;
    }
    if (op >= 0x90U && op <= 0xcfU) {
        const auto normalized = op >= 0xb0U ? op - 0x20U : op;
        const bool wide = (normalized >= 0x9bU && normalized <= 0xa5U) || normalized >= 0xabU;
        const bool shift = normalized >= 0xa3U && normalized <= 0xa5U;
        const auto dest = op >= 0xb0U ? a4 : a8;
        read(op >= 0xb0U ? a4 : b8, wide);
        read(op >= 0xb0U ? b4 : c8, wide && !shift);
        write(dest, wide); return e;
    }
    if (op >= 0xd0U && op <= 0xe2U) {
        read(op <= 0xd7U ? b4 : b8); write(op <= 0xd7U ? a4 : a8); return e;
    }
    std::fill(e.reads.begin(), e.reads.end(), true);
    e.complete = false;
    return e;
}

void Union(Bits& into, const Bits& from) {
    for (std::size_t i = 0; i < into.size(); ++i) into[i] = into[i] || from[i];
}
} // namespace

InstructionRegisterEffects AnalyzeRegisterEffects(
    const IrInstruction& instruction, std::size_t register_count) {
    return DecodeEffects(instruction, register_count);
}

MethodLiveness::MethodLiveness(const MethodIr& ir, std::span<const BlockId> exit_owners)
    : live_out_(ir.blocks().size()), live_in_(ir.blocks().size()) {
    const auto count = ir.code().registers_size;
    if (!exit_owners.empty() && exit_owners.size() != ir.blocks().size())
        throw std::invalid_argument("liveness exit owner count mismatch");
    std::vector<std::vector<BlockId>> successors(ir.blocks().size());
    const auto owner = [&](BlockId id) { return exit_owners.empty() ? id : exit_owners[id]; };
    for (const auto& block : ir.blocks()) {
        auto& targets = successors.at(owner(block.id));
        for (const auto& edge : block.successors)
            if (edge.kind != IrEdgeKind::Exception &&
                std::find(targets.begin(), targets.end(), edge.target) == targets.end())
                targets.push_back(edge.target);
    }
    std::vector<Bits> in(ir.blocks().size(), Bits(count)), out = in;
    std::vector<std::vector<Effects>> effects(ir.blocks().size());
    std::map<std::uint32_t, BlockId> starts;
    for (const auto& block : ir.blocks()) {
        starts.emplace(block.start_offset, block.id);
        for (const auto& ins : block.instructions) effects[block.id].push_back(DecodeEffects(ins, count));
    }
    bool changed;
    do {
        changed = false;
        for (auto it = ir.blocks().rbegin(); it != ir.blocks().rend(); ++it) {
            const auto& block = *it;
            Bits next(count);
            for (const auto target : successors.at(owner(block.id))) Union(next, in.at(target));
            auto current = next;
            for (auto i = block.instructions.size(); i-- > 0U;) {
                const auto& ins = block.instructions[i];
                const auto& effect = effects[block.id][i];
                for (std::size_t r = 0; r < count; ++r)
                    current[r] = effect.reads[r] || (current[r] && !effect.writes[r]);
                // A throwing instruction has not committed its destination
                // on the exceptional edge: union handler inputs AFTER kills.
                if (ins.can_throw) for (const auto& region : ir.code().tries) {
                    if (ins.dex_offset < region.start_address ||
                        ins.dex_offset - region.start_address >= region.instruction_count) continue;
                    for (const auto& handler : region.handlers) Union(current, in.at(starts.at(handler.address)));
                }
            }
            if (current != in[block.id] || next != out[block.id]) {
                in[block.id] = std::move(current); out[block.id] = std::move(next); changed = true;
            }
        }
    } while (changed);
    for (const auto& block : ir.blocks()) for (std::uint32_t r = 0; r < count; ++r) {
        if (out[block.id][r]) live_out_[block.id].push_back(static_cast<std::uint16_t>(r));
        if (in[block.id][r]) live_in_[block.id].push_back(static_cast<std::uint16_t>(r));
    }
}
} // namespace birch::dex
