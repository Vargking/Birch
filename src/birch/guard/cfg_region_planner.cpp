#include "cfg_region_planner.h"
#include "birch/dex/region_exception_contract.h"
#include "birch/dex/monitor_depth.h"

#include <algorithm>
#include <deque>
#include <map>
#include <stdexcept>

namespace birch::guard::detail {
namespace {
using Bits = std::vector<bool>;
bool Movable(const dex::DecodedInstruction& ins) {
    if (ins.kind != dex::InstructionKind::Normal &&
        ins.kind != dex::InstructionKind::ConditionalBranch &&
        ins.kind != dex::InstructionKind::UnconditionalBranch) return false;
    return ins.opcode != 0x1dU && ins.opcode != 0x1eU && ins.opcode != 0x0dU &&
        ins.opcode != 0x26U && ins.opcode != 0x6fU && ins.opcode != 0x75U && ins.opcode < 0xfaU;
}
std::optional<RegionValue> Value(std::uint16_t reg, const dex::RegisterTypeFrame& frame) {
    const auto& type = frame.at(reg);
    if (type.uninitialized) return std::nullopt;
    RegionValue value{reg, {}, type.constant32};
    switch (type.kind) {
        case dex::RegisterTypeKind::Scalar32:
            if (!type.constant32) return std::nullopt;
            break; // preserve raw const, including polymorphic zero
        case dex::RegisterTypeKind::Int32: value.descriptor = "I"; break;
        case dex::RegisterTypeKind::Float32: value.descriptor = "F"; break;
        case dex::RegisterTypeKind::Reference:
            if (type.descriptor.empty()) return std::nullopt;
            value.descriptor = type.descriptor; break;
        case dex::RegisterTypeKind::LongLow: value.descriptor = "J"; break;
        case dex::RegisterTypeKind::DoubleLow: value.descriptor = "D"; break;
        default: return std::nullopt;
    }
    if (value.words() == 2U && (reg + 1U >= frame.size() ||
        frame[reg + 1U].kind != dex::RegisterTypeKind::WideHigh)) return std::nullopt;
    return value;
}

bool PreservesHandlerType(const dex::RegisterTypeSnapshot& input,
                          const dex::RegisterTypeSnapshot& handler) {
    using Kind = dex::RegisterTypeKind;
    if (input.uninitialized || handler.uninitialized ||
        input.kind == Kind::Unusable || handler.kind == Kind::Unusable) return false;
    if (input.kind == handler.kind) {
        if (input.descriptor != handler.descriptor) return false;
        // Zero is verifier-polymorphic; a nonzero scalar must not enter a
        // handler that relies on a zero/null value from all original throws.
        return input.kind != Kind::Scalar32 || handler.constant32 != 0U || input.constant32 == 0U;
    }
    if (input.kind != Kind::Scalar32 || !input.constant32) return false;
    return handler.kind == Kind::Int32 || handler.kind == Kind::Float32 ||
        (handler.kind == Kind::Reference && *input.constant32 == 0U);
}

class Analysis final {
public:
    const dex::CodeItem& code;
    const GuardConfig& config;
    dex::MethodTypeAnalysis types;
    std::vector<dex::InstructionRegisterEffects> effects;
    std::vector<Bits> live_before;
    std::vector<std::vector<std::size_t>> successors, predecessors;
    std::map<std::uint32_t, Bits> handler_inputs;
    dex::MethodMonitorDepth monitors;

    Analysis(const dex::DexFile& file, const dex::DexEncodedMethod& method,
             const dex::CodeItem& input, const GuardConfig& cfg)
        : code(input), config(cfg), monitors(dex::BuildMethodIr(input)) {
        const auto ir = dex::BuildMethodIr(code);
        const dex::MethodLiveness liveness(ir);
        std::map<std::uint32_t, std::size_t> indices;
        std::vector<std::uint32_t> offsets;
        for (std::size_t i = 0; i < code.instructions.size(); ++i) {
            const auto& ins = code.instructions[i];
            indices.emplace(ins.offset, i);
            if (ins.kind != dex::InstructionKind::Payload) offsets.push_back(ins.offset);
            effects.push_back(dex::AnalyzeRegisterEffects({ins.offset, ins.opcode, ins.code_units, ins.can_throw}, code.registers_size));
        }
        dex::MethodTypeAnalysisOptions options;
        options.capture_exit_offsets = offsets;
        options.capture_type_snapshots = true;
        types = dex::AnalyzeMethodTypes(file, method, code, options);
        live_before.assign(code.instructions.size(), Bits(code.registers_size));
        std::map<std::uint32_t, dex::BlockId> blocks;
        for (const auto& block : ir.blocks()) blocks.emplace(block.start_offset, block.id);
        for (const auto& region : code.tries) for (const auto& handler : region.handlers) {
            auto& inputs = handler_inputs.try_emplace(handler.address, code.registers_size, false).first->second;
            for (auto reg : liveness.LiveIn(blocks.at(handler.address))) inputs[reg] = true;
        }
        for (const auto& block : ir.blocks()) {
            Bits live(code.registers_size);
            for (auto reg : liveness.LiveOut(block.id)) live[reg] = true;
            for (auto i = block.instructions.size(); i-- > 0U;) {
                const auto index = indices.at(block.instructions[i].dex_offset);
                for (std::size_t reg = 0; reg < live.size(); ++reg)
                    live[reg] = effects[index].reads[reg] || (live[reg] && !effects[index].writes[reg]);
                // Exceptional successors see pre-instruction registers, not
                // the uncommitted destination of a throwing instruction.
                if (block.instructions[i].can_throw) for (const auto& region : code.tries) {
                    const auto offset = block.instructions[i].dex_offset;
                    if (offset < region.start_address || offset - region.start_address >= region.instruction_count) continue;
                    for (const auto& handler : region.handlers)
                        for (std::size_t reg = 0; reg < live.size(); ++reg)
                            live[reg] = live[reg] || handler_inputs.at(handler.address)[reg];
                }
                live_before[index] = live;
            }
        }
        successors.resize(code.instructions.size());
        predecessors.resize(code.instructions.size());
        for (std::size_t i = 0; i < code.instructions.size(); ++i) {
            const auto& ins = code.instructions[i];
            for (auto target : ins.targets) if (indices.contains(target)) successors[i].push_back(indices.at(target));
            if (ins.kind != dex::InstructionKind::Payload && ins.kind != dex::InstructionKind::Return &&
                ins.kind != dex::InstructionKind::Throw && ins.kind != dex::InstructionKind::UnconditionalBranch &&
                i + 1U < code.instructions.size() && code.instructions[i + 1U].kind != dex::InstructionKind::Payload)
                successors[i].push_back(i + 1U);
            for (auto next : successors[i]) predecessors[next].push_back(i);
        }
    }

    std::optional<CfgRegion> Try(std::size_t first, std::size_t end) const {
        const auto start_offset = code.instructions[first].offset, end_offset = code.instructions[end].offset;
        if ((code.instructions[first].opcode >= 0x0aU && code.instructions[first].opcode <= 0x0cU) ||
            (code.instructions[end].opcode >= 0x0aU && code.instructions[end].opcode <= 0x0cU)) return std::nullopt;
        const auto exception_contract = dex::RegionExceptionContract::Prove(code, start_offset, end_offset);
        if (!exception_contract) return std::nullopt;
        // Even a region containing only arithmetic becomes throwable when
        // replaced by invoke-static. If a monitor may be held, retain a
        // catch-all in the caller; a typed catch is not a general unlock path.
        if (!monitors.DefinitelyEmpty(start_offset) && !exception_contract->catches_all()) return std::nullopt;
        Bits writes(code.registers_size);
        bool has_exit = false;
        for (auto i = first; i < end; ++i) {
            if (!Movable(code.instructions[i]) || !effects[i].complete) return std::nullopt;
            for (auto pred : predecessors[i]) if (i != first && (pred < first || pred >= end)) return std::nullopt;
            for (auto next : successors[i]) {
                if (next < first || next > end) return std::nullopt;
                has_exit = has_exit || next == end;
            }
            for (std::size_t reg = 0; reg < writes.size(); ++reg) writes[reg] = writes[reg] || effects[i].writes[reg];
        }
        if (!has_exit) return std::nullopt;
        // The caller retains the monitor stack; no monitor instruction moves.
        // A throw in the helper returns directly to the original caller catch.
        // That catch must not observe any local write hidden in the helper,
        // including its monitor identity and writes before a later throw.
        for (auto handler : exception_contract->handlers())
            for (std::size_t reg = 0; reg < writes.size(); ++reg)
                if (writes[reg] && handler_inputs.at(handler)[reg]) return std::nullopt;
        const auto entry = types.entry_register_types.find(start_offset), exit = types.entry_register_types.find(end_offset);
        if (entry == types.entry_register_types.end() || exit == types.entry_register_types.end()) return std::nullopt;
        // invoke-static adds an exceptional edge at the region ENTRY, even
        // when every moved instruction is nonthrowing. A handler local may
        // only acquire its original type later, outside this region. Checking
        // hidden writes alone would miss undefined/incompatible entry values.
        for (auto handler : exception_contract->handlers()) {
            const auto frame = types.entry_register_types.find(handler);
            if (frame == types.entry_register_types.end()) return std::nullopt;
            for (std::size_t reg = 0; reg < writes.size(); ++reg)
                if (handler_inputs.at(handler)[reg] &&
                    !PreservesHandlerType(entry->second.at(reg), frame->second.at(reg))) return std::nullopt;
        }
        CfgRegion result;
        result.first = first; result.end = end;
        result.start_offset = start_offset; result.end_offset = end_offset;
        for (std::uint16_t reg = 0; reg < writes.size(); ++reg) {
            if (!writes[reg] || !live_before[end][reg]) continue;
            auto value = Value(reg, exit->second);
            if (!value) return std::nullopt;
            if (value->constant32) result.constant_outputs.push_back(*value);
            else {
                if (result.output) return std::nullopt;
                result.output = *value;
            }
            if (value->words() == 2U) {
                if (!writes[reg + 1U] || !live_before[end][reg + 1U]) return std::nullopt;
                ++reg;
            }
        }
        // Region-local definite assignment is a CFG intersection, not a
        // textual scan. A value defined on one arm is still an input on the
        // other arm, and a loop cannot invent an initialized entry value.
        std::vector<Bits> before(end - first, Bits(code.registers_size, true));
        std::vector<bool> reached(end - first), queued(end - first);
        before[0] = Bits(code.registers_size);
        reached[0] = queued[0] = true;
        std::deque<std::size_t> pending{first};
        while (!pending.empty()) {
            const auto i = pending.front(); pending.pop_front(); queued[i - first] = false;
            auto after = before[i - first];
            for (std::size_t reg = 0; reg < after.size(); ++reg) after[reg] = after[reg] || effects[i].writes[reg];
            for (auto next : successors[i]) {
                if (next == end || next == first) continue;
                auto merged = reached[next - first] ? before[next - first] : after;
                if (reached[next - first])
                    for (std::size_t reg = 0; reg < merged.size(); ++reg) merged[reg] = merged[reg] && after[reg];
                if (!reached[next - first] || merged != before[next - first]) {
                    reached[next - first] = true; before[next - first] = std::move(merged);
                    if (!queued[next - first]) { queued[next - first] = true; pending.push_back(next); }
                }
            }
        }
        if (std::find(reached.begin(), reached.end(), false) != reached.end()) return std::nullopt;
        Bits inputs(code.registers_size);
        for (auto i = first; i < end; ++i)
            for (std::size_t reg = 0; reg < inputs.size(); ++reg)
                inputs[reg] = inputs[reg] || (effects[i].reads[reg] && !before[i - first][reg]);
        // A conditional write followed by a returned live value implicitly
        // reads the entry value on every non-writing exit. The helper return
        // is a new consumer even when the original region never read it.
        if (result.output) {
            for (auto i = first; i < end; ++i) {
                if (std::find(successors[i].begin(), successors[i].end(), end) == successors[i].end()) continue;
                for (unsigned word = 0; word < result.output->words(); ++word) {
                    const auto reg = result.output->reg + word;
                    if (!before[i - first][reg] && !effects[i].writes[reg]) inputs[reg] = true;
                }
            }
        }
        for (std::uint16_t reg = 0; reg < inputs.size(); ++reg) {
            if (!inputs[reg]) continue;
            auto value = Value(reg, entry->second);
            if (!value) return std::nullopt;
            if (!value->constant32) result.argument_words = static_cast<std::uint16_t>(result.argument_words + value->words());
            result.inputs.push_back(*value);
            if (value->words() == 2U) {
                if (!inputs[reg + 1U]) return std::nullopt;
                ++reg;
            }
        }
        const auto call_units = 3U + result.argument_words * 2U + (result.output ? 1U : 0U) + result.constant_outputs.size() * 3U;
        if (call_units + 8U >= end_offset - start_offset || result.argument_words > 32U ||
            code.registers_size + result.argument_words + 5U > std::min<std::uint32_t>(255U, config.budget.max_registers_per_method)) return std::nullopt;
        return result;
    }
};
}

std::vector<CfgRegion> CfgRegionPlanner::Plan(const dex::DexFile& file,
    const dex::DexEncodedMethod& method, const dex::CodeItem& code, const GuardConfig& config,
    std::size_t maximum_units) {
    if (maximum_units < kMinimumRegionUnits || maximum_units > kMaximumRegionUnits)
        throw std::invalid_argument("invalid CFG region size bound");
    std::vector<CfgRegion> result;
    const Analysis analysis(file, method, code, config);
    for (std::size_t first = 0; first + 1U < code.instructions.size();) {
        if (!Movable(code.instructions[first])) { ++first; continue; }
        auto end = first + 1U;
        while (end + 1U < code.instructions.size() &&
            code.instructions[end + 1U].offset - code.instructions[first].offset <= maximum_units) ++end;
        std::optional<CfgRegion> best;
        for (; end > first && code.instructions[end].offset - code.instructions[first].offset >= kMinimumRegionUnits; --end) {
            best = analysis.Try(first, end);
            if (best) break;
        }
        if (!best) { ++first; continue; }
        first = best->end;
        result.push_back(std::move(*best));
    }
    return result;
}
}
