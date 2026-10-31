#include "linear_region_outliner.h"

#include "model_support.h"
#include "strength_policy.h"
#include "birch/dex/cloner.h"
#include "birch/dex/code.h"
#include "birch/dex/liveness.h"
#include "birch/dex/verifier.h"
#include "birch/guard/scope.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>

namespace birch::guard::detail {
namespace {
// Only exact constants and values with a proven verifier descriptor may cross
// a new call boundary. Definition identity is retained separately from type:
// two different String results are not interchangeable live outputs. In
// particular, a new-instance is never transported while uninitialized.
struct Origin {
    enum class Kind { Unknown, Argument, Constant } kind{Kind::Unknown};
    std::uint32_t value{};
    std::string descriptor;
    bool operator==(const Origin&) const = default;
};
using Frame = std::vector<Origin>;
using Bits = std::vector<bool>;

Origin Constant(const dex::DecodedInstruction& ins) {
    std::uint32_t value{};
    if (ins.opcode == 0x12U) {
        const auto nibble = static_cast<std::uint32_t>(ins.code_units[0] >> 12U);
        value = (nibble & 8U) != 0U ? nibble | 0xfffffff0U : nibble;
    } else if (ins.opcode == 0x13U) {
        value = static_cast<std::uint32_t>(static_cast<std::int32_t>(
            static_cast<std::int16_t>(ins.code_units.at(1U))));
    } else if (ins.opcode == 0x14U) {
        value = ins.code_units.at(1U) | (static_cast<std::uint32_t>(ins.code_units.at(2U)) << 16U);
    } else {
        value = static_cast<std::uint32_t>(ins.code_units.at(1U)) << 16U;
    }
    return {Origin::Kind::Constant, value, {}};
}

std::vector<Frame> Trace(const dex::DexFile& file, const dex::MethodSpec& method, std::string_view owner,
                       const dex::CodeItem& code,
                       const std::vector<dex::InstructionRegisterEffects>& effects) {
    Frame frame(code.registers_size);
    auto reg = static_cast<std::uint16_t>(code.registers_size - code.ins_size);
    std::vector<std::string> parameters = method.parameter_types;
    if ((method.access_flags & kStatic) == 0U) parameters.insert(parameters.begin(), std::string(owner));
    for (const auto& parameter : parameters) {
        if (parameter != "J" && parameter != "D")
            frame.at(reg) = {Origin::Kind::Argument, reg, parameter};
        reg = static_cast<std::uint16_t>(reg + TypeWordCount(parameter));
    }
    if (reg != code.registers_size) throw std::logic_error("linear outline parameter layout mismatch");
    std::vector<Frame> result{frame};
    for (std::size_t i = 0U; i < code.instructions.size(); ++i) {
        const auto& ins = code.instructions[i];
        const auto first = ins.code_units.front();
        Origin value;
        if (ins.opcode >= 0x12U && ins.opcode <= 0x15U) value = Constant(ins);
        else if ((ins.opcode >= 1U && ins.opcode <= 3U) ||
                 (ins.opcode >= 7U && ins.opcode <= 9U)) {
            const auto form = (ins.opcode - 1U) % 3U;
            const auto src = form == 0U ? first >> 12U : ins.code_units.at(form == 1U ? 1U : 2U);
            value = frame.at(src);
        } else {
            std::string type;
            if (ins.opcode == 0x1aU || ins.opcode == 0x1bU) type = "Ljava/lang/String;";
            else if (ins.opcode == 0x1cU) type = "Ljava/lang/Class;";
            else if (ins.opcode == 0x23U) type = file.descriptor(ins.code_units.at(1U));
            else if (ins.opcode == 0x62U) type = file.descriptor(file.fields().at(ins.code_units.at(1U)).type_idx);
            else if ((ins.opcode == 0x0aU || ins.opcode == 0x0cU) && i != 0U) {
                const auto& previous = code.instructions[i - 1U];
                if ((previous.opcode >= 0x6eU && previous.opcode <= 0x72U) ||
                    (previous.opcode >= 0x74U && previous.opcode <= 0x78U)) {
                    const auto& id = file.methods().at(previous.code_units.at(1U));
                    type = file.descriptor(file.protos().at(id.proto_idx).return_type_idx);
                } else if (previous.opcode == 0x24U || previous.opcode == 0x25U) {
                    type = file.descriptor(previous.code_units.at(1U));
                }
            }
            if (!type.empty() && type != "V" && type != "J" && type != "D")
                value = {Origin::Kind::Argument,
                    static_cast<std::uint32_t>(code.registers_size + i + 1U), std::move(type)};
        }
        // check-cast refines a descriptor. Do not pass a stale, broader
        // parameter type into a helper that relies on that refinement.
        for (std::size_t r = 0U; r < frame.size(); ++r)
            if (effects[i].writes[r]) frame[r] = value;
        result.push_back(frame);
    }
    return result;
}

struct Region {
    std::size_t first{};
    std::size_t end{}; // instruction index, exclusive
    Bits inputs;
    std::vector<std::uint16_t> arguments;
};

std::optional<Region> FindRegion(
    std::size_t first, const dex::CodeItem& code,
    const std::vector<dex::InstructionRegisterEffects>& effects,
    const std::vector<Bits>& live_after, const std::vector<Frame>& frames,
    std::uint32_t register_budget) {
    Bits written(code.registers_size), inputs(code.registers_size);
    std::optional<Region> best;
    // Leave the final return in the caller. Never separate invoke/filled-array
    // from its move-result, or transport an uninitialized allocation.
    for (auto end = first; end + 1U < code.instructions.size(); ++end) {
        const auto& ins = code.instructions[end];
        const auto units = ins.offset + ins.width - code.instructions[first].offset;
        if (units > LinearRegionOutliner::kMaximumRegionUnits) break;
        for (std::size_t r = 0; r < written.size(); ++r) {
            inputs[r] = inputs[r] || (effects[end].reads[r] && !written[r]);
            written[r] = written[r] || effects[end].writes[r];
        }
        if (units < LinearRegionOutliner::kMinimumRegionUnits) continue;
        const auto next_op = code.instructions[end + 1U].opcode;
        if (next_op >= 0x0aU && next_op <= 0x0cU) continue;
        bool valid = true;
        std::vector<std::uint16_t> args;
        for (std::uint16_t r = 0; r < written.size(); ++r) {
            if (written[r] && live_after[end][r] &&
                (frames[first][r].kind == Origin::Kind::Unknown ||
                 frames[first][r] != frames[end + 1U][r])) { valid = false; break; }
            if (!inputs[r]) continue;
            const auto& input = frames[first][r];
            if (input.kind == Origin::Kind::Unknown) { valid = false; break; }
            if (input.kind == Origin::Kind::Argument) args.push_back(r);
            if (input.kind == Origin::Kind::Constant && r > 255U) { valid = false; break; }
        }
        // Either 35c or an already-contiguous range: no caller register
        // expansion or parallel-copy ambiguity. Helper move/from16 destinations
        // must fit in 8 bits. Constants retain verifier-polymorphic bits.
        const bool contiguous = args.empty() || std::equal(args.begin() + 1U, args.end(), args.begin(),
            [](auto next, auto previous) { return next == previous + 1U; });
        const bool low = args.empty() || (args.size() <= 5U && args.back() <= 15U);
        if (!valid || args.size() > 255U || (!args.empty() && args.back() > 255U) ||
            (!low && !contiguous) ||
            code.registers_size + args.size() + 5U > register_budget) continue;
        best = Region{first, end + 1U, inputs, std::move(args)};
    }
    return best;
}

void CopySlice(const dex::MethodBodySpec& source, std::uint32_t start,
               std::uint32_t end, dex::MethodBodySpec& target) {
    const auto base = static_cast<std::uint32_t>(target.code_units.size());
    target.code_units.insert(target.code_units.end(), source.code_units.begin() + start,
                             source.code_units.begin() + end);
    for (const auto& patch : source.references) {
        if (patch.code_unit < start || patch.code_unit >= end) continue;
        auto relocated = patch;
        relocated.code_unit = base + patch.code_unit - start;
        target.references.push_back(std::move(relocated));
    }
}

std::vector<dex::MethodSpec> Outline(
    const dex::DexFile& file, const dex::DexEncodedMethod& encoded,
    dex::MethodSpec& method, std::string_view owner, const GuardConfig& config,
    std::set<std::string, std::less<>>& used, std::size_t& ordinal,
    LinearOutlineResult& result) {
    const auto code = dex::DecodeCodeItem(file, encoded.code_off);
    if (code.insns.size() < LinearRegionOutliner::kCallerThreshold || !code.tries.empty() ||
        method.name == "<init>" || method.name == "<clinit>" ||
        (method.access_flags & (0x0020U | 0x20000U)) != 0U ||
        code.instructions.empty() || code.instructions.back().kind != dex::InstructionKind::Return)
        return {};
    std::vector<dex::InstructionRegisterEffects> effects;
    for (std::size_t i = 0; i < code.instructions.size(); ++i) {
        const auto& ins = code.instructions[i];
        if ((!ins.targets.empty()) || ins.kind == dex::InstructionKind::Payload ||
            (i + 1U != code.instructions.size() && ins.kind != dex::InstructionKind::Normal) ||
            ins.opcode == 0x1dU || ins.opcode == 0x1eU || ins.opcode == 0x6fU ||
            ins.opcode == 0x75U || ins.opcode == 0x0dU || ins.opcode >= 0xfaU) return {};
        auto effect = dex::AnalyzeRegisterEffects(
            {ins.offset, ins.opcode, ins.code_units, ins.can_throw}, code.registers_size);
        if (!effect.complete) return {};
        effects.push_back(std::move(effect));
    }
    const auto frames = Trace(file, method, owner, code, effects);
    std::vector<Bits> live_after(effects.size(), Bits(code.registers_size));
    Bits live(code.registers_size);
    for (auto i = effects.size(); i-- > 0U;) {
        live_after[i] = live;
        for (std::size_t r = 0; r < live.size(); ++r)
            live[r] = effects[i].reads[r] || (live[r] && !effects[i].writes[r]);
    }
    std::vector<Region> regions;
    for (std::size_t i = 0; i + 1U < effects.size();) {
        if (code.instructions[i].opcode >= 0x0aU && code.instructions[i].opcode <= 0x0cU) {
            ++i;
            continue;
        }
        auto region = FindRegion(i, code, effects, live_after, frames, config.budget.max_registers_per_method);
        if (!region) { ++i; continue; }
        i = region->end;
        regions.push_back(std::move(*region));
    }
    if (regions.empty()) return {};
    const auto old = std::move(method.body);
    method.body = {};
    method.body.registers_size = old.registers_size;
    method.body.ins_size = old.ins_size;
    method.body.outs_size = old.outs_size;
    std::vector<dex::MethodSpec> helpers;
    std::uint32_t cursor = 0U;
    for (const auto& region : regions) {
        const auto start = code.instructions[region.first].offset;
        const auto end = code.instructions[region.end].offset;
        CopySlice(old, cursor, start, method.body);
        dex::MethodSpec helper;
        helper.name = SyntheticName(utils::StableHash64(owner, config.seed), "linear-region", ordinal++, used);
        used.insert(helper.name);
        helper.access_flags = kPrivate | kStatic | kSynthetic;
        helper.body.registers_size = static_cast<std::uint16_t>(old.registers_size + region.arguments.size());
        helper.body.ins_size = static_cast<std::uint16_t>(region.arguments.size());
        helper.body.outs_size = old.outs_size;
        for (std::size_t arg = 0; arg < region.arguments.size(); ++arg) {
            const auto dst = region.arguments[arg];
            const auto& type = frames[region.first][dst].descriptor;
            helper.parameter_types.push_back(type);
            const bool reference = type.front() == 'L' || type.front() == '[';
            helper.body.code_units.insert(helper.body.code_units.end(), {
                static_cast<std::uint16_t>((reference ? 0x08U : 0x02U) | (dst << 8U)),
                static_cast<std::uint16_t>(old.registers_size + arg)});
        }
        for (std::uint16_t r = 0; r < region.inputs.size(); ++r) {
            const auto& origin = frames[region.first][r];
            if (!region.inputs[r] || origin.kind != Origin::Kind::Constant) continue;
            helper.body.code_units.insert(helper.body.code_units.end(), {
                static_cast<std::uint16_t>(0x14U | (r << 8U)),
                static_cast<std::uint16_t>(origin.value), static_cast<std::uint16_t>(origin.value >> 16U)});
        }
        CopySlice(old, start, end, helper.body);
        helper.body.code_units.push_back(0x000eU);
        AppendInvoke(method.body.code_units, 0x71U, region.arguments, method.body,
            {std::string(owner), helper.name, "V", helper.parameter_types});
        method.body.outs_size = std::max(method.body.outs_size, helper.body.ins_size);
        helpers.push_back(std::move(helper));
        cursor = end;
        result.moved_code_units += end - start;
        ++result.regions;
    }
    CopySlice(old, cursor, static_cast<std::uint32_t>(old.code_units.size()), method.body);
    ++result.methods;
    return helpers;
}
} // namespace

LinearOutlineResult LinearRegionOutliner::Apply(
    const dex::DexFile& source, const GuardConfig& config) {
    LinearOutlineResult result;
    if (!StrengthPolicy::RequiresFullStrength(config) || config.budget.max_call_depth_increase == 0U) return result;
    const ScopeMatcher scope(config.scope);
    dex::DexClassCloner cloner(source);
    dex::DexBuilder builder(source.version());
    for (std::size_t c = 0; c < source.classes().size(); ++c) {
        auto klass = cloner.Clone(c);
        if (scope.IsProtected(klass.descriptor) && scope.AllowsCodeTransforms(klass.descriptor) &&
            (klass.access_flags & kInterface) == 0U) {
            std::set<std::string, std::less<>> used;
            // Include unresolved method references too; never capture a call
            // that was previously intended for an inherited/private API.
            for (const auto& id : source.methods())
                if (source.descriptor(id.class_idx) == klass.descriptor) used.insert(source.string(id.name_idx));
            std::size_t ordinal = 0U;
            std::vector<dex::MethodSpec> helpers;
            const auto& data = source.class_data(c);
            for (const bool direct : {true, false}) {
                auto& methods = direct ? klass.direct_methods : klass.virtual_methods;
                const auto& encoded = direct ? data.direct_methods : data.virtual_methods;
                if (methods.size() != encoded.size()) throw std::logic_error("linear outline clone method mismatch");
                for (std::size_t m = 0; m < methods.size(); ++m) {
                    if (encoded[m].code_off == 0U) continue;
                    auto added = Outline(source, encoded[m], methods[m], klass.descriptor, config, used, ordinal, result);
                    for (auto& helper : added) helpers.push_back(std::move(helper));
                }
            }
            for (auto& helper : helpers) klass.direct_methods.push_back(std::move(helper));
        }
        builder.AddClass(std::move(klass));
    }
    if (result.regions != 0U) {
        result.bytes = builder.Build();
        dex::VerifyDexOrThrow(dex::DexFile::Parse(result.bytes), dex::VerificationLevel::Full);
    }
    return result;
}
} // namespace birch::guard::detail
