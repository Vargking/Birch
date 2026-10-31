#include "cfg_region_outliner.h"

#include "cfg_region_planner.h"
#include "control_flow_flattener.h"
#include "model_support.h"
#include "strength_policy.h"
#include "birch/dex/cloner.h"
#include "birch/dex/ir.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/scope.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>

namespace birch::guard::detail {
namespace {
using Plans = std::map<std::string, std::vector<CfgRegion>, std::less<>>;
bool Reference(std::string_view type) { return !type.empty() && (type.front() == 'L' || type.front() == '['); }
void Constant(std::vector<std::uint16_t>& units, std::uint16_t reg, std::uint32_t bits) {
    units.insert(units.end(), {static_cast<std::uint16_t>(0x14U | (reg << 8U)),
        static_cast<std::uint16_t>(bits), static_cast<std::uint16_t>(bits >> 16U)});
}
void Move(std::vector<std::uint16_t>& units, const RegionValue& value, std::uint16_t dest, std::uint16_t src) {
    const auto op = value.words() == 2U ? 0x05U : Reference(value.descriptor) ? 0x08U : 0x02U;
    units.insert(units.end(), {static_cast<std::uint16_t>(op | (dest << 8U)), src});
}
dex::MethodSpec Helper(const dex::MethodBodySpec& original, const dex::CodeItem& code, const CfgRegion& region) {
    dex::MethodSpec result;
    result.name = region.helper;
    result.access_flags = kPrivate | kStatic | kSynthetic;
    if (region.output) result.return_type = region.output->descriptor;
    result.body.registers_size = static_cast<std::uint16_t>(code.registers_size + region.argument_words);
    result.body.ins_size = region.argument_words;
    result.body.outs_size = code.outs_size;
    auto argument = code.registers_size;
    for (const auto& input : region.inputs) {
        if (input.constant32) Constant(result.body.code_units, input.reg, *input.constant32);
        else {
            result.parameter_types.push_back(input.descriptor);
            Move(result.body.code_units, input, input.reg, argument);
            argument = static_cast<std::uint16_t>(argument + input.words());
        }
    }
    if (argument != result.body.registers_size) throw std::logic_error("CFG outline argument word mismatch");
    const auto start = code.instructions.at(region.first).offset, end = code.instructions.at(region.end).offset;
    const auto base = static_cast<std::uint32_t>(result.body.code_units.size());
    result.body.code_units.insert(result.body.code_units.end(), original.code_units.begin() + start, original.code_units.begin() + end);
    for (const auto& reference : original.references) {
        if (reference.code_unit < start || reference.code_unit >= end) continue;
        auto moved = reference;
        moved.code_unit = base + reference.code_unit - start;
        result.body.references.push_back(std::move(moved));
    }
    const auto return_op = !region.output ? 0x0eU : region.output->words() == 2U ? 0x10U : Reference(region.output->descriptor) ? 0x11U : 0x0fU;
    result.body.code_units.push_back(static_cast<std::uint16_t>(return_op | (region.output ? region.output->reg << 8U : 0U)));
    return result;
}
}

CfgOutlineResult CfgRegionOutliner::Apply(const dex::DexFile& source, const GuardConfig& config,
                                         const Targets* targets) {
    CfgOutlineResult result;
    if (!StrengthPolicy::RequiresFullStrength(config) || config.budget.max_call_depth_increase == 0U) return result;
    const ScopeMatcher scope(config.scope);
    dex::DexClassCloner cloner(source);
    dex::DexBuilder builder(source.version());
    Plans plans;
    for (std::size_t c = 0; c < source.classes().size(); ++c) {
        auto klass = cloner.Clone(c);
        if (scope.IsProtected(klass.descriptor) && scope.AllowsCodeTransforms(klass.descriptor) && (klass.access_flags & kInterface) == 0U) {
            std::set<std::string, std::less<>> used;
            for (const auto& id : source.methods())
                if (source.descriptor(id.class_idx) == klass.descriptor) used.insert(source.string(id.name_idx));
            std::size_t ordinal = 0U;
            std::vector<dex::MethodSpec> helpers;
            const auto& data = source.class_data(c);
            for (bool direct : {true, false}) {
                const auto& methods = direct ? klass.direct_methods : klass.virtual_methods;
                const auto& encoded = direct ? data.direct_methods : data.virtual_methods;
                if (methods.size() != encoded.size()) throw std::logic_error("CFG outline clone method mismatch");
                for (std::size_t m = 0; m < methods.size(); ++m) {
                    const auto& method = methods[m];
                    const auto key = source.method_key(encoded[m].method_idx);
                    if (targets && !targets->contains(key)) continue;
                    if (!encoded[m].code_off || method.name == "<init>" || method.name == "<clinit>" ||
                        (method.access_flags & (0x0020U | 0x20000U)) != 0U) continue;
                    const auto code = dex::DecodeCodeItem(source, encoded[m].code_off);
                    // Pre-materialization partitioning reserves room for all
                    // later passes. Small methods do not need call boundaries.
                    if (!targets && code.insns.size() < 512U && dex::BuildMethodIr(code).blocks().size() < 48U) continue;
                    auto regions = CfgRegionPlanner::Plan(source, encoded[m], code, config,
                        targets ? targets->at(key) : CfgRegionPlanner::kMaximumRegionUnits);
                    if (regions.empty()) continue;
                    for (auto& region : regions) {
                        region.helper = SyntheticName(utils::StableHash64(klass.descriptor, config.seed), "cfg-region", ordinal++, used);
                        used.insert(region.helper);
                        helpers.push_back(Helper(method.body, code, region));
                        result.moved_code_units += code.instructions[region.end].offset - code.instructions[region.first].offset;
                        ++result.regions;
                    }
                    plans.emplace(source.method_key(encoded[m].method_idx), std::move(regions));
                    ++result.methods;
                }
            }
            for (auto& helper : helpers) klass.direct_methods.push_back(std::move(helper));
        }
        builder.AddClass(std::move(klass));
    }
    if (plans.empty()) return result;
    dex::CodeAddressMaps addresses;
    const auto allocated = dex::DexFile::Parse(builder.Build(&addresses));
    std::map<std::pair<std::string, std::string>, std::uint16_t> ids;
    for (std::size_t i = 0; i < allocated.methods().size(); ++i) {
        if (i > std::numeric_limits<std::uint16_t>::max()) throw std::length_error("CFG outline method ID overflow");
        const auto& method = allocated.methods()[i];
        ids.emplace(std::pair{allocated.descriptor(method.class_idx), allocated.string(method.name_idx)}, static_cast<std::uint16_t>(i));
    }
    std::vector<dex::CodePrefix> prefixes;
    for (std::size_t c = 0; c < allocated.classes().size(); ++c) {
        const auto owner = allocated.descriptor(allocated.classes()[c].class_idx);
        const auto& data = allocated.class_data(c);
        for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& method : *methods) {
                const auto found = plans.find(allocated.method_key(method.method_idx));
                if (found == plans.end()) continue;
                const auto code = dex::DecodeCodeItem(allocated, method.code_off);
                dex::CodePrefix prefix;
                prefix.code_off = method.code_off;
                std::uint16_t extra{};
                for (const auto& region : found->second) extra = std::max(extra, region.argument_words);
                prefix.replacement_registers_size = static_cast<std::uint16_t>(code.registers_size + extra);
                prefix.replacement_outs_size = std::max(code.outs_size, extra);
                prefix.code_units = ControlFlowFlattener::BuildParameterMigration(allocated, method, code, extra);
                const auto& relocated = addresses.at(allocated.method_key(method.method_idx));
                for (const auto& region : found->second) {
                    const auto start = relocated.at(region.start_offset);
                    const auto end = relocated.at(region.end_offset);
                    auto& units = prefix.linear_replacements[start];
                    auto argument = code.registers_size;
                    for (const auto& input : region.inputs) if (!input.constant32) {
                        Move(units, input, argument, input.reg);
                        argument = static_cast<std::uint16_t>(argument + input.words());
                    }
                    units.insert(units.end(), {static_cast<std::uint16_t>(0x77U | (region.argument_words << 8U)),
                        ids.at({owner, region.helper}), code.registers_size});
                    if (region.output) {
                        const auto op = region.output->words() == 2U ? 0x0bU : Reference(region.output->descriptor) ? 0x0cU : 0x0aU;
                        units.push_back(static_cast<std::uint16_t>(op | (region.output->reg << 8U)));
                    }
                    for (const auto& output : region.constant_outputs) Constant(units, output.reg, *output.constant32);
                    prefix.outline_span_ends.emplace(start, end);
                }
                prefixes.push_back(std::move(prefix));
            }
        }
    }
    result.bytes = dex::RewriteCodePrefixes(allocated, prefixes);
    dex::VerifyDexOrThrow(dex::DexFile::Parse(result.bytes), dex::VerificationLevel::Full);
    return result;
}
}
