#include "constant_program_outliner.h"

#include "model_support.h"
#include "strength_policy.h"
#include "birch/dex/cloner.h"
#include "birch/dex/code.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/constant_runtime.h"
#include "birch/guard/scope.h"
#include "birch/utils/hash.h"

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>

namespace birch::guard::detail {
namespace {
struct Program {
    std::uint32_t start{};
    std::uint32_t end{};
    std::uint16_t reg{};
    std::vector<std::uint16_t> units; // normalized to v0
    std::string helper;
    std::uint32_t token{};
};
using Plans = std::map<std::string, std::vector<Program>, std::less<>>;

std::vector<Program> FindPrograms(const dex::DexFile& file,
                                  const dex::CodeItem& code, std::uint64_t seed) {
    std::set<std::uint32_t> boundaries;
    for (const auto& instruction : code.instructions)
        boundaries.insert(instruction.targets.begin(), instruction.targets.end());
    for (const auto& region : code.tries) {
        boundaries.insert(region.start_address);
        boundaries.insert(region.start_address + region.instruction_count);
        for (const auto& handler : region.handlers) boundaries.insert(handler.address);
    }
    const std::set<std::string, std::less<>> barriers{
        RuntimeConstantMethodName(seed), RuntimeFloatConstantMethodName(seed),
        RuntimeNullConstantMethodName(seed)};
    std::vector<Program> result;
    for (std::size_t i = 0; i < code.instructions.size(); ++i) {
        const auto& first = code.instructions[i];
        if (first.opcode != 0x14U) continue;
        const auto reg = static_cast<std::uint16_t>(first.code_units.front() >> 8U);
        if (reg > 15U) continue;
        auto end = i + 1U;
        while (end < code.instructions.size()) {
            const auto& instruction = code.instructions[end];
            const auto unit = instruction.code_units.front();
            if ((instruction.opcode != 0xd0U && instruction.opcode != 0xd7U) ||
                ((unit >> 8U) & 0xfU) != reg || (unit >> 12U) != reg ||
                boundaries.contains(instruction.offset)) break;
            ++end;
        }
        if (end - i < 9U || end == code.instructions.size()) continue;
        const auto& barrier = code.instructions[end];
        if (barrier.opcode != 0x71U || barrier.code_units.front() != 0x1071U ||
            barrier.code_units.at(2U) != reg) continue;
        const auto& method = file.methods().at(barrier.code_units.at(1U));
        if (!barriers.contains(file.string(method.name_idx))) continue;
        Program program;
        program.start = first.offset;
        program.end = barrier.offset;
        program.reg = reg;
        program.units = {0x0014U, first.code_units.at(1U), first.code_units.at(2U)};
        for (auto step = i + 1U; step < end; ++step) {
            program.units.push_back(code.instructions[step].opcode);
            program.units.push_back(code.instructions[step].code_units.at(1U));
        }
        result.push_back(std::move(program));
        i = end - 1U;
    }
    return result;
}

void Append32(std::vector<std::uint16_t>& units, std::uint32_t value) {
    units.push_back(static_cast<std::uint16_t>(value));
    units.push_back(static_cast<std::uint16_t>(value >> 16U));
}

dex::MethodSpec BuildHelper(std::string name, const std::vector<Program*>& programs) {
    dex::MethodSpec method;
    method.name = std::move(name);
    method.return_type = "I";
    method.parameter_types = {"I"};
    method.access_flags = kPrivate | kStatic | kSynthetic;
    method.body.registers_size = 2U;
    method.body.ins_size = 1U;
    auto& units = method.body.code_units;
    units = {0x012cU, 0U, 0U, 0x010fU}; // sparse-switch v1; fallback return v1
    std::map<std::int32_t, std::uint32_t> cases;
    for (const auto* program : programs) {
        cases.emplace(std::bit_cast<std::int32_t>(program->token),
                      static_cast<std::uint32_t>(units.size()));
        units.insert(units.end(), program->units.begin(), program->units.end());
        units.push_back(0x000fU);
    }
    if ((units.size() & 1U) != 0U) units.push_back(0x0012U);
    const auto payload = static_cast<std::uint32_t>(units.size());
    units[1U] = static_cast<std::uint16_t>(payload);
    units[2U] = static_cast<std::uint16_t>(payload >> 16U);
    units.push_back(0x0200U);
    units.push_back(static_cast<std::uint16_t>(cases.size()));
    for (const auto& [key, address] : cases) {
        (void)address;
        Append32(units, std::bit_cast<std::uint32_t>(key));
    }
    for (const auto& [key, address] : cases) {
        (void)key;
        Append32(units, address);
    }
    return method;
}
} // namespace

ConstantOutlineResult ConstantProgramOutliner::Apply(
    const dex::DexFile& source, const GuardConfig& config,
    const std::set<std::string, std::less<>>* targets) {
    ConstantOutlineResult result;
    if (!StrengthPolicy::RequiresFullStrength(config) || config.budget.max_call_depth_increase == 0U) return result;
    const ScopeMatcher scope(config.scope);
    Plans plans;
    std::map<std::string, std::vector<dex::MethodSpec>, std::less<>> helpers;
    for (std::size_t c = 0; c < source.classes().size(); ++c) {
        const auto owner = source.descriptor(source.classes()[c].class_idx);
        if (!scope.IsProtected(owner) || !scope.AllowsCodeTransforms(owner)) continue;
        const auto& data = source.class_data(c);
        for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& method : *methods) {
                if (method.code_off == 0U) continue;
                if (targets && !targets->contains(source.method_key(method.method_idx))) continue;
                const auto code = dex::DecodeCodeItem(source, method.code_off);
                if (!targets && code.insns.size() < kCallerThreshold) continue;
                auto programs = FindPrograms(source, code, config.seed);
                if (!programs.empty()) plans.emplace(source.method_key(method.method_idx), std::move(programs));
            }
        }
        std::set<std::string, std::less<>> used;
        for (const auto& method : source.methods())
            if (source.descriptor(method.class_idx) == owner) used.insert(source.string(method.name_idx));
        std::vector<Program*> batch;
        std::size_t batch_units = 7U;
        std::size_t ordinal = 0U;
        const auto helper_seed = utils::StableHash64(owner, config.seed);
        const auto flush = [&]() {
            if (batch.empty()) return;
            auto name = SyntheticName(helper_seed, "constant-program", ordinal++, used);
            used.insert(name);
            std::set<std::uint32_t> tokens;
            for (std::size_t i = 0; i < batch.size(); ++i) {
                auto token = static_cast<std::uint32_t>(utils::StableHash64(name, helper_seed ^ i));
                while (!tokens.insert(token).second) ++token;
                batch[i]->token = token;
                batch[i]->helper = name;
            }
            helpers[owner].push_back(BuildHelper(std::move(name), batch));
            batch.clear();
            batch_units = 7U;
            ++result.helpers;
        };
        for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& method : *methods) {
                const auto found = plans.find(source.method_key(method.method_idx));
                if (found == plans.end()) continue;
                for (auto& program : found->second) {
                    const auto cost = program.units.size() + 5U; // return + sparse case
                    if (cost + 7U > kHelperBudget) throw std::length_error("constant program exceeds outline budget");
                    if (batch_units + cost > kHelperBudget) flush();
                    batch.push_back(&program);
                    batch_units += cost;
                    ++result.programs;
                    result.arithmetic_steps += (program.units.size() - 3U) / 2U;
                }
            }
        }
        flush();
    }
    if (helpers.empty()) return result;
    // Allocate method IDs before writing callsites. Builder relocation may
    // promote const-string to jumbo: rediscover sites, never reuse old offsets.
    dex::DexClassCloner cloner(source);
    dex::DexBuilder builder(source.version());
    for (std::size_t c = 0; c < source.classes().size(); ++c) {
        auto klass = cloner.Clone(c);
        if (auto found = helpers.find(klass.descriptor); found != helpers.end())
            for (auto& helper : found->second) klass.direct_methods.push_back(std::move(helper));
        builder.AddClass(std::move(klass));
    }
    const auto allocated = dex::DexFile::Parse(builder.Build());
    std::map<std::pair<std::string, std::string>, std::uint16_t> ids;
    for (std::size_t i = 0; i < allocated.methods().size(); ++i) {
        if (i > std::numeric_limits<std::uint16_t>::max()) throw std::length_error("outline method ID overflow");
        const auto& method = allocated.methods()[i];
        ids.emplace(std::pair{allocated.descriptor(method.class_idx), allocated.string(method.name_idx)},
                    static_cast<std::uint16_t>(i));
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
                const auto sites = FindPrograms(allocated, code, config.seed);
                if (sites.size() != found->second.size()) throw std::logic_error("constant outline plan lost sites");
                dex::CodePrefix prefix;
                prefix.code_off = method.code_off;
                prefix.replacement_outs_size = std::max<std::uint16_t>(code.outs_size, 1U);
                for (std::size_t i = 0; i < sites.size(); ++i) {
                    const auto& site = sites[i];
                    const auto& plan = found->second[i];
                    if (site.units != plan.units || site.reg != plan.reg) throw std::logic_error("constant outline program changed");
                    prefix.linear_replacements.emplace(site.start, std::vector<std::uint16_t>{
                        static_cast<std::uint16_t>(0x14U | (site.reg << 8U)),
                        static_cast<std::uint16_t>(plan.token), static_cast<std::uint16_t>(plan.token >> 16U),
                        0x1071U, ids.at({owner, plan.helper}), site.reg,
                        static_cast<std::uint16_t>(0x0aU | (site.reg << 8U))});
                    prefix.arithmetic_span_ends.emplace(site.start, site.end);
                }
                prefixes.push_back(std::move(prefix));
            }
        }
    }
    result.bytes = dex::RewriteCodePrefixes(allocated, prefixes);
    dex::VerifyDexOrThrow(dex::DexFile::Parse(result.bytes), dex::VerificationLevel::Full);
    return result;
}
} // namespace birch::guard::detail
