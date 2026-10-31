#include "output_code_budget.h"

#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "support/cff_shape.h"
#include "support/string_dex_interpreter.h"

#include <cassert>
#include <cstddef>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace {
namespace dex = birch::dex;
using birch::guard::detail::OutputCodeBudget;

auto Config() {
    auto config = birch::guard::GuardConfig::Defaults();
    config.scope.protect = {{"Lfinal/**;"}};
    config.scope.keep.clear();
    config.budget.max_code_units_per_method = 65000U;
    config.passes.at("strength.anti_automation_profile") = {true, 1.0};
    return config;
}

auto Fixture(std::string owner, std::size_t units, bool is_virtual = false) {
    dex::ClassSpec klass;
    klass.descriptor = std::move(owner);
    dex::MethodSpec method;
    method.name = "run";
    method.access_flags = is_virtual ? 0x0001U : 0x0009U;
    method.body.registers_size = is_virtual ? 1U : 0U;
    method.body.ins_size = is_virtual ? 1U : 0U;
    method.body.code_units.resize(units, 0U);
    method.body.code_units.back() = 0x000eU;
    (is_virtual ? klass.virtual_methods : klass.direct_methods).push_back(std::move(method));
    dex::MethodSpec abstract_method;
    abstract_method.name = "noCode";
    abstract_method.access_flags = 0x0401U;
    klass.access_flags = 0x0401U;
    klass.virtual_methods.push_back(std::move(abstract_method));
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    return dex::DexFile::Parse(builder.Build());
}

void Reject(const dex::DexFile& file, const birch::guard::GuardConfig& config,
            const OutputCodeBudget::ClassMap& renames = {}) {
    bool rejected = false;
    try {
        OutputCodeBudget::Verify(file, config, renames);
    } catch (const std::length_error& error) {
        rejected = std::string(error.what()).find("final serialized code-unit limit") !=
                   std::string::npos;
    }
    assert(rejected);
}

void BoundariesAndScope() {
    auto config = Config();
    OutputCodeBudget::Verify(Fixture("Lfinal/Fixture;", 16000U), config);
    const auto oversized = Fixture("Lfinal/Fixture;", 16001U);
    Reject(oversized, config);
    Reject(Fixture("Lfinal/Fixture;", 16001U, true), config);
    const auto renamed = Fixture("Lhidden/a;", 16001U);
    const OutputCodeBudget::ClassMap renames{{"Lfinal/Fixture;", "Lhidden/a;"}};
    Reject(renamed, config, renames);
    // Scope exclusions are evaluated against original owners, never renamed ones.
    OutputCodeBudget::Verify(renamed, config);
    OutputCodeBudget::Verify(Fixture("Lthirdparty/Existing;", 20000U), config);
    config.scope.keep = {{"Lfinal/Fixture;"}};
    OutputCodeBudget::Verify(oversized, config);
    OutputCodeBudget::Verify(renamed, config, renames);
    config.scope.keep.clear();
    config.scope.protect.front().allow_code_transforms = false;
    OutputCodeBudget::Verify(oversized, config);
    config.scope.protect.front().allow_code_transforms = true;
    config.budget.max_code_units_per_method = 100U;
    OutputCodeBudget::Verify(Fixture("Lfinal/Fixture;", 100U), config);
    Reject(Fixture("Lfinal/Fixture;", 101U), config);
    Reject(Fixture("Lx/birch/Generated;", 101U), config);
    bool ambiguous = false;
    try {
        OutputCodeBudget::Verify(renamed, config,
            {{"Lfinal/A;", "Lhidden/a;"}, {"Lfinal/B;", "Lhidden/a;"}});
    } catch (const std::invalid_argument&) {
        ambiguous = true;
    }
    assert(ambiguous);
}

void FinalRemapJumboGrowth() {
    dex::MethodSpec method;
    method.name = "run";
    method.body.registers_size = 1U;
    method.body.code_units = {0x001aU, 0U}; // const-string v0, "!"
    method.body.string_references.push_back({"!", 1U});
    method.body.code_units.resize(15999U, 0U);
    method.body.code_units.push_back(0x000eU);
    dex::ClassSpec klass;
    klass.descriptor = "Lfinal/Fixture;";
    klass.direct_methods.push_back(std::move(method));
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    for (unsigned i = 0U; i < 65536U; ++i) builder.AddString("a" + std::to_string(i));
    const auto source = dex::DexFile::Parse(builder.Build());
    const auto config = Config();
    dex::VerifyDexOrThrow(source, dex::VerificationLevel::Full);
    OutputCodeBudget::Verify(source, config);
    assert(source.string(0U) == "!");
    const auto replaced = dex::DexFile::Parse(source.ReplaceStrings({{0U, {"zzzzz", 5U}}}));
    const auto final = dex::DexFile::Parse(
        dex::ApplyIdRemap(replaced, dex::BuildCanonicalRemap(replaced)));
    dex::VerifyDexOrThrow(final, dex::VerificationLevel::Full);
    const auto code = dex::DecodeCodeItem(final, final.class_data(0U).direct_methods[0U].code_off);
    assert(code.insns.size() == 16001U && code.instructions.front().opcode == 0x1bU);
    Reject(final, config);
}

void CffStringWidthIsFinal() {
    dex::ClassSpec klass;
    klass.descriptor = "Lfinal/StableWidth;";
    for (bool nonzero : {false, true}) {
        dex::MethodSpec method;
        method.name = nonzero ? "one" : "zero";
        method.return_type = "Ljava/lang/String;";
        method.body.registers_size = 2U;
        method.body.code_units = {
            static_cast<std::uint16_t>(nonzero ? 0x1112U : 0x0112U),
            0x0138U, 9U,                 // @1 if-eqz v1, @10
            0x001aU, 0U, 0x0011U,       // @3 load, return
            0x000dU,                    // @6 handler
            0x001aU, 0U, 0x0011U,       // @7 load, return
            0x001aU, 0U, 0x0011U};      // @10 load, return
        method.body.string_references = {{"!", 4U}, {"!", 8U}, {"!", 11U}};
        method.body.try_regions = {{3U, 2U, {{std::nullopt, 6U}}}};
        klass.direct_methods.push_back(std::move(method));
    }
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    for (unsigned i = 0U; i < 65536U; ++i) builder.AddString("a" + std::to_string(i));
    const auto source = dex::DexFile::Parse(builder.Build());
    dex::VerifyDexOrThrow(source, dex::VerificationLevel::Full);
    auto config = Config();
    for (auto& [id, pass] : config.passes) pass.enabled = false;
    for (const auto* id : {"cfg.flattening", "cfg.dead_blocks", "cfg.multi_state_dispatch",
                           "cfg.table_dispatch", "strength.anti_automation_profile"})
        config.passes.at(id) = {true, 1.0};
    config.seed = 0x4a554d424f434646ULL;
    config.budget.max_added_blocks_per_method = 1024U;
    config.budget.max_method_growth_ratio = 10000.0;
    const auto lowered = dex::DexFile::Parse(
        birch::guard::DexCodeLowering(config).Apply(source).bytes);
    OutputCodeBudget::Verify(lowered, config);
    birch::test::StringDexInterpreter original(source), protected_code(lowered);
    for (const auto* name : {"zero", "one"}) {
        assert(original.Execute("Lfinal/StableWidth;", name) == u"!");
        assert(protected_code.Execute("Lfinal/StableWidth;", name) == u"!");
    }
    assert(lowered.string(0U) == "!");
    const auto replaced = dex::DexFile::Parse(lowered.ReplaceStrings({{0U, {"zzzzz", 5U}}}));
    const auto remap = dex::BuildCanonicalRemap(replaced);
    assert(remap.strings.at(0U) > 0xffffU);
    const auto final = dex::DexFile::Parse(dex::ApplyIdRemap(replaced, remap));
    dex::VerifyDexOrThrow(final, dex::VerificationLevel::Full);
    OutputCodeBudget::Verify(final, config);
    for (const auto& method : lowered.class_data(0U).direct_methods) {
        const auto code = dex::DecodeCodeItem(lowered, method.code_off);
        const auto key = lowered.method_key(method.method_idx);
        bool found = false;
        for (const auto& final_method : final.class_data(0U).direct_methods) {
            if (final.method_key(final_method.method_idx) != key) continue;
            const auto final_code = dex::DecodeCodeItem(final, final_method.code_off);
            assert(final_code.insns.size() == code.insns.size());
            assert(final_code.tries.size() == code.tries.size());
            const auto ir = dex::BuildMethodIr(final_code);
            assert(ir.blocks().size() >= 1024U && final_code.insns.size() <= 16000U);
            const auto shape = birch::test::MeasureCffShape(ir);
            assert(shape.max_empty_fan_in <= 16U && shape.max_empty_run <= 2U);
            unsigned strings = 0U;
            for (const auto& instruction : final_code.instructions) {
                assert(instruction.opcode != 0x1aU);
                if (instruction.opcode == 0x1bU) ++strings;
            }
            assert(strings == 3U);
            found = true;
        }
        assert(found);
    }
    birch::test::StringDexInterpreter renamed_code(final);
    for (const auto* name : {"zero", "one"})
        assert(renamed_code.Execute("Lfinal/StableWidth;", name) == u"zzzzz");
}
} // namespace

int main() {
    BoundariesAndScope();
    FinalRemapJumboGrowth();
    CffStringWidthIsFinal();
    std::cout << "Final code-budget boundaries, scope, CFF width stability and jumbo remap passed\n";
}
