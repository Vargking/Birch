#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "support/int_dex_interpreter.h"
#include "support/string_dex_interpreter.h"
#include "support/cff_shape.h"

#include <array>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

birch::dex::DexFile Fixture(bool high_registers = false, bool cold_component = false) {
    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lsemantic/Arithmetic;";
    birch::dex::MethodSpec method;
    method.name = "calculate";
    method.return_type = "I";
    method.parameter_types = {"I", "I"};
    method.access_flags = 0x0009U;
    method.body.registers_size = 5U;
    method.body.ins_size = 2U;
    method.body.code_units = {
        0x0012U,                 // @0 sum=0
        0x01ddU, 0x0f03U,       // @1 count=p0 & 15
        0x0138U, 8U,            // @3 if count==0 goto @11
        0x0090U, 0x0400U,       // @5 sum += p1 (wraps)
        0x01d8U, 0xff01U,       // @7 --count
        0x0029U, 0xfffaU,       // @9 goto @3
        0x033aU, 5U,            // @11 if p0<0 goto @16
        0x0097U, 0x0400U,       // @13 sum ^= p1
        0x000fU,                 // @15 return sum
        0x007bU,                 // @16 sum = -sum (wraps)
        0x000fU,
    };
    if (cold_component) {
        // Disconnected source code still feeds a real return through a typed
        // CFF tail. The verifier seeds its private registers as undefined.
        method.body.code_units.insert(method.body.code_units.end(),
                                      {0x7012U, 0x0029U, 0xfffeU});
    }
    if (high_registers) {
        method.body.registers_size = 32U;
        // Same business body, but the dispatcher now needs v16..v255 forms.
        method.body.code_units.insert(method.body.code_units.begin(),
                                      {0x0302U, 30U, 0x0402U, 31U});
    }
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    return birch::dex::DexFile::Parse(builder.Build());
}

std::size_t CheckSemantics(bool high_registers, bool cold_component = false) {
    std::size_t comparisons = 0;
    const auto source = Fixture(high_registers, cold_component);
    birch::dex::VerifyDexOrThrow(source, birch::dex::VerificationLevel::Full);
    const auto original = birch::dex::DecodeCodeItem(
        source, source.class_data(0U).direct_methods.front().code_off);
    for (unsigned strategy = 0; strategy < 6U; ++strategy) {
        if ((high_registers || cold_component) && strategy != 5U) continue;
        for (std::uint64_t seed : {1ULL, 777331ULL, 0x123456789abcdefULL}) {
            auto config = birch::guard::GuardConfig::Defaults();
            for (auto& [id, pass] : config.passes) pass.enabled = false;
            config.seed = seed;
            config.scope.protect = {{"Lsemantic/**;"}};
            config.scope.keep.clear();
            config.strength.anti_automation_profile = false;
            config.budget.max_method_growth_ratio = 10000.0;
            config.budget.max_added_blocks_per_method = 256;
            const auto enable = [&](const char* id) {
                config.passes.at(id).enabled = true;
                config.passes.at(id).intensity = 1.0;
            };
            enable("cfg.flattening");
            if (strategy == 1U || strategy == 5U) enable("cfg.nested_flattening");
            if (strategy == 2U || strategy == 5U) enable("cfg.multi_state_dispatch");
            if (strategy == 3U || strategy == 5U) enable("cfg.mixed_ps_ss_if");
            if (strategy >= 4U) {
                enable("cfg.condition_expansion");
                enable("cfg.conditional_nesting");
                enable("cfg.bogus_edges");
                enable("cfg.dead_blocks");
                enable("anti_analysis.path_explosion");
            }
            if (strategy == 5U) {
                config.budget.max_added_blocks_per_method = 1024U;
                config.strength.anti_automation_profile = true;
                enable("strength.anti_automation_profile");
                enable("anti_analysis.register_shape");
            }
            const auto result = birch::guard::DexCodeLowering(config).Apply(source);
            assert(result.pass_applications.at("cfg.flattening") == 1U);
            if (strategy == 5U) assert(result.cfg_blocks_added >= 1024U);
            const auto output = birch::dex::DexFile::Parse(result.bytes);
            birch::dex::VerifyDexOrThrow(output, birch::dex::VerificationLevel::Full);
            const auto transformed = birch::dex::DecodeCodeItem(
                output, output.class_data(0U).direct_methods.front().code_off);
            assert(transformed.insns != original.insns);
            if (strategy == 5U) {
                assert(transformed.insns.size() <= 16000U);
                const auto shape = birch::test::MeasureCffShape(birch::dex::BuildMethodIr(transformed));
                std::cout << "seed=" << seed << " empty_gotos=" << shape.empty_gotos
                          << " fan_in=" << shape.max_empty_fan_in << " run=" << shape.max_empty_run
                          << " switches=" << shape.switches << " table=" << shape.largest_switch << '\n';
                assert(shape.max_empty_run <= 2U);
                assert(shape.max_empty_fan_in <= 16U);
                assert(shape.largest_switch <= 128U);
                assert(shape.switches >= 8U);
            }
            std::vector<std::uint32_t> values{
                0U, 1U, 15U, 16U, 0x7fffffffU, 0x80000000U, 0xffffffffU};
            auto random = static_cast<std::uint32_t>(seed);
            for (unsigned i = 0; i < 16U; ++i) {
                random = random * 1664525U + 1013904223U;
                values.push_back(random);
            }
            for (auto x : values) for (auto y : values) {
                const std::array args{x, y};
                const auto expected = (x & 0x80000000U) != 0U ?
                    0U - ((x & 15U) * y) : ((x & 15U) * y) ^ y;
                assert(birch::test::IntDexInterpreter::Execute(original, args) == expected);
                assert(birch::test::IntDexInterpreter::Execute(transformed, args) == expected);
                ++comparisons;
            }
        }
    }
    return comparisons;
}

std::size_t CheckLargeTypedMethod() {
    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lsemantic/LargeTyped;";
    birch::dex::MethodSpec method;
    method.name = "calculate";
    method.return_type = "I";
    method.parameter_types = {"I", "I"};
    method.access_flags = 0x0009U;
    method.body.registers_size = 32U;
    method.body.ins_size = 2U;
    // All locals have proven types; 64 diamonds share a verifier domain.
    // Exercise the unchanged 16000-unit gate with many live typed edges.
    for (std::uint16_t reg = 0U; reg < 30U; ++reg)
        method.body.code_units.insert(method.body.code_units.end(),
            {static_cast<std::uint16_t>(0x13U | (reg << 8U)), 1U});
    method.body.code_units.insert(method.body.code_units.end(),
        {0x0302U, 30U, 0x0402U, 31U});
    for (std::size_t i = 0U; i < 64U; ++i)
        method.body.code_units.insert(method.body.code_units.end(),
            {0x033aU, 6U, 0x0090U, 0x0400U, 0x0029U, 4U, 0x0097U, 0x0400U});
    method.body.code_units.push_back(0x000fU);
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    const auto source = birch::dex::DexFile::Parse(builder.Build());
    birch::dex::VerifyDexOrThrow(source, birch::dex::VerificationLevel::Full);
    const auto original = birch::dex::DecodeCodeItem(
        source, source.class_data(0U).direct_methods.front().code_off);
    std::size_t comparisons = 0U;
    for (std::uint64_t seed : {1ULL, 777331ULL, 0x123456789abcdefULL}) {
        auto config = birch::guard::GuardConfig::Defaults();
        for (auto& [id, pass] : config.passes) pass.enabled = false;
        config.seed = seed;
        config.scope.protect = {{"Lsemantic/**;"}};
        config.scope.keep.clear();
        config.strength.anti_automation_profile = true;
        config.budget.max_method_growth_ratio = 10000.0;
        config.budget.max_added_blocks_per_method = 1024U;
        for (const auto* id : {"cfg.flattening", "cfg.nested_flattening",
                "cfg.multi_state_dispatch", "cfg.mixed_ps_ss_if", "cfg.condition_expansion",
                "cfg.conditional_nesting", "cfg.bogus_edges", "cfg.dead_blocks",
                "anti_analysis.path_explosion", "anti_analysis.register_shape",
                "strength.anti_automation_profile"}) {
            config.passes.at(id).enabled = true;
            config.passes.at(id).intensity = 1.0;
        }
        const auto result = birch::guard::DexCodeLowering(config).Apply(source);
        assert(result.cfg_blocks_added >= 1024U);
        const auto output = birch::dex::DexFile::Parse(result.bytes);
        birch::dex::VerifyDexOrThrow(output, birch::dex::VerificationLevel::Full);
        // Outlining adds methods that sort before calculate. Never confuse
        // the first synthetic region with the original program's entry.
        const auto& methods = output.class_data(0U).direct_methods;
        const auto entry = std::find_if(methods.begin(), methods.end(), [&](const auto& candidate) {
            return output.method_key(candidate.method_idx) == "Lsemantic/LargeTyped;->calculate(II)I";
        });
        assert(entry != methods.end());
        assert(methods.size() > 1U);
        const auto transformed = birch::dex::DecodeCodeItem(
            output, entry->code_off);
        assert(transformed.insns.size() <= 16000U);
        const auto shape = birch::test::MeasureCffShape(birch::dex::BuildMethodIr(transformed));
        assert(shape.max_empty_fan_in <= 16U && shape.max_empty_run <= 2U);
        std::cout << "large typed seed=" << seed << " units=" << transformed.insns.size() << '\n';
        birch::test::StringDexInterpreter oracle(output);
        for (auto x : {0U, 1U, 0x7fffffffU, 0x80000000U, 0xffffffffU})
            for (auto y : {0U, 1U, 0x12345678U, 0x80000000U, 0xffffffffU}) {
                const std::array args{x, y};
                const auto expected = (x & 0x80000000U) != 0U ? 1U : 1U + 64U * y;
                assert(birch::test::IntDexInterpreter::Execute(original, args) == expected);
                const auto actual = oracle.ExecuteScalar("Lsemantic/LargeTyped;", "calculate", args, "(II)I");
                if (actual != expected) {
                    std::cerr << "large typed mismatch seed=" << seed << " x=" << x
                              << " y=" << y << " expected=" << expected
                              << " actual=" << actual << '\n';
                }
                assert(actual == expected);
                ++comparisons;
            }
    }
    return comparisons;
}

} // namespace

int main() {
    const auto comparisons = CheckSemantics(false) + CheckSemantics(true) +
        CheckSemantics(false, true) + CheckSemantics(true, true) + CheckLargeTypedMethod();
    std::cout << comparisons << " input/output semantic comparisons passed\n";
}
