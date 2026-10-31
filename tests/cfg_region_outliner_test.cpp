#include "cfg_region_outliner.h"
#include "cfg_region_planner.h"
#include "model_support.h"
#include "birch/dex/cloner.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "birch/io/file.h"
#include "support/cff_shape.h"
#include "support/string_dex_interpreter.h"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <iostream>

namespace {
using namespace birch;
using namespace guard::detail;
constexpr auto owner = "Lregions/Program;";

dex::DexFile Single(dex::MethodSpec method, bool wrapper = false, std::uint16_t input = 37U) {
    dex::ClassSpec klass;
    klass.descriptor = owner;
    if (wrapper) {
        dex::MethodSpec read;
        read.name = "read";
        read.return_type = "I";
        read.body.registers_size = read.body.outs_size = 1U;
        read.body.code_units = {0x0013U, input};
        AppendInvoke(read.body.code_units, 0x71U, {0U}, read.body, {owner, method.name, "I", {"I"}});
        read.body.code_units.insert(read.body.code_units.end(), {0x000aU, 0x000fU});
        klass.direct_methods.push_back(std::move(read));
    }
    klass.direct_methods.push_back(std::move(method));
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    return dex::DexFile::Parse(builder.Build());
}

dex::MethodSpec Branches(bool loop) {
    dex::MethodSpec run;
    run.name = "run";
    run.return_type = "I";
    run.parameter_types = {"I"};
    run.body.registers_size = 20U;
    run.body.ins_size = 1U;
    run.body.code_units = {0x0002U, 19U};
    for (unsigned i = 0; i < (loop ? 10U : 70U); ++i) {
        if (loop) run.body.code_units.insert(run.body.code_units.end(), {0x5212U}); // v2=5
        const auto start = run.body.code_units.size();
        const auto repeats = loop ? 7U : 1U;
        for (unsigned j = 0; j < repeats; ++j)
            run.body.code_units.insert(run.body.code_units.end(), {
                0x00d8U, 0x0100U, 0x01ddU, 0x0100U, // v0++; v1=v0&1
                0x0138U, 5U, 0x00d8U, 0x0300U, 0x0328U, 0x00d8U, 0x0700U});
        if (loop) {
            run.body.code_units.insert(run.body.code_units.end(), {0x02d8U, 0xff02U, 0x023aU});
            const auto at = run.body.code_units.size() - 1U;
            run.body.code_units.push_back(static_cast<std::uint16_t>(static_cast<std::int16_t>(
                static_cast<std::int64_t>(start) - static_cast<std::int64_t>(at))));
        }
    }
    run.body.code_units.push_back(0x000fU);
    return run;
}

std::uint32_t Execute(const dex::DexFile& file) {
    dex::VerifyDexOrThrow(file, dex::VerificationLevel::Full);
    test::StringDexInterpreter oracle(file, 2000000000ULL);
    return oracle.ExecuteScalar(owner, "read");
}

void ConditionalLiveOutput(const guard::GuardConfig& config) {
    dex::MethodSpec run;
    run.name = "run";
    run.return_type = "I";
    run.parameter_types = {"I"};
    run.body.registers_size = 20U;
    run.body.ins_size = 1U;
    run.body.code_units = {0x0002U, 19U};
    for (unsigned i = 0; i < 40U; ++i) {
        // When p0==0 the region writes no v0, but its helper must still
        // return the caller's old v0. There is no explicit region read of v0.
        run.body.code_units.insert(run.body.code_units.end(), {
            0x1338U, 4U, 0x0013U, static_cast<std::uint16_t>(100U + i)});
        for (unsigned j = 0; j < 28U; ++j)
            run.body.code_units.insert(run.body.code_units.end(), {0x0113U, 17U});
    }
    run.body.code_units.push_back(0x000fU);
    const auto file = Single(run);
    const auto& method = file.class_data(0U).direct_methods[0U];
    const auto plans = CfgRegionPlanner::Plan(file, method, dex::DecodeCodeItem(file, method.code_off), config);
    assert(std::any_of(plans.begin(), plans.end(), [](const auto& region) {
        return region.output && region.output->reg == 0U &&
            std::any_of(region.inputs.begin(), region.inputs.end(), [](const auto& value) { return value.reg == 0U; });
    }));
    for (const auto input : {0U, 37U}) {
        const auto source = Single(run, true, static_cast<std::uint16_t>(input));
        const auto expected = input == 0U ? 0U : 139U;
        assert(Execute(source) == expected);
        const auto outlined = CfgRegionOutliner::Apply(source, config);
        assert(outlined.regions > 2U);
        assert(Execute(dex::DexFile::Parse(outlined.bytes)) == expected);
        const auto lowered = guard::DexCodeLowering(config).Apply(source);
        assert(Execute(dex::DexFile::Parse(lowered.bytes)) == expected);
    }
}

void TypedBoundaries(const guard::GuardConfig& config) {
    for (const std::string type : {"I", "F", "J", "D", "Ljava/lang/String;"}) {
        const bool wide = type == "J" || type == "D";
        const bool ref = type.front() == 'L';
        dex::MethodSpec run;
        run.name = "typed";
        run.return_type = type;
        run.parameter_types = {type, "I"};
        run.body.registers_size = 20U;
        run.body.ins_size = wide ? 3U : 2U;
        const auto op = wide ? 0x05U : ref ? 0x08U : 0x02U;
        run.body.code_units = {static_cast<std::uint16_t>(op), static_cast<std::uint16_t>(wide ? 17U : 18U)};
        for (unsigned i = 0; i < 20U; ++i) {
            // One arm keeps the output, the other copies the typed parameter.
            run.body.code_units.insert(run.body.code_units.end(), {0x1338U, 4U,
                static_cast<std::uint16_t>(op), static_cast<std::uint16_t>(wide ? 17U : 18U)});
            for (unsigned j = 0; j < 30U; ++j) run.body.code_units.insert(run.body.code_units.end(), {0x0413U, 9U});
        }
        run.body.code_units.push_back(static_cast<std::uint16_t>(wide ? 0x10U : ref ? 0x11U : 0x0fU));
        const auto source = Single(run);
        dex::VerifyDexOrThrow(source, dex::VerificationLevel::Full);
        const auto outlined = CfgRegionOutliner::Apply(source, config);
        assert(outlined.regions > 2U);
        const auto final = dex::DexFile::Parse(outlined.bytes);
        dex::VerifyDexOrThrow(final, dex::VerificationLevel::Full);
        bool typed_return = false;
        for (const auto& id : final.methods()) if (final.string(id.name_idx) != "typed" &&
            final.descriptor(final.protos()[id.proto_idx].return_type_idx) == type) typed_return = true;
        assert(typed_return);
    }
}

void Exclusions(const guard::GuardConfig& config) {
    auto run = Branches(false);
    for (const auto flag : {0x0020U, 0x20000U}) {
        auto blocked = run;
        blocked.access_flags |= flag;
        assert(CfgRegionOutliner::Apply(Single(blocked), config).regions == 0U);
    }
    auto disabled = config;
    disabled.budget.max_call_depth_increase = 0U;
    assert(CfgRegionOutliner::Apply(Single(run), disabled).regions == 0U);
    disabled = config;
    disabled.scope.protect.clear();
    assert(CfgRegionOutliner::Apply(Single(run), disabled).regions == 0U);
    run.parameter_types = {"I", "I"};
    run.body.ins_size = 2U;
    run.body.code_units = {0x0002U, 18U, 0x0102U, 19U};
    for (unsigned i = 0; i < 180U; ++i)
        run.body.code_units.insert(run.body.code_units.end(), {0x00d8U, 0x0100U, 0x01d8U, 0x0101U});
    run.body.code_units.insert(run.body.code_units.end(), {0x10b0U, 0x000fU});
    const auto two_outputs = Single(run);
    const auto& method = two_outputs.class_data(0U).direct_methods[0U];
    const auto code = dex::DecodeCodeItem(two_outputs, method.code_off);
    const auto plans = CfgRegionPlanner::Plan(two_outputs, method, code, config);
    // Only the suffix that consumes both outputs is movable. A middle slice
    // would need two returns and must be rejected, not lose either register.
    assert(plans.size() == 1U && plans.front().end_offset == code.instructions.back().offset);

    // No uninitialized allocation may cross the new call boundary.
    dex::MethodSpec uninitialized;
    uninitialized.name = "allocation";
    uninitialized.body.registers_size = uninitialized.body.outs_size = 2U;
    uninitialized.body.code_units = {0x0022U, 0U};
    uninitialized.body.references.push_back({dex::TypeReference{"Ljava/lang/Object;"}, 1U, false});
    uninitialized.body.code_units.insert(uninitialized.body.code_units.end(), 800U, 0x0107U);
    AppendInvoke(uninitialized.body.code_units, 0x70U, {1U}, uninitialized.body,
        {"Ljava/lang/Object;", "<init>", "V", {}});
    uninitialized.body.code_units.push_back(0x000eU);
    const auto original = Single(uninitialized);
    const auto outlined = CfgRegionOutliner::Apply(original, config);
    // Whole allocation+initialization cannot fit a region, and neither input
    // nor live output can transport its uninitialized identity.
    assert(outlined.regions == 0U);
}

void WriterBoundaries() {
    const auto file = Single(Branches(false));
    const auto& method = file.class_data(0U).direct_methods[0];
    auto reject = [&](dex::CodePrefix prefix) {
        prefix.code_off = method.code_off;
        bool threw = false;
        try { (void)dex::RewriteCodePrefixes(file, {prefix}); }
        catch (const std::exception&) { threw = true; }
        assert(threw);
    };
    dex::CodePrefix overlap;
    overlap.linear_replacements.emplace(2U, std::vector<std::uint16_t>{0x0012U});
    overlap.outline_span_ends.emplace(2U, 13U);
    overlap.arithmetic_span_ends.emplace(2U, 4U);
    reject(overlap);
    overlap.arithmetic_span_ends.clear();
    overlap.outline_span_ends = {{4U, 13U}}; // external goto enters interior / missing replacement
    reject(overlap);
    overlap.outline_span_ends = {{2U, 9U}}; // outgoing branch beyond continuation
    reject(overlap);
    overlap.outline_span_ends = {{3U, 13U}}; // noninstruction boundary
    reject(overlap);
}

void Relocation() {
    // Jumbo promotion pushes an if-eqz beyond int16 and creates two
    // instructions. The map must point past that inserted goto/32.
    dex::MethodSpec run;
    run.name = "layout";
    run.body.registers_size = 1U;
    run.body.code_units = {0x0012U, 0x0038U, 32767U, 0x001aU, 0U};
    run.body.references.push_back({std::string("zzzz"), 4U, false});
    run.body.code_units.resize(32768U, 0U);
    run.body.code_units.push_back(0x000eU);
    dex::ClassSpec klass;
    klass.descriptor = owner;
    klass.direct_methods.push_back(std::move(run));
    dex::DexBuilder builder;
    builder.AddClass(klass);
    for (unsigned i = 0; i < 65536U; ++i) builder.AddString("a" + std::to_string(i));
    dex::CodeAddressMaps maps;
    const auto file = dex::DexFile::Parse(builder.Build(&maps));
    const auto& map = maps.at(std::string(owner) + "->layout()V");
    assert(map.at(3U) == 6U && map.at(5U) == 9U && map.at(32768U) == 32772U);
    const auto code = dex::DecodeCodeItem(file, file.class_data(0U).direct_methods[0U].code_off);
    assert(code.instructions[1U].opcode == 0x39U && code.instructions[2U].opcode == 0x2aU);
    dex::VerifyDexOrThrow(file, dex::VerificationLevel::Full);
}
}

int main() {
    auto config = guard::GuardConfig::Parse(io::ReadTextFile(
        std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs/release_full.json"));
    config.scope.protect = {{"Lregions/**;"}};
    config.scope.keep.clear();
    ConditionalLiveOutput(config);
    TypedBoundaries(config);
    Exclusions(config);
    WriterBoundaries();
    Relocation();
    for (bool loop : {false, true}) {
        const auto source = Single(Branches(loop), true);
        const auto expected = Execute(source);
        const auto result = CfgRegionOutliner::Apply(source, config);
        assert(result.methods == 1U && result.regions > 2U && result.moved_code_units > 512U);
        assert(Execute(dex::DexFile::Parse(result.bytes)) == expected);
        for (const auto seed : {1ULL, 777331ULL, 16919314818285478265ULL}) {
            config.seed = seed;
            const auto lowered = guard::DexCodeLowering(config).Apply(source);
            const auto final = dex::DexFile::Parse(lowered.bytes);
            assert(Execute(final) == expected);
            for (const auto& method : final.class_data(0U).direct_methods) {
                const auto code = dex::DecodeCodeItem(final, method.code_off);
                const auto ir = dex::BuildMethodIr(code);
                assert(code.insns.size() <= 16000U && ir.blocks().size() >= 1024U);
                const auto shape = test::MeasureCffShape(ir);
                assert(shape.max_empty_fan_in <= 16U && shape.max_empty_run <= 2U);
            }
            std::cout << "cfg regions loop=" << loop << " seed=" << seed << " passed\n";
        }
    }
}
