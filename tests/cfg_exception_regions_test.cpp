#include "cfg_region_planner.h"
#include "cff_partition_planner.h"
#include "model_runtime.h"
#include "birch/dex/builder.h"
#include "birch/dex/cloner.h"
#include "birch/dex/region_exception_contract.h"
#include "birch/dex/monitor_depth.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "birch/io/file.h"
#include "support/cff_shape.h"
#include "support/string_dex_interpreter.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <filesystem>
#include <iostream>

namespace {
using namespace birch;
using namespace guard::detail;
constexpr auto owner = "Lexception_regions/Program;";

dex::DexFile Fixture(unsigned locks, bool handler_reads_output = false, unsigned repeats = 35U) {
    dex::ClassSpec klass;
    klass.descriptor = owner;
    dex::MethodSpec maybe;
    maybe.name = "maybe";
    maybe.parameter_types = {"I"};
    maybe.body.registers_size = 2U;
    maybe.body.ins_size = 1U;
    // Negative input throws null (NPE); nonnegative input returns normally.
    maybe.body.code_units = {0x013bU, 4U, 0x0012U, 0x0027U, 0x000eU};
    klass.direct_methods.push_back(std::move(maybe));

    dex::MethodSpec run;
    run.name = "run";
    run.return_type = "I";
    run.parameter_types = {"I"};
    run.body.registers_size = 20U;
    run.body.ins_size = run.body.outs_size = 1U;
    auto& u = run.body.code_units;
    u = {0x0002U, 19U, 0x021cU, 0U}; // v0=p0; v2=class object
    run.body.references.push_back({dex::TypeReference{owner}, 3U, false});
    for (unsigned i = 0; i < locks; ++i) u.push_back(0x021dU);
    const auto start = static_cast<std::uint32_t>(u.size());
    for (unsigned i = 0; i < repeats; ++i) {
        u.insert(u.end(), {0x00d8U, 0x0100U}); // v0++
        if (i == repeats / 2U) {
            const auto at = static_cast<std::uint32_t>(u.size());
            u.insert(u.end(), {0x0177U, 0U, 19U});
            run.body.references.push_back({dex::MethodReference{owner, "maybe", "V", {"I"}}, at + 1U, false});
        }
    }
    const auto end = static_cast<std::uint32_t>(u.size());
    for (unsigned i = 0; i < locks; ++i) u.push_back(0x021eU);
    u.push_back(0x000fU);
    const auto handler = static_cast<std::uint32_t>(u.size());
    u.push_back(0x030dU);
    for (unsigned i = 0; i < locks; ++i) u.push_back(0x021eU);
    if (!handler_reads_output) u.insert(u.end(), {0x0013U, 0xfff9U});
    u.push_back(0x000fU);
    run.body.try_regions.push_back({start, end - start,
        {{locks ? std::optional<std::string>{} : std::string("Ljava/lang/RuntimeException;"), handler}}});
    klass.direct_methods.push_back(std::move(run));
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    return dex::DexFile::Parse(builder.Build());
}

const dex::DexEncodedMethod& Run(const dex::DexFile& file) {
    for (const auto& m : file.class_data(0U).direct_methods)
        if (file.string(file.methods()[m.method_idx].name_idx) == "run") return m;
    throw std::runtime_error("fixture run method missing");
}

void Equivalent(const dex::DexFile& file, unsigned repeats, bool reads_output = false) {
    dex::VerifyDexOrThrow(file, dex::VerificationLevel::Full);
    test::StringDexInterpreter oracle(file, 2000000000ULL);
    for (const auto input : {0U, 37U, 0x7fffffffU, 0x80000000U, 0xffffffffU}) {
        const std::array args{input};
        const auto expected = (input & 0x80000000U) == 0U ? input + repeats :
            reads_output ? input + repeats / 2U + 1U : 0xfffffff9U;
        assert(oracle.ExecuteScalar(owner, "run", args, "(I)I") == expected);
    }
}

void Boundaries(const guard::GuardConfig& config) {
    const auto file = Fixture(2U);
    const auto& method = Run(file);
    const auto code = dex::DecodeCodeItem(file, method.code_off);
    const auto& t = code.tries.front();
    const auto start = t.start_address, end = start + t.instruction_count;
    assert(dex::RegionExceptionContract::Prove(code, start, end));
    const dex::MethodMonitorDepth monitors(dex::BuildMethodIr(code));
    assert(monitors.DefinitelyEmpty(0U));
    assert(!monitors.DefinitelyEmpty(start));
    assert(!monitors.DefinitelyEmpty(end));
    assert(monitors.DefinitelyEmpty(end + 2U));
    assert(!dex::RegionExceptionContract::Prove(code, start - 1U, end));
    assert(!dex::RegionExceptionContract::Prove(code, start, end + 1U));
    assert(!dex::RegionExceptionContract::Prove(code, t.handlers.front().address,
        static_cast<std::uint32_t>(code.insns.size())));
    // Writer independently rechecks monitor/context boundaries; a planner
    // cannot smuggle monitor-enter or an exception entry into a replacement.
    for (const auto bounds : {std::pair{start - 1U, end}, std::pair{start, end + 1U}}) {
        dex::CodePrefix prefix;
        prefix.code_off = method.code_off;
        prefix.linear_replacements.emplace(bounds.first, std::vector<std::uint16_t>{0U});
        prefix.outline_span_ends.emplace(bounds.first, bounds.second);
        bool rejected = false;
        try { (void)dex::RewriteCodePrefixes(file, {prefix}); }
        catch (const std::invalid_argument&) { rejected = true; }
        assert(rejected);
    }
    const auto observes = Fixture(1U, true);
    Equivalent(observes, 35U, true);
    const auto& blocked = Run(observes);
    assert(CfgRegionPlanner::Plan(observes, blocked,
        dex::DecodeCodeItem(observes, blocked.code_off), config).empty());

    auto typed_lock = dex::DexClassCloner(file).Clone(0U);
    for (auto& m : typed_lock.direct_methods) if (m.name == "run")
        m.body.try_regions.front().handlers.front().type = "Ljava/lang/RuntimeException;";
    dex::DexBuilder builder;
    builder.AddClass(std::move(typed_lock));
    const auto unsafe = dex::DexFile::Parse(builder.Build());
    const auto& unsafe_method = Run(unsafe);
    // A typed catch cannot authorize introducing arbitrary throwing calls
    // while locked, even when every moved original instruction was legal.
    assert(CfgRegionPlanner::Plan(unsafe, unsafe_method,
        dex::DecodeCodeItem(unsafe, unsafe_method.code_off), config).empty());
}

void HandlerEntryTypes(const guard::GuardConfig& config) {
    for (const bool old_reference : {false, true}) {
        auto klass = dex::DexClassCloner(Fixture(0U)).Clone(0U);
        for (auto& method : klass.direct_methods) if (method.name == "run") {
            auto& body = method.body;
            body.code_units = {0x0002U, 19U, 0x021cU, 0U};
            body.references = {{dex::TypeReference{owner}, 3U, false}};
            if (old_reference) body.code_units.push_back(0x2407U); // v4=v2, reference
            const auto start = static_cast<std::uint32_t>(body.code_units.size());
            for (unsigned i = 0; i < 20U; ++i)
                body.code_units.insert(body.code_units.end(), {0x00d8U, 0x0100U});
            // v4 is undefined (or a reference) throughout the arithmetic,
            // but all original throws see the subsequently assigned int.
            body.code_units.insert(body.code_units.end(), {0x0402U, 19U});
            const auto invoke = static_cast<std::uint32_t>(body.code_units.size());
            body.code_units.insert(body.code_units.end(), {0x0177U, 0U, 19U});
            body.references.push_back({dex::MethodReference{owner, "maybe", "V", {"I"}}, invoke + 1U, false});
            const auto end = static_cast<std::uint32_t>(body.code_units.size());
            body.code_units.push_back(0x000fU);
            const auto handler = static_cast<std::uint32_t>(body.code_units.size());
            body.code_units.insert(body.code_units.end(), {0x030dU, 0x040fU});
            body.try_regions = {{start, end - start, {{std::nullopt, handler}}}};
        }
        dex::DexBuilder builder;
        builder.AddClass(std::move(klass));
        const auto file = dex::DexFile::Parse(builder.Build());
        dex::VerifyDexOrThrow(file, dex::VerificationLevel::Full);
        const auto& method = Run(file);
        assert(CfgRegionPlanner::Plan(file, method,
            dex::DecodeCodeItem(file, method.code_off), config, 32U).empty());
        test::StringDexInterpreter oracle(file);
        for (const auto input : {37U, 0xffffffffU}) {
            const std::array args{input};
            assert(oracle.ExecuteScalar(owner, "run", args, "(I)I") ==
                ((input & 0x80000000U) ? input : input + 20U));
        }
    }
}

void UnknownMonitorDepth() {
    // Deliberately non-verifier-valid CFG, used only to check the conservative
    // lattice: the join has incoming depths 0 and 1, never definitely empty.
    dex::MethodSpec run;
    run.name = "run";
    run.body.registers_size = 1U;
    run.body.code_units = {0x0038U, 3U, 0x001dU, 0x0000U, 0x000eU};
    dex::ClassSpec klass;
    klass.descriptor = owner;
    klass.direct_methods.push_back(std::move(run));
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    const auto file = dex::DexFile::Parse(builder.Build());
    const auto& method = Run(file);
    const dex::MethodMonitorDepth monitors(dex::BuildMethodIr(dex::DecodeCodeItem(file, method.code_off)));
    assert(monitors.DefinitelyEmpty(0U));
    assert(!monitors.DefinitelyEmpty(3U));
    assert(!monitors.DefinitelyEmpty(4U));
    assert(!monitors.DefinitelyEmpty(99U));
}

void Check(unsigned locks, unsigned repeats, const guard::GuardConfig& config, bool lower) {
    const auto source = Fixture(locks, false, repeats);
    Equivalent(source, repeats);
    const auto& method = Run(source);
    const auto code = dex::DecodeCodeItem(source, method.code_off);
    const auto plans = CfgRegionPlanner::Plan(source, method, code, config);
    assert(!plans.empty());
    assert(std::any_of(plans.begin(), plans.end(), [&](const auto& plan) {
        for (auto i = plan.first; i < plan.end; ++i)
            if (code.instructions[i].opcode == 0x77U) return true;
        return false;
    }));
    const CffPartitionRequired feedback({{source.method_key(method.method_idx), "synthetic exact-layout feedback"}});
    const auto outlined = CffPartitionPlanner::Refine(source, config, feedback);
    const auto output = dex::DexFile::Parse(outlined.bytes);
    Equivalent(output, repeats);
    for (const auto& m : output.class_data(0U).direct_methods) {
        const auto c = dex::DecodeCodeItem(output, m.code_off);
        const auto name = output.string(output.methods()[m.method_idx].name_idx);
        const auto count = static_cast<unsigned>(std::count_if(c.instructions.begin(), c.instructions.end(),
            [](const auto& i) { return i.opcode == 0x1dU; }));
        assert(count == (name == "run" ? locks : 0U));
    }
    if (!lower) return;
    // The code-lowering stage consumes the same typed runtime barrier that
    // the production model stage injects. Keep the synthetic business CFG
    // unchanged instead of disabling constant protection for this test.
    dex::DexBuilder runtime_builder;
    dex::DexClassCloner cloner(output);
    for (std::size_t c = 0; c < output.classes().size(); ++c)
        runtime_builder.AddClass(cloner.Clone(c));
    runtime_builder.AddClass(ModelRuntimeBuilder::BuildConstantBarrierHelper(
        {owner}, config.seed, config.seed));
    const auto prepared = dex::DexFile::Parse(runtime_builder.Build());
    const auto lowered = guard::DexCodeLowering(config).Apply(prepared);
    const auto final = dex::DexFile::Parse(lowered.bytes);
    Equivalent(final, repeats);
    std::size_t checked = 0U;
    for (std::size_t c = 0; c < final.classes().size(); ++c) {
      if (final.descriptor(final.classes()[c].class_idx) != owner) continue;
      for (const auto& m : final.class_data(c).direct_methods) {
        const auto c = dex::DecodeCodeItem(final, m.code_off);
        const auto ir = dex::BuildMethodIr(c);
        assert(c.insns.size() <= 16000U && ir.blocks().size() >= 1024U);
        const auto shape = test::MeasureCffShape(ir);
        assert(shape.max_empty_fan_in <= 16U && shape.max_empty_run <= 2U);
        ++checked;
      }
    }
    assert(checked > 2U);
}
} // namespace

int main() {
    auto config = guard::GuardConfig::Parse(io::ReadTextFile(
        std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs/release_full.json"));
    config.scope.protect = {{"Lexception_regions/**;"}};
    config.scope.keep.clear();
    Boundaries(config);
    HandlerEntryTypes(config);
    UnknownMonitorDepth();
    Check(0U, 35U, config, false);
    Check(1U, 35U, config, false);
    Check(2U, 35U, config, true);
    // Below the obsolete 48-unit source floor, but profitable after a typed
    // call; exercise feedback rather than a special class/seed exemption.
    Check(1U, 14U, config, false);
    std::cout << "uniform catches, caller-owned locks, cross-frame throws, live handler rejection and short regions passed\n";
}
