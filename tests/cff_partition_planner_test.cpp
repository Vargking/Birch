#include "cff_partition_planner.h"
#include "cfg_region_planner.h"
#include "birch/dex/builder.h"
#include "birch/dex/verifier.h"
#include "birch/dex/region_exception_contract.h"
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
constexpr auto owner = "Lpartition/Program;";
constexpr auto first_key = "Lpartition/Program;->first(I)I";
constexpr auto second_key = "Lpartition/Program;->second(I)I";

dex::MethodSpec Program(std::string name, bool backwards = false) {
    dex::MethodSpec method;
    method.name = std::move(name);
    method.return_type = "I";
    method.parameter_types = {"I"};
    method.body.registers_size = 20U;
    method.body.ins_size = 1U;
    auto& units = method.body.code_units;
    units = {0x0002U, 19U, 0x021cU, 0U}; // v0=p0; v2=class monitor
    method.body.references.push_back({dex::TypeReference{owner}, 3U, false});
    if (backwards) units.insert(units.end(), {0x0029U, 0U});
    const auto prefix = static_cast<std::uint32_t>(units.size());
    // <512 source units and fewer than 48 basic blocks: the old up-front
    // heuristic intentionally leaves this method alone.
    for (unsigned i = 0; i < 10U; ++i)
        units.insert(units.end(), {0x00d8U, 0x0100U, 0x01ddU, 0x0100U,
            0x0138U, 5U, 0x00d8U, 0x0300U, 0x0328U, 0x00d8U, 0x0700U});
    const auto monitor = static_cast<std::uint32_t>(units.size());
    units.push_back(0x021dU);
    const auto start = static_cast<std::uint32_t>(units.size());
    units.insert(units.end(), {0x021fU, 0U}); // throwable instruction gives the handler a real type frame
    method.body.references.push_back({dex::TypeReference{"Ljava/lang/Class;"}, start + 1U, false});
    for (unsigned i = 0; i < 30U; ++i) units.insert(units.end(), {0x00d8U, 0x0100U});
    if (backwards) {
        // The textual prefix is also reachable while locked. Outlining is
        // safe only when the caller retains every monitor instruction.
        units.insert(units.end(), {0x003aU, static_cast<std::uint16_t>(
            static_cast<std::int32_t>(prefix) - static_cast<std::int32_t>(units.size()))});
        units[5U] = static_cast<std::uint16_t>(monitor - 4U);
    }
    const auto end = static_cast<std::uint32_t>(units.size());
    units.insert(units.end(), {0x021eU, 0x000fU});
    const auto handler = static_cast<std::uint32_t>(units.size());
    units.insert(units.end(), {0x030dU, 0x021eU, 0x0327U});
    method.body.try_regions.push_back({start, end - start, {{std::nullopt, handler}}});
    return method;
}

dex::DexFile Fixture(bool backwards = false) {
    dex::ClassSpec klass;
    klass.descriptor = owner;
    klass.direct_methods = {Program("first", backwards), Program("second", backwards)};
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    return dex::DexFile::Parse(builder.Build());
}

void Equivalent(const dex::DexFile& before, const dex::DexFile& after) {
    dex::VerifyDexOrThrow(after, dex::VerificationLevel::Full);
    test::StringDexInterpreter original(before, 2000000000ULL), transformed(after, 2000000000ULL);
    for (const auto name : {"first", "second"})
        for (const auto input : {0U, 1U, 37U, 0x7fffffffU, 0x80000000U, 0xffffffffU}) {
            const std::array args{input};
            assert(original.ExecuteScalar(owner, name, args, "(I)I") ==
                   transformed.ExecuteScalar(owner, name, args, "(I)I"));
        }
}

void FailClosed(const dex::DexFile& file, const guard::GuardConfig& config,
                const CffPartitionRequired& request) {
    bool rejected = false;
    try { (void)CffPartitionPlanner::Refine(file, config, request); }
    catch (const std::length_error& error) {
        rejected = std::string(error.what()).find("original-layout-diagnostic") != std::string::npos;
    }
    assert(rejected);
}
}

int main() {
    auto config = guard::GuardConfig::Parse(io::ReadTextFile(
        std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs/release_full.json"));
    config.scope.protect = {{"Lpartition/**;"}};
    config.scope.keep.clear();
    config.seed = 16919314818285478265ULL;
    const CffPartitionRequired request({{first_key, "original-layout-diagnostic"},
                                       {second_key, "second-layout-diagnostic"}});
    assert(request.failures().size() == 2U);
    assert(std::string(request.what()).find("over-budget methods=2") != std::string::npos);
    const auto source = Fixture();
    dex::VerifyDexOrThrow(source, dex::VerificationLevel::Full);
    assert(CfgRegionOutliner::Apply(source, config).bytes.empty());
    const auto refined = CffPartitionPlanner::Refine(source, config, request);
    assert(refined.methods == 2U && refined.regions >= 2U);
    const auto output = dex::DexFile::Parse(refined.bytes);
    Equivalent(source, output);
    for (const auto& method : source.class_data(0U).direct_methods) {
        const auto code = dex::DecodeCodeItem(source, method.code_off);
        const auto plans = CfgRegionPlanner::Plan(source, method, code, config, 96U);
        assert(!plans.empty());
        for (const auto& plan : plans) {
            assert(dex::RegionExceptionContract::Prove(code, plan.start_offset, plan.end_offset));
            for (auto i = plan.first; i < plan.end; ++i)
                assert(code.instructions[i].opcode != 0x1dU && code.instructions[i].opcode != 0x1eU);
        }
    }
    // Holding a monitor is not itself a reason to reject a call boundary.
    // Backward edges must not make the lock instructions move into a helper.
    const auto backwards = CffPartitionPlanner::Refine(Fixture(true), config, request);
    const auto backwards_file = dex::DexFile::Parse(backwards.bytes);
    dex::VerifyDexOrThrow(backwards_file, dex::VerificationLevel::Full);
    for (const auto& method : backwards_file.class_data(0U).direct_methods) {
        const auto name = backwards_file.string(backwards_file.methods()[method.method_idx].name_idx);
        const auto code = dex::DecodeCodeItem(backwards_file, method.code_off);
        if (name == "first" || name == "second") continue;
        for (const auto& ins : code.instructions) assert(ins.opcode != 0x1dU && ins.opcode != 0x1eU);
    }
    auto disabled = config;
    disabled.budget.max_call_depth_increase = 0U;
    FailClosed(source, disabled, request);
    FailClosed(source, config, CffPartitionRequired({{"Lmissing/Type;->absent()V", "original-layout-diagnostic"}}));
    // The normal production path must preserve the lock and every integer
    // boundary result; all generated helpers still receive full protection.
    const auto lowered = guard::DexCodeLowering(config).Apply(source);
    const auto final = dex::DexFile::Parse(lowered.bytes);
    Equivalent(source, final);
    for (const auto& method : final.class_data(0U).direct_methods) {
        const auto code = dex::DecodeCodeItem(final, method.code_off);
        const auto ir = dex::BuildMethodIr(code);
        assert(code.insns.size() <= 16000U && ir.blocks().size() >= 1024U);
        const auto shape = test::MeasureCffShape(ir);
        assert(shape.max_empty_fan_in <= 16U && shape.max_empty_run <= 2U);
    }
    std::cout << "adaptive multi-method partition, monitor proof, semantics and fail-closed passed\n";
}
