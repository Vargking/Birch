#include "constant_program_outliner.h"
#include "cff_partition_planner.h"
#include "model_runtime.h"
#include "model_support.h"
#include "birch/dex/builder.h"
#include "birch/dex/ir.h"
#include "birch/dex/remap.h"
#include "birch/dex/verifier.h"
#include "birch/guard/constant_runtime.h"
#include "birch/guard/dex_lowering.h"
#include "birch/guard/model_lowering.h"
#include "birch/io/file.h"
#include "support/cff_shape.h"
#include "support/string_dex_interpreter.h"

#include <array>
#include <bit>
#include <cassert>
#include <filesystem>
#include <iostream>

namespace {
using namespace birch;
using namespace birch::guard::detail;
constexpr auto owner = "Loutline/Constants;";
constexpr std::size_t count = 48U;
constexpr std::array<std::uint32_t, 8U> values{
    0U, 1U, 0xffffffffU, 0x80000000U, 0x7fffffffU,
    0x3f800000U, 0x7fc12345U, 0xdeadbeefU};

std::uint32_t Value(std::size_t i) { return values[i % values.size()] ^ static_cast<std::uint32_t>(i / values.size()); }

dex::DexFile Fixture(bool materialized, std::uint64_t seed, std::size_t program_count = count) {
    auto barrier = ModelRuntimeBuilder::BuildConstantBarrierHelper({}, seed, seed);
    dex::ClassSpec klass;
    klass.descriptor = owner;
    for (unsigned variant = 0; variant < 4U; ++variant) {
        const bool floating = variant == 2U;
        const bool reference = variant == 3U;
        const std::uint16_t reg = variant == 1U ? 15U : 1U;
        dex::MethodSpec method;
        method.name = std::array{"intLow", "intHigh", "floatBits", "nulls"}[variant];
        method.return_type = "I";
        method.body.registers_size = variant == 1U ? 253U : 2U;
        method.body.outs_size = 1U;
        auto& code = method.body.code_units;
        code = {0x0012U};
        for (std::size_t i = 0; i < program_count; ++i) {
            auto initial = reference ? 0U : Value(i);
            std::array<std::int16_t, 56U> literals{};
            if (materialized) {
                for (std::size_t step = 0; step < literals.size(); ++step)
                    literals[step] = std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(i * 751U + step * 131U + 0x8001U));
                for (auto step = literals.size(); step != 0U;) {
                    --step;
                    const auto literal = static_cast<std::uint32_t>(static_cast<std::int32_t>(literals[step]));
                    if ((step & 1U) == 0U) initial ^= literal;
                    else initial -= literal;
                }
            }
            code.insert(code.end(), {static_cast<std::uint16_t>(0x14U | (reg << 8U)),
                static_cast<std::uint16_t>(initial), static_cast<std::uint16_t>(initial >> 16U)});
            if (materialized) {
                for (std::size_t step = 0; step < literals.size(); ++step)
                    code.insert(code.end(), {static_cast<std::uint16_t>(((step & 1U) == 0U ? 0xd7U : 0xd0U) | (reg << 8U) | (reg << 12U)),
                        static_cast<std::uint16_t>(literals[step])});
                AppendInvoke35c(code, 0x71U, {reg}, method.body,
                    {barrier.descriptor, floating ? guard::RuntimeFloatConstantMethodName(seed) :
                        reference ? guard::RuntimeNullConstantMethodName(seed) : guard::RuntimeConstantMethodName(seed),
                        floating ? "F" : reference ? "Ljava/lang/Object;" : "I", {"I"}});
                code.push_back(static_cast<std::uint16_t>((reference ? 0x0cU : 0x0aU) | (reg << 8U)));
            } else if (floating) {
                AppendInvoke35c(code, 0x71U, {reg}, method.body,
                    {"Ljava/lang/Float;", "intBitsToFloat", "F", {"I"}});
                code.push_back(static_cast<std::uint16_t>(0x0aU | (reg << 8U)));
            }
            if (floating) {
                AppendInvoke35c(code, 0x71U, {reg}, method.body,
                    {"Ljava/lang/Float;", "floatToRawIntBits", "I", {"F"}});
                code.push_back(static_cast<std::uint16_t>(0x0aU | (reg << 8U)));
            }
            if (reference) {
                code.insert(code.end(), {static_cast<std::uint16_t>(0x1fU | (reg << 8U)), 0U});
                method.body.references.push_back({dex::TypeReference{"Ljava/lang/String;"},
                    static_cast<std::uint32_t>(code.size() - 1U), false});
                code.insert(code.end(), {static_cast<std::uint16_t>(0x38U | (reg << 8U)), 3U, 0x1012U});
            } else {
                code.insert(code.end(), {0x00daU, 0x1f00U}); // mul-int/lit8 v0, v0, 31
                code.insert(code.end(), {0x0097U, static_cast<std::uint16_t>(reg << 8U)});
            }
        }
        code.push_back(0x000fU);
        klass.direct_methods.push_back(std::move(method));
    }
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    if (materialized) builder.AddClass(std::move(barrier));
    return dex::DexFile::Parse(builder.Build());
}

void Check(const dex::DexFile& file, std::size_t program_count = count) {
    dex::VerifyDexOrThrow(file, dex::VerificationLevel::Full);
    test::StringDexInterpreter runtime(file, 500000000U);
    std::uint32_t expected = 0U;
    for (std::size_t i = 0; i < program_count; ++i) expected = (expected * 31U) ^ Value(i);
    assert(expected != 0U); // a broken decoder returning only zero must not pass
    for (const auto name : {"intLow", "intHigh", "floatBits"})
        assert(runtime.ExecuteScalar(owner, name) == expected);
    assert(runtime.ExecuteScalar(owner, "nulls") == 0U);
}

std::size_t CountArithmetic(const dex::DexFile& file) {
    std::size_t count_steps = 0U;
    for (std::size_t c = 0; c < file.classes().size(); ++c)
        for (const auto& method : file.class_data(c).direct_methods)
            if (method.code_off)
                for (const auto& instruction : dex::DecodeCodeItem(file, method.code_off).instructions)
                    count_steps += instruction.opcode == 0xd0U || instruction.opcode == 0xd7U;
    return count_steps;
}

void CheckSpanBoundaries() {
    // A live branch into a candidate's arithmetic interior must be rejected,
    // even if its register types happen to agree after relocation.
    for (const bool live_entry : {false, true}) {
        dex::ClassSpec klass;
        klass.descriptor = "Loutline/Span;";
        dex::MethodSpec method;
        method.name = "read";
        method.return_type = "I";
        method.body.registers_size = 1U;
        method.body.code_units = {0x0014U, 1U, 0U, 0x0038U, static_cast<std::uint16_t>(live_entry ? 7U : 9U),
            0x0014U, 10U, 0U, 0x00d7U, 2U, 0x00d0U, 3U, 0x000fU};
        klass.direct_methods.push_back(std::move(method));
        dex::DexBuilder builder;
        builder.AddClass(std::move(klass));
        const auto source = dex::DexFile::Parse(builder.Build());
        dex::CodePrefix prefix;
        prefix.code_off = source.class_data(0U).direct_methods.front().code_off;
        prefix.linear_replacements.emplace(5U, std::vector<std::uint16_t>{0x0014U, 11U, 0U});
        prefix.arithmetic_span_ends.emplace(5U, 12U);
        bool rejected = false;
        try {
            const auto output = dex::DexFile::Parse(dex::RewriteCodePrefixes(source, {prefix}));
            test::StringDexInterpreter runtime(output);
            assert(runtime.ExecuteScalar("Loutline/Span;", "read") == 11U);
        } catch (const std::invalid_argument&) { rejected = true; }
        assert(rejected == live_entry);
    }
}
} // namespace

int main() {
    CheckSpanBoundaries();
    auto config = guard::GuardConfig::Parse(io::ReadTextFile(
        std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs/release_full.json"));
    config.scope.protect = {{"Loutline/**;"}};
    config.scope.keep.clear();
    for (const auto seed : {1ULL, 777331ULL, 20260821ULL}) {
        config.seed = seed;
        const auto source = Fixture(true, seed);
        Check(source);
        const auto outlined = ConstantProgramOutliner::Apply(source, config);
        assert(outlined.programs == count * 4U);
        assert(outlined.arithmetic_steps == count * 4U * 56U);
        assert(outlined.helpers > 1U && outlined.helpers < outlined.programs);
        const auto output = dex::DexFile::Parse(outlined.bytes);
        assert(CountArithmetic(source) == CountArithmetic(output));
        Check(output);

        // A real monitor-isolated dispatcher exceeded 16000 with only ~1500
        // materialized units. These callers must not miss constant factoring.
        const auto medium = Fixture(true, seed, 10U);
        for (std::size_t c = 0; c < medium.classes().size(); ++c)
            if (medium.descriptor(medium.classes()[c].class_idx) == owner)
                for (const auto& method : medium.class_data(c).direct_methods) {
                    const auto units = dex::DecodeCodeItem(medium, method.code_off).insns.size();
                    assert(units >= 1024U && units < 2048U);
                }
        const auto medium_outlined = ConstantProgramOutliner::Apply(medium, config);
        assert(medium_outlined.programs == 40U);
        const auto medium_output = dex::DexFile::Parse(medium_outlined.bytes);
        assert(CountArithmetic(medium) == CountArithmetic(medium_output));
        Check(medium_output, 10U);

        // Exact layout feedback must also reach callers below the ordinary
        // source-size threshold, without extracting unrelated methods.
        const auto tiny = Fixture(true, seed, 2U);
        assert(ConstantProgramOutliner::Apply(tiny, config).bytes.empty());
        const CffPartitionRequired request({{std::string(owner) + "->intLow()I", "tiny-layout"}});
        const auto targeted = CffPartitionPlanner::OutlineConstants(tiny, config, request);
        assert(targeted.programs == 2U && targeted.helpers == 1U);
        const auto tiny_output = dex::DexFile::Parse(targeted.bytes);
        assert(CountArithmetic(tiny) == CountArithmetic(tiny_output));
        Check(tiny_output, 2U);
        auto no_calls = config;
        no_calls.budget.max_call_depth_increase = 0U;
        assert(CffPartitionPlanner::OutlineConstants(tiny, no_calls, request).bytes.empty());

        // A few hundred source units become thousands during materialization.
        // Exercise the production two-stage path, not only the extraction API.
        const auto small = Fixture(false, seed);
        Check(small);
        const auto modeled = guard::DexModelLowering(config).Apply(small);
        const auto model = dex::DexFile::Parse(modeled.bytes);
        const auto lowered = guard::DexCodeLowering(config).Apply(model);
        const auto final = dex::DexFile::Parse(lowered.bytes);
        Check(final);
        std::size_t protected_methods = 0U;
        for (std::size_t c = 0; c < final.classes().size(); ++c) {
            if (final.descriptor(final.classes()[c].class_idx) != owner) continue;
            for (const auto& method : final.class_data(c).direct_methods) {
                const auto code = dex::DecodeCodeItem(final, method.code_off);
                const auto ir = dex::BuildMethodIr(code);
                assert(code.insns.size() <= 16000U && ir.blocks().size() >= 1024U);
                const auto shape = test::MeasureCffShape(ir);
                assert(shape.max_empty_fan_in <= 16U && shape.max_empty_run <= 2U);
                ++protected_methods;
            }
        }
        assert(protected_methods > 4U);
        std::cout << "seed=" << seed << " programs=" << outlined.programs
                  << " arithmetic=" << outlined.arithmetic_steps << " protected_methods=" << protected_methods << '\n';
    }
}
