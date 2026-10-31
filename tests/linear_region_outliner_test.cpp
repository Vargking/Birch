#include "linear_region_outliner.h"
#include "model_support.h"
#include "birch/dex/cloner.h"
#include "birch/dex/ir.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "birch/guard/model_lowering.h"
#include "birch/io/file.h"
#include "support/cff_shape.h"
#include "support/string_dex_interpreter.h"

#include <array>
#include <cassert>
#include <filesystem>
#include <iostream>
#include <set>

namespace {
using namespace birch;
using namespace birch::guard::detail;
constexpr auto owner = "Llinear/Program;";
constexpr auto string_type = "Ljava/lang/String;";
constexpr std::size_t iterations = 100U;

void Const(dex::MethodBodySpec& body, unsigned reg, std::uint32_t bits) {
    body.code_units.insert(body.code_units.end(), {static_cast<std::uint16_t>(0x14U | (reg << 8U)),
        static_cast<std::uint16_t>(bits), static_cast<std::uint16_t>(bits >> 16U)});
}
void String(dex::MethodBodySpec& body, unsigned reg, const std::string& value) {
    const auto at = static_cast<std::uint32_t>(body.code_units.size());
    body.code_units.insert(body.code_units.end(), {static_cast<std::uint16_t>(0x1aU | (reg << 8U)), 0U});
    body.references.push_back({value, at + 1U, false});
}
void Field(dex::MethodBodySpec& body, unsigned opcode, unsigned reg, const std::string& name,
           const std::string& type = "I") {
    const auto at = static_cast<std::uint32_t>(body.code_units.size());
    body.code_units.insert(body.code_units.end(), {static_cast<std::uint16_t>(opcode | (reg << 8U)), 0U});
    body.references.push_back({dex::FieldReference{owner, name, type}, at + 1U, false});
}
void Invoke(dex::MethodBodySpec& body, const std::vector<std::uint16_t>& args,
            const std::string& name, const std::string& result, std::vector<std::string> parameters) {
    AppendInvoke(body.code_units, 0x71U, args, body, {owner, name, result, std::move(parameters)});
}
void Length(dex::MethodBodySpec& body, std::uint16_t src, unsigned dst) {
    AppendInvoke(body.code_units, 0x6eU, {src}, body, {string_type, "length", "I", {}});
    body.code_units.push_back(static_cast<std::uint16_t>(0x0aU | (dst << 8U)));
}

// Origin variants exercise argument aliases, invoke results, const-string,
// initialized arrays and static reference fields without guessing object types.
dex::DexFile Fixture(unsigned variant = 0U) {
    dex::ClassSpec klass;
    klass.descriptor = owner;
    klass.static_fields = {{"total", "I", kStatic, dex::EncodedValueSpec{std::int32_t{0}}, {}},
        {"text", string_type, kStatic, dex::EncodedValueSpec{dex::StringReference{"Birch"}}, {}}};
    const std::string fourth = variant == 3U ? "[I" : string_type;
    dex::MethodSpec consume;
    consume.name = "consume";
    consume.parameter_types = {string_type, "I", "F", fourth};
    consume.body.registers_size = 8U;
    consume.body.ins_size = 4U;
    consume.body.outs_size = 1U;
    Length(consume.body, 4U, 0U);
    AppendInvoke(consume.body.code_units, 0x71U, {6U}, consume.body,
        {"Ljava/lang/Float;", "floatToRawIntBits", "I", {"F"}});
    consume.body.code_units.push_back(0x010aU);
    if (variant == 3U) consume.body.code_units.push_back(0x7221U);
    else Length(consume.body, 7U, 2U);
    consume.body.code_units.insert(consume.body.code_units.end(),
        {0x0090U, 0x0500U, 0x0097U, 0x0100U, 0x20b0U});
    Field(consume.body, 0x60U, 1U, "total");
    consume.body.code_units.push_back(0x01b0U);
    Field(consume.body, 0x67U, 1U, "total");
    consume.body.code_units.push_back(0x000eU);
    klass.direct_methods.push_back(std::move(consume));

    dex::MethodSpec null_sink;
    null_sink.name = "nullSink";
    null_sink.parameter_types = {"Ljava/lang/Object;"};
    null_sink.body.registers_size = 2U;
    null_sink.body.ins_size = 1U;
    null_sink.body.outs_size = 1U;
    AppendInvoke(null_sink.body.code_units, 0x71U, {1U}, null_sink.body,
        {"Ljava/lang/System;", "identityHashCode", "I", {"Ljava/lang/Object;"}});
    null_sink.body.code_units.push_back(0x000aU);
    Field(null_sink.body, 0x60U, 1U, "total");
    null_sink.body.code_units.push_back(0x01b0U);
    Field(null_sink.body, 0x67U, 1U, "total");
    null_sink.body.code_units.push_back(0x000eU);
    klass.direct_methods.push_back(std::move(null_sink));

    dex::MethodSpec echo;
    echo.name = "echo";
    echo.return_type = string_type;
    echo.parameter_types = {string_type};
    echo.body.registers_size = echo.body.ins_size = 1U;
    echo.body.code_units = {0x0011U};
    klass.direct_methods.push_back(std::move(echo));

    dex::MethodSpec run;
    run.name = "run";
    run.return_type = "I";
    run.parameter_types = {string_type, "I", "F"};
    run.body.registers_size = 20U;
    run.body.ins_size = 3U;
    run.body.outs_size = 4U;
    run.body.code_units = {0x0008U, 17U, 0x0102U, 18U, 0x0202U, 19U};
    if (variant == 0U) {
        Invoke(run.body, {0U}, "echo", string_type, {string_type});
        run.body.code_units.push_back(0x0a0cU);
    } else if (variant == 1U) String(run.body, 10U, "Birch");
    else if (variant == 2U) Field(run.body, 0x62U, 10U, "text", string_type);
    else {
        Const(run.body, 3U, 5U);
        const auto at = static_cast<std::uint32_t>(run.body.code_units.size());
        run.body.code_units.insert(run.body.code_units.end(), {0x3a23U, 0U});
        run.body.references.push_back({dex::TypeReference{"[I"}, at + 1U, false});
    }
    for (std::uint32_t i = 0U; i < iterations; ++i) {
        Const(run.body, 4U, i);
        Const(run.body, 5U, 0x80000000U | i); // -0 and exact float raw bits
        Invoke(run.body, {0U, 4U, 5U, 10U}, "consume", "V", {string_type, "I", "F", fourth});
        Invoke(run.body, {0U, 1U, 2U, 10U}, "consume", "V", {string_type, "I", "F", fourth});
        run.body.code_units.push_back(0x0312U); // same zero feeds int and reference consumers
        Invoke(run.body, {3U}, "nullSink", "V", {"Ljava/lang/Object;"});
        Field(run.body, 0x67U, 3U, "totalZero");
    }
    Field(run.body, 0x60U, 0U, "total");
    run.body.code_units.push_back(0x000fU);
    klass.direct_methods.push_back(std::move(run));
    klass.static_fields.push_back({"totalZero", "I", kStatic, dex::EncodedValueSpec{std::int32_t{0}}, {}});

    dex::MethodSpec read;
    read.name = "read";
    read.return_type = "I";
    read.body.registers_size = read.body.outs_size = 3U;
    String(read.body, 0U, "Birch");
    Const(read.body, 1U, 0xfffffff9U);
    Const(read.body, 2U, 0x7fc12345U);
    Invoke(read.body, {0U, 1U, 2U}, "run", "I", {string_type, "I", "F"});
    read.body.code_units.insert(read.body.code_units.end(), {0x000aU, 0x000fU});
    klass.direct_methods.push_back(std::move(read));
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    return dex::DexFile::Parse(builder.Build());
}

void Check(const dex::DexFile& file) {
    dex::VerifyDexOrThrow(file, dex::VerificationLevel::Full);
    std::uint32_t expected = 0U;
    for (std::uint32_t i = 0U; i < iterations; ++i) {
        expected += ((5U + i) ^ (0x80000000U | i)) + 5U;
        expected += ((5U + 0xfffffff9U) ^ 0x7fc12345U) + 5U;
    }
    assert(expected != 0U);
    // Model wrappers and their generated runtime are also fully protected.
    // Keep all 200 business calls rather than trimming the workload to fit the
    // smaller default string-oracle instruction allowance.
    test::StringDexInterpreter runtime(file, 10000000000ULL);
    assert(runtime.ExecuteScalar(owner, "read") == expected);
}

dex::DexFile Single(dex::MethodSpec method) {
    dex::ClassSpec klass;
    klass.descriptor = owner;
    klass.direct_methods.push_back(std::move(method));
    dex::DexBuilder builder;
    builder.AddClass(std::move(klass));
    return dex::DexFile::Parse(builder.Build());
}

void CheckExclusions(const guard::GuardConfig& config) {
    // A genuinely changing live output must not be silently discarded; unknown
    // equals unknown is not an equality proof. No internal slice is independent.
    dex::MethodSpec changing;
    changing.name = "changing";
    changing.return_type = "I";
    changing.body.registers_size = 1U;
    changing.body.code_units = {0x0012U};
    for (std::size_t i = 0; i < 800U; ++i)
        changing.body.code_units.insert(changing.body.code_units.end(), {0x00d8U, 0x0100U});
    changing.body.code_units.push_back(0x000fU);
    assert(LinearRegionOutliner::Apply(Single(changing), config).regions == 0U);
    changing.access_flags |= 0x0020U;
    assert(LinearRegionOutliner::Apply(Single(changing), config).regions == 0U);
    changing.access_flags &= ~0x0020U;
    changing.name = "<clinit>";
    changing.return_type = "V";
    changing.body.code_units.back() = 0x000eU;
    assert(LinearRegionOutliner::Apply(Single(changing), config).regions == 0U);

    // A long sequence retaining a not-yet-initialized allocation cannot pass it
    // to another method, including through move-object aliases.
    dex::MethodSpec allocation;
    allocation.name = "allocation";
    allocation.body.registers_size = allocation.body.outs_size = 2U;
    allocation.body.code_units = {0x0022U, 0U};
    allocation.body.references.push_back({dex::TypeReference{"Ljava/lang/Object;"}, 1U, false});
    for (std::size_t i = 0; i < 1600U; ++i) allocation.body.code_units.push_back(0x0107U);
    AppendInvoke(allocation.body.code_units, 0x70U, {1U}, allocation.body,
        {"Ljava/lang/Object;", "<init>", "V", {}});
    allocation.body.code_units.push_back(0x000eU);
    assert(LinearRegionOutliner::Apply(Single(allocation), config).regions == 0U);

    dex::MethodSpec plain;
    plain.name = "plain";
    plain.body.registers_size = 1U;
    plain.body.code_units.assign(1600U, 0U);
    plain.body.code_units.push_back(0x000eU);
    for (unsigned variant = 0; variant < 4U; ++variant) {
        auto blocked = plain;
        if (variant == 0U) blocked.body.code_units[0] = 0x0128U; // branch, even fallthrough goto
        if (variant == 1U) blocked.body.code_units[0] = 0x001dU; // monitor
        if (variant == 2U) blocked.access_flags |= 0x20000U; // declared-synchronized
        if (variant == 3U) {
            blocked.body.code_units[1599U] = 0x000dU;
            blocked.body.try_regions.push_back({0U, 1U, {{std::nullopt, 1599U}}});
        }
        assert(LinearRegionOutliner::Apply(Single(blocked), config).regions == 0U);
    }
    auto disabled = config;
    disabled.budget.max_call_depth_increase = 0U;
    assert(LinearRegionOutliner::Apply(Single(plain), disabled).regions == 0U);
    disabled = config;
    disabled.scope.protect.clear();
    assert(LinearRegionOutliner::Apply(Single(plain), disabled).regions == 0U);
}

void CheckHighRange(const guard::GuardConfig& config) {
    dex::MethodSpec run;
    run.name = "high";
    run.parameter_types = {string_type};
    run.body.registers_size = 20U;
    run.body.ins_size = run.body.outs_size = 1U;
    for (std::size_t i = 0; i < 520U; ++i)
        AppendInvoke(run.body.code_units, 0x6eU, {19U}, run.body, {string_type, "length", "I", {}});
    run.body.code_units.push_back(0x000eU);
    const auto result = LinearRegionOutliner::Apply(Single(run), config);
    assert(result.regions > 1U);
    const auto file = dex::DexFile::Parse(result.bytes);
    bool range = false;
    for (const auto& method : file.class_data(0U).direct_methods)
        for (const auto& ins : dex::DecodeCodeItem(file, method.code_off).instructions)
            range |= ins.opcode == 0x77U;
    assert(range);
}
} // namespace

int main() {
    auto config = guard::GuardConfig::Parse(io::ReadTextFile(
        std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs/release_full.json"));
    config.scope.protect = {{"Llinear/**;"}};
    config.scope.keep.clear();
    CheckExclusions(config);
    CheckHighRange(config);
    for (unsigned variant = 0U; variant < 4U; ++variant) {
        const auto source = Fixture(variant);
        Check(source);
        const auto result = LinearRegionOutliner::Apply(source, config);
        assert(result.methods == 1U && result.regions > 1U && result.moved_code_units > 1000U);
        Check(dex::DexFile::Parse(result.bytes));
    }
    for (const auto seed : {1ULL, 777331ULL, 20260821ULL}) {
        config.seed = seed;
        const auto source = Fixture();
        const auto modeled = guard::DexModelLowering(config).Apply(source);
        const auto model = dex::DexFile::Parse(modeled.bytes);
        std::set<std::string, std::less<>> input;
        for (const auto& klass : source.classes()) input.insert(source.descriptor(klass.class_idx));
        // Include all generated companions, just like the production APK path.
        for (const auto& klass : model.classes()) {
            const auto name = model.descriptor(klass.class_idx);
            if (!input.contains(name)) config.scope.protect.push_back({name, true, true, true});
        }
        const auto lowered = guard::DexCodeLowering(config).Apply(model);
        const auto final = dex::DexFile::Parse(lowered.bytes);
        Check(final);
        std::size_t protected_methods = 0U;
        for (std::size_t c = 0; c < final.classes().size(); ++c) {
            const auto& data = final.class_data(c);
            for (const auto* methods : {&data.direct_methods, &data.virtual_methods})
                for (const auto& method : *methods) {
                    if (!method.code_off) continue;
                    const auto code = dex::DecodeCodeItem(final, method.code_off);
                    const auto ir = dex::BuildMethodIr(code);
                    assert(code.insns.size() <= 16000U && ir.blocks().size() >= 1024U);
                    const auto shape = test::MeasureCffShape(ir);
                    assert(shape.max_empty_fan_in <= 16U && shape.max_empty_run <= 2U);
                    ++protected_methods;
                }
        }
        assert(protected_methods > 10U);
        std::cout << "linear outlining seed=" << seed << " protected_methods=" << protected_methods << std::endl;
        config.scope.protect = {{"Llinear/**;"}};
    }
}
