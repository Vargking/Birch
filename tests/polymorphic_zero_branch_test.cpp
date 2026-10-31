#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/type_analysis.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "birch/guard/model_lowering.h"
#include "birch/io/file.h"
#include "support/string_dex_interpreter.h"

#include <cassert>
#include <filesystem>
#include <iostream>

namespace {
constexpr auto owner = "Lzero/Branches;";

birch::dex::DexFile Fixture() {
    using namespace birch::dex;
    ClassSpec klass;
    klass.descriptor = owner;
    for (const auto opcode : {0x38U, 0x39U}) {
        for (const auto copied : {false, true}) {
            MethodSpec method;
            method.name = "read" + std::to_string(opcode) + (copied ? "Copy" : "Direct");
            method.return_type = "F";
            method.body.registers_size = 2U;
            method.body.code_units = {0x0012U}; // const/4 v0, 0: int/null/float
            if (copied) method.body.code_units.push_back(0x0101U); // move v1, v0
            method.body.code_units.insert(method.body.code_units.end(), {
                static_cast<std::uint16_t>(opcode | (copied ? 0x100U : 0U)),
                3U, 0x000fU, 0x000fU});
            MethodSpec bits;
            bits.name = method.name + "Bits";
            bits.return_type = "I";
            bits.body.registers_size = 1U;
            bits.body.outs_size = 1U;
            bits.body.code_units = {0x0071U, 0U, 0U, 0x000aU,
                                   0x1071U, 0U, 0U, 0x000aU, 0x000fU};
            bits.body.references = {
                {MethodReference{owner, method.name, "F", {}}, 1U, false},
                {MethodReference{"Ljava/lang/Float;", "floatToRawIntBits", "I", {"F"}}, 5U, false}};
            klass.direct_methods.push_back(std::move(method));
            klass.direct_methods.push_back(std::move(bits));
        }
    }
    DexBuilder builder;
    builder.AddClass(std::move(klass));
    return DexFile::Parse(builder.Build());
}

void Check(const birch::dex::DexFile& file) {
    birch::dex::VerifyDexOrThrow(file, birch::dex::VerificationLevel::Full);
    birch::test::StringDexInterpreter runtime(file);
    for (const auto opcode : {0x38U, 0x39U})
        for (const auto copied : {false, true})
            assert(runtime.ExecuteScalar(owner, "read" + std::to_string(opcode) +
                (copied ? "Copy" : "Direct") + "Bits") == 0U);
}
} // namespace

int main() {
    const auto source = Fixture();
    Check(source);
    for (const auto& method : source.class_data(0U).direct_methods) {
        if (source.proto_key(source.methods().at(method.method_idx).proto_idx) != "()F") continue;
        const auto code = birch::dex::DecodeCodeItem(source, method.code_off);
        const auto types = birch::dex::AnalyzeMethodTypes(source, method, code);
        assert(types.issues.empty());
        assert(types.polymorphic_zero_constants.contains(0U));
    }
    auto config = birch::guard::GuardConfig::Parse(birch::io::ReadTextFile(
        std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs/release_full.json"));
    config.scope.protect = {{"Lzero/**;"}};
    config.scope.keep.clear();
    for (const auto seed : {1ULL, 777331ULL, 20260821ULL}) {
        config.seed = seed;
        const auto modeled = birch::guard::DexModelLowering(config).Apply(source);
        const auto model = birch::dex::DexFile::Parse(modeled.bytes);
        Check(model);
        const auto output = birch::guard::DexCodeLowering(config).Apply(model);
        Check(birch::dex::DexFile::Parse(output.bytes));
    }
    std::cout << "Zero equality tests preserve polymorphic float constants under full protection\n";
}
