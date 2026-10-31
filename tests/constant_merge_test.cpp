#include "birch/dex/builder.h"
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
constexpr auto owner = "Lmerge/Constants;";

birch::dex::DexFile Fixture() {
    using namespace birch::dex;
    ClassSpec klass;
    klass.descriptor = owner;
    for (const auto type : {"I", "F", "Ljava/lang/String;"}) {
        const bool reference = type[0] == 'L';
        for (const bool reverse : {false, true}) {
            MethodSpec method;
            method.name = std::string(reference ? "ref" : type) + (reverse ? "Reverse" : "Forward");
            method.parameter_types = {type, "I"};
            method.return_type = reference ? "I" : type;
            method.body.registers_size = 3U;
            method.body.ins_size = 2U;
            const auto literal_op = static_cast<std::uint16_t>(type[0] == 'F' ? 0x15U : 0x13U);
            const auto literal = static_cast<std::uint16_t>(type[0] == 'F' ? 0x3f00U : reference ? 0U : 5U);
            const auto move = static_cast<std::uint16_t>(reference ? 0x1007U : 0x1001U);
            method.body.code_units = reverse ?
                std::vector<std::uint16_t>{0x0238U, 4U, move, 0x0328U, literal_op, literal} :
                std::vector<std::uint16_t>{0x0238U, 5U, literal_op, literal, 0x0228U, move};
            if (reference) {
                method.body.code_units.insert(method.body.code_units.end(), {
                    0x0038U, 4U, 0x1012U, 0x000fU, 0x2012U, 0x000fU});
            } else {
                method.body.code_units.push_back(0x000fU);
            }
            for (const bool typed_arm : {false, true}) {
                MethodSpec wrapper;
                wrapper.name = method.name + (typed_arm ? "Typed" : "Literal");
                wrapper.return_type = "I";
                wrapper.body.registers_size = 2U;
                wrapper.body.outs_size = 2U;
                if (reference) {
                    wrapper.body.code_units = {0x001aU, 0U};
                    wrapper.body.references.push_back({std::string("non-null"), 1U, false});
                } else {
                    wrapper.body.code_units = {literal_op,
                        static_cast<std::uint16_t>(type[0] == 'F' ? 0x3f80U : 9U)};
                }
                const bool condition = reverse ? !typed_arm : typed_arm;
                wrapper.body.code_units.push_back(condition ? 0x0112U : 0x1112U);
                wrapper.body.code_units.insert(wrapper.body.code_units.end(), {0x2071U, 0U, 0x0010U, 0x000aU});
                wrapper.body.references.push_back({MethodReference{owner, method.name,
                    method.return_type, method.parameter_types}, 4U, false});
                if (type[0] == 'F') {
                    wrapper.body.code_units.insert(wrapper.body.code_units.end(), {0x1071U, 0U, 0U, 0x000aU});
                    wrapper.body.references.push_back({MethodReference{"Ljava/lang/Float;",
                        "floatToRawIntBits", "I", {"F"}}, 8U, false});
                }
                wrapper.body.code_units.push_back(0x000fU);
                klass.direct_methods.push_back(std::move(wrapper));
            }
            klass.direct_methods.push_back(std::move(method));
        }
    }
    DexBuilder builder;
    builder.AddClass(std::move(klass));
    return DexFile::Parse(builder.Build());
}

void Check(const birch::dex::DexFile& file) {
    birch::dex::VerifyDexOrThrow(file, birch::dex::VerificationLevel::Full);
    birch::test::StringDexInterpreter runtime(file);
    for (const auto type : {"I", "F", "ref"}) {
        for (const auto order : {"Reverse", "Forward"}) {
            for (const bool typed : {false, true}) {
                const auto name = std::string(type) + order + (typed ? "Typed" : "Literal");
                const auto expected = type[0] == 'F' ? (typed ? 0x3f800000U : 0x3f000000U) :
                    type[0] == 'I' ? (typed ? 9U : 5U) : (typed ? 1U : 2U);
                assert(runtime.ExecuteScalar(owner, name) == expected);
            }
        }
    }
}
} // namespace

int main() {
    const auto source = Fixture();
    Check(source);
    for (const auto& method : source.class_data(0U).direct_methods) {
        if (source.type_list(source.protos().at(source.methods().at(method.method_idx).proto_idx).parameters_off).empty()) continue;
        const auto code = birch::dex::DecodeCodeItem(source, method.code_off);
        const auto types = birch::dex::AnalyzeMethodTypes(source, method, code);
        const auto& key = source.method_key(method.method_idx);
        const auto constant = key.find("Reverse") != std::string::npos ? 4U : 2U;
        assert(types.polymorphic_zero_constants.contains(constant) ||
               types.constant_uses.at(constant) != birch::dex::ConstantUseType::Unconstrained);
    }
    auto config = birch::guard::GuardConfig::Parse(birch::io::ReadTextFile(
        std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs/release_full.json"));
    config.scope.protect = {{"Lmerge/**;"}};
    config.scope.keep.clear();
    for (const auto seed : {1ULL, 777331ULL, 20260821ULL}) {
        config.seed = seed;
        const auto modeled = birch::guard::DexModelLowering(config).Apply(source);
        const auto model = birch::dex::DexFile::Parse(modeled.bytes);
        Check(model);
        const auto output = birch::guard::DexCodeLowering(config).Apply(model);
        Check(birch::dex::DexFile::Parse(output.bytes));
    }
    std::cout << "Constants retain typed uses across both CFG join orders\n";
}
