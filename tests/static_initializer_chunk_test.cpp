#include "birch/dex/builder.h"
#include "birch/dex/cloner.h"
#include "birch/dex/ir.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "birch/guard/model_lowering.h"
#include "birch/io/file.h"
#include "support/string_dex_interpreter.h"

#include <cassert>
#include <filesystem>
#include <iostream>

namespace {
constexpr auto owner = "Lbulk/ResourceFields;";
constexpr std::size_t count = 1536U;

birch::dex::DexFile Fixture() {
    using namespace birch::dex;
    ClassSpec klass;
    klass.descriptor = owner;
    for (std::size_t i = 0; i < count; ++i)
        klass.static_fields.push_back({"f" + std::to_string(i), "I", 0x19U,
            EncodedValueSpec{static_cast<std::int32_t>(1000U + i)}, {}});
    // The original body must run after every synthesized initialization chunk.
    MethodSpec clinit;
    clinit.name = "<clinit>";
    clinit.access_flags = 0x10008U;
    clinit.body.registers_size = 1U;
    clinit.body.code_units = {0x0013U, 42U, 0x0067U, 0U, 0x000eU};
    clinit.body.references.push_back({FieldReference{owner, "f0", "I"}, 3U, false});
    klass.direct_methods.push_back(std::move(clinit));
    MethodSpec getter;
    getter.name = "read";
    getter.return_type = "I";
    getter.body.registers_size = 2U;
    getter.body.code_units = {
        0x0060U, 0U, 0x0160U, 0U, 0x10b0U,
        0x0160U, 0U, 0x10b0U, 0x000fU};
    getter.body.references = {
        {FieldReference{owner, "f0", "I"}, 1U, false},
        {FieldReference{owner, "f768", "I"}, 3U, false},
        {FieldReference{owner, "f1535", "I"}, 6U, false}};
    klass.direct_methods.push_back(std::move(getter));
    DexBuilder builder;
    builder.AddClass(std::move(klass));
    return DexFile::Parse(builder.Build());
}

void Execute(const birch::dex::DexFile& file) {
    birch::dex::VerifyDexOrThrow(file, birch::dex::VerificationLevel::Full);
    birch::test::StringDexInterpreter runtime(file, 500000000U);
    assert(runtime.ExecuteScalar(owner, "read") == 42U + 1768U + 2535U);
}
} // namespace

int main() {
    const auto source = Fixture();
    Execute(source);
    auto config = birch::guard::GuardConfig::Parse(birch::io::ReadTextFile(
        std::filesystem::path(BIRCH_TEST_SOURCE_DIR) / "configs/release_full.json"));
    config.scope.protect = {{"Lbulk/**;"}};
    config.scope.keep.clear();
    for (const std::uint64_t seed : {1ULL, 20260821ULL}) {
        config.seed = seed;
        const auto modeled = birch::guard::DexModelLowering(config).Apply(source);
        const auto model = birch::dex::DexFile::Parse(modeled.bytes);
        Execute(model);
        birch::dex::DexClassCloner cloner(model);
        std::size_t chunks = 0U;
        for (std::size_t c = 0; c < model.classes().size(); ++c) {
            if (model.descriptor(model.classes()[c].class_idx) != owner) continue;
            const auto klass = cloner.Clone(c);
            assert(klass.static_fields.size() == count);
            for (const auto& field : klass.static_fields) {
                assert((field.access_flags & 0x10U) != 0U); // never drop final
                assert(!field.static_value);
            }
            for (const auto& method : klass.direct_methods)
                if ((method.access_flags & 0x100aU) == 0x100aU) {
                    ++chunks;
                    assert(method.body.code_units.size() <= 272U);
                }
        }
        assert(chunks >= 50U);
        const auto lowered = birch::guard::DexCodeLowering(config).Apply(model);
        const auto output = birch::dex::DexFile::Parse(lowered.bytes);
        Execute(output);
        std::size_t protected_methods = 0U;
        for (std::size_t c = 0; c < output.classes().size(); ++c) {
            if (output.descriptor(output.classes()[c].class_idx) != owner) continue;
            for (const auto& method : output.class_data(c).direct_methods) {
                const auto code = birch::dex::DecodeCodeItem(output, method.code_off);
                assert(code.insns.size() <= 16000U);
                assert(birch::dex::BuildMethodIr(code).blocks().size() >= 1024U);
                ++protected_methods;
            }
        }
        assert(protected_methods >= chunks + 2U);
    }
    std::cout << "1536 final fields: ordered chunks, full-strength CFF and execution passed\n";
}
