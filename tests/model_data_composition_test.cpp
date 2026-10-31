#include "birch/dex/builder.h"
#include "birch/dex/verifier.h"
#include "birch/guard/model_lowering.h"
#include "support/string_dex_interpreter.h"
#include "model_strings.h"

#include <cassert>
#include <iostream>

namespace {
constexpr auto owner = "Lcomposition/Arrays;";
constexpr auto literal = "literal-after-array-read";

birch::dex::DexFile ArrayFixture() {
    using namespace birch::dex;
    ClassSpec klass;
    klass.descriptor = owner;
    klass.static_fields.push_back({"values", "[I", 0x0aU, {}, {}});
    MethodSpec clinit;
    clinit.name = "<clinit>";
    clinit.access_flags = 0x10008U;
    clinit.body.registers_size = 1U;
    clinit.body.code_units = {0x1012U, 0x0023U, 0U, 0x0069U, 0U, 0x000eU};
    clinit.body.references = {
        {TypeReference{"[I"}, 2U, false},
        {FieldReference{owner, "values", "[I"}, 4U, false}};
    klass.direct_methods.push_back(std::move(clinit));
    MethodSpec getter;
    getter.name = "read";
    getter.return_type = "Ljava/lang/String;";
    getter.body.registers_size = 2U;
    getter.body.code_units = {
        0x0112U, 0x0062U, 0U, 0x0044U, 0x0100U, 0x001aU, 0U, 0x0011U};
    getter.body.references = {
        {FieldReference{owner, "values", "[I"}, 2U, false},
        {std::string(literal), 6U, false}};
    klass.direct_methods.push_back(std::move(getter));
    DexBuilder builder;
    builder.AddClass(std::move(klass));
    return DexFile::Parse(builder.Build());
}

void CheckJumboSiteIdentity() {
    using namespace birch;
    dex::ClassSpec klass;
    klass.descriptor = "Lcomposition/Jumbo;";
    dex::MethodSpec method;
    method.name = "read";
    method.return_type = "Ljava/lang/String;";
    method.body.registers_size = 1U;
    method.body.code_units = {0x001aU, 0U, 0x001aU, 0U, 0x0011U};
    // Deliberately out-of-order patches: identity follows instruction order.
    method.body.references = {
        {std::string("zzzz-second-literal"), 3U, false},
        {std::string("zzzz-first-literal"), 1U, false}};
    klass.direct_methods.push_back(std::move(method));
    auto config = guard::GuardConfig::Defaults();
    for (auto& [id, pass] : config.passes) {
        (void)id;
        pass.enabled = false;
    }
    config.passes.at("data.string_encryption").enabled = true;
    config.passes.at("data.string_encryption").intensity = 1.0;
    guard::detail::StringRewritePlan plan;
    guard::detail::ModelStringProtection::CollectStringValues(klass, config, plan);
    assert(plan.sites.size() == 2U);
    auto helpers = guard::detail::ModelStringProtection::BuildStringHelper(
        {klass.descriptor}, plan.values, plan.split_values, config.seed, config.seed);
    dex::DexBuilder builder;
    for (std::size_t i = 0; i < 65536U; ++i)
        builder.AddString("padding-" + std::to_string(i));
    builder.AddClass(std::move(klass));
    for (auto& helper : helpers.classes) builder.AddClass(std::move(helper));
    const auto source = dex::DexFile::Parse(builder.Build());
    dex::VerifyDexOrThrow(source, dex::VerificationLevel::Full);
    bool promoted = false;
    for (std::size_t c = 0; c < source.classes().size(); ++c) {
        if (source.descriptor(source.classes()[c].class_idx) != "Lcomposition/Jumbo;") continue;
        const auto code = dex::DecodeCodeItem(source, source.class_data(c).direct_methods.front().code_off);
        assert(code.instructions.at(0).opcode == 0x1bU);
        assert(code.instructions.at(1).offset == 3U);
        promoted = true;
    }
    assert(promoted);
    std::size_t rewritten = 0U;
    guard::ModelLoweringResult report;
    const auto bytes = guard::detail::ModelStringProtection::RewriteStringCallsites(
        source, plan, helpers.entry_descriptor, config.seed, rewritten, report);
    assert(rewritten == 2U);
    const auto output = dex::DexFile::Parse(bytes);
    dex::VerifyDexOrThrow(output, dex::VerificationLevel::Full);
    assert(test::StringDexInterpreter(output).Execute("Lcomposition/Jumbo;", "read") ==
           u"zzzz-second-literal");
}
} // namespace

int main() {
    CheckJumboSiteIdentity();
    const auto source = ArrayFixture();
    birch::dex::VerifyDexOrThrow(source, birch::dex::VerificationLevel::Full);
    assert(birch::test::StringDexInterpreter(source).Execute(owner, "read") ==
           u"literal-after-array-read");
    for (const bool split : {false, true}) {
        auto config = birch::guard::GuardConfig::Defaults();
        for (auto& [id, pass] : config.passes) {
            (void)id;
            pass.enabled = false;
            pass.intensity = 1.0;
        }
        config.scope.protect = {{"Lcomposition/**;"}};
        config.scope.keep.clear();
        config.passes.at("data.string_encryption").enabled = true;
        config.passes.at("data.array_virtualization").enabled = true;
        config.passes.at("data.array_splitting").enabled = split;
        const auto result = birch::guard::DexModelLowering(config).Apply(source);
        assert(result.virtualized_arrays == 1U);
        assert(result.split_arrays == (split ? 1U : 0U));
        assert(result.encrypted_strings == 1U);
        const auto output = birch::dex::DexFile::Parse(result.bytes);
        birch::dex::VerifyDexOrThrow(output, birch::dex::VerificationLevel::Full);
        assert(birch::test::StringDexInterpreter(output).Execute(owner, "read") ==
               u"literal-after-array-read");
        for (std::size_t i = 0; i < output.strings().size(); ++i)
            assert(output.string(static_cast<std::uint32_t>(i)) != literal);
    }
    std::cout << "Array rewrites preserve string-vault site selection and execution\n";
}
