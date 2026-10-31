#include "birch/dex/builder.h"
#include "birch/dex/cloner.h"
#include "birch/dex/verifier.h"
#include "birch/guard/model_lowering.h"
#include "support/string_dex_interpreter.h"

#include <array>
#include <bit>
#include <cassert>
#include <iostream>

namespace {
constexpr auto owner = "Lstaticfix/Fields;";
constexpr std::array<std::uint32_t, 8U> float_bits{
    0U, 0x80000000U, 0x3fc00000U, 0xbfc00000U,
    0x7f800000U, 0xff800000U, 0x7fc01234U, 1U};

birch::guard::GuardConfig Config(bool strings, bool constants, bool splitting = false) {
    auto config = birch::guard::GuardConfig::Defaults();
    for (auto& [id, pass] : config.passes) {
        (void)id;
        pass.enabled = false;
        pass.intensity = 1.0;
    }
    config.scope.protect = {{"Lstaticfix/**;"}};
    config.scope.keep.clear();
    config.passes.at("data.string_encryption").enabled = strings;
    config.passes.at("data.string_splitting").enabled = splitting;
    config.passes.at("data.constant_splitting").enabled = constants;
    return config;
}

birch::dex::DexFile Fixture(std::uint16_t registers, bool existing_clinit) {
    using namespace birch::dex;
    DexBuilder builder;
    ClassSpec klass;
    klass.descriptor = owner;
    for (std::size_t i = 0; i < float_bits.size(); ++i) {
        const auto name = "f" + std::to_string(i);
        klass.static_fields.push_back({name, "F", 0x19U,
            EncodedValueSpec{std::bit_cast<float>(float_bits[i])}, {}});
        MethodSpec getter;
        getter.name = name;
        getter.return_type = "I";
        getter.body.registers_size = 1U;
        getter.body.outs_size = 1U;
        // invoke-static {v0}, Float.floatToRawIntBits(F)I
        getter.body.code_units = {0x0060U, 0U, 0x1071U, 0U, 0U, 0x000aU, 0x000fU};
        getter.body.references = {
            {FieldReference{owner, name, "F"}, 1U, false},
            {MethodReference{"Ljava/lang/Float;", "floatToRawIntBits", "I", {"F"}}, 3U, false}};
        klass.direct_methods.push_back(std::move(getter));
    }
    const std::array<std::string, 5U> types{"Z", "B", "C", "S", "I"};
    const std::array<EncodedValueSpec, 5U> values{
        EncodedValueSpec{true}, EncodedValueSpec{std::int8_t{-123}},
        EncodedValueSpec{char16_t{0xfedc}}, EncodedValueSpec{std::int16_t{-23456}},
        EncodedValueSpec{std::int32_t{-123456789}}};
    for (std::size_t i = 0; i < types.size(); ++i) {
        const auto name = "i" + std::to_string(i);
        klass.static_fields.push_back({name, types[i], 0x19U, values[i], {}});
        MethodSpec getter;
        getter.name = name;
        getter.return_type = "I";
        getter.body.registers_size = 1U;
        getter.body.code_units = {static_cast<std::uint16_t>(i < 4U ? 0x63U + i : 0x60U), 0U, 0x000fU};
        getter.body.references.push_back({FieldReference{owner, name, types[i]}, 1U, false});
        klass.direct_methods.push_back(std::move(getter));
    }
    klass.static_fields.push_back({"stored", "Ljava/lang/String;", 0x19U,
        EncodedValueSpec{StringReference{"static-vault-value"}}, {}});
    klass.static_fields.push_back({"body", "Ljava/lang/String;", 0x09U, {}, {}});
    for (const auto* name : {"stored", "body"}) {
        MethodSpec getter;
        getter.name = name;
        getter.return_type = "Ljava/lang/String;";
        getter.body.registers_size = 1U;
        getter.body.code_units = {0x0062U, 0U, 0x0011U};
        getter.body.references.push_back({FieldReference{owner, name, getter.return_type}, 1U, false});
        klass.direct_methods.push_back(std::move(getter));
    }
    if (existing_clinit) {
        MethodSpec clinit;
        clinit.name = "<clinit>";
        clinit.access_flags = 0x10008U;
        clinit.body.registers_size = registers;
        clinit.body.code_units = {
            0x001aU, 0U, 0x0069U, 0U, // body = original literal
            0x1012U, 0x0023U, 0U,     // new byte[1]
            0x0026U, 5U, 0U,         // fill-array-data -> @12
            0x000eU, 0x0000U,
            0x0300U, 1U, 1U, 0U, 0x005aU};
        clinit.body.references = {
            {std::string("original-clinit-literal"), 1U, false},
            {FieldReference{owner, "body", "Ljava/lang/String;"}, 3U, false},
            {TypeReference{"[B"}, 6U, false}};
        klass.direct_methods.push_back(std::move(clinit));
    }
    builder.AddClass(std::move(klass));
    ClassSpec external;
    external.descriptor = "Lthirdparty/Untouched;";
    external.static_fields.push_back({"secret", "Ljava/lang/String;", 0x19U,
        EncodedValueSpec{StringReference{"external-must-not-enter-vault"}}, {}});
    external.static_fields.push_back({"number", "I", 0x19U, EncodedValueSpec{std::int32_t{42}}, {}});
    builder.AddClass(std::move(external));
    return DexFile::Parse(builder.Build());
}

void Check(const birch::dex::DexFile& dex, bool existing_clinit) {
    birch::dex::VerifyDexOrThrow(dex, birch::dex::VerificationLevel::Full);
    birch::test::StringDexInterpreter runtime(dex);
    for (std::size_t i = 0; i < float_bits.size(); ++i)
        assert(runtime.ExecuteScalar(owner, "f" + std::to_string(i)) == float_bits[i]);
    const std::array<std::uint32_t, 5U> integers{
        1U, static_cast<std::uint32_t>(-123), 0xfedcU,
        static_cast<std::uint32_t>(-23456), static_cast<std::uint32_t>(-123456789)};
    for (std::size_t i = 0; i < integers.size(); ++i)
        assert(runtime.ExecuteScalar(owner, "i" + std::to_string(i)) == integers[i]);
    assert(runtime.Execute(owner, "stored") == u"static-vault-value");
    if (existing_clinit) assert(runtime.Execute(owner, "body") == u"original-clinit-literal");
}
} // namespace

int main() {
    const std::array configs{
        Config(true, false), Config(false, true), Config(true, true),
        Config(false, false, true), Config(false, true, true), Config(true, true, true)};
    for (bool existing : {false, true}) {
        for (const auto registers : {1U, 16U, 253U, 255U}) {
            const auto source = Fixture(static_cast<std::uint16_t>(registers), existing);
            Check(source, existing);
            for (const auto& config : configs) {
                const auto result = birch::guard::DexModelLowering(config).Apply(source);
                const auto output = birch::dex::DexFile::Parse(result.bytes);
                Check(output, existing);
                birch::dex::DexClassCloner cloner(output);
                for (std::size_t i = 0; i < output.classes().size(); ++i) {
                    const auto klass = cloner.Clone(i);
                    if (klass.descriptor == "Lthirdparty/Untouched;") {
                        assert(klass.direct_methods.empty());
                        assert(klass.static_fields.size() == 2U);
                        for (const auto& field : klass.static_fields) assert(field.static_value.has_value());
                    }
                }
                if (config.passes.at("data.string_encryption").enabled ||
                    config.passes.at("data.string_splitting").enabled) {
                    for (std::size_t i = 0; i < output.strings().size(); ++i) {
                        const auto value = output.string(static_cast<std::uint32_t>(i));
                        assert(value != "static-vault-value");
                        assert(value != "original-clinit-literal");
                    }
                }
            }
        }
    }
    std::cout << "Static float bits, narrow fields, scope, v0, payload alignment and clinit string sites passed\n";
}
