#include "birch/dex/builder.h"
#include "birch/dex/verifier.h"
#include "cff_switch_emitter.h"
#include "cff_transition_encoder.h"
#include "cff_joint_token.h"
#include "support/int_dex_interpreter.h"

#include <array>
#include <cassert>
#include <iostream>
#include <numeric>

namespace {
using birch::guard::detail::CffAssembler;
using birch::guard::detail::CffSwitchEmitter;
using birch::guard::detail::CffTransitionEncoder;

void Check(std::uint16_t reg, std::uint32_t base, std::uint8_t buckets,
           std::uint64_t seed, bool multi_state, bool fallthrough, bool cached) {
    CffAssembler assembler;
    assembler.UseCompactBranches();
    const auto dispatcher = assembler.NewLabel();
    const auto invalid = assembler.NewLabel();
    CffSwitchEmitter switches(assembler, invalid);
    const CffTransitionEncoder::Registers registers{
        reg, static_cast<std::uint16_t>(reg + 1U),
        static_cast<std::uint16_t>(reg + 2U), static_cast<std::uint16_t>(reg + 3U)};
    constexpr auto bucket_base = 0x12345678U;
    constexpr auto mask = 0xfedcba98U;
    const auto mask_register = static_cast<std::uint16_t>(reg + 4U);
    CffTransitionEncoder encoder(assembler, registers, base, bucket_base, buckets,
        mask, multi_state, dispatcher, invalid, seed, std::nullopt, std::nullopt,
        cached ? std::optional(mask_register) : std::nullopt);
    std::vector<std::uint32_t> keys(193U);
    std::iota(keys.begin(), keys.end(), 0U);
    std::vector<CffAssembler::Label> entries, checks;
    for ([[maybe_unused]] auto key : keys) {
        entries.push_back(assembler.NewLabel());
        checks.push_back(assembler.NewLabel());
    }
    if (cached) assembler.EmitConst32(mask_register, mask);
    assembler.Emit({static_cast<std::uint16_t>(0x02U | (registers.selector << 8U)), 256U});
    switches.Emit(registers.selector, keys, entries, true);
    for (std::size_t i = 0U; i < entries.size(); ++i) {
        assembler.Bind(entries[i]);
        encoder.Emit(base + static_cast<std::uint32_t>(i));
    }
    encoder.Bind(fallthrough);
    assembler.Bind(dispatcher);
    if (multi_state) {
        assembler.EmitConst32(registers.temporary, mask);
        assembler.EmitXor(registers.temporary, registers.temporary, registers.state);
        assembler.EmitXor(registers.temporary, registers.temporary, registers.selector);
        assembler.EmitXor(registers.temporary, registers.temporary, registers.joint);
        assembler.EmitIf16(static_cast<std::uint16_t>(0x39U | (registers.temporary << 8U)), invalid);
    }
    auto state_keys = keys;
    for (auto& key : state_keys) key += base;
    switches.Emit(registers.state, state_keys, checks, true);
    for (std::size_t i = 0U; i < checks.size(); ++i) {
        assembler.Bind(checks[i]);
        // Check state and selector independently, not just their joint XOR.
        assembler.Emit({static_cast<std::uint16_t>(0x02U | (registers.temporary << 8U)), 256U});
        assembler.EmitConst32(registers.joint, static_cast<std::uint32_t>(i));
        assembler.EmitXor(registers.temporary, registers.temporary, registers.joint);
        assembler.EmitIf16(static_cast<std::uint16_t>(0x39U | (registers.temporary << 8U)), invalid);
        assembler.Emit({static_cast<std::uint16_t>(0x0fU | (registers.selector << 8U))});
    }
    assembler.Bind(invalid);
    assembler.EmitConst32(registers.selector, 0xdeadbeefU);
    assembler.Emit({static_cast<std::uint16_t>(0x0fU | (registers.selector << 8U))});
    switches.EmitPayloads(registers.temporary);
    auto units = std::move(assembler).Finish();
    switches.PatchPayloads(units);

    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Ltransition/Fixture;";
    birch::dex::MethodSpec method;
    method.name = "encode";
    method.return_type = "I";
    method.parameter_types = {"I"};
    method.access_flags = 0x0009U;
    method.body.registers_size = 257U;
    method.body.ins_size = 1U;
    method.body.code_units = std::move(units);
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    const auto file = birch::dex::DexFile::Parse(builder.Build());
    birch::dex::VerifyDexOrThrow(file, birch::dex::VerificationLevel::Full);
    const auto code = birch::dex::DecodeCodeItem(file, file.class_data(0U).direct_methods.front().code_off);
    for (std::uint32_t i = 0U; i < keys.size(); ++i)
        assert(birch::test::IntDexInterpreter::Execute(code, std::array{i}) == bucket_base + i % buckets);
    assert(birch::test::IntDexInterpreter::Execute(code, std::array{193U}) == 0xdeadbeefU);
}

void CheckJointGuard(std::uint16_t reg, bool cached, int corrupt) {
    CffAssembler assembler;
    assembler.UseCompactBranches();
    const auto invalid = assembler.NewLabel();
    const auto selector = static_cast<std::uint16_t>(reg + 1U);
    const auto joint = static_cast<std::uint16_t>(reg + 2U);
    const auto temporary = static_cast<std::uint16_t>(reg + 3U);
    const auto mask_register = static_cast<std::uint16_t>(reg + 4U);
    constexpr auto mask = 0xfedcba98U;
    assembler.EmitConst32(reg, 0x7ffffffeU);
    assembler.EmitConst32(selector, 0x87654321U);
    assembler.EmitConst32(mask_register, mask);
    const birch::guard::detail::CffJointToken token(assembler, mask,
        cached ? std::optional(mask_register) : std::nullopt);
    token.Emit(joint, reg, selector);
    if (corrupt >= 0) {
        const auto target = static_cast<std::uint16_t>(reg + corrupt);
        assembler.Emit({static_cast<std::uint16_t>(0xdfU | (target << 8U)),
                        static_cast<std::uint16_t>(target | 0x0100U)});
    }
    token.Guard(temporary, joint, reg, selector, invalid);
    assembler.EmitConst32(temporary, 7U);
    assembler.Emit({static_cast<std::uint16_t>(0x0fU | (temporary << 8U))});
    assembler.Bind(invalid);
    assembler.EmitConst32(temporary, 0U);
    assembler.Emit({static_cast<std::uint16_t>(0x0fU | (temporary << 8U))});
    birch::dex::DexBuilder builder;
    birch::dex::ClassSpec klass;
    klass.descriptor = "Ltransition/GuardFixture;";
    birch::dex::MethodSpec method;
    method.name = "guard"; method.return_type = "I"; method.access_flags = 0x0009U;
    method.body.registers_size = static_cast<std::uint16_t>(reg + 5U);
    method.body.code_units = std::move(assembler).Finish();
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    const auto file = birch::dex::DexFile::Parse(builder.Build());
    birch::dex::VerifyDexOrThrow(file, birch::dex::VerificationLevel::Full);
    const auto code = birch::dex::DecodeCodeItem(file, file.class_data(0U).direct_methods.front().code_off);
    assert(birch::test::IntDexInterpreter::Execute(code, {}) == (corrupt < 0 ? 7U : 0U));
}
} // namespace

int main() {
    for (auto reg : {0U, 16U, 250U}) {
        for (bool cached : {false, true}) {
            for (int corrupt : {-1, 0, 1, 2})
                CheckJointGuard(static_cast<std::uint16_t>(reg), cached, corrupt);
            if (cached) CheckJointGuard(static_cast<std::uint16_t>(reg), true, 4);
        }
    }
    for (auto reg : {0U, 16U, 250U})
        for (auto base : {0U, 0x10000000U, 0x7fffffc0U, 0xffffffc0U})
            for (auto buckets : {3U, 5U, 16U})
                for (auto seed : {1ULL, 777331ULL, 0xfedcba9876543210ULL})
                    for (bool multi_state : {false, true})
                      for (bool fallthrough : {false, true})
                       for (bool cached : {false, true})
                        Check(static_cast<std::uint16_t>(reg), base,
                              static_cast<std::uint8_t>(buckets), seed, multi_state, fallthrough, cached);
    std::cout << "166752 shared transition state/selector/joint comparisons passed\n";
}
