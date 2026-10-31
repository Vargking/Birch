#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/verifier.h"
#include "cff_assembler.h"
#include "cff_code_budget.h"
#include "cff_switch_emitter.h"
#include "strength_policy.h"
#include "dead_state_emitter.h"
#include "support/int_dex_interpreter.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

using birch::guard::detail::CffAssembler;
using birch::guard::detail::DeadStateEmitter;

birch::dex::CodeItem Decode(std::vector<std::uint16_t> units, std::uint16_t registers,
                            bool parameter = false) {
    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lencoding/Fixture;";
    birch::dex::MethodSpec method;
    method.name = "execute";
    method.return_type = "I";
    method.access_flags = 0x0009U;
    if (parameter)
        method.parameter_types = {"I"};
    method.body.registers_size = registers;
    method.body.ins_size = parameter ? 1U : 0U;
    method.body.code_units = std::move(units);
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    const auto dex = birch::dex::DexFile::Parse(builder.Build());
    birch::dex::VerifyDexOrThrow(dex, birch::dex::VerificationLevel::Full);
    return birch::dex::DecodeCodeItem(dex, dex.class_data(0U).direct_methods.front().code_off);
}

void Return(CffAssembler &assembler, std::uint16_t reg) {
    assembler.Emit({static_cast<std::uint16_t>(0x0fU | (reg << 8U))});
}

void CheckConstantsAndAlignment() {
    constexpr std::array values{0U,          7U,          8U,          32767U,
                                32768U,      0xfffffff8U, 0xfffffff7U, 0xffff8000U,
                                0xffff7fffU, 0x7fffffffU, 0x80000000U, 0xffffffffU};
    for (std::uint16_t reg : {0U, 15U, 16U, 255U}) {
        for (const auto value : values) {
            CffAssembler assembler;
            assembler.EmitConst32(reg, value);
            Return(assembler, reg);
            const auto code = Decode(std::move(assembler).Finish(), reg + 1U);
            assert(birch::test::IntDexInterpreter::Execute(code, {}) == value);
        }
        for (unsigned prefix : {0U, 1U}) {
            CffAssembler assembler;
            if (prefix != 0U)
                assembler.Emit({0U});
            const auto before = assembler.position();
            assembler.AlignPayload(reg);
            assert(assembler.position() % 2U == 0U);
            assert(assembler.position() - before == (prefix == 0U ? 0U : reg <= 15U ? 1U : 3U));
            if (prefix == 0U)
                assembler.EmitConst32(reg, 0U);
            Return(assembler, reg);
            const auto code = Decode(std::move(assembler).Finish(), reg + 1U);
            assert(birch::test::IntDexInterpreter::Execute(code, {}) == 0U);
        }
    }
}

void CheckXor() {
    for (const auto &regs : std::array{std::array<std::uint16_t, 3>{0U, 0U, 1U},
                                       std::array<std::uint16_t, 3>{1U, 0U, 1U},
                                       std::array<std::uint16_t, 3>{15U, 15U, 0U},
                                       std::array<std::uint16_t, 3>{16U, 16U, 255U},
                                       std::array<std::uint16_t, 3>{255U, 16U, 0U}}) {
        CffAssembler assembler;
        assembler.EmitConst32(regs[1], 0x80000000U);
        assembler.EmitConst32(regs[2], 0xdeadbeefU);
        assembler.EmitXor(regs[0], regs[1], regs[2]);
        Return(assembler, regs[0]);
        const auto code = Decode(std::move(assembler).Finish(), 256U);
        assert(birch::test::IntDexInterpreter::Execute(code, {}) == 0x5eadbeefU);
    }
}

void CheckStateEdges() {
    constexpr std::array edges{std::pair{0U, 1U},
                               std::pair{1U, 0U},
                               std::pair{0xfffffffeU, 1U},
                               std::pair{1U, 0xfffffffeU},
                               std::pair{0x7fffffffU, 0x80000000U},
                               std::pair{0x80000000U, 0x7fffffffU},
                               std::pair{0U, 65000U},
                               std::pair{65000U, 0U},
                               std::pair{0x12345678U, 0xabcdef01U}};
    for (std::uint16_t reg : {0U, 15U, 16U, 255U}) {
        for (std::uint64_t seed : {0ULL, 1ULL, 127ULL, 0xfedcba9876543210ULL}) {
            for (const auto &[current, target] : edges) {
                CffAssembler assembler;
                const auto dispatcher = assembler.NewLabel();
                // The dispatcher returns the decoded token, making otherwise
                // unreachable transitions executable by the independent oracle.
                assembler.EmitConst32(reg, current);
                DeadStateEmitter edges_emitter(assembler, reg, dispatcher, seed, true);
                edges_emitter.Emit(current, target, seed ^ 0x123456789abcdefULL);
                edges_emitter.BindDecoder();
                assembler.Bind(dispatcher);
                Return(assembler, reg);
                const auto code = Decode(std::move(assembler).Finish(), reg + 1U);
                assert(birch::test::IntDexInterpreter::Execute(code, {}) == target);

                CffAssembler relative;
                relative.EmitConst32(reg, current);
                if (!relative.EmitRelativeEncodedState(reg, current, target, seed))
                    relative.EmitEncodedState(reg, target, seed);
                Return(relative, reg);
                const auto relative_code = Decode(std::move(relative).Finish(), reg + 1U);
                assert(birch::test::IntDexInterpreter::Execute(relative_code, {}) == target);
            }
        }
    }
    // Binding an unused decoder must not emit a read of an undefined register.
    CffAssembler assembler;
    const auto dispatcher = assembler.NewLabel();
    DeadStateEmitter unused(assembler, 15U, dispatcher, 1U, true);
    unused.BindDecoder();
    assert(assembler.position() == 0U);
    assembler.Bind(dispatcher);
    assembler.EmitConst32(15U, 42U);
    Return(assembler, 15U);
    assert(birch::test::IntDexInterpreter::Execute(Decode(std::move(assembler).Finish(), 16U),
                                                   {}) == 42U);
}

void CheckGroupedDecoders() {
    for (std::uint16_t reg : {0U, 15U}) {
        for (bool local : {false, true}) {
            CffAssembler assembler;
            assembler.UseCompactBranches();
            const auto dispatcher = assembler.NewLabel();
            std::vector<CffAssembler::Label> cases;
            for (unsigned i = 0; i < 32U; ++i)
                cases.push_back(assembler.NewLabel());
            // v16 is the selector parameter, kept outside every state register.
            for (unsigned i = 0; i < cases.size(); ++i) {
                assembler.EmitConst32(14U, i);
                assembler.Emit({0x0002U, 16U});        // move/from16 v0, v16
                assembler.EmitIf16(0xe032U, cases[i]); // if-eq v0, v14
            }
            assembler.EmitConst32(reg, 0U);
            Return(assembler, reg);
            DeadStateEmitter emitter(assembler, reg, dispatcher, 127U, local);
            for (unsigned i = 0; i < cases.size(); ++i) {
                if (i != 0U && i % 16U == 0U)
                    emitter.BindDecoder();
                assembler.Bind(cases[i]);
                // Include more padding than a generated runtime call/conditional
                // every eighth case, exercising the worst local jump distances.
                if (i % 8U == 0U)
                    for (unsigned n = 0; n < 12U; ++n)
                        assembler.Emit({0U});
                assembler.EmitConst32(reg, 0x10000000U + i);
                emitter.Emit(0x10000000U + i, 0x10000100U + i, i + 1U);
            }
            emitter.BindDecoder();
            assembler.Bind(dispatcher);
            Return(assembler, reg);
            const auto code = Decode(std::move(assembler).Finish(), 17U, true);
            for (std::uint32_t i = 0; i < cases.size(); ++i)
                assert(birch::test::IntDexInterpreter::Execute(code, std::array{i}) ==
                       0x10000100U + i);
        }
    }
}

void CheckLayoutBudget() {
    using namespace birch::guard::detail;
    auto config = birch::guard::GuardConfig::Defaults();
    config.passes.at("strength.anti_automation_profile").enabled = true;
    config.passes.at("strength.anti_automation_profile").intensity = 1.0;
    config.budget.max_code_units_per_method = 65000U;
    config.budget.max_method_growth_ratio = 10000.0;
    assert(StrengthPolicy::CodeUnitLimit(config) == 16000U);
    assert(StrengthPolicy::GrowthLimit(65000U, std::numeric_limits<double>::max()) ==
        std::numeric_limits<std::size_t>::max());
    CffCodeBudget budget(config, 100U);
    budget.Reserve("body", 8000U);
    budget.Reserve("dead", 8000U);
    assert(budget.Fits());
    budget.Reconcile(16000U);
    budget.Reserve("padding", 1U);
    assert(!budget.Fits());
    bool refused = false;
    try { budget.Require("boundary", 1024U); } catch (const std::length_error&) { refused = true; }
    assert(refused);
    refused = false;
    try { budget.Reconcile(16000U); } catch (const std::logic_error&) { refused = true; }
    assert(refused);
    config.budget.max_method_growth_ratio = 1.0;
    CffCodeBudget growth(config, 100U);
    growth.Reserve("exact", 100U);
    assert(growth.Fits());
    growth.Reserve("extra", 1U);
    assert(!growth.Fits());
    for (const auto reg : {0U, 16U, 255U}) for (const auto packed : {false, true}) {
        CffAssembler assembler;
        const auto target = assembler.NewLabel();
        CffSwitchEmitter dispatch(assembler, target);
        assembler.Bind(target);
        dispatch.Emit(static_cast<std::uint16_t>(reg), {1U, 2U, 3U}, {target, target, target}, packed);
        dispatch.Emit(static_cast<std::uint16_t>(reg), {7U, 99U}, {target, target}, true);
        const auto planned = dispatch.PlannedPayloadEnd(assembler.position(), static_cast<std::uint16_t>(reg));
        dispatch.EmitPayloads(static_cast<std::uint16_t>(reg));
        assert(planned == assembler.position());
        auto units = std::move(assembler).Finish();
        dispatch.PatchPayloads(units);
    }
}

void CheckBranchLimits() {
    for (const int displacement : {-129, -128, -1, 0, 1, 127, 128}) {
        CffAssembler assembler;
        const auto target = assembler.NewLabel();
        if (displacement <= 0) {
            assembler.Bind(target);
            for (int n = 0; n < -displacement; ++n)
                assembler.Emit({0U});
            assembler.EmitGoto8(target);
        } else {
            assembler.EmitGoto8(target);
            for (int n = 1; n < displacement; ++n)
                assembler.Emit({0U});
            assembler.Bind(target);
        }
        assembler.Emit({0x000eU});
        bool rejected = false;
        try {
            const auto units = std::move(assembler).Finish();
            const auto at = displacement <= 0 ? -displacement : 0;
            assert((units.at(at) >> 8U) == (static_cast<std::uint32_t>(displacement) & 255U));
        } catch (const std::length_error &) {
            rejected = true;
        }
        assert(rejected == (displacement == 0 || displacement < -128 || displacement > 127));
    }
    for (bool compact : {false, true}) {
        for (std::uint32_t value : {0U, 1U, 0x80000000U}) {
            CffAssembler assembler;
            if (compact)
                assembler.UseCompactBranches();
            const auto zero = assembler.NewLabel();
            assembler.EmitConst32(0U, value);
            assembler.EmitIf16(0x0038U, zero);
            assembler.EmitConst32(0U, 11U);
            Return(assembler, 0U);
            assembler.Bind(zero);
            assembler.EmitConst32(0U, 22U);
            Return(assembler, 0U);
            assert(birch::test::IntDexInterpreter::Execute(
                       Decode(std::move(assembler).Finish(), 1U), {}) == (value == 0U ? 22U : 11U));
        }
    }
    for (const unsigned distance : {32767U, 32768U}) {
        CffAssembler assembler;
        assembler.UseCompactBranches();
        const auto target = assembler.NewLabel();
        assembler.EmitGoto32(target);
        while (assembler.position() < distance)
            assembler.Emit({0U});
        assembler.Bind(target);
        assembler.Emit({0x000eU});
        bool rejected = false;
        try {
            (void)std::move(assembler).Finish();
        } catch (const std::length_error &) {
            rejected = true;
        }
        assert(rejected == (distance > 32767U));
    }
}

} // namespace

int main() {
    CheckConstantsAndAlignment();
    CheckXor();
    CheckStateEdges();
    CheckGroupedDecoders();
    CheckBranchLimits();
    CheckLayoutBudget();
    std::cout << "CFF encoding, wraparound, grouped decoders and branch limits "
                 "passed\n";
}
