#include "birch/dex/builder.h"
#include "birch/dex/verifier.h"
#include "cff_switch_emitter.h"
#include "dead_state_router.h"
#include "support/int_dex_interpreter.h"

#include <array>
#include <algorithm>
#include <cassert>
#include <iostream>
#include <numeric>

namespace {
using birch::guard::detail::CffAssembler;
using birch::guard::detail::CffSwitchEmitter;
using birch::guard::detail::DeadStateRouter;

birch::dex::CodeItem Decode(std::vector<std::uint16_t> units) {
    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lrouter/Fixture;";
    birch::dex::MethodSpec method;
    method.name = "route";
    method.return_type = "I";
    method.parameter_types = {"I", "I"};
    method.access_flags = 0x0009U;
    method.body.registers_size = 258U;
    method.body.ins_size = 2U;
    method.body.code_units = std::move(units);
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    const auto file = birch::dex::DexFile::Parse(builder.Build());
    birch::dex::VerifyDexOrThrow(file, birch::dex::VerificationLevel::Full);
    return birch::dex::DecodeCodeItem(file, file.class_data(0).direct_methods.front().code_off);
}

std::size_t Check(std::uint16_t reg, std::vector<std::uint32_t> states, bool packed, std::uint64_t seed) {
    const std::uint16_t scratch = reg == 0U ? 1U : 0U;
    CffAssembler assembler;
    assembler.UseCompactBranches();
    const auto fail = assembler.NewLabel();
    const auto root = assembler.NewLabel();
    CffSwitchEmitter switches(assembler, fail);
    std::vector<CffAssembler::Label> cases, entries{root};
    for (std::size_t i = 0; i < states.size(); ++i) cases.push_back(assembler.NewLabel());
    for (std::size_t i = 0; i < states.size() * 2U; ++i) entries.push_back(assembler.NewLabel());
    DeadStateRouter router(assembler, reg, states, cases, packed, seed);
    // Explicit fallback entry for every occupied shard, fed an unknown token.
    std::vector<std::size_t> occupied;
    for (std::size_t i = 0; i < router.shards().size(); ++i)
        if (!router.shards()[i].keys.empty()) {
            occupied.push_back(i);
            entries.push_back(assembler.NewLabel());
        }
    assembler.Emit({static_cast<std::uint16_t>(0x02U | (scratch << 8U)), 256U});
    std::vector<std::uint32_t> entry_keys(entries.size());
    std::iota(entry_keys.begin(), entry_keys.end(), 0U);
    switches.Emit(scratch, entry_keys, entries, true);

    assembler.Bind(root);
    assembler.Emit({static_cast<std::uint16_t>(0x02U | (reg << 8U)), 257U});
    router.EmitSelector(scratch);
    std::vector<std::uint32_t> shard_keys;
    std::vector<CffAssembler::Label> shard_labels;
    for (auto shard : occupied) {
        shard_keys.push_back(static_cast<std::uint32_t>(shard));
        shard_labels.push_back(router.shards()[shard].dispatcher);
    }
    switches.Emit(scratch, shard_keys, shard_labels, false, fail, true);
    router.EmitFallback(occupied.front(), seed);
    for (std::size_t i = 0; i < states.size() * 2U; ++i) {
        if (i % 8U == 0U) router.FlushLocalDecoders();
        assembler.Bind(entries[1U + i]);
        const auto index = i % states.size();
        if (i < states.size()) router.EmitEntry(index);
        else {
            const auto current = i % 2U == 0U ? states[index] + 53U : states[index] ^ 0xdeadbeefU;
            assembler.EmitConst32(reg, current);
            router.EmitEdge(current, index, seed ^ i);
        }
    }
    router.FlushLocalDecoders();
    for (std::size_t i = 0; i < occupied.size(); ++i) {
        assembler.Bind(entries[1U + states.size() * 2U + i]);
        assembler.Emit({static_cast<std::uint16_t>(0x02U | (reg << 8U)), 257U});
        router.EmitFallback(occupied[i], seed ^ i);
    }
    for (std::size_t i = 0; i < router.shards().size(); ++i) {
        router.BindShard(i);
        const auto& shard = router.shards()[i];
        if (shard.keys.empty()) continue;
        switches.Emit(reg, shard.keys, shard.targets, packed, fail, true);
        router.EmitFallback(i, seed + i);
    }
    for (std::size_t i = 0; i < cases.size(); ++i) {
        assembler.Bind(cases[i]);
        assembler.EmitConst32(scratch, states[i]);
        assembler.EmitXor(scratch, scratch, reg);
        assembler.EmitIf16(static_cast<std::uint16_t>(0x39U | (scratch << 8U)), fail);
        assembler.Emit({static_cast<std::uint16_t>(0x0fU | (reg << 8U))});
    }
    assembler.Bind(fail);
    assembler.EmitConst32(reg, 0xfeedfaceU);
    assembler.Emit({static_cast<std::uint16_t>(0x0fU | (reg << 8U))});
    switches.EmitPayloads(scratch);
    auto units = std::move(assembler).Finish();
    switches.PatchPayloads(units);
    const auto code = Decode(std::move(units));
    std::size_t comparisons = 0;
    const auto run = [&](std::uint32_t entry, std::uint32_t value, std::uint32_t expected) {
        assert(birch::test::IntDexInterpreter::Execute(code, std::array{entry, value}) == expected);
        ++comparisons;
    };
    for (std::uint32_t i = 0; i < states.size(); ++i) {
        run(0U, states[i], states[i]);
        run(1U + i, 0xfeedfaceU, states[i]);
        run(1U + static_cast<std::uint32_t>(states.size()) + i, 0U, states[i]);
    }
    // Exercise both root and shard defaults with genuinely unknown tokens,
    // including sparse selector buckets that have no switch cases.
    for (auto value : {0U, 1U, 0x7fffffffU, 0x80000000U, 0xffffffffU}) {
        if (std::find(states.begin(), states.end(), value) != states.end()) continue;
        const auto shard = packed ? (value - states.front()) >> 7U : value & (router.shards().size() - 1U);
        auto selected = occupied.front();
        if (shard < router.shards().size() && !router.shards()[shard].keys.empty()) selected = shard;
        const auto& table = router.shards()[selected];
        run(0U, value, table.keys[(selected == shard ? seed + selected : seed) % table.keys.size()]);
    }
    for (std::size_t i = 0; i < occupied.size(); ++i) {
        const auto& table = router.shards()[occupied[i]];
        run(static_cast<std::uint32_t>(1U + states.size() * 2U + i), 0x12345678U,
            table.keys[(seed ^ i) % table.keys.size()]);
    }
    return comparisons;
}
} // namespace

int main() {
    std::size_t comparisons = 0;
    for (std::uint16_t reg : {0U, 15U, 16U, 255U}) {
        for (std::uint64_t seed : {1ULL, 127ULL, 0xfedcba9876543210ULL}) {
            for (auto first : {0x10000000U, 0xffffff00U, 0x7fffff00U}) {
                std::vector<std::uint32_t> states(513U);
                std::iota(states.begin(), states.end(), first);
                comparisons += Check(reg, states, true, seed);
            }
            for (bool empty_buckets : {false, true}) {
                std::vector<std::uint32_t> states(513U);
                for (std::uint32_t i = 0; i < states.size(); ++i)
                    states[i] = (i * 0x9e3779b9U + 0x12345678U) << (empty_buckets ? 5U : 0U);
                comparisons += Check(reg, states, false, seed);
            }
        }
    }
    std::cout << comparisons << " dead-state entry/relative/root/fallback comparisons passed\n";
}
