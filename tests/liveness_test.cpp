#include "birch/dex/liveness.h"

#include <cassert>
#include <iostream>
#include <numeric>
#include <set>

namespace {
using namespace birch::dex;
void Append(CodeItem& code, std::vector<std::uint16_t> units,
            InstructionKind kind = InstructionKind::Normal,
            std::vector<std::uint32_t> targets = {}, bool throws = false) {
    const auto offset = static_cast<std::uint32_t>(code.insns.size());
    code.instructions.push_back({offset, static_cast<std::uint8_t>(units.front() & 255U),
        static_cast<std::uint32_t>(units.size()), kind, units, std::move(targets), throws});
    code.insns.insert(code.insns.end(), units.begin(), units.end());
}

std::set<std::uint16_t> Before(std::vector<std::uint16_t> units,
                             const std::vector<std::uint16_t>& after = {}) {
    CodeItem code;
    code.registers_size = 20U;
    Append(code, {0x0128U}, InstructionKind::UnconditionalBranch, {1U});
    Append(code, std::move(units));
    for (auto reg : after) Append(code, {static_cast<std::uint16_t>(0x0fU | (reg << 8U))});
    Append(code, {0x000eU}, InstructionKind::Return);
    const MethodLiveness live(BuildMethodIr(std::move(code)));
    return {live.LiveOut(0U).begin(), live.LiveOut(0U).end()};
}

void CheckOperands() {
    assert((Before({0x2101U}) == std::set<std::uint16_t>{2U}));
    assert((Before({0x2104U}) == std::set<std::uint16_t>{2U, 3U}));
    assert((Before({0x0105U, 16U}) == std::set<std::uint16_t>{16U, 17U}));
    assert((Before({0x0009U, 18U, 17U}) == std::set<std::uint16_t>{17U}));
    assert(Before({0x0116U, 1U}, {1U, 2U}).empty()); // wide definition kills both
    assert((Before({0x0120U, 0U}) == std::set<std::uint16_t>{0U}));
    assert((Before({0x011fU, 0U}, {1U}) == std::set<std::uint16_t>{1U}));
    assert((Before({0x0145U, 0x0302U}, {1U, 2U}) == std::set<std::uint16_t>{2U, 3U}));
    assert((Before({0x014cU, 0x0304U}) == std::set<std::uint16_t>{1U, 2U, 3U, 4U}));
    assert((Before({0x2153U, 0U}, {1U, 2U}) == std::set<std::uint16_t>{2U}));
    assert((Before({0x215aU, 0U}) == std::set<std::uint16_t>{1U, 2U}));
    assert((Before({0x0168U, 0U}) == std::set<std::uint16_t>{1U, 2U}));
    assert((Before({0x5071U, 0U, 0x4321U}) == std::set<std::uint16_t>{0U, 1U, 2U, 3U, 4U}));
    assert((Before({0x0377U, 0U, 16U}) == std::set<std::uint16_t>{16U, 17U, 18U}));
    assert((Before({0x21bbU}) == std::set<std::uint16_t>{1U, 2U, 3U})); // add-long/2addr
    assert((Before({0x21c3U}) == std::set<std::uint16_t>{1U, 2U})); // shl-long/2addr
    assert((Before({0x019bU, 0x0402U}) == std::set<std::uint16_t>{2U, 3U, 4U, 5U}));
    assert((Before({0x2181U}, {1U, 2U}) == std::set<std::uint16_t>{2U})); // int-to-long
    assert((Before({0x218aU}) == std::set<std::uint16_t>{2U, 3U})); // double-to-int
    const auto unknown = Before({0x00e3U});
    assert(unknown.size() == 20U); // unknown op never supplies a speculative kill
}

void CheckExceptionAndLoop() {
    CodeItem code;
    code.registers_size = 4U;
    Append(code, {0x0128U}, InstructionKind::UnconditionalBranch, {1U});
    Append(code, {0x001aU, 0U}, InstructionKind::Normal, {}, true); // throws before v0 write
    Append(code, {0x000eU}, InstructionKind::Return);
    Append(code, {0x010dU});
    Append(code, {0x0011U}, InstructionKind::Return); // handler needs old v0
    code.tries.push_back({1U, 2U, {{std::nullopt, 4U}}});
    const MethodLiveness live(BuildMethodIr(code));
    assert((live.LiveOut(0U) == std::vector<std::uint16_t>{0U}));
    assert((live.LiveIn(0U) == std::vector<std::uint16_t>{0U}));
    assert((live.LiveIn(3U) == std::vector<std::uint16_t>{0U}));
    code.tries.clear();
    const MethodLiveness no_exception(BuildMethodIr(code));
    assert(no_exception.LiveOut(0U).empty());

    CodeItem loop;
    loop.registers_size = 2U;
    Append(loop, {0x0128U}, InstructionKind::UnconditionalBranch, {1U});
    Append(loop, {0x00d8U, 0x0100U});
    Append(loop, {0x0139U, 0xfffeU}, InstructionKind::ConditionalBranch, {1U});
    Append(loop, {0x000fU}, InstructionKind::Return);
    const MethodLiveness loop_live(BuildMethodIr(loop));
    assert((loop_live.LiveOut(0U) == std::vector<std::uint16_t>{0U, 1U}));
}

void CheckSharedExits() {
    CodeItem code;
    code.registers_size = 2U;
    // B0 -> B1 -> B2 -> B3. Originally B0/B1 do not need v0;
    // sharing B1 with B2 adds a verifier path to B3, which reads v0.
    Append(code, {0x0128U}, InstructionKind::UnconditionalBranch, {1U});
    Append(code, {0x0128U}, InstructionKind::UnconditionalBranch, {2U});
    Append(code, {0x1012U});
    Append(code, {0x0128U}, InstructionKind::UnconditionalBranch, {4U});
    Append(code, {0x000fU}, InstructionKind::Return);
    const auto ir = BuildMethodIr(code);
    const MethodLiveness original(ir);
    assert(original.LiveOut(0U).empty());
    const std::vector<BlockId> owners{0U, 1U, 1U, 3U};
    const MethodLiveness expanded(ir, owners);
    assert((expanded.LiveOut(0U) == std::vector<std::uint16_t>{0U}));
    assert((expanded.LiveOut(1U) == std::vector<std::uint16_t>{0U}));
}
}

int main() {
    CheckOperands();
    CheckExceptionAndLoop();
    CheckSharedExits();
    std::cout << "Liveness: wide, invoke/range, casts, 2addr, unknown, pre-throw and loop checks passed\n";
}
