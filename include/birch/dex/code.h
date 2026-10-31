#pragma once

#include "birch/dex/dex_file.h"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace birch::dex {

enum class InstructionKind {
    Normal,
    ConditionalBranch,
    UnconditionalBranch,
    Switch,
    Return,
    Throw,
    Payload,
};

struct DecodedInstruction {
    std::uint32_t offset{}; // Code-unit offset relative to insns[].
    std::uint8_t opcode{};
    std::uint32_t width{};
    InstructionKind kind{InstructionKind::Normal};
    std::vector<std::uint16_t> code_units;
    std::vector<std::uint32_t> targets;
    bool can_throw{};
};

struct CatchHandler {
    std::optional<std::uint32_t> type_idx;
    std::uint32_t address{};
};

struct TryRegion {
    std::uint32_t start_address{};
    std::uint32_t instruction_count{};
    std::vector<CatchHandler> handlers;
};

struct CodeItem {
    std::uint32_t file_offset{};
    std::uint16_t registers_size{};
    std::uint16_t ins_size{};
    std::uint16_t outs_size{};
    std::uint32_t debug_info_off{};
    std::vector<std::uint16_t> insns;
    std::vector<DecodedInstruction> instructions;
    std::vector<TryRegion> tries;
};

CodeItem DecodeCodeItem(const DexFile& dex, std::uint32_t file_offset);

} // namespace birch::dex
