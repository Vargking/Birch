#pragma once

#include "birch/dex/code.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace birch::dex {

using BlockId = std::uint32_t;

enum class IrEdgeKind {
    Fallthrough,
    Branch,
    SwitchCase,
    Exception,
};

struct IrInstruction {
    std::uint32_t dex_offset{};
    std::uint8_t dex_opcode{};
    std::vector<std::uint16_t> encoded;
    bool can_throw{};
};

struct IrEdge {
    BlockId target{};
    IrEdgeKind kind{IrEdgeKind::Fallthrough};
    std::optional<std::uint32_t> catch_type_idx;
};

struct IrBasicBlock {
    BlockId id{};
    std::uint32_t start_offset{};
    std::vector<IrInstruction> instructions;
    std::vector<IrEdge> successors;
};

class MethodIr final {
public:
    [[nodiscard]] const CodeItem& code() const noexcept { return code_; }
    [[nodiscard]] const std::vector<IrBasicBlock>& blocks() const noexcept { return blocks_; }
    [[nodiscard]] BlockId entry() const noexcept { return entry_; }

private:
    friend MethodIr BuildMethodIr(CodeItem code);
    CodeItem code_;
    std::vector<IrBasicBlock> blocks_;
    BlockId entry_{};
};

MethodIr BuildMethodIr(CodeItem code);

} // namespace birch::dex
