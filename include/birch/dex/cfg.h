#pragma once

#include "birch/dex/ir.h"

#include <cstddef>
#include <vector>

namespace birch::dex {

class ControlFlowGraph final {
public:
    explicit ControlFlowGraph(const MethodIr& method);

    [[nodiscard]] const std::vector<std::vector<BlockId>>& predecessors() const noexcept {
        return predecessors_;
    }
    [[nodiscard]] std::vector<bool> Reachable() const;
    [[nodiscard]] bool Verify() const;

private:
    const MethodIr* method_{};
    std::vector<std::vector<BlockId>> predecessors_;
};

} // namespace birch::dex
