#include "birch/dex/cfg.h"

#include <algorithm>
#include <queue>

namespace birch::dex {

ControlFlowGraph::ControlFlowGraph(const MethodIr& method) : method_(&method) {
    predecessors_.resize(method.blocks().size());
    for (const auto& block : method.blocks()) {
        for (const auto& edge : block.successors) {
            if (edge.target < predecessors_.size()) {
                predecessors_[edge.target].push_back(block.id);
            }
        }
    }
    for (auto& predecessors : predecessors_) {
        std::sort(predecessors.begin(), predecessors.end());
        predecessors.erase(std::unique(predecessors.begin(), predecessors.end()),
                           predecessors.end());
    }
}

std::vector<bool> ControlFlowGraph::Reachable() const {
    std::vector<bool> visited(method_->blocks().size(), false);
    if (visited.empty() || method_->entry() >= visited.size()) {
        return visited;
    }
    std::queue<BlockId> queue;
    visited[method_->entry()] = true;
    queue.push(method_->entry());
    while (!queue.empty()) {
        const auto id = queue.front();
        queue.pop();
        for (const auto& edge : method_->blocks()[id].successors) {
            if (edge.target < visited.size() && !visited[edge.target]) {
                visited[edge.target] = true;
                queue.push(edge.target);
            }
        }
    }
    return visited;
}

bool ControlFlowGraph::Verify() const {
    if (method_->blocks().empty()) {
        return true;
    }
    if (method_->entry() >= method_->blocks().size() ||
        predecessors_.size() != method_->blocks().size()) {
        return false;
    }
    for (std::size_t index = 0; index < method_->blocks().size(); ++index) {
        const auto& block = method_->blocks()[index];
        if (block.id != index || block.instructions.empty()) {
            return false;
        }
        for (const auto& edge : block.successors) {
            if (edge.target >= method_->blocks().size()) {
                return false;
            }
        }
    }
    return true;
}

} // namespace birch::dex
