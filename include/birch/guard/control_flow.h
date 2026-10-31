#pragma once

#include "birch/dex/ir.h"

#include <cstdint>
#include <string>
#include <vector>

namespace birch::guard {

enum class ControlFlowStrategy {
    Flattening,
    NestedFlattening,
    MultiStateDispatcher,
    BogusReachableBranch,
    LoopStateMachine,
    ConditionalExpansion,
    ConditionalNesting,
    PackedSparseIfMix,
    IndirectTableDispatch,
    ExceptionDispatcher,
    CallbackStyle,
    TailRecursionEquivalent,
    DeadBlockWithOpaqueGuard,
    BlockReordering,
};

struct ControlFlowPlan {
    ControlFlowStrategy strategy{};
    std::uint64_t seed{};
    double intensity{};
    std::uint32_t dispatcher_states{};
    std::uint32_t added_blocks{};
    std::uint32_t added_edges{};
    std::uint32_t added_try_regions{};
    bool verifier_safe{true};
    std::string lowering;
};

ControlFlowPlan PlanControlFlowTransform(const dex::MethodIr& method,
                                         ControlFlowStrategy strategy,
                                         std::uint64_t seed,
                                         double intensity);
void ValidateControlFlowPlan(const dex::MethodIr& method, const ControlFlowPlan& plan,
                             std::uint32_t max_blocks, std::uint32_t max_try_regions);

} // namespace birch::guard
