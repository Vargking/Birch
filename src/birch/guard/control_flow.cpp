#include "birch/guard/control_flow.h"
#include "birch/dex/cfg.h"

#include <cmath>
#include <stdexcept>

namespace birch::guard {

ControlFlowPlan PlanControlFlowTransform(const dex::MethodIr& method,
                                         ControlFlowStrategy strategy,
                                         std::uint64_t seed,
                                         double intensity) {
    if (!std::isfinite(intensity) || intensity < 0.0 || intensity > 1.0) {
        throw std::invalid_argument("control-flow intensity must be in [0,1]");
    }
    if (method.blocks().empty()) throw std::invalid_argument("cannot transform an empty method");
    const auto scale = static_cast<std::uint32_t>(1U + intensity * 15.0);
    ControlFlowPlan plan{strategy, seed, intensity, scale, 0U, 0U, 0U, true, {}};
    switch (strategy) {
        case ControlFlowStrategy::Flattening:
            plan.added_blocks = scale; plan.added_edges = scale * 2U; plan.lowering = "packed-switch dispatcher with state register"; break;
        case ControlFlowStrategy::NestedFlattening:
            plan.dispatcher_states = scale * 2U; plan.added_blocks = scale * 2U; plan.added_edges = scale * 4U; plan.lowering = "nested packed/sparse-switch dispatchers"; break;
        case ControlFlowStrategy::MultiStateDispatcher:
            plan.dispatcher_states = scale * 3U; plan.added_blocks = scale; plan.added_edges = scale * 3U; plan.lowering = "two-register state pair plus sparse-switch"; break;
        case ControlFlowStrategy::BogusReachableBranch:
            plan.added_blocks = scale; plan.added_edges = scale * 2U; plan.lowering = "opaque-guarded legal branch with verifier-visible target"; break;
        case ControlFlowStrategy::LoopStateMachine:
            plan.added_blocks = scale; plan.added_edges = scale * 3U; plan.lowering = "loop rewritten as explicit state machine"; break;
        case ControlFlowStrategy::ConditionalExpansion:
            plan.added_blocks = scale; plan.added_edges = scale * 2U; plan.lowering = "boolean normalization and split conditional blocks"; break;
        case ControlFlowStrategy::ConditionalNesting:
            plan.added_blocks = scale * 2U; plan.added_edges = scale * 3U; plan.lowering = "nested if/else chain with opaque state"; break;
        case ControlFlowStrategy::PackedSparseIfMix:
            plan.added_blocks = scale; plan.added_edges = scale * 3U; plan.lowering = "mixed packed-switch, sparse-switch and if edges"; break;
        case ControlFlowStrategy::IndirectTableDispatch:
            plan.added_blocks = scale; plan.added_edges = scale * 2U; plan.lowering = "computed index into sparse-switch table"; break;
        case ControlFlowStrategy::ExceptionDispatcher:
            plan.added_blocks = scale; plan.added_edges = scale * 2U; plan.added_try_regions = scale; plan.lowering = "legal try/catch dispatcher with typed handlers"; break;
        case ControlFlowStrategy::CallbackStyle:
            plan.added_blocks = scale * 2U; plan.added_edges = scale * 3U; plan.lowering = "synthetic callback state carrier methods"; break;
        case ControlFlowStrategy::TailRecursionEquivalent:
            plan.added_blocks = scale; plan.added_edges = scale * 2U; plan.lowering = "bounded recursion-equivalent state loop"; break;
        case ControlFlowStrategy::DeadBlockWithOpaqueGuard:
            plan.added_blocks = scale; plan.added_edges = scale; plan.lowering = "opaque false guard guarding legal dead blocks"; break;
        case ControlFlowStrategy::BlockReordering:
            plan.added_blocks = 0U; plan.added_edges = 0U; plan.lowering = "stable block permutation with repaired branch targets"; break;
    }
    return plan;
}

void ValidateControlFlowPlan(const dex::MethodIr& method, const ControlFlowPlan& plan,
                             std::uint32_t max_blocks, std::uint32_t max_try_regions) {
    dex::ControlFlowGraph cfg(method);
    if (!cfg.Verify()) throw std::invalid_argument("source CFG is invalid");
    if (!plan.verifier_safe) throw std::invalid_argument("control-flow plan is not verifier safe");
    if (plan.added_blocks > max_blocks || plan.added_try_regions > max_try_regions) {
        throw std::invalid_argument("control-flow plan exceeds safety budget");
    }
}

} // namespace birch::guard
