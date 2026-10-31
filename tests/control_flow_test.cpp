#include "birch/guard/control_flow.h"

#include "birch/dex/ir.h"

#include <cassert>

int main() {
    birch::dex::CodeItem code;
    code.insns = {0x000e};
    code.instructions.push_back({0U, 0x0eU, 1U, birch::dex::InstructionKind::Return, {0x000e}, {}, false});
    const auto method = birch::dex::BuildMethodIr(std::move(code));
    constexpr birch::guard::ControlFlowStrategy strategies[] = {
        birch::guard::ControlFlowStrategy::Flattening,
        birch::guard::ControlFlowStrategy::NestedFlattening,
        birch::guard::ControlFlowStrategy::MultiStateDispatcher,
        birch::guard::ControlFlowStrategy::BogusReachableBranch,
        birch::guard::ControlFlowStrategy::LoopStateMachine,
        birch::guard::ControlFlowStrategy::ConditionalExpansion,
        birch::guard::ControlFlowStrategy::ConditionalNesting,
        birch::guard::ControlFlowStrategy::PackedSparseIfMix,
        birch::guard::ControlFlowStrategy::IndirectTableDispatch,
        birch::guard::ControlFlowStrategy::ExceptionDispatcher,
        birch::guard::ControlFlowStrategy::CallbackStyle,
        birch::guard::ControlFlowStrategy::TailRecursionEquivalent,
        birch::guard::ControlFlowStrategy::DeadBlockWithOpaqueGuard,
        birch::guard::ControlFlowStrategy::BlockReordering,
    };
    for (const auto strategy : strategies) {
        const auto plan = birch::guard::PlanControlFlowTransform(method, strategy, 7U, 0.75);
        birch::guard::ValidateControlFlowPlan(method, plan, 1000U, 1000U);
        assert(plan.verifier_safe);
        assert(!plan.lowering.empty());
    }
    return 0;
}
