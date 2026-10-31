#include "birch/guard/opaque.h"

#include <cassert>

int main() {
    using namespace birch::guard;
    const OpaqueRuntimeState state{0x1234U, 0x5678U, 0x9abcU, 0xdef0U, 1U, 2U, 7U};
    constexpr OpaqueStrategy strategies[] = {
        OpaqueStrategy::NumberTheory, OpaqueStrategy::PolynomialFiniteField,
        OpaqueStrategy::MatrixNilpotent, OpaqueStrategy::BitwisePermutation,
        OpaqueStrategy::FloatingPoint, OpaqueStrategy::HashCollision,
        OpaqueStrategy::CrossMethodState, OpaqueStrategy::CrossClassState,
        OpaqueStrategy::CryptoRelation, OpaqueStrategy::GraphProblem,
        OpaqueStrategy::ClassLoadingState, OpaqueStrategy::ReferenceIdentity,
        OpaqueStrategy::HistoryState, OpaqueStrategy::OverflowSemantics,
        OpaqueStrategy::JniInput,
    };
    for (const auto strategy : strategies) {
        const auto spec = GenerateOpaquePredicate(strategy, 17U, 0.75);
        const auto first = EvaluateOpaquePredicate(spec, state);
        assert(first == spec.expected_true);
        assert(first == EvaluateOpaquePredicate(spec, state));
        auto inverted = spec;
        inverted.expected_true = !spec.expected_true;
        assert(EvaluateOpaquePredicate(inverted, state) == !first);
        assert(!DescribeOpaquePredicate(spec).empty());
    }
    return 0;
}
