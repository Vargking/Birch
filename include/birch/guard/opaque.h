#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace birch::guard {

enum class OpaqueStrategy {
    NumberTheory,
    PolynomialFiniteField,
    MatrixNilpotent,
    BitwisePermutation,
    FloatingPoint,
    HashCollision,
    CrossMethodState,
    CrossClassState,
    CryptoRelation,
    GraphProblem,
    ClassLoadingState,
    ReferenceIdentity,
    HistoryState,
    OverflowSemantics,
    JniInput,
};

struct OpaquePredicateSpec {
    OpaqueStrategy strategy{OpaqueStrategy::BitwisePermutation};
    std::uint64_t seed{};
    std::uint32_t rounds{4U};
    std::uint32_t state_slots{2U};
    bool expected_true{true};
    bool may_throw{};
};

struct OpaqueRuntimeState {
    std::uint64_t method_state{};
    std::uint64_t class_state{};
    std::uint64_t history_hash{};
    std::uint64_t loading_cookie{};
    std::uintptr_t reference_a{};
    std::uintptr_t reference_b{};
    std::int64_t jni_value{};
};

OpaquePredicateSpec GenerateOpaquePredicate(OpaqueStrategy strategy,
                                           std::uint64_t seed,
                                           double intensity);
bool EvaluateOpaquePredicate(const OpaquePredicateSpec& spec,
                             const OpaqueRuntimeState& state);
std::string DescribeOpaquePredicate(const OpaquePredicateSpec& spec);

} // namespace birch::guard
