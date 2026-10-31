#include "birch/guard/opaque.h"

#include "birch/dex/checksum.h"
#include "birch/guard/opaque_runtime.h"
#include "birch/utils/hash.h"

#include <array>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace birch::guard {
namespace {

std::uint64_t Mix(std::uint64_t value) {
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    return value ^ (value >> 31U);
}

std::uint64_t PowMod(std::uint64_t base, std::uint64_t exponent, std::uint64_t modulus) {
    std::uint64_t result = 1U;
    base %= modulus;
    while (exponent != 0U) {
        if ((exponent & 1U) != 0U) result = (result * base) % modulus;
        base = (base * base) % modulus;
        exponent >>= 1U;
    }
    return result;
}

std::uint64_t MatrixTraceIdentity(std::uint64_t seed, std::uint32_t rounds) {
    // A 2x2 nilpotent matrix N has N^2 = 0. We compute (I+N)^k and
    // deliberately keep the matrix operations visible to a DEX lifter.
    std::uint64_t a = 1U;
    std::uint64_t b = Mix(seed) | 1U;
    std::uint64_t c = 0U;
    std::uint64_t d = 1U;
    for (std::uint32_t i = 0; i < rounds; ++i) {
        const auto next_a = a * a + b * c;
        const auto next_b = a * b + b * d;
        const auto next_c = c * a + d * c;
        const auto next_d = c * b + d * d;
        a = next_a; b = next_b; c = next_c; d = next_d;
    }
    return (a + d) ^ (b * c);
}

bool ConsecutiveProductIsEven(std::uint64_t value) {
    return ((value * (value - 1U)) & 1U) == 0U;
}

std::uint32_t JavaHash(std::string_view value) {
    std::uint32_t hash = 0U;
    for (const auto ch : value) {
        hash = hash * 31U + static_cast<std::uint8_t>(ch);
    }
    return hash;
}

std::string Token(std::uint64_t seed, std::string_view domain,
                  std::size_t ordinal, std::uint32_t attempt = 0U) {
    std::ostringstream stream;
    stream << 'a' << std::hex << std::setfill('0') << std::setw(8)
           << static_cast<std::uint32_t>(Mix(
                  seed ^ Mix(ordinal + (static_cast<std::uint64_t>(attempt) << 32U)) ^
                  Mix(utils::StableHash64(std::string(domain)))));
    return stream.str();
}

} // namespace

std::string RuntimeOpaqueClassDescriptor(std::uint64_t seed, std::size_t shard,
                                         std::uint32_t attempt) {
    return "L" + Token(seed, "rx", shard, attempt) + "/" +
           Token(seed ^ 0x6c626c5f6fULL, "ry", shard, attempt) + ";";
}

std::string RuntimeOpaqueMethodName(std::uint64_t seed, std::size_t strategy) {
    return Token(seed ^ 0x6d6574686f64ULL, "rz", strategy);
}

std::string RuntimeOpaqueFieldName(std::uint64_t seed, std::size_t shard,
                                   std::size_t slot) {
    return Token(seed ^ 0x6669656c64ULL, "rw",
                 shard * kRuntimeOpaqueStateFields + slot);
}

std::string RuntimeExceptionClassDescriptor(std::uint64_t seed,
                                            std::uint32_t attempt) {
    return "L" + Token(seed ^ 0x657863657074ULL, "ex", 0U, attempt) + "/" +
           Token(seed ^ 0x666c6f776865ULL, "ey", 0U, attempt) + ";";
}

std::string RuntimeExceptionMethodName(std::uint64_t seed) {
    return Token(seed ^ 0x6578636d6574ULL, "ez", 0U);
}

std::string RuntimeExceptionFieldName(std::uint64_t seed,
                                      std::size_t slot) {
    return Token(seed ^ 0x657863666965ULL, "ew", slot);
}

OpaquePredicateSpec GenerateOpaquePredicate(OpaqueStrategy strategy,
                                           std::uint64_t seed,
                                           double intensity) {
    if (!std::isfinite(intensity) || intensity < 0.0 || intensity > 1.0) {
        throw std::invalid_argument("opaque predicate intensity must be in [0,1]");
    }
    OpaquePredicateSpec spec;
    spec.strategy = strategy;
    spec.seed = seed;
    spec.rounds = 2U + static_cast<std::uint32_t>(intensity * 14.0);
    spec.state_slots = 2U + static_cast<std::uint32_t>(intensity * 4.0);
    spec.expected_true = (Mix(seed) & 1U) != 0U;
    spec.may_throw = strategy == OpaqueStrategy::FloatingPoint || strategy == OpaqueStrategy::JniInput;
    return spec;
}

bool EvaluateOpaquePredicate(const OpaquePredicateSpec& spec,
                             const OpaqueRuntimeState& state) {
    const auto mixed = Mix(spec.seed ^ state.method_state ^ (state.class_state << 1U));
    bool value = false;
    switch (spec.strategy) {
        case OpaqueStrategy::NumberTheory: {
            constexpr std::uint64_t prime = 4294967291ULL;
            const auto base = (mixed % (prime - 1U)) + 1U;
            value = PowMod(base, prime - 1U, prime) == 1U;
            break;
        }
        case OpaqueStrategy::PolynomialFiniteField: {
            constexpr std::uint64_t p = 65537U;
            const auto x = mixed % p;
            const auto x2 = (x * x) % p;
            const auto x3 = (x2 * x) % p;
            const auto x4 = (x3 * x) % p;
            const auto polynomial =
                (((x2 + 3U) * x % p + 5U) * x + 7U) % p;
            const auto expanded =
                (x4 + 3U * x2 + 5U * x + 7U) % p;
            value = polynomial == expanded;
            break;
        }
        case OpaqueStrategy::MatrixNilpotent:
            value = MatrixTraceIdentity(spec.seed ^ state.class_state, spec.rounds) != 0U;
            break;
        case OpaqueStrategy::BitwisePermutation: {
            auto x = mixed;
            for (std::uint32_t i = 0; i < spec.rounds; ++i) x = (x ^ (x << 13U)) ^ ((x >> 7U) ^ (x << 17U));
            auto y = x;
            for (std::uint32_t i = 0; i < spec.rounds; ++i) y = (y >> 17U) ^ (y << 13U) ^ (y >> 7U);
            value = ConsecutiveProductIsEven(x ^ y);
            break;
        }
        case OpaqueStrategy::FloatingPoint: {
            const auto nan = std::numeric_limits<double>::quiet_NaN();
            const auto finite = static_cast<double>(mixed & 0xffffU) + 1.0;
            value = std::isnan(nan) && !std::isfinite(nan) && finite > 0.0;
            break;
        }
        case OpaqueStrategy::HashCollision: {
            std::array<std::uint8_t, 16> input{};
            for (std::size_t i = 0; i < input.size(); ++i) input[i] = static_cast<std::uint8_t>(mixed >> ((i % 8U) * 8U));
            const auto digest = dex::Sha1(input);
            const auto selector = static_cast<std::size_t>(digest[0] & 1U);
            constexpr std::array<std::string_view, 2U> left{"FB", "Aa"};
            constexpr std::array<std::string_view, 2U> right{"Ea", "BB"};
            value = left[selector] != right[selector] &&
                    JavaHash(left[selector]) == JavaHash(right[selector]);
            break;
        }
        case OpaqueStrategy::CrossMethodState:
            value = ConsecutiveProductIsEven(
                Mix(state.method_state ^ spec.seed));
            break;
        case OpaqueStrategy::CrossClassState:
            value = ConsecutiveProductIsEven(
                Mix(state.class_state + state.method_state));
            break;
        case OpaqueStrategy::CryptoRelation: {
            const auto x = Mix(mixed);
            auto accumulator = x;
            for (std::uint32_t round = 0U; round < spec.rounds; ++round) {
                accumulator += 0x9e3779b97f4a7c15ULL ^ round;
                accumulator ^= accumulator << (5U + round % 11U);
                accumulator ^= accumulator >> (7U + round % 13U);
            }
            value = ConsecutiveProductIsEven(accumulator);
            break;
        }
        case OpaqueStrategy::GraphProblem: {
            const auto vertices = 5U + (spec.rounds % 4U);
            std::array<std::uint16_t, 9U> adjacency{};
            for (std::uint32_t vertex = 0U; vertex < vertices; ++vertex) {
                adjacency[vertex] |= static_cast<std::uint16_t>(
                    1U << ((vertex + 1U) % vertices));
                adjacency[vertex] |= static_cast<std::uint16_t>(
                    (mixed >> vertex) & ((1U << vertices) - 1U));
            }
            std::uint16_t reached = 1U;
            for (std::uint32_t round = 0U; round < vertices; ++round) {
                auto expanded = reached;
                for (std::uint32_t vertex = 0U; vertex < vertices; ++vertex) {
                    if ((reached & (1U << vertex)) != 0U) {
                        expanded |= adjacency[vertex];
                    }
                }
                reached = expanded;
            }
            value = (reached & (1U << (vertices - 1U))) != 0U;
            break;
        }
        case OpaqueStrategy::ClassLoadingState:
            value = ConsecutiveProductIsEven(
                Mix(state.loading_cookie ^ spec.seed));
            break;
        case OpaqueStrategy::ReferenceIdentity:
            value = ConsecutiveProductIsEven(
                Mix(state.reference_a ^ (state.reference_b << 1U)));
            break;
        case OpaqueStrategy::HistoryState:
            value = ConsecutiveProductIsEven(
                Mix(state.history_hash ^ spec.seed));
            break;
        case OpaqueStrategy::OverflowSemantics: {
            const auto signed_value = static_cast<std::int32_t>(mixed);
            const auto wrapped = static_cast<std::uint32_t>(signed_value) + 0x80000000U;
            value = (wrapped ^ 0x80000000U) == static_cast<std::uint32_t>(signed_value);
            break;
        }
        case OpaqueStrategy::JniInput:
            value = ConsecutiveProductIsEven(
                Mix(static_cast<std::uint64_t>(state.jni_value) ^ spec.seed));
            break;
    }
    // The generated spec deliberately chooses whether a predicate is used in
    // its positive or negated form.  Applying that bit here keeps the model
    // evaluator and the DEX lowering contract aligned; previously
    // `expected_true == false` was reported as true for every strategy.
    return spec.expected_true ? value : !value;
}

std::string DescribeOpaquePredicate(const OpaquePredicateSpec& spec) {
    std::ostringstream stream;
    stream << "opaque(strategy=" << static_cast<unsigned>(spec.strategy)
           << ",seed=" << spec.seed << ",rounds=" << spec.rounds
           << ",state_slots=" << spec.state_slots << ",expected="
           << (spec.expected_true ? "true" : "false") << ')';
    return stream.str();
}

} // namespace birch::guard
