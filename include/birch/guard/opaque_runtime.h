#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace birch::guard {

// Every predicate pass has a corresponding helper slot.  Keep this list as
// the single source of truth for model injection and code-site lowering.
inline constexpr std::array<std::string_view, 14U> kRuntimeOpaquePasses{
    "predicate.number_theory",
    "predicate.polynomial",
    "predicate.matrix",
    "predicate.bitwise",
    "predicate.cross_process",
    "predicate.cross_class_state",
    "predicate.history",
    "predicate.overflow",
    "predicate.floating_point",
    "predicate.hash_collision",
    "predicate.crypto",
    "predicate.graph_problem",
    "predicate.class_loading_state",
    "predicate.reference_identity",
};

inline constexpr std::size_t kRuntimeOpaqueClassShards = 2U;
inline constexpr std::size_t kRuntimeOpaqueStateFields = 4U;

// Exception-oriented CFG passes share one stateful cross-class helper.  The
// helper is injected during model lowering, called from both sides of every
// generated try/catch edge, and then participates in normal code/name passes.
inline constexpr std::array<std::string_view, 6U> kRuntimeExceptionPasses{
    "cfg.exception_dispatch",
    "cfg.callback_style",
    "anti_analysis.legal_exception_layout",
    "anti_analysis.verifier_safe_overlap_substitute",
    "anti_analysis.decompiler_resilience",
    "anti_analysis.legal_overlapping_handlers",
};
inline constexpr std::size_t kRuntimeExceptionStateFields = 2U;

[[nodiscard]] std::string RuntimeOpaqueClassDescriptor(std::uint64_t seed,
                                                       std::size_t shard,
                                                       std::uint32_t attempt);
[[nodiscard]] std::string RuntimeOpaqueMethodName(std::uint64_t seed,
                                                  std::size_t strategy);
[[nodiscard]] std::string RuntimeOpaqueFieldName(std::uint64_t seed,
                                                 std::size_t shard,
                                                 std::size_t slot);
[[nodiscard]] std::string RuntimeExceptionClassDescriptor(
    std::uint64_t seed, std::uint32_t attempt);
[[nodiscard]] std::string RuntimeExceptionMethodName(std::uint64_t seed);
[[nodiscard]] std::string RuntimeExceptionFieldName(std::uint64_t seed,
                                                    std::size_t slot);

} // namespace birch::guard
