#pragma once

#include "birch/dex/code.h"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace birch::dex {

enum class ConstantUseType : std::uint8_t {
    Unconstrained,
    Int32,
    Float32,
    Reference,
    Conflict,
};

struct MethodTypeIssue {
    std::uint32_t instruction_offset{};
    std::string message;
};

// A supported API for transformations that create typed call boundaries.
// Domain signatures are opaque equality keys, not serialized type records.
enum class RegisterTypeKind : std::uint8_t {
    Unusable, Scalar32, Int32, Float32, Reference, LongLow, DoubleLow, WideHigh
};
struct RegisterTypeSnapshot {
    RegisterTypeKind kind{RegisterTypeKind::Unusable};
    std::string descriptor;
    bool uninitialized{};
    std::optional<std::uint32_t> constant32;
};
using RegisterTypeFrame = std::vector<RegisterTypeSnapshot>;

struct MethodTypeAnalysis {
    std::map<std::uint32_t, ConstantUseType> constant_uses;
    std::map<std::uint32_t, std::set<std::string>>
        constant_reference_descriptors;
    // A zero literal is verifier-polymorphic: the same definition may be
    // consumed as int/float/null along different CFG edges. Such definitions
    // must stay as const instructions instead of being replaced by a typed
    // runtime helper.
    std::set<std::uint32_t> polymorphic_zero_constants;
    std::vector<MethodTypeIssue> issues;
    // Exact verifier-category/descriptor signatures, not hashes. Constant
    // provenance is intentionally excluded; zero-vs-nonzero scalar is not.
    std::map<std::uint32_t, std::string> exit_type_domains;
    std::map<std::uint32_t, std::vector<std::string>> exit_register_domains;
    std::map<std::uint32_t, RegisterTypeFrame> entry_register_types;
    std::map<std::uint32_t, RegisterTypeFrame> exit_register_types;
};

struct MethodTypeAnalysisOptions {
    std::span<const std::uint32_t> capture_exit_offsets;
    // Only registers definitely redefined before entering a shared domain
    // may be excluded (e.g. the dispatcher's private integer scratch pair).
    std::span<const std::uint16_t> excluded_domain_registers;
    // Optional proven live-out sets. Register indices are included in the
    // signature, so differing live sets never share a verifier domain.
    const std::map<std::uint32_t, std::vector<std::uint16_t>>* live_exit_registers{};
    bool capture_register_domains{};
    bool capture_type_snapshots{};
};

// Performs a verifier-oriented register dataflow analysis. In addition to
// reporting definite primitive/reference mismatches, it records how each
// polymorphic 32-bit const definition is consumed so rewriting passes can
// preserve the verifier type selected by the original method.
[[nodiscard]] MethodTypeAnalysis AnalyzeMethodTypes(
    const DexFile& dex, const DexEncodedMethod& method, const CodeItem& code,
    MethodTypeAnalysisOptions options = {});

} // namespace birch::dex
