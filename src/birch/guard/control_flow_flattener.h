#pragma once

#include "birch/dex/code.h"
#include "birch/dex/remap.h"
#include "strength_policy.h"

#include <map>
#include <optional>
#include <span>
#include <string>

namespace birch::guard::detail {

enum class DispatcherEncoding : std::uint8_t {
    Sparse,
    Packed,
    Mixed,
};

struct FlattenedReplacement {
    dex::CodePrefix code;
    bool used_sparse_dispatch{};
    bool used_packed_dispatch{};
    bool used_layered_dispatch{};
    bool used_multi_state_dispatch{};
    bool used_mixed_guard{};
    std::size_t expanded_conditions{};
    std::size_t nested_conditions{};
    std::size_t bogus_edges{};
    std::size_t dead_cases{};
    std::size_t exploded_conditions{};
    std::size_t generated_calls{};
};

// Full-strength builds use a hard structural floor.  The floor is expressed
// in final decoded CFG blocks (not in emitted padding instructions), so a
// configuration cannot accidentally claim CFF coverage while leaving a
// mostly linear method behind.
inline constexpr auto kMinimumFullStrengthCfgBlocks = StrengthPolicy::kMinimumFullStrengthCfgBlocks;
inline constexpr auto kMaximumArtCompilerCodeUnits = StrengthPolicy::kMaximumArtCompilerCodeUnits;

struct FlatteningFeatures {
    bool layered_dispatch{};
    bool multi_state_dispatch{};
    DispatcherEncoding dispatcher_encoding{DispatcherEncoding::Sparse};
    bool condition_expansion{};
    bool conditional_nesting{};
    bool bogus_edges{};
    bool dead_blocks{};
    bool path_explosion{};
    bool generated_calls{};
    std::optional<std::uint16_t> callback_helper_method;
    // Runtime identity/volatile barrier used after state materialization. It
    // preserves the int value while blocking method-local constant folding.
    std::optional<std::uint16_t> runtime_state_barrier_method;
};

struct MaterializedRegisterLayout {
    std::uint16_t first_scratch{};
    std::uint16_t second_scratch{};
    std::vector<std::uint16_t> parameter_prologue;
};

using MaterializedRegisterLayouts =
    std::map<std::string, MaterializedRegisterLayout, std::less<>>;


class ControlFlowFlattener final {
public:
    static bool IsGeneratedCallDescriptor(std::string_view descriptor);

    static std::vector<std::uint16_t> BuildParameterMigration(
        const dex::DexFile& dex_file, const dex::DexEncodedMethod& encoded,
        const dex::CodeItem& code, std::uint16_t register_delta);

    static std::optional<FlattenedReplacement> BuildFlattenedReplacement(
        const dex::DexFile& dex_file, const dex::DexEncodedMethod& encoded,
        const dex::CodeItem& code, std::string_view method_key,
        std::span<const std::uint16_t> prefix_units,
        const std::vector<dex::CodePrefix::TryRegion>& prefix_tries,
        const std::map<std::uint32_t, std::vector<std::uint16_t>>& replacements,
        const GuardConfig& config, FlatteningFeatures features,
        const MaterializedRegisterLayout* materialized_layout);
};

} // namespace birch::guard::detail
