#pragma once

#include "birch/dex/builder.h"
#include "birch/guard/model_lowering.h"

#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>

namespace birch::guard::detail {


// Internal model-lowering component; helpers remain local to its translation unit.
class ModelRuntimeBuilder final {
public:
    static bool HasRuntimeOpaquePasses(const GuardConfig& config);

    static bool HasRuntimeExceptionPasses(const GuardConfig& config);

    static bool HasRuntimeConstantPasses(const GuardConfig& config);

    static dex::ClassSpec BuildConstantBarrierHelper(
        const std::set<std::string, std::less<>>& descriptors,
        std::uint64_t descriptor_seed, std::uint64_t method_seed);

    static std::vector<dex::ClassSpec> BuildOpaqueHelpers(
        const std::set<std::string, std::less<>>& descriptors,
        std::uint64_t descriptor_seed, std::uint64_t method_seed,
        const GuardConfig& config);

    static dex::ClassSpec BuildExceptionFlowHelper(
        const std::set<std::string, std::less<>>& descriptors,
        std::uint64_t descriptor_seed, std::uint64_t method_seed,
        const GuardConfig& config);

    static std::uint64_t SourceShardSeed(const std::vector<dex::ClassSpec>& classes,
                                  std::uint64_t seed);

};

} // namespace birch::guard::detail
