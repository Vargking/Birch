#pragma once

#include "birch/dex/builder.h"
#include "birch/guard/model_lowering.h"

#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>

namespace birch::guard::detail {

struct StringHelperBundle {
    std::string entry_descriptor;
    std::vector<dex::ClassSpec> classes;
};


struct StringRewritePlan {
    struct Site {
        std::string value;
        std::uint8_t mask{};
    };
    std::set<std::string, std::less<>> values;
    std::set<std::string, std::less<>> split_values;
    // Per-method const-string ordinal, not a relocatable code-unit address.
    std::map<std::string, Site, std::less<>> sites;
};


// Internal model-lowering component; helpers remain local to its translation unit.
class ModelStringProtection final {
public:
    static StringHelperBundle BuildStringHelper(
        const std::set<std::string, std::less<>>& descriptors,
        const std::set<std::string, std::less<>>& values,
        const std::set<std::string, std::less<>>& split_values,
        std::uint64_t descriptor_seed, std::uint64_t method_seed);

    static void CollectStringValues(const dex::ClassSpec& klass, const GuardConfig& config,
                             StringRewritePlan& plan);

    static std::vector<std::uint8_t> RewriteStringCallsites(
        const dex::DexFile& source, const StringRewritePlan& plan,
        std::string_view helper_descriptor, std::uint64_t seed,
        std::size_t& rewritten_count, ModelLoweringResult& report);

};

} // namespace birch::guard::detail
