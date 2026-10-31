#pragma once

#include "birch/dex/builder.h"
#include "birch/guard/model_lowering.h"

#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>

namespace birch::guard::detail {

enum class ReflectionStringKind : std::uint8_t {
    Class,
    Method,
    Field,
};

struct ReflectionSiteReplacement {
    ReflectionStringKind kind{};
    std::string source;
    std::string target;
};


using ReflectionSiteMap =
    std::map<std::string, ReflectionSiteReplacement, std::less<>>;


// Internal model-lowering component; helpers remain local to its translation unit.
class ModelReflectionProtection final {
public:
    static ReflectionSiteMap BuildReflectionSiteMap(
        const dex::DexFile& source, const ReflectionRenamePlan& plan);

    static void ApplyReflectionSiteMap(std::vector<dex::ClassSpec>& classes,
                                const ReflectionSiteMap& replacements);

    static void IndirectReflectionTargets(
        dex::ClassSpec& klass, const GuardConfig& config,
        ModelLoweringResult& report,
        std::vector<dex::ClassSpec>& generated_classes,
        std::set<std::string, std::less<>>& used_descriptors);

};

} // namespace birch::guard::detail
