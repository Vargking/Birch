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
class ModelMethodStructure final {
public:
    static void ApplyTailRecursionBeforeClassSplit(
        dex::ClassSpec& klass, const GuardConfig& config,
        ModelLoweringResult& report);

    static void InlineTrivialMethods(dex::ClassSpec& klass, const GuardConfig& config,
                              ModelLoweringResult& report);

    static void TransformClass(
        dex::ClassSpec& klass, const GuardConfig& config,
        ModelLoweringResult& report,
        std::vector<dex::ClassSpec>& generated_classes,
        std::set<std::string, std::less<>>& used_descriptors);

};

} // namespace birch::guard::detail
