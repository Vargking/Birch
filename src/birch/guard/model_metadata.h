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
class ModelMetadata final {
public:
    static void AddMetadataNoise(dex::ClassSpec& klass, const GuardConfig& config,
                          ModelLoweringResult& report);

    static void RenameDebugParameters(dex::ClassSpec& klass, const GuardConfig& config,
                               ModelLoweringResult& report);

};

} // namespace birch::guard::detail
