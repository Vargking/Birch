#pragma once

#include "model_strings.h"

namespace birch::guard::detail {

// Materializes encoded static values without changing the original clinit's
// register ABI, payload alignment, exception coverage or string-site plan.
class StaticFieldInitializer final {
public:
    static void Rewrite(std::vector<dex::ClassSpec>& classes,
                        const GuardConfig& config,
                        std::string_view string_helper_descriptor,
                        const StringRewritePlan& strings,
                        ModelLoweringResult& report,
                        bool generated_classes = false);
};

} // namespace birch::guard::detail
