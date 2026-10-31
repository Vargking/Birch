#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/config.h"

#include <map>
#include <string>

namespace birch::guard::detail {

// Check the serialized code_item, not a pre-remap emission estimate. Class
// renames must not make protected owners disappear from the original scope.
class OutputCodeBudget final {
public:
    using ClassMap = std::map<std::string, std::string, std::less<>>;
    static void Verify(const dex::DexFile& file, const GuardConfig& config,
                       const ClassMap& class_renames = {});
};

} // namespace birch::guard::detail
