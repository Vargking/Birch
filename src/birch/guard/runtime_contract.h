#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/config.h"

#include <functional>
#include <set>
#include <string>
#include <vector>

namespace birch::guard::detail {

struct RuntimeContractKeeps {
    std::set<std::string, std::less<>> classes;
    std::set<std::string, std::less<>> methods;
    std::set<std::string, std::less<>> fields;
    std::vector<std::string> warnings;
};

// Resolve runtime-visible contracts before any global renaming.
class RuntimeContractAnalyzer final {
public:
    static RuntimeContractKeeps CollectRuntimeContractKeeps(
        const std::vector<std::reference_wrapper<const dex::DexFile>>& dex_files,
        const ScopeConfig& scope, const dex::DexFile* framework_dex = nullptr);
};

} // namespace birch::guard::detail

