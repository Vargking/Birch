#pragma once

#include "birch/dex/dex_file.h"

#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace birch::guard::detail {

class MethodConflictPlanner final {
public:
    using Conflicts = std::map<std::string, std::set<std::string, std::less<>>, std::less<>>;

    // Distinct source names may share a color only if their signatures cannot
    // meet at a symbolic owner, including inherited direct/static methods and
    // methods arriving through separate interface branches.
    [[nodiscard]] static Conflicts Build(
        const std::vector<std::reference_wrapper<const dex::DexFile>>& files,
        const dex::DexFile* framework);
};

} // namespace birch::guard::detail
