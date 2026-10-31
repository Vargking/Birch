#pragma once

#include "birch/dex/linker.h"

namespace birch::guard::detail {

// Keep package equalities and separations required by access/override checks. Class
// simple names remain obfuscated; no visibility flags or keep scopes change.
class PackageAccessPlanner final {
public:
    static std::map<std::string, std::string, std::less<>> RequiredPrefixes(
        const std::vector<std::reference_wrapper<const dex::DexFile>>& files,
        const dex::DexFile* framework,
        const std::set<std::string, std::less<>>& renamed_classes);
};

} // namespace birch::guard::detail
