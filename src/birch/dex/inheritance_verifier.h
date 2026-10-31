#pragma once

#include "birch/dex/linkage_verifier.h"

namespace birch::dex::detail {

class InheritanceVerifier final {
public:
    static void Analyze(const DexLinker& linker,
        const std::vector<std::reference_wrapper<const DexFile>>& files,
        const LinkageRenames& renames, LinkageReport& report);
};

} // namespace birch::dex::detail
