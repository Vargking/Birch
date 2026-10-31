#pragma once

#include "birch/dex/linkage_verifier.h"
#include "birch/guard/zip.h"

#include <filesystem>

namespace birch::guard::detail {

class OutputLinkage final {
public:
    static void VerifyDex(const std::filesystem::path& input,
        const dex::DexFile& output, const dex::DexFile* framework,
        const dex::LinkageRenames& renames);
    static void VerifyApk(const std::filesystem::path& input,
        const ZipArchive& output, const dex::DexFile* framework,
        const dex::LinkageRenames& renames);
};

} // namespace birch::guard::detail
