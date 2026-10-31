#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/zip.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace birch::guard {

enum class AndroidBinaryKind {
    Manifest,
    Resources,
    Dex,
    Other,
};

struct ApkEntryInfo {
    std::string name;
    AndroidBinaryKind kind{AndroidBinaryKind::Other};
    std::size_t dex_index{};
    std::uint8_t dex_version{};
    bool dex_checksum_valid{};
};

struct ApkInspection {
    std::vector<ApkEntryInfo> entries;
    std::size_t manifest_count{};
    std::size_t resources_count{};
    std::size_t dex_count{};
};

ApkInspection InspectApk(const ZipArchive& archive);

} // namespace birch::guard
