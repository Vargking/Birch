#pragma once

#include "birch/guard/zip.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace birch::io {

// Recognizes reserved root DEX candidates; DexEntryOrdinal/DexEntryNames
// validate their canonical spelling and range instead of ignoring bad names.
[[nodiscard]] bool IsDexEntryName(std::string_view name) noexcept;
[[nodiscard]] std::uint32_t DexEntryOrdinal(std::string_view name);
[[nodiscard]] std::vector<std::string> DexEntryNames(
    const guard::ZipArchive& archive);
[[nodiscard]] std::string NextDexEntryName(const guard::ZipArchive& archive);

} // namespace birch::io
