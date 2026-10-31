#pragma once
#include "birch/io/path.h"
#include <filesystem>
#include <string>
#include <string_view>
#include <algorithm>

namespace birch::gui {
using io::Utf8Path;
[[nodiscard]] inline std::string LowerExtension(const std::filesystem::path& path) {
    auto extension = path.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char c) {
        return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    });
    return extension;
}
}
