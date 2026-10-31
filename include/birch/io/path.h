#pragma once
#include <filesystem>
#include <string>
#include <string_view>

namespace birch::io {
// Configuration and GUI strings are UTF-8; native Windows path(string) uses an ANSI code page.
[[nodiscard]] inline std::filesystem::path Utf8Path(std::string_view value) {
    return std::filesystem::path(std::u8string(value.begin(), value.end()));
}
[[nodiscard]] inline std::string PathUtf8(const std::filesystem::path& path) {
    const auto text = path.u8string();
    return std::string(text.begin(), text.end());
}
}
