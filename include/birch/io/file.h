#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace birch::io {

[[nodiscard]] std::vector<std::uint8_t> ReadBinaryFile(
    const std::filesystem::path& path);
[[nodiscard]] std::string ReadTextFile(const std::filesystem::path& path);
void WriteBinaryFile(const std::filesystem::path& path,
                     const std::vector<std::uint8_t>& bytes);
void WriteTextFile(const std::filesystem::path& path, std::string_view text);

} // namespace birch::io
