#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <map>

namespace birch::guard {

struct AxmlChunk {
    std::uint16_t type{};
    std::uint16_t header_size{};
    std::uint32_t size{};
    std::uint32_t offset{};
};

class AxmlDocument final {
public:
    static AxmlDocument Parse(std::span<const std::uint8_t> bytes);
    [[nodiscard]] const std::vector<AxmlChunk>& chunks() const noexcept { return chunks_; }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }
    [[nodiscard]] const std::vector<std::string>& strings() const noexcept { return strings_; }
    [[nodiscard]] std::vector<std::uint8_t> RenameStringsInPlace(
        const std::map<std::string, std::string, std::less<>>& replacements) const;

private:
    std::vector<std::uint8_t> bytes_;
    std::vector<AxmlChunk> chunks_;
    std::vector<std::string> strings_;
};

} // namespace birch::guard
