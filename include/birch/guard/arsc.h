#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include <map>

namespace birch::guard {

struct ArscChunk {
    std::uint16_t type{};
    std::uint16_t header_size{};
    std::uint32_t size{};
    std::uint32_t offset{};
};

class ArscTable final {
public:
    static ArscTable Parse(std::span<const std::uint8_t> bytes);
    [[nodiscard]] const std::vector<ArscChunk>& chunks() const noexcept { return chunks_; }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }
    [[nodiscard]] std::vector<std::string> strings() const;
    // Only package key pools, never type names or user-facing string values.
    [[nodiscard]] std::vector<std::string> resource_names() const;
    [[nodiscard]] std::vector<std::uint8_t> RenameStrings(
        const std::map<std::string, std::string, std::less<>>& replacements) const;
    [[nodiscard]] std::vector<std::uint8_t> RenameResources(
        const std::map<std::string, std::string, std::less<>>& name_replacements,
        const std::map<std::string, std::string, std::less<>>& path_replacements) const;

private:
    std::vector<std::uint8_t> bytes_;
    std::vector<ArscChunk> chunks_;
};

} // namespace birch::guard
