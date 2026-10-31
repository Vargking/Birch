#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <span>
#include <vector>

namespace birch::guard {

enum class ZipCompression : std::uint16_t {
    Stored = 0,
    Deflate = 8,
};

struct ZipEntry {
    std::string name;
    std::vector<std::uint8_t> data;
    ZipCompression compression{ZipCompression::Stored};
    std::uint32_t external_attributes{};
    std::uint16_t flags{};
    std::uint16_t mod_time{};
    std::uint16_t mod_date{};
    std::uint32_t alignment{1U};
    std::uint32_t local_offset{};
    std::uint32_t data_offset{};
};

class ZipArchive final {
public:
    void Add(ZipEntry entry);
    void RenameEntry(std::string_view old_name, std::string new_name);
    bool RemoveEntry(std::string_view name) noexcept;
    static ZipArchive Read(const std::filesystem::path& path);
    static ZipArchive Read(std::span<const std::uint8_t> bytes);

    [[nodiscard]] const std::vector<ZipEntry>& entries() const noexcept { return entries_; }
    [[nodiscard]] const ZipEntry* Find(std::string_view name) const noexcept;
    [[nodiscard]] ZipEntry* FindMutable(std::string_view name) noexcept;
    [[nodiscard]] std::vector<std::uint8_t> Write() const;

private:
    std::vector<ZipEntry> entries_;
};

} // namespace birch::guard
