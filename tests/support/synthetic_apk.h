#pragma once

#include "birch/guard/zip.h"

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace birch::test {
namespace apk_detail {
inline void Append16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
}
inline void Append32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    for (unsigned i = 0U; i < 4U; ++i)
        bytes.push_back(static_cast<std::uint8_t>(value >> (8U * i)));
}
inline void Put32(std::vector<std::uint8_t>& bytes, std::size_t at, std::uint32_t value) {
    for (unsigned i = 0U; i < 4U; ++i)
        bytes.at(at + i) = static_cast<std::uint8_t>(value >> (8U * i));
}
} // namespace apk_detail

// Parser/pipeline input generated from public format fields, not an embedded
// application. It is deliberately not an installable Android application.
inline std::vector<std::uint8_t> MinimalManifest(unsigned min_sdk = 21U) {
    using namespace apk_detail;
    constexpr std::array<std::string_view, 4> strings{
        "manifest", "uses-sdk", "http://schemas.android.com/apk/res/android", "minSdkVersion"};
    std::vector<std::uint8_t> pool;
    Append16(pool, 0x0001U);
    Append16(pool, 28U);
    Append32(pool, 0U); // Patched after appending the string data.
    Append32(pool, static_cast<std::uint32_t>(strings.size()));
    Append32(pool, 0U);
    Append32(pool, 0x100U); // UTF-8.
    constexpr auto data_start = 28U + 4U * strings.size();
    Append32(pool, static_cast<std::uint32_t>(data_start));
    Append32(pool, 0U);
    pool.resize(data_start, 0U);
    for (std::size_t i = 0U; i < strings.size(); ++i) {
        Put32(pool, 28U + 4U * i, static_cast<std::uint32_t>(pool.size() - data_start));
        pool.push_back(static_cast<std::uint8_t>(strings[i].size()));
        pool.push_back(static_cast<std::uint8_t>(strings[i].size()));
        pool.insert(pool.end(), strings[i].begin(), strings[i].end());
        pool.push_back(0U);
    }
    while (pool.size() % 4U != 0U) pool.push_back(0U);
    Put32(pool, 4U, static_cast<std::uint32_t>(pool.size()));

    std::vector<std::uint8_t> result;
    Append16(result, 0x0003U);
    Append16(result, 8U);
    Append32(result, 0U);
    result.insert(result.end(), pool.begin(), pool.end());
    const auto node = [&](std::uint16_t type, std::uint32_t size, std::uint32_t name) {
        Append16(result, type);
        Append16(result, 16U);
        Append32(result, size);
        Append32(result, 1U); // Line number.
        Append32(result, 0xffffffffU); // No comment.
        Append32(result, 0xffffffffU); // No element namespace.
        Append32(result, name);
    };
    const auto start = [&](std::uint32_t name, std::uint16_t count) {
        node(0x0102U, 36U + 20U * count, name);
        Append16(result, 20U);
        Append16(result, 20U);
        Append16(result, count);
        Append16(result, 0U);
        Append16(result, 0U);
        Append16(result, 0U);
    };
    start(0U, 0U); // manifest
    start(1U, 1U); // uses-sdk
    Append32(result, 2U); // Android namespace URI.
    Append32(result, 3U); // minSdkVersion.
    Append32(result, 0xffffffffU);
    Append16(result, 8U);
    result.push_back(0U);
    result.push_back(0x10U); // TYPE_INT_DEC.
    Append32(result, min_sdk);
    node(0x0103U, 24U, 1U);
    node(0x0103U, 24U, 0U);
    Put32(result, 4U, static_cast<std::uint32_t>(result.size()));
    return result;
}

inline std::vector<std::uint8_t> EmptyResources() {
    return {0x02U, 0x00U, 0x0cU, 0x00U, 0x0cU, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U};
}

inline guard::ZipArchive ApkWithDex(std::span<const std::uint8_t> dex, unsigned min_sdk = 21U) {
    guard::ZipArchive archive;
    archive.Add({"AndroidManifest.xml", MinimalManifest(min_sdk), guard::ZipCompression::Stored});
    archive.Add({"resources.arsc", EmptyResources(), guard::ZipCompression::Stored});
    archive.Add({"classes.dex", {dex.begin(), dex.end()}, guard::ZipCompression::Stored});
    return archive;
}
} // namespace birch::test
