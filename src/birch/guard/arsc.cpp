#include "birch/guard/arsc.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace birch::guard {
namespace {

constexpr std::uint16_t kTableType = 0x0002U;
constexpr std::uint16_t kStringPoolType = 0x0001U;
constexpr std::uint16_t kPackageType = 0x0200U;
constexpr std::uint32_t kUtf8Flag = 0x00000100U;
constexpr std::uint32_t kSortedFlag = 0x00000001U;
constexpr std::uint32_t kNoEntry = 0xffffffffU;

std::uint16_t ReadU16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) {
        throw std::runtime_error("truncated ARSC uint16");
    }
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U;
}

std::uint32_t ReadU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        throw std::runtime_error("truncated ARSC uint32");
    }
    return static_cast<std::uint32_t>(bytes[offset]) |
           static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
           static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U |
           static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
}

void PatchU32(std::vector<std::uint8_t>& bytes, std::size_t offset,
              std::uint32_t value) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        throw std::runtime_error("ARSC uint32 patch exceeds output");
    }
    for (unsigned shift = 0U; shift < 32U; shift += 8U) {
        bytes[offset + shift / 8U] = static_cast<std::uint8_t>(value >> shift);
    }
}

void AppendU16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
}

std::vector<std::uint16_t> Utf8ToUtf16(std::string_view value) {
    std::vector<std::uint16_t> result;
    for (std::size_t cursor = 0; cursor < value.size();) {
        const auto first = static_cast<std::uint8_t>(value[cursor]);
        std::size_t width = 0U;
        std::uint32_t codepoint = 0U;
        if (first <= 0x7fU) { width = 1U; codepoint = first; }
        else if (first >= 0xc2U && first <= 0xdfU) { width = 2U; codepoint = first & 0x1fU; }
        else if (first >= 0xe0U && first <= 0xefU) { width = 3U; codepoint = first & 0x0fU; }
        else if (first >= 0xf0U && first <= 0xf4U) { width = 4U; codepoint = first & 0x07U; }
        else throw std::runtime_error("invalid UTF-8 in ARSC string");
        if (cursor + width > value.size()) throw std::runtime_error("truncated UTF-8 in ARSC string");
        for (std::size_t i = 1U; i < width; ++i) {
            const auto next = static_cast<std::uint8_t>(value[cursor + i]);
            if ((next & 0xc0U) != 0x80U) throw std::runtime_error("invalid UTF-8 continuation in ARSC string");
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if (codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            throw std::runtime_error("invalid Unicode scalar in ARSC string");
        }
        if (codepoint <= 0xffffU) result.push_back(static_cast<std::uint16_t>(codepoint));
        else {
            const auto adjusted = codepoint - 0x10000U;
            result.push_back(static_cast<std::uint16_t>(0xd800U + (adjusted >> 10U)));
            result.push_back(static_cast<std::uint16_t>(0xdc00U + (adjusted & 0x3ffU)));
        }
        cursor += width;
    }
    return result;
}

void AppendUtf8(std::string& output, std::uint32_t codepoint) {
    if (codepoint <= 0x7fU) output.push_back(static_cast<char>(codepoint));
    else if (codepoint <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else if (codepoint <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    }
}

std::string Utf16ToUtf8(std::span<const std::uint8_t> bytes, std::size_t offset,
                        std::uint32_t units) {
    std::string result;
    for (std::uint32_t i = 0U; i < units; ++i) {
        const auto first = ReadU16(bytes, offset + static_cast<std::size_t>(i) * 2U);
        std::uint32_t codepoint = first;
        if (first >= 0xd800U && first <= 0xdbffU) {
            if (++i >= units) throw std::runtime_error("truncated ARSC UTF-16 surrogate pair");
            const auto second = ReadU16(bytes, offset + static_cast<std::size_t>(i) * 2U);
            if (second < 0xdc00U || second > 0xdfffU) throw std::runtime_error("invalid ARSC UTF-16 surrogate pair");
            codepoint = 0x10000U + ((first - 0xd800U) << 10U) + (second - 0xdc00U);
        } else if (first >= 0xdc00U && first <= 0xdfffU) {
            throw std::runtime_error("unpaired ARSC UTF-16 low surrogate");
        }
        AppendUtf8(result, codepoint);
    }
    return result;
}

std::uint32_t ReadLength8(std::span<const std::uint8_t> bytes, std::size_t& cursor,
                          std::size_t end) {
    if (cursor >= end) throw std::runtime_error("truncated ARSC UTF-8 length");
    const auto first = bytes[cursor++];
    if ((first & 0x80U) == 0U) return first;
    if (cursor >= end) throw std::runtime_error("truncated ARSC long UTF-8 length");
    return static_cast<std::uint32_t>(first & 0x7fU) << 8U | bytes[cursor++];
}

std::uint32_t ReadLength16(std::span<const std::uint8_t> bytes, std::size_t& cursor,
                           std::size_t end) {
    if (cursor > end || end - cursor < 2U) throw std::runtime_error("truncated ARSC UTF-16 length");
    const auto first = ReadU16(bytes, cursor);
    cursor += 2U;
    if ((first & 0x8000U) == 0U) return first;
    if (cursor > end || end - cursor < 2U) throw std::runtime_error("truncated ARSC long UTF-16 length");
    const auto second = ReadU16(bytes, cursor);
    cursor += 2U;
    return static_cast<std::uint32_t>(first & 0x7fffU) << 16U | second;
}

struct StringPoolData {
    std::uint16_t header_size{};
    std::uint32_t style_count{};
    std::uint32_t flags{};
    std::uint32_t styles_start{};
    std::vector<std::string> strings;
    std::vector<std::uint32_t> style_offsets;
    std::vector<std::uint8_t> style_data;
};

StringPoolData DecodeStringPool(std::span<const std::uint8_t> bytes,
                                std::size_t offset) {
    if (ReadU16(bytes, offset) != kStringPoolType) throw std::runtime_error("not an ARSC string pool");
    const auto header_size = ReadU16(bytes, offset + 2U);
    const auto chunk_size = ReadU32(bytes, offset + 4U);
    const auto count = ReadU32(bytes, offset + 8U);
    const auto style_count = ReadU32(bytes, offset + 12U);
    const auto flags = ReadU32(bytes, offset + 16U);
    const auto strings_start = ReadU32(bytes, offset + 20U);
    const auto styles_start = ReadU32(bytes, offset + 24U);
    if (header_size < 28U || chunk_size < header_size || offset + chunk_size > bytes.size() ||
        static_cast<std::uint64_t>(header_size) +
            (static_cast<std::uint64_t>(count) + style_count) * 4U > strings_start ||
        strings_start >= chunk_size) {
        throw std::runtime_error("invalid ARSC string pool header");
    }
    if (style_count != 0U && (styles_start < strings_start || styles_start > chunk_size)) {
        throw std::runtime_error("invalid ARSC style data offset");
    }
    const auto strings_end = styles_start == 0U ? chunk_size : styles_start;
    const auto utf8 = (flags & kUtf8Flag) != 0U;
    StringPoolData result;
    result.header_size = header_size;
    result.style_count = style_count;
    result.flags = flags;
    result.styles_start = styles_start;
    result.strings.reserve(count);
    for (std::uint32_t i = 0U; i < count; ++i) {
        const auto relative = ReadU32(bytes, offset + header_size + i * 4U);
        if (relative >= strings_end - strings_start) throw std::runtime_error("ARSC string offset exceeds pool");
        std::size_t cursor = offset + strings_start + relative;
        if (utf8) {
            const auto units = ReadLength8(bytes, cursor, offset + strings_end);
            const auto byte_length = ReadLength8(bytes, cursor, offset + strings_end);
            if (cursor + byte_length >= offset + strings_end || bytes[cursor + byte_length] != 0U) {
                throw std::runtime_error("ARSC UTF-8 string exceeds pool");
            }
            std::string value(reinterpret_cast<const char*>(bytes.data() + cursor), byte_length);
            if (Utf8ToUtf16(value).size() != units) throw std::runtime_error("ARSC UTF-8 length mismatch");
            result.strings.push_back(std::move(value));
        } else {
            const auto units = ReadLength16(bytes, cursor, offset + strings_end);
            const auto bytes_needed = static_cast<std::uint64_t>(units) * 2U + 2U;
            if (bytes_needed > offset + strings_end - cursor ||
                ReadU16(bytes, cursor + static_cast<std::size_t>(units) * 2U) != 0U) {
                throw std::runtime_error("ARSC UTF-16 string exceeds pool");
            }
            result.strings.push_back(Utf16ToUtf8(bytes, cursor, units));
        }
    }
    result.style_offsets.reserve(style_count);
    for (std::uint32_t i = 0U; i < style_count; ++i) {
        result.style_offsets.push_back(ReadU32(
            bytes, offset + header_size + static_cast<std::size_t>(count + i) * 4U));
    }
    if (styles_start != 0U) {
        result.style_data.assign(bytes.begin() + offset + styles_start,
                                 bytes.begin() + offset + chunk_size);
    }
    return result;
}

std::vector<std::uint8_t> EncodeStringPool(
    const StringPoolData& pool,
    const std::map<std::string, std::string, std::less<>>& replacements) {
    auto values = pool.strings;
    bool changed = false;
    for (std::size_t i = 0U; i < values.size(); ++i) {
        const auto found = replacements.find(values[i]);
        if (found == replacements.end() || found->second == values[i]) continue;
        if (i < pool.style_offsets.size() && pool.style_offsets[i] != kNoEntry) {
            throw std::runtime_error("cannot resize styled ARSC string: " + values[i]);
        }
        values[i] = found->second;
        changed = true;
    }
    if (!changed) return {};

    std::vector<std::uint8_t> result(pool.header_size, 0U);
    result[0U] = static_cast<std::uint8_t>(kStringPoolType);
    result[1U] = static_cast<std::uint8_t>(kStringPoolType >> 8U);
    result[2U] = static_cast<std::uint8_t>(pool.header_size);
    result[3U] = static_cast<std::uint8_t>(pool.header_size >> 8U);
    result.resize(static_cast<std::size_t>(pool.header_size) +
                  (values.size() + pool.style_offsets.size()) * 4U, 0U);
    PatchU32(result, 8U, static_cast<std::uint32_t>(values.size()));
    PatchU32(result, 12U, static_cast<std::uint32_t>(pool.style_offsets.size()));
    PatchU32(result, 16U, pool.flags & ~kSortedFlag);
    const auto strings_start = static_cast<std::uint32_t>(result.size());
    PatchU32(result, 20U, strings_start);
    for (std::size_t i = 0U; i < pool.style_offsets.size(); ++i) {
        PatchU32(result, pool.header_size + values.size() * 4U + i * 4U,
                 pool.style_offsets[i]);
    }
    const auto utf8 = (pool.flags & kUtf8Flag) != 0U;
    for (std::size_t i = 0U; i < values.size(); ++i) {
        if (result.size() - strings_start > std::numeric_limits<std::uint32_t>::max()) {
            throw std::length_error("ARSC string pool offset exceeds uint32");
        }
        PatchU32(result, pool.header_size + i * 4U,
                 static_cast<std::uint32_t>(result.size() - strings_start));
        const auto utf16 = Utf8ToUtf16(values[i]);
        if (utf8) {
            const auto append_length = [&](std::uint32_t value) {
                if (value <= 0x7fU) result.push_back(static_cast<std::uint8_t>(value));
                else if (value <= 0x7fffU) {
                    result.push_back(static_cast<std::uint8_t>(0x80U | (value >> 8U)));
                    result.push_back(static_cast<std::uint8_t>(value));
                } else throw std::length_error("ARSC UTF-8 string length exceeds format limit");
            };
            append_length(static_cast<std::uint32_t>(utf16.size()));
            append_length(static_cast<std::uint32_t>(values[i].size()));
            result.insert(result.end(), values[i].begin(), values[i].end());
            result.push_back(0U);
        } else {
            const auto append_length = [&](std::uint32_t value) {
                if (value <= 0x7fffU) AppendU16(result, static_cast<std::uint16_t>(value));
                else {
                    AppendU16(result, static_cast<std::uint16_t>(0x8000U | (value >> 16U)));
                    AppendU16(result, static_cast<std::uint16_t>(value));
                }
            };
            append_length(static_cast<std::uint32_t>(utf16.size()));
            for (const auto unit : utf16) AppendU16(result, unit);
            AppendU16(result, 0U);
        }
    }
    while ((result.size() & 3U) != 0U) result.push_back(0U);
    if (!pool.style_data.empty()) {
        PatchU32(result, 24U, static_cast<std::uint32_t>(result.size()));
        result.insert(result.end(), pool.style_data.begin(), pool.style_data.end());
        while ((result.size() & 3U) != 0U) result.push_back(0U);
    } else {
        PatchU32(result, 24U, 0U);
    }
    if (result.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("ARSC string pool exceeds uint32");
    }
    PatchU32(result, 4U, static_cast<std::uint32_t>(result.size()));
    return result;
}

struct RewriteContext {
    const std::map<std::string, std::string, std::less<>>& names;
    const std::map<std::string, std::string, std::less<>>& paths;
    const std::map<std::string, std::string, std::less<>>& all;
    bool all_pools{};
};

std::vector<std::uint8_t> RewriteChunk(std::span<const std::uint8_t> bytes,
                                       std::size_t offset,
                                       const RewriteContext& context,
                                       bool root,
                                       std::vector<ArscChunk>* parsed = nullptr) {
    const auto type = ReadU16(bytes, offset);
    const auto header_size = ReadU16(bytes, offset + 2U);
    const auto size = ReadU32(bytes, offset + 4U);
    if (header_size < 8U || size < header_size || offset + size > bytes.size()) {
        throw std::runtime_error("invalid ARSC chunk bounds");
    }
    if (parsed != nullptr) {
        parsed->push_back({type, header_size, size, static_cast<std::uint32_t>(offset)});
    }
    if (type == kStringPoolType) {
        const auto rewritten = EncodeStringPool(DecodeStringPool(bytes, offset), context.all);
        if (!rewritten.empty()) return rewritten;
        return {bytes.begin() + offset, bytes.begin() + offset + size};
    }
    if (type != kTableType && type != kPackageType) {
        return {bytes.begin() + offset, bytes.begin() + offset + size};
    }

    if (type == kTableType && !root) throw std::runtime_error("nested ARSC table chunk");
    if (type == kPackageType && header_size < 284U) {
        throw std::runtime_error("ARSC package header is too small");
    }
    const auto old_type_pool = type == kPackageType ? ReadU32(bytes, offset + 268U) : 0U;
    const auto old_key_pool = type == kPackageType ? ReadU32(bytes, offset + 276U) : 0U;
    std::vector<std::uint8_t> output(bytes.begin() + offset,
                                     bytes.begin() + offset + header_size);
    std::optional<std::uint32_t> new_type_pool;
    std::optional<std::uint32_t> new_key_pool;
    bool consumed_global_pool = false;
    std::size_t cursor = offset + header_size;
    while (cursor < offset + size) {
        const auto child_size = ReadU32(bytes, cursor + 4U);
        if (child_size < 8U || cursor + child_size > offset + size) {
            throw std::runtime_error("ARSC child chunk exceeds container");
        }
        const auto old_relative = static_cast<std::uint32_t>(cursor - offset);
        const auto new_relative = static_cast<std::uint32_t>(output.size());
        const auto child_type = ReadU16(bytes, cursor);
        if (parsed != nullptr && child_type != kPackageType) {
            parsed->push_back({child_type, ReadU16(bytes, cursor + 2U), child_size,
                               static_cast<std::uint32_t>(cursor)});
        }
        const std::map<std::string, std::string, std::less<>>* replacements = &context.all;
        if (!context.all_pools && child_type == kStringPoolType) {
            if (type == kPackageType && old_relative == old_key_pool) replacements = &context.names;
            else if (type == kTableType && !consumed_global_pool) {
                replacements = &context.paths;
                consumed_global_pool = true;
            } else replacements = nullptr;
        }
        std::vector<std::uint8_t> child;
        if (child_type == kStringPoolType && replacements != nullptr) {
            child = EncodeStringPool(DecodeStringPool(bytes, cursor), *replacements);
            if (child.empty()) child.assign(bytes.begin() + cursor,
                                            bytes.begin() + cursor + child_size);
        } else if (child_type == kPackageType) {
            child = RewriteChunk(bytes, cursor, context, false, parsed);
        } else {
            child.assign(bytes.begin() + cursor, bytes.begin() + cursor + child_size);
        }
        if (type == kPackageType && old_relative == old_type_pool) new_type_pool = new_relative;
        if (type == kPackageType && old_relative == old_key_pool) new_key_pool = new_relative;
        output.insert(output.end(), child.begin(), child.end());
        cursor += child_size;
    }
    if (cursor != offset + size) throw std::runtime_error("ARSC container child alignment mismatch");
    if (output.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("ARSC chunk exceeds uint32");
    }
    PatchU32(output, 4U, static_cast<std::uint32_t>(output.size()));
    if (type == kPackageType) {
        if (old_type_pool != 0U && !new_type_pool.has_value()) throw std::runtime_error("ARSC package type pool missing");
        if (old_key_pool != 0U && !new_key_pool.has_value()) throw std::runtime_error("ARSC package key pool missing");
        if (new_type_pool.has_value()) PatchU32(output, 268U, *new_type_pool);
        if (new_key_pool.has_value()) PatchU32(output, 276U, *new_key_pool);
    }
    return output;
}

} // namespace

ArscTable ArscTable::Parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 12U || ReadU16(bytes, 0U) != kTableType) {
        throw std::runtime_error("invalid resource table header");
    }
    if (ReadU16(bytes, 2U) < 12U || ReadU32(bytes, 4U) != bytes.size()) {
        throw std::runtime_error("invalid resource table size");
    }
    ArscTable result;
    result.bytes_.assign(bytes.begin(), bytes.end());
    const std::map<std::string, std::string, std::less<>> empty;
    const RewriteContext context{empty, empty, empty, false};
    (void)RewriteChunk(bytes, 0U, context, true, &result.chunks_);
    return result;
}

std::vector<std::string> ArscTable::strings() const {
    std::vector<std::string> result;
    const auto bytes = std::span<const std::uint8_t>(bytes_.data(), bytes_.size());
    for (const auto& chunk : chunks_) {
        if (chunk.type != kStringPoolType) continue;
        const auto pool = DecodeStringPool(bytes, chunk.offset);
        result.insert(result.end(), pool.strings.begin(), pool.strings.end());
    }
    return result;
}

std::vector<std::uint8_t> ArscTable::RenameStrings(
    const std::map<std::string, std::string, std::less<>>& replacements) const {
    const RewriteContext context{replacements, replacements, replacements, true};
    auto output = RewriteChunk(bytes_, 0U, context, true);
    (void)ArscTable::Parse(output);
    return output;
}

std::vector<std::string> ArscTable::resource_names() const {
    std::vector<std::string> result;
    for (const auto& chunk : chunks_) {
        if (chunk.type != kPackageType) continue;
        const auto relative = ReadU32(bytes_, chunk.offset + 276U);
        if (relative < chunk.header_size || relative >= chunk.size) {
            throw std::runtime_error("invalid ARSC package key pool offset");
        }
        const auto pool = DecodeStringPool(bytes_, chunk.offset + relative);
        result.insert(result.end(), pool.strings.begin(), pool.strings.end());
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

std::vector<std::uint8_t> ArscTable::RenameResources(
    const std::map<std::string, std::string, std::less<>>& name_replacements,
    const std::map<std::string, std::string, std::less<>>& path_replacements) const {
    const std::map<std::string, std::string, std::less<>> empty;
    const RewriteContext context{name_replacements, path_replacements, empty, false};
    auto output = RewriteChunk(bytes_, 0U, context, true);
    (void)ArscTable::Parse(output);
    return output;
}

} // namespace birch::guard
