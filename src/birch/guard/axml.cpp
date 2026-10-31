#include "birch/guard/axml.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>
#include <map>
#include <vector>

namespace birch::guard {
namespace {

std::uint16_t ReadU16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) throw std::runtime_error("truncated AXML uint16");
    return static_cast<std::uint16_t>(bytes[offset]) | static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U;
}

std::uint32_t ReadU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) throw std::runtime_error("truncated AXML uint32");
    return static_cast<std::uint32_t>(bytes[offset]) | static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
           static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U | static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
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
        else throw std::runtime_error("invalid UTF-8 AXML string");
        if (cursor + width > value.size()) throw std::runtime_error("truncated UTF-8 AXML string");
        for (std::size_t i = 1U; i < width; ++i) {
            const auto next = static_cast<std::uint8_t>(value[cursor + i]);
            if ((next & 0xc0U) != 0x80U) throw std::runtime_error("invalid UTF-8 AXML continuation");
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if (codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            throw std::runtime_error("invalid Unicode scalar in AXML string");
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
    for (std::uint32_t i = 0; i < units; ++i) {
        const auto first = ReadU16(bytes, offset + static_cast<std::size_t>(i) * 2U);
        std::uint32_t codepoint = first;
        if (first >= 0xd800U && first <= 0xdbffU) {
            if (++i >= units) throw std::runtime_error("truncated UTF-16 surrogate pair in AXML");
            const auto second = ReadU16(bytes, offset + static_cast<std::size_t>(i) * 2U);
            if (second < 0xdc00U || second > 0xdfffU) throw std::runtime_error("invalid UTF-16 surrogate pair in AXML");
            codepoint = 0x10000U + ((first - 0xd800U) << 10U) + (second - 0xdc00U);
        } else if (first >= 0xdc00U && first <= 0xdfffU) {
            throw std::runtime_error("unpaired UTF-16 low surrogate in AXML");
        }
        AppendUtf8(result, codepoint);
    }
    return result;
}

std::vector<std::string> DecodeStringPool(
    std::span<const std::uint8_t> bytes, const AxmlChunk& chunk) {
    if (chunk.type != 0x0001U || chunk.header_size < 28U) return {};
    const auto offset = static_cast<std::size_t>(chunk.offset);
    const auto count = ReadU32(bytes, offset + 8U);
    const auto style_count = ReadU32(bytes, offset + 12U);
    const auto flags = ReadU32(bytes, offset + 16U);
    const auto strings_start = ReadU32(bytes, offset + 20U);
    const auto styles_start = ReadU32(bytes, offset + 24U);
    const auto utf8 = (flags & 0x100U) != 0U;
    const auto arrays_size = (static_cast<std::uint64_t>(count) + style_count) * 4U;
    if (strings_start < chunk.header_size || strings_start >= chunk.size ||
        static_cast<std::uint64_t>(chunk.header_size) + arrays_size > strings_start ||
        offset + chunk.size > bytes.size()) {
        throw std::runtime_error("invalid AXML string pool");
    }
    const auto strings_end = styles_start == 0U ? chunk.size : styles_start;
    std::vector<std::string> values;
    values.reserve(count);
    auto read_length8 = [&](std::size_t& cursor) {
        if (cursor >= offset + strings_end) throw std::runtime_error("truncated AXML string length");
        const auto first = bytes[cursor++];
        if ((first & 0x80U) == 0U) return static_cast<std::uint32_t>(first);
        if (cursor >= offset + strings_end) throw std::runtime_error("truncated AXML long string length");
        return static_cast<std::uint32_t>(first & 0x7fU) << 8U |
               static_cast<std::uint32_t>(bytes[cursor++]);
    };
    auto read_length16 = [&](std::size_t& cursor) {
        const auto first = ReadU16(bytes, cursor);
        cursor += 2U;
        if ((first & 0x8000U) == 0U) return static_cast<std::uint32_t>(first);
        const auto second = ReadU16(bytes, cursor);
        cursor += 2U;
        return static_cast<std::uint32_t>(first & 0x7fffU) << 16U |
               static_cast<std::uint32_t>(second);
    };
    for (std::uint32_t i = 0U; i < count; ++i) {
        const auto relative = ReadU32(bytes, offset + chunk.header_size + i * 4U);
        if (relative >= strings_end - strings_start) {
            throw std::runtime_error("AXML string offset exceeds string data");
        }
        std::size_t cursor = offset + strings_start + relative;
        if (utf8) {
            const auto declared_units = read_length8(cursor);
            const auto byte_length = read_length8(cursor);
            if (cursor + byte_length >= offset + strings_end ||
                bytes[cursor + byte_length] != 0U) {
                throw std::runtime_error("AXML UTF-8 string payload exceeds string data");
            }
            std::string value(reinterpret_cast<const char*>(bytes.data() + cursor), byte_length);
            if (Utf8ToUtf16(value).size() != declared_units) {
                throw std::runtime_error("AXML UTF-8 string length mismatch");
            }
            values.push_back(std::move(value));
        } else {
            const auto units = read_length16(cursor);
            if (units > (offset + strings_end - cursor) / 2U ||
                cursor + static_cast<std::size_t>(units) * 2U + 2U > offset + strings_end) {
                throw std::runtime_error("AXML UTF-16 string payload exceeds string data");
            }
            const auto terminator = cursor + static_cast<std::size_t>(units) * 2U;
            if (ReadU16(bytes, terminator) != 0U) {
                throw std::runtime_error("AXML UTF-16 string is not terminated");
            }
            values.push_back(Utf16ToUtf8(bytes, cursor, units));
        }
    }
    return values;
}

} // namespace

AxmlDocument AxmlDocument::Parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 8U || ReadU16(bytes, 0U) != 0x0003U) throw std::runtime_error("invalid binary XML header");
    const auto total_size = ReadU32(bytes, 4U);
    if (total_size != bytes.size()) throw std::runtime_error("binary XML size mismatch");
    AxmlDocument result;
    result.bytes_.assign(bytes.begin(), bytes.end());
    const AxmlChunk root{ReadU16(bytes, 0U), ReadU16(bytes, 2U), total_size, 0U};
    if (root.header_size < 8U || root.header_size > root.size) {
        throw std::runtime_error("invalid binary XML root header");
    }
    result.chunks_.push_back(root);
    std::size_t cursor = root.header_size;
    while (cursor < root.size) {
        if (bytes.size() - cursor < 8U) throw std::runtime_error("truncated binary XML chunk");
        const AxmlChunk chunk{ReadU16(bytes, cursor), ReadU16(bytes, cursor + 2U), ReadU32(bytes, cursor + 4U), static_cast<std::uint32_t>(cursor)};
        if (chunk.header_size < 8U || chunk.size < chunk.header_size || chunk.size > bytes.size() - cursor) throw std::runtime_error("invalid binary XML chunk size");
        result.chunks_.push_back(chunk);
        cursor += chunk.size;
    }
    if (cursor != root.size) throw std::runtime_error("binary XML child chunks exceed root");
    for (const auto& chunk : result.chunks_) {
        if (chunk.type == 0x0001U) {
            if (!result.strings_.empty()) {
                throw std::runtime_error("AXML contains multiple string pools");
            }
            result.strings_ = DecodeStringPool(bytes, chunk);
        }
    }
    return result;
}

std::vector<std::uint8_t> AxmlDocument::RenameStringsInPlace(
    const std::map<std::string, std::string, std::less<>>& replacements) const {
    if (replacements.empty()) return bytes_;
    const auto source = std::span<const std::uint8_t>(bytes_.data(), bytes_.size());
    const auto patch_u32 = [](std::vector<std::uint8_t>& output, std::size_t at,
                              std::uint32_t value) {
        if (at > output.size() || output.size() - at < 4U) {
            throw std::runtime_error("AXML uint32 patch exceeds output");
        }
        for (unsigned shift = 0U; shift < 32U; shift += 8U) {
            output[at + shift / 8U] = static_cast<std::uint8_t>(value >> shift);
        }
    };
    std::optional<AxmlChunk> string_pool;
    for (const auto& chunk : chunks_) {
        if (chunk.type != 0x0001U || chunk.header_size < 28U) continue;
        if (string_pool.has_value()) throw std::runtime_error("AXML contains multiple string pools");
        string_pool = chunk;
    }
    if (!string_pool.has_value()) throw std::runtime_error("AXML has no string pool");
    const auto chunk = *string_pool;
    const auto offset = static_cast<std::size_t>(chunk.offset);
    const auto count = ReadU32(source, offset + 8U);
    const auto style_count = ReadU32(source, offset + 12U);
    auto flags = ReadU32(source, offset + 16U);
    const auto strings_start = ReadU32(source, offset + 20U);
    const auto styles_start = ReadU32(source, offset + 24U);
    const auto utf8 = (flags & 0x100U) != 0U;
    const auto arrays_size = (static_cast<std::uint64_t>(count) + style_count) * 4U;
    if (strings_start < chunk.header_size || strings_start >= chunk.size ||
        static_cast<std::uint64_t>(chunk.header_size) + arrays_size > strings_start ||
        offset + chunk.size > source.size()) {
        throw std::runtime_error("invalid AXML string pool");
    }
    if (styles_start != 0U && (styles_start < strings_start || styles_start > chunk.size)) {
        throw std::runtime_error("invalid AXML style pool offset");
    }
    if (style_count != 0U && styles_start == 0U) {
        throw std::runtime_error("AXML style offsets exist without style data");
    }
    const auto strings_end = styles_start == 0U ? chunk.size : styles_start;
    auto read_length8 = [&](std::size_t& cursor) {
        if (cursor >= offset + strings_end) throw std::runtime_error("truncated AXML string length");
        const auto first = source[cursor++];
        if ((first & 0x80U) == 0U) return static_cast<std::uint32_t>(first);
        if (cursor >= offset + strings_end) throw std::runtime_error("truncated AXML long string length");
        return static_cast<std::uint32_t>(first & 0x7fU) << 8U |
               static_cast<std::uint32_t>(source[cursor++]);
    };
    auto read_length16 = [&](std::size_t& cursor) {
        const auto first = ReadU16(source, cursor);
        cursor += 2U;
        if ((first & 0x8000U) == 0U) return static_cast<std::uint32_t>(first);
        const auto second = ReadU16(source, cursor);
        cursor += 2U;
        return static_cast<std::uint32_t>(first & 0x7fffU) << 16U |
               static_cast<std::uint32_t>(second);
    };
    std::vector<std::string> values;
    values.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto relative = ReadU32(source, offset + chunk.header_size + i * 4U);
        if (relative >= strings_end - strings_start) {
            throw std::runtime_error("AXML string offset exceeds string data");
        }
        std::size_t cursor = offset + strings_start + relative;
        if (utf8) {
            const auto declared_units = read_length8(cursor);
            const auto byte_length = read_length8(cursor);
            if (cursor + byte_length >= offset + strings_end || source[cursor + byte_length] != 0U) {
                throw std::runtime_error("AXML UTF-8 string payload exceeds string data");
            }
            std::string value(reinterpret_cast<const char*>(source.data() + cursor), byte_length);
            if (Utf8ToUtf16(value).size() != declared_units) {
                throw std::runtime_error("AXML UTF-8 string length mismatch");
            }
            values.push_back(std::move(value));
        } else {
            const auto units = read_length16(cursor);
            if (units > (offset + strings_end - cursor) / 2U ||
                cursor + static_cast<std::size_t>(units) * 2U + 2U > offset + strings_end) {
                throw std::runtime_error("AXML UTF-16 string payload exceeds string data");
            }
            const auto terminator = cursor + static_cast<std::size_t>(units) * 2U;
            if (ReadU16(source, terminator) != 0U) throw std::runtime_error("AXML UTF-16 string is not terminated");
            values.push_back(Utf16ToUtf8(source, cursor, units));
        }
    }

    bool changed = false;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto found = replacements.find(values[i]);
        if (found == replacements.end() || found->second == values[i]) continue;
        if (i < style_count) {
            const auto style_offset = ReadU32(
                source, offset + chunk.header_size + static_cast<std::size_t>(count) * 4U + i * 4U);
            if (style_offset != 0xffffffffU) {
                throw std::runtime_error("cannot resize a styled AXML string: " + values[i]);
            }
        }
        values[i] = found->second;
        changed = true;
    }
    if (!changed) return bytes_;

    std::vector<std::uint8_t> rebuilt(bytes_.begin() + offset,
                                      bytes_.begin() + offset + chunk.header_size);
    rebuilt.resize(static_cast<std::size_t>(chunk.header_size) +
                   (static_cast<std::size_t>(count) + style_count) * 4U, 0U);
    if (style_count != 0U) {
        const auto old_styles = offset + chunk.header_size + static_cast<std::size_t>(count) * 4U;
        const auto new_styles = static_cast<std::size_t>(chunk.header_size) +
                                static_cast<std::size_t>(count) * 4U;
        std::copy_n(source.begin() + old_styles, static_cast<std::size_t>(style_count) * 4U,
                    rebuilt.begin() + new_styles);
    }
    if (rebuilt.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("AXML string offset table exceeds uint32 size");
    }
    const auto new_strings_start = static_cast<std::uint32_t>(rebuilt.size());
    const auto append_u16 = [&](std::uint16_t value) {
        rebuilt.push_back(static_cast<std::uint8_t>(value));
        rebuilt.push_back(static_cast<std::uint8_t>(value >> 8U));
    };
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto relative = static_cast<std::uint32_t>(rebuilt.size() - new_strings_start);
        patch_u32(rebuilt, chunk.header_size + static_cast<std::size_t>(i) * 4U, relative);
        const auto utf16_value = Utf8ToUtf16(values[i]);
        if (utf8) {
            const auto append_length8 = [&](std::uint32_t value) {
                if (value <= 0x7fU) rebuilt.push_back(static_cast<std::uint8_t>(value));
                else if (value <= 0x7fffU) {
                    rebuilt.push_back(static_cast<std::uint8_t>(0x80U | (value >> 8U)));
                    rebuilt.push_back(static_cast<std::uint8_t>(value));
                } else throw std::length_error("AXML UTF-8 string length exceeds format limit");
            };
            append_length8(static_cast<std::uint32_t>(utf16_value.size()));
            append_length8(static_cast<std::uint32_t>(values[i].size()));
            rebuilt.insert(rebuilt.end(), values[i].begin(), values[i].end());
            rebuilt.push_back(0U);
        } else {
            const auto append_length16 = [&](std::uint32_t value) {
                if (value <= 0x7fffU) append_u16(static_cast<std::uint16_t>(value));
                else {
                    append_u16(static_cast<std::uint16_t>(0x8000U | (value >> 16U)));
                    append_u16(static_cast<std::uint16_t>(value));
                }
            };
            append_length16(static_cast<std::uint32_t>(utf16_value.size()));
            for (const auto unit : utf16_value) append_u16(unit);
            append_u16(0U);
        }
    }
    while ((rebuilt.size() & 3U) != 0U) rebuilt.push_back(0U);
    std::uint32_t new_styles_start = 0U;
    if (styles_start != 0U) {
        new_styles_start = static_cast<std::uint32_t>(rebuilt.size());
        rebuilt.insert(rebuilt.end(), bytes_.begin() + offset + styles_start,
                       bytes_.begin() + offset + chunk.size);
        while ((rebuilt.size() & 3U) != 0U) rebuilt.push_back(0U);
    }
    if (rebuilt.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("AXML string pool exceeds uint32 size");
    }
    flags &= ~1U;
    patch_u32(rebuilt, 4U, static_cast<std::uint32_t>(rebuilt.size()));
    patch_u32(rebuilt, 16U, flags);
    patch_u32(rebuilt, 20U, new_strings_start);
    patch_u32(rebuilt, 24U, new_styles_start);

    std::vector<std::uint8_t> result;
    result.reserve(bytes_.size() - chunk.size + rebuilt.size());
    result.insert(result.end(), bytes_.begin(), bytes_.begin() + offset);
    result.insert(result.end(), rebuilt.begin(), rebuilt.end());
    result.insert(result.end(), bytes_.begin() + offset + chunk.size, bytes_.end());
    if (result.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("AXML output exceeds uint32 size");
    }
    patch_u32(result, 4U, static_cast<std::uint32_t>(result.size()));
    (void)AxmlDocument::Parse(result);
    return result;
}

} // namespace birch::guard
