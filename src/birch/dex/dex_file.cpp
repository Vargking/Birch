#include "birch/dex/dex_file.h"

#include "birch/dex/leb128.h"
#include "birch/dex/checksum.h"
#include "birch/dex/code.h"

#include <cstring>
#include <cmath>
#include <algorithm>
#include <functional>
#include <limits>
#include <set>
#include <tuple>

namespace birch::dex {
namespace {

constexpr std::uint32_t kDexHeaderSize = 0x70U;
constexpr std::uint32_t kDexHeaderV41Size = 0x78U;
constexpr std::uint32_t kEndianConstant = 0x12345678U;
constexpr std::uint32_t kNoIndex = 0xffffffffU;

std::vector<std::uint16_t> Utf16Units(std::string_view value) {
    std::vector<std::uint16_t> result;
    for (std::size_t i = 0; i < value.size();) {
        const auto first = static_cast<std::uint8_t>(value[i]);
        std::uint32_t codepoint = 0U;
        std::size_t width = 0U;
        if (first <= 0x7fU) { codepoint = first; width = 1U; }
        else if (first >= 0xc0U && first <= 0xdfU) { codepoint = first & 0x1fU; width = 2U; }
        else if (first >= 0xe0U && first <= 0xefU) { codepoint = first & 0x0fU; width = 3U; }
        else throw std::runtime_error("invalid MUTF-8 while checking DEX order");
        if (i + width > value.size()) throw std::runtime_error("truncated MUTF-8 while checking DEX order");
        for (std::size_t part = 1U; part < width; ++part) {
            const auto next = static_cast<std::uint8_t>(value[i + part]);
            if ((next & 0xc0U) != 0x80U) throw std::runtime_error("invalid MUTF-8 continuation");
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if (codepoint <= 0xffffU) result.push_back(static_cast<std::uint16_t>(codepoint));
        else { const auto adjusted = codepoint - 0x10000U; result.push_back(static_cast<std::uint16_t>(0xd800U + (adjusted >> 10U))); result.push_back(static_cast<std::uint16_t>(0xdc00U + (adjusted & 0x3ffU))); }
        i += width;
    }
    return result;
}

std::uint16_t ReadU16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) {
        throw DexParseError(DexErrorCode::Truncated, offset, "truncated uint16");
    }
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U;
}

std::uint32_t ReadU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        throw DexParseError(DexErrorCode::Truncated, offset, "truncated uint32");
    }
    return static_cast<std::uint32_t>(bytes[offset]) |
           static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
           static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U |
           static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
}

void WriteU16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value); bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void WriteU32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32U; shift += 8U) bytes[offset + shift / 8U] = static_cast<std::uint8_t>(value >> shift);
}

void AppendU16(std::vector<std::uint8_t>& bytes, std::uint16_t value) { bytes.push_back(static_cast<std::uint8_t>(value)); bytes.push_back(static_cast<std::uint8_t>(value >> 8U)); }
void AppendU32(std::vector<std::uint8_t>& bytes, std::uint32_t value) { for (unsigned shift = 0; shift < 32U; shift += 8U) bytes.push_back(static_cast<std::uint8_t>(value >> shift)); }
void PatchU16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) { if (offset > bytes.size() || bytes.size() - offset < 2U) throw DexParseError(DexErrorCode::OutOfBounds, offset, "DEX patch exceeds file"); WriteU16(bytes, offset, value); }

void PatchU32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) throw DexParseError(DexErrorCode::OutOfBounds, offset, "DEX patch exceeds file");
    WriteU32(bytes, offset, value);
}

Leb128Value ReadUlebChecked(std::span<const std::uint8_t> bytes, std::size_t offset) {
    try {
        return ReadUleb128(bytes, offset);
    } catch (const std::runtime_error& error) {
        throw DexParseError(DexErrorCode::InvalidClassData, offset, error.what());
    }
}

bool IsSupportedVersion(std::uint32_t version) {
    return version == 35U || version == 37U || version == 38U ||
           version == 39U || version == 40U || version == 41U;
}

void ValidateCountRange(std::uint32_t count, std::uint32_t item_size,
                        std::uint32_t offset, std::size_t file_size) {
    if ((count == 0U) != (offset == 0U)) {
        throw DexParseError(DexErrorCode::InvalidHeader, offset,
                            count == 0U ?
                                "DEX section offset must be zero when size is zero" :
                                "DEX section offset must be non-zero when size is non-zero");
    }
    const auto end = static_cast<std::uint64_t>(offset) +
                     static_cast<std::uint64_t>(count) * item_size;
    if (end > file_size) {
        throw DexParseError(DexErrorCode::OutOfBounds, offset,
                            "DEX section exceeds file");
    }
}

void ValidateTypeList(std::span<const std::uint8_t> bytes, std::uint32_t offset,
                      std::uint32_t type_count, std::uint32_t file_size,
                      std::size_t source_offset) {
    if (offset == 0U) {
        return;
    }
    if (static_cast<std::uint64_t>(offset) + 4U > file_size) {
        throw DexParseError(DexErrorCode::OutOfBounds, source_offset,
                            "type_list header exceeds file");
    }
    const auto size = ReadU32(bytes, offset);
    if (static_cast<std::uint64_t>(offset) + 4U +
            static_cast<std::uint64_t>(size) * 2U > file_size) {
        throw DexParseError(DexErrorCode::OutOfBounds, offset,
                            "type_list exceeds file");
    }
    for (std::uint32_t i = 0; i < size; ++i) {
        const auto entry_offset = static_cast<std::size_t>(offset) + 4U +
                                  static_cast<std::size_t>(i) * 2U;
        if (ReadU16(bytes, entry_offset) >= type_count) {
            throw DexParseError(DexErrorCode::InvalidIndex, entry_offset,
                                "type_list contains invalid type index");
        }
    }
}

DexString ReadString(std::span<const std::uint8_t> bytes, std::uint32_t offset) {
    const auto length = ReadUlebChecked(bytes, offset);
    std::size_t cursor = static_cast<std::size_t>(offset) + length.size;
    const std::size_t payload_start = cursor;
    std::uint32_t utf16_units = 0;
    while (true) {
        if (cursor >= bytes.size()) {
            throw DexParseError(DexErrorCode::Truncated, cursor,
                                "unterminated MUTF-8 string");
        }
        const auto first = bytes[cursor];
        if (first == 0U) {
            break;
        }
        std::size_t encoded_size = 1U;
        if (first >= 0xc0U && first <= 0xdfU) {
            encoded_size = 2U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            encoded_size = 3U;
        } else if (first > 0x7fU) {
            throw DexParseError(DexErrorCode::InvalidString, cursor,
                                "invalid MUTF-8 leading byte");
        }
        if (cursor > bytes.size() || bytes.size() - cursor < encoded_size) {
            throw DexParseError(DexErrorCode::Truncated, cursor,
                                "truncated MUTF-8 sequence");
        }
        for (std::size_t i = 1; i < encoded_size; ++i) {
            if ((bytes[cursor + i] & 0xc0U) != 0x80U) {
                throw DexParseError(DexErrorCode::InvalidString, cursor + i,
                                    "invalid MUTF-8 continuation byte");
            }
        }
        cursor += encoded_size;
        ++utf16_units;
    }
    if (utf16_units != length.value) {
        throw DexParseError(DexErrorCode::InvalidString, offset,
                            "MUTF-8 length does not match utf16_size");
    }
    DexString result;
    result.utf16_length = length.value;
    result.data_offset = offset;
    result.mutf8.assign(reinterpret_cast<const char*>(bytes.data() + payload_start),
                        cursor - payload_start);
    result.encoded_size = static_cast<std::uint32_t>(cursor + 1U - offset);
    return result;
}

} // namespace

DexParseError::DexParseError(DexErrorCode code, std::size_t offset, std::string message)
    : std::runtime_error(std::move(message)), code_(code), offset_(offset) {}

DexFile DexFile::Parse(std::span<const std::uint8_t> bytes) {
    DexFile result;
    result.ParseImpl(bytes, 0U);
    return result;
}

DexFile DexFile::ParseContainerEntry(std::span<const std::uint8_t> bytes,
                                     std::uint32_t header_offset) {
    DexFile result;
    result.ParseImpl(bytes, header_offset);
    return result;
}

DexContainer DexContainer::Parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kDexHeaderSize) {
        throw DexParseError(DexErrorCode::Truncated, 0U, "DEX container is truncated");
    }
    DexContainer result;
    result.bytes_.assign(bytes.begin(), bytes.end());
    const auto owned = std::span<const std::uint8_t>(result.bytes_.data(), result.bytes_.size());
    const auto first = DexFile::ParseContainerEntry(owned, 0U);
    if (first.version() != 41U) {
        result.dex_files_.push_back(first);
        return result;
    }
    const auto container_size = first.header().container_size;
    for (std::size_t offset = 0U; offset + kDexHeaderV41Size <= owned.size(); offset += 4U) {
        if (std::memcmp(owned.data() + offset, "dex\n041\0", 8U) != 0) continue;
        if (ReadU32(owned, offset + 0x24U) != kDexHeaderV41Size ||
            ReadU32(owned, offset + 0x70U) != container_size ||
            ReadU32(owned, offset + 0x74U) != offset) continue;
        result.dex_files_.push_back(DexFile::ParseContainerEntry(
            owned, static_cast<std::uint32_t>(offset)));
    }
    if (result.dex_files_.empty() || result.dex_files_.front().header().header_offset != 0U) {
        throw DexParseError(DexErrorCode::InvalidHeader, 0U,
                            "DEX 041 container has no header at offset zero");
    }
    for (std::size_t i = 1U; i < result.dex_files_.size(); ++i) {
        if (result.dex_files_[i - 1U].header().header_offset >=
            result.dex_files_[i].header().header_offset) {
            throw DexParseError(DexErrorCode::InvalidHeader,
                                result.dex_files_[i].header().header_offset,
                                "DEX 041 container header offsets are not unique");
        }
    }
    return result;
}

void DexFile::ParseImpl(std::span<const std::uint8_t> bytes,
                        std::uint32_t header_offset) {
    bytes_.assign(bytes.begin(), bytes.end());
    const std::span<const std::uint8_t> owned(bytes_.data(), bytes_.size());
    header_.header_offset = header_offset;
    ParseHeader(owned);
    ParseIds(owned);
    ParseMap(owned);
    ParseClassData(owned);
}

void DexFile::ParseHeader(std::span<const std::uint8_t> bytes) {
    const auto base = static_cast<std::size_t>(header_.header_offset);
    if (base > bytes.size() || bytes.size() - base < kDexHeaderSize) {
        throw DexParseError(DexErrorCode::Truncated, base, "DEX header is truncated");
    }
    if (std::memcmp(bytes.data() + base, "dex\n", 4U) != 0 || bytes[base + 7U] != 0U ||
        bytes[base + 4U] < '0' || bytes[base + 4U] > '9' ||
        bytes[base + 5U] < '0' || bytes[base + 5U] > '9' ||
        bytes[base + 6U] < '0' || bytes[base + 6U] > '9') {
        throw DexParseError(DexErrorCode::InvalidMagic, base, "invalid DEX magic");
    }
    const auto version = static_cast<std::uint32_t>(bytes[base + 4U] - '0') * 100U +
                         static_cast<std::uint32_t>(bytes[base + 5U] - '0') * 10U +
                         static_cast<std::uint32_t>(bytes[base + 6U] - '0');
    if (!IsSupportedVersion(version)) {
        throw DexParseError(DexErrorCode::UnsupportedVersion, base + 4U,
                            "unsupported DEX version");
    }
    version_ = static_cast<std::uint8_t>(version);
    const auto expected_header_size = version == 41U ? kDexHeaderV41Size : kDexHeaderSize;
    if (base > bytes.size() || bytes.size() - base < expected_header_size) {
        throw DexParseError(DexErrorCode::Truncated, base, "versioned DEX header is truncated");
    }
    header_.checksum = ReadU32(bytes, base + 0x08U);
    header_.signature.assign(bytes.begin() + base + 0x0cU, bytes.begin() + base + 0x20U);
    auto read_header = [&](std::size_t offset) { return ReadU32(bytes, base + offset); };
    header_.file_size = read_header(0x20U);
    header_.header_size = read_header(0x24U);
    header_.endian_tag = read_header(0x28U);
    header_.link_size = read_header(0x2cU);
    header_.link_off = read_header(0x30U);
    header_.map_off = read_header(0x34U);
    header_.string_ids_size = read_header(0x38U);
    header_.string_ids_off = read_header(0x3cU);
    header_.type_ids_size = read_header(0x40U);
    header_.type_ids_off = read_header(0x44U);
    header_.proto_ids_size = read_header(0x48U);
    header_.proto_ids_off = read_header(0x4cU);
    header_.field_ids_size = read_header(0x50U);
    header_.field_ids_off = read_header(0x54U);
    header_.method_ids_size = read_header(0x58U);
    header_.method_ids_off = read_header(0x5cU);
    header_.class_defs_size = read_header(0x60U);
    header_.class_defs_off = read_header(0x64U);
    header_.data_size = read_header(0x68U);
    header_.data_off = read_header(0x6cU);
    if (version == 41U) {
        header_.container_size = read_header(0x70U);
        const auto declared_header_offset = read_header(0x74U);
        if (declared_header_offset != base) {
            throw DexParseError(DexErrorCode::InvalidHeader, base + 0x74U,
                                "DEX 041 header_offset does not match header position");
        }
        header_.header_offset = declared_header_offset;
    } else {
        if (base != 0U) {
            throw DexParseError(DexErrorCode::InvalidHeader, base,
                                "pre-041 DEX cannot be embedded in a DEX container");
        }
        header_.container_size = header_.file_size;
        header_.header_offset = 0U;
    }
    if (header_.header_size != expected_header_size) {
        throw DexParseError(DexErrorCode::InvalidHeader, base + 0x24U,
                            "invalid DEX header size");
    }
    if (header_.endian_tag != kEndianConstant) {
        throw DexParseError(DexErrorCode::InvalidEndian, base + 0x28U,
                            "reverse-endian DEX is not supported");
    }
    if (version == 41U) {
        if (header_.container_size != bytes.size()) {
            throw DexParseError(DexErrorCode::InvalidHeader, base + 0x70U,
                                "DEX 041 container_size does not match input size");
        }
        if (header_.file_size < header_.header_size ||
            static_cast<std::uint64_t>(base) + header_.file_size > bytes.size()) {
            throw DexParseError(DexErrorCode::InvalidHeader, base + 0x20U,
                                "DEX 041 file range exceeds container");
        }
    } else if (header_.file_size != bytes.size()) {
        throw DexParseError(DexErrorCode::InvalidHeader, base + 0x20U,
                            "file_size does not match input size");
    }
    CheckRange(header_.data_off, header_.data_size, DexErrorCode::OutOfBounds,
               "data section");
    CheckRange(header_.link_off, header_.link_size, DexErrorCode::OutOfBounds,
               "link section");
    if (header_.map_off == 0U) {
        throw DexParseError(DexErrorCode::InvalidMap, 0x34U, "map_off is zero");
    }
}

void DexFile::CheckRange(std::uint64_t offset, std::uint64_t size, DexErrorCode code,
                         std::string_view what) const {
    if (offset > bytes_.size() || size > bytes_.size() - offset) {
        throw DexParseError(code, static_cast<std::size_t>(offset),
                            std::string(what) + " exceeds file");
    }
}

void DexFile::CheckIndex(std::uint32_t index, std::uint32_t size, std::size_t offset,
                         std::string_view what) const {
    if (index >= size) {
        throw DexParseError(DexErrorCode::InvalidIndex, offset,
                            std::string(what) + " index out of range");
    }
}

void DexFile::EnsureStandaloneWritable() const {
    if (header_.header_offset != 0U || header_.container_size != bytes_.size() ||
        header_.file_size != bytes_.size()) {
        throw std::runtime_error(
            "rewriting a shared/multi-header DEX 041 container requires DexContainer writer");
    }
}

void DexFile::ParseIds(std::span<const std::uint8_t> bytes) {
    ValidateCountRange(header_.string_ids_size, 4U, header_.string_ids_off, bytes.size());
    ValidateCountRange(header_.type_ids_size, 4U, header_.type_ids_off, bytes.size());
    ValidateCountRange(header_.proto_ids_size, 12U, header_.proto_ids_off, bytes.size());
    ValidateCountRange(header_.field_ids_size, 8U, header_.field_ids_off, bytes.size());
    ValidateCountRange(header_.method_ids_size, 8U, header_.method_ids_off, bytes.size());
    ValidateCountRange(header_.class_defs_size, 32U, header_.class_defs_off, bytes.size());

    strings_.reserve(header_.string_ids_size);
    for (std::uint32_t i = 0; i < header_.string_ids_size; ++i) {
        const auto offset = static_cast<std::size_t>(header_.string_ids_off) + i * 4U;
        const auto data_offset = ReadU32(bytes, offset);
        CheckRange(data_offset, 1U, DexErrorCode::OutOfBounds, "string data");
        strings_.push_back(ReadString(bytes, data_offset));
    }
    types_.reserve(header_.type_ids_size);
    for (std::uint32_t i = 0; i < header_.type_ids_size; ++i) {
        const auto offset = static_cast<std::size_t>(header_.type_ids_off) + i * 4U;
        const auto descriptor_idx = ReadU32(bytes, offset);
        CheckIndex(descriptor_idx, header_.string_ids_size, offset, "descriptor");
        types_.push_back({descriptor_idx});
    }
    protos_.reserve(header_.proto_ids_size);
    for (std::uint32_t i = 0; i < header_.proto_ids_size; ++i) {
        const auto offset = static_cast<std::size_t>(header_.proto_ids_off) + i * 12U;
        DexProtoId value{ReadU32(bytes, offset), ReadU32(bytes, offset + 4U),
                         ReadU32(bytes, offset + 8U)};
        CheckIndex(value.shorty_idx, header_.string_ids_size, offset, "shorty");
        CheckIndex(value.return_type_idx, header_.type_ids_size, offset + 4U, "return type");
        ValidateTypeList(bytes, value.parameters_off, header_.type_ids_size,
                         header_.container_size, offset + 8U);
        protos_.push_back(value);
    }
    fields_.reserve(header_.field_ids_size);
    for (std::uint32_t i = 0; i < header_.field_ids_size; ++i) {
        const auto offset = static_cast<std::size_t>(header_.field_ids_off) + i * 8U;
        DexFieldId value{ReadU16(bytes, offset), ReadU16(bytes, offset + 2U),
                         ReadU32(bytes, offset + 4U)};
        CheckIndex(value.class_idx, header_.type_ids_size, offset, "field class");
        CheckIndex(value.type_idx, header_.type_ids_size, offset + 2U, "field type");
        CheckIndex(value.name_idx, header_.string_ids_size, offset + 4U, "field name");
        fields_.push_back(value);
    }
    methods_.reserve(header_.method_ids_size);
    for (std::uint32_t i = 0; i < header_.method_ids_size; ++i) {
        const auto offset = static_cast<std::size_t>(header_.method_ids_off) + i * 8U;
        DexMethodId value{ReadU16(bytes, offset), ReadU16(bytes, offset + 2U),
                          ReadU32(bytes, offset + 4U)};
        CheckIndex(value.class_idx, header_.type_ids_size, offset, "method class");
        CheckIndex(value.proto_idx, header_.proto_ids_size, offset + 2U, "method proto");
        CheckIndex(value.name_idx, header_.string_ids_size, offset + 4U, "method name");
        methods_.push_back(value);
    }
    classes_.reserve(header_.class_defs_size);
    for (std::uint32_t i = 0; i < header_.class_defs_size; ++i) {
        const auto offset = static_cast<std::size_t>(header_.class_defs_off) + i * 32U;
        DexClassDef value{ReadU32(bytes, offset), ReadU32(bytes, offset + 4U),
                          ReadU32(bytes, offset + 8U), ReadU32(bytes, offset + 12U),
                          ReadU32(bytes, offset + 16U), ReadU32(bytes, offset + 20U),
                          ReadU32(bytes, offset + 24U), ReadU32(bytes, offset + 28U)};
        CheckIndex(value.class_idx, header_.type_ids_size, offset, "class");
        if (value.superclass_idx != kNoIndex) {
            CheckIndex(value.superclass_idx, header_.type_ids_size, offset + 8U, "superclass");
        }
        if (value.source_file_idx != kNoIndex) {
            CheckIndex(value.source_file_idx, header_.string_ids_size, offset + 16U,
                       "source file");
        }
        ValidateTypeList(bytes, value.interfaces_off, header_.type_ids_size,
                         header_.container_size, offset + 12U);
        if (value.annotations_off != 0U) {
            CheckRange(value.annotations_off, 1U, DexErrorCode::OutOfBounds, "annotations");
        }
        if (value.class_data_off != 0U) {
            CheckRange(value.class_data_off, 1U, DexErrorCode::OutOfBounds, "class data");
        }
        if (value.static_values_off != 0U) {
            CheckRange(value.static_values_off, 1U, DexErrorCode::OutOfBounds, "static values");
        }
        classes_.push_back(value);
    }
}

void DexFile::ParseMap(std::span<const std::uint8_t> bytes) {
    CheckRange(header_.map_off, 4U, DexErrorCode::InvalidMap, "map list");
    const auto count = ReadU32(bytes, header_.map_off);
    if (count == 0U) {
        throw DexParseError(DexErrorCode::InvalidMap, header_.map_off, "empty map list");
    }
    CheckRange(static_cast<std::uint64_t>(header_.map_off) + 4U,
               static_cast<std::uint64_t>(count) * 12U, DexErrorCode::InvalidMap,
               "map entries");
    map_.reserve(count);
    std::set<std::uint16_t> seen_types;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto offset = static_cast<std::size_t>(header_.map_off) + 4U + i * 12U;
        const auto type = ReadU16(bytes, offset);
        const auto unused = ReadU16(bytes, offset + 2U);
        DexMapItem item{type, ReadU32(bytes, offset + 4U),
                        ReadU32(bytes, offset + 8U)};
        if (unused != 0U) {
            throw DexParseError(DexErrorCode::InvalidMap, offset + 2U,
                                "map item reserved field is non-zero");
        }
        if (item.size == 0U) {
            throw DexParseError(DexErrorCode::InvalidMap, offset + 4U,
                                "map item has zero size");
        }
        if (!seen_types.insert(item.type).second) {
            throw DexParseError(DexErrorCode::InvalidMap, offset,
                                "duplicate map item type");
        }
        if (item.offset >= header_.container_size) {
            throw DexParseError(DexErrorCode::InvalidMap, offset + 8U,
                                "map item offset exceeds file");
        }
        map_.push_back(item);
    }

    bool found_string_data = false;
    for (const auto& item : map_) {
        if (item.type != 0x2002U) continue;
        found_string_data = true;
        if (item.size != strings_.size()) {
            throw DexParseError(DexErrorCode::InvalidMap, item.offset,
                                "string_data map count does not match string_ids");
        }
        std::set<std::uint32_t> physical_offsets;
        std::size_t cursor = item.offset;
        for (std::uint32_t i = 0; i < item.size; ++i) {
            if (cursor > std::numeric_limits<std::uint32_t>::max()) {
                throw DexParseError(DexErrorCode::IntegerOverflow, cursor,
                                    "string_data offset exceeds DEX address space");
            }
            const auto offset = static_cast<std::uint32_t>(cursor);
            if (!physical_offsets.insert(offset).second) {
                throw DexParseError(DexErrorCode::InvalidMap, cursor,
                                    "duplicate physical string_data item");
            }
            const auto value = ReadString(bytes, offset);
            cursor += value.encoded_size;
        }
        for (const auto& value : strings_) {
            if (!physical_offsets.contains(value.data_offset)) {
                throw DexParseError(DexErrorCode::InvalidMap, value.data_offset,
                                    "string_id does not reference the mapped string_data section");
            }
        }
    }
    if (!strings_.empty() && !found_string_data) {
        throw DexParseError(DexErrorCode::InvalidMap, header_.map_off,
                            "DEX with strings has no string_data map item");
    }

    for (const auto& item : map_) {
        if (item.type == 0x0007U) {
            if (version_ < 38U) {
                throw DexParseError(DexErrorCode::InvalidMap, item.offset,
                                    "call_site_id section requires DEX 038 or newer");
            }
            CheckRange(item.offset, static_cast<std::uint64_t>(item.size) * 4U,
                       DexErrorCode::InvalidMap, "call_site_id section");
            call_sites_.reserve(item.size);
            for (std::uint32_t i = 0; i < item.size; ++i) {
                const auto entry_offset = item.offset + i * 4U;
                const auto encoded_array_off = ReadU32(bytes, entry_offset);
                if (encoded_array_off == 0U || encoded_array_off >= header_.container_size) {
                    throw DexParseError(DexErrorCode::InvalidIndex, entry_offset,
                                        "call_site_id encoded array offset is invalid");
                }
                (void)ReadUlebChecked(bytes, encoded_array_off);
                call_sites_.push_back({encoded_array_off, entry_offset});
            }
        } else if (item.type == 0x0008U) {
            if (version_ < 38U) {
                throw DexParseError(DexErrorCode::InvalidMap, item.offset,
                                    "method_handle section requires DEX 038 or newer");
            }
            CheckRange(item.offset, static_cast<std::uint64_t>(item.size) * 8U,
                       DexErrorCode::InvalidMap, "method_handle section");
            method_handles_.reserve(item.size);
            for (std::uint32_t i = 0; i < item.size; ++i) {
                const auto entry_offset = item.offset + i * 8U;
                const auto handle_type = ReadU16(bytes, entry_offset);
                const auto unused1 = ReadU16(bytes, entry_offset + 2U);
                const auto member_idx = ReadU16(bytes, entry_offset + 4U);
                const auto unused2 = ReadU16(bytes, entry_offset + 6U);
                if (handle_type > 8U) {
                    throw DexParseError(DexErrorCode::InvalidIndex, entry_offset,
                                        "method_handle type is invalid");
                }
                if (unused1 != 0U || unused2 != 0U) {
                    throw DexParseError(DexErrorCode::InvalidMap, entry_offset + 2U,
                                        "method_handle reserved field is non-zero");
                }
                const auto member_count = handle_type <= 3U ? fields_.size() : methods_.size();
                if (member_idx >= member_count) {
                    throw DexParseError(DexErrorCode::InvalidIndex, entry_offset + 4U,
                                        "method_handle member index is invalid");
                }
                method_handles_.push_back({handle_type, member_idx, entry_offset});
            }
        }
    }
}

void DexFile::ParseClassData(std::span<const std::uint8_t> bytes) {
    class_data_.resize(classes_.size());
    for (std::size_t class_index = 0; class_index < classes_.size(); ++class_index) {
        const auto data_offset = classes_[class_index].class_data_off;
        if (data_offset == 0U) {
            continue;
        }
        std::size_t cursor = data_offset;
        const auto static_count = ReadUlebChecked(bytes, cursor); cursor += static_count.size;
        const auto instance_count = ReadUlebChecked(bytes, cursor); cursor += instance_count.size;
        const auto direct_count = ReadUlebChecked(bytes, cursor); cursor += direct_count.size;
        const auto virtual_count = ReadUlebChecked(bytes, cursor); cursor += virtual_count.size;
        if (static_count.value > header_.field_ids_size ||
            instance_count.value > header_.field_ids_size ||
            direct_count.value > header_.method_ids_size ||
            virtual_count.value > header_.method_ids_size) {
            throw DexParseError(DexErrorCode::InvalidClassData, data_offset,
                                "class_data count exceeds ID table");
        }
        auto& output = class_data_[class_index];
        auto fields = [&](std::uint32_t count, std::vector<DexEncodedField>& target) {
            std::uint32_t index = 0;
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto delta = ReadUlebChecked(bytes, cursor); cursor += delta.size;
                const auto flags = ReadUlebChecked(bytes, cursor); cursor += flags.size;
                if (delta.value > std::numeric_limits<std::uint32_t>::max() - index) {
                    throw DexParseError(DexErrorCode::IntegerOverflow, cursor,
                                        "field index delta overflows");
                }
                index += delta.value;
                CheckIndex(index, header_.field_ids_size, cursor, "encoded field");
                target.push_back({index, flags.value});
            }
        };
        auto methods = [&](std::uint32_t count, std::vector<DexEncodedMethod>& target) {
            std::uint32_t index = 0;
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto delta = ReadUlebChecked(bytes, cursor); cursor += delta.size;
                const auto flags = ReadUlebChecked(bytes, cursor); cursor += flags.size;
                const auto code = ReadUlebChecked(bytes, cursor); cursor += code.size;
                if (delta.value > std::numeric_limits<std::uint32_t>::max() - index) {
                    throw DexParseError(DexErrorCode::IntegerOverflow, cursor,
                                        "method index delta overflows");
                }
                index += delta.value;
                CheckIndex(index, header_.method_ids_size, cursor, "encoded method");
                if (code.value != 0U) {
                    CheckRange(code.value, 16U, DexErrorCode::OutOfBounds, "code item");
                }
                target.push_back({index, flags.value, code.value});
            }
        };
        fields(static_count.value, output.static_fields);
        fields(instance_count.value, output.instance_fields);
        methods(direct_count.value, output.direct_methods);
        methods(virtual_count.value, output.virtual_methods);
    }
}

const DexClassData& DexFile::class_data(std::size_t index) const {
    if (index >= class_data_.size()) {
        throw std::out_of_range("class data index out of range");
    }
    return class_data_[index];
}

std::string DexFile::string(std::uint32_t string_idx) const {
    if (string_idx >= strings_.size()) {
        throw std::out_of_range("string index out of range");
    }
    return strings_[string_idx].mutf8;
}

std::string DexFile::descriptor(std::uint32_t type_idx) const {
    if (type_idx >= types_.size()) {
        throw std::out_of_range("type index out of range");
    }
    return string(types_[type_idx].descriptor_idx);
}

bool DexFile::VerifyChecksums() const {
    const auto base = static_cast<std::size_t>(header_.header_offset);
    if (header_.file_size < header_.header_size || base > bytes_.size() ||
        header_.file_size > bytes_.size() - base) {
        return false;
    }
    const auto signature = Sha1(std::span<const std::uint8_t>(
        bytes_.data() + base + 0x20U, header_.file_size - 0x20U));
    if (!std::equal(signature.begin(), signature.end(),
                    bytes_.begin() + base + 0x0cU)) {
        return false;
    }
    return Adler32(std::span<const std::uint8_t>(
        bytes_.data() + base + 0x0cU, header_.file_size - 0x0cU)) == header_.checksum;
}

bool DexFile::VerifyCanonicalOrder(std::string* issue) const {
    const auto fail = [&](std::string message) {
        if (issue != nullptr) *issue = std::move(message);
        return false;
    };
    for (std::size_t i = 1; i < strings_.size(); ++i) {
        if (Utf16Units(strings_[i - 1U].mutf8) >= Utf16Units(strings_[i].mutf8)) return fail("string_ids out of order at " + std::to_string(i));
    }
    for (std::size_t i = 1; i < types_.size(); ++i) {
        if (types_[i - 1U].descriptor_idx >= types_[i].descriptor_idx) return fail("type_ids out of order at " + std::to_string(i));
    }
    for (const auto& type : types_) if (type.descriptor_idx >= strings_.size()) return fail("type descriptor index out of range");
    for (const auto& proto : protos_) if (proto.shorty_idx >= strings_.size() || proto.return_type_idx >= types_.size()) return fail("proto index out of range");
    for (const auto& field : fields_) if (field.class_idx >= types_.size() || field.type_idx >= types_.size() || field.name_idx >= strings_.size()) return fail("field index out of range");
    for (const auto& method : methods_) if (method.class_idx >= types_.size() || method.proto_idx >= protos_.size() || method.name_idx >= strings_.size()) return fail("method index out of range");
    for (std::size_t i = 1; i < protos_.size(); ++i) {
        const auto left_parameters = type_list(protos_[i - 1U].parameters_off);
        const auto right_parameters = type_list(protos_[i].parameters_off);
        if (std::tie(protos_[i - 1U].return_type_idx, left_parameters) >=
            std::tie(protos_[i].return_type_idx, right_parameters)) return fail("proto_ids out of order at " + std::to_string(i));
    }
    for (std::size_t i = 1; i < fields_.size(); ++i) {
        if (std::tie(fields_[i - 1U].class_idx, fields_[i - 1U].name_idx, fields_[i - 1U].type_idx) >=
            std::tie(fields_[i].class_idx, fields_[i].name_idx, fields_[i].type_idx)) return fail("field_ids out of order at " + std::to_string(i));
    }
    for (std::size_t i = 1; i < methods_.size(); ++i) {
        if (std::tie(methods_[i - 1U].class_idx, methods_[i - 1U].name_idx, methods_[i - 1U].proto_idx) >=
            std::tie(methods_[i].class_idx, methods_[i].name_idx, methods_[i].proto_idx)) return fail("method_ids out of order at " + std::to_string(i));
    }
    std::map<std::uint32_t, std::size_t> class_positions;
    for (std::size_t i = 0; i < classes_.size(); ++i) {
        if (!class_positions.emplace(classes_[i].class_idx, i).second) {
            return fail("duplicate class_def type at " + std::to_string(i));
        }
    }
    for (std::size_t i = 0; i < classes_.size(); ++i) {
        const auto& definition = classes_[i];
        if (definition.superclass_idx != kNoIndex) {
            const auto parent = class_positions.find(definition.superclass_idx);
            if (parent != class_positions.end() && parent->second >= i) {
                return fail("class_def appears before its superclass at " + std::to_string(i));
            }
        }
        for (const auto interface_idx : type_list(definition.interfaces_off)) {
            const auto interface = class_positions.find(interface_idx);
            if (interface != class_positions.end() && interface->second >= i) {
                return fail("class_def appears before its interface at " + std::to_string(i));
            }
        }
    }
    if (issue != nullptr) issue->clear();
    return true;
}

std::vector<std::uint16_t> DexFile::type_list(std::uint32_t offset) const {
    if (offset == 0U) {
        return {};
    }
    CheckRange(offset, 4U, DexErrorCode::OutOfBounds, "type list");
    const auto count = ReadU32(bytes_, offset);
    CheckRange(static_cast<std::uint64_t>(offset) + 4U,
               static_cast<std::uint64_t>(count) * 2U, DexErrorCode::OutOfBounds,
               "type list entries");
    std::vector<std::uint16_t> result;
    result.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto entry_offset = static_cast<std::size_t>(offset) + 4U + i * 2U;
        const auto type_idx = ReadU16(bytes_, entry_offset);
        CheckIndex(type_idx, header_.type_ids_size, entry_offset, "type list");
        result.push_back(type_idx);
    }
    return result;
}

std::string DexFile::proto_key(std::uint32_t proto_idx) const {
    if (proto_idx >= protos_.size()) {
        throw std::out_of_range("proto index out of range");
    }
    const auto& proto = protos_[proto_idx];
    std::string key{"("};
    for (const auto parameter : type_list(proto.parameters_off)) {
        key += descriptor(parameter);
    }
    key += ')';
    key += descriptor(proto.return_type_idx);
    return key;
}

std::string DexFile::field_key(std::uint32_t field_idx) const {
    if (field_idx >= fields_.size()) {
        throw std::out_of_range("field index out of range");
    }
    const auto& field = fields_[field_idx];
    return descriptor(field.class_idx) + "->" + string(field.name_idx) + ":" +
           descriptor(field.type_idx);
}

std::string DexFile::method_key(std::uint32_t method_idx) const {
    if (method_idx >= methods_.size()) {
        throw std::out_of_range("method index out of range");
    }
    const auto& method = methods_[method_idx];
    return descriptor(method.class_idx) + "->" + string(method.name_idx) +
           proto_key(method.proto_idx);
}

std::vector<std::uint8_t> DexFile::ReplaceStringInPlace(
    std::uint32_t string_idx, std::string_view mutf8, std::uint32_t utf16_length) const {
    EnsureStandaloneWritable();
    if (string_idx >= strings_.size()) {
        throw std::out_of_range("string index out of range");
    }
    if (mutf8.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("MUTF-8 string may not contain an embedded NUL");
    }
    std::vector<std::uint8_t> encoded;
    std::uint32_t value = utf16_length;
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) byte = static_cast<std::uint8_t>(byte | 0x80U);
        encoded.push_back(byte);
    } while (value != 0U);
    encoded.insert(encoded.end(), mutf8.begin(), mutf8.end());
    encoded.push_back(0U);
    if (encoded.size() != strings_[string_idx].encoded_size) {
        throw std::length_error("in-place string replacement must preserve encoded item size");
    }
    return ReplaceStringsInPlace({{string_idx, {std::string(mutf8), utf16_length}}});
}

std::vector<std::uint8_t> DexFile::ReplaceStringsInPlace(
    const std::map<std::uint32_t, std::pair<std::string, std::uint32_t>>& replacements) const {
    EnsureStandaloneWritable();
    std::vector<std::uint8_t> result = bytes_;
    for (const auto& [string_idx, replacement] : replacements) {
        if (string_idx >= strings_.size()) throw std::out_of_range("string index out of range");
        if (replacement.first.find('\0') != std::string::npos) throw std::invalid_argument("MUTF-8 replacement has embedded NUL");
        std::vector<std::uint8_t> encoded;
        auto value = replacement.second;
        do { auto byte = static_cast<std::uint8_t>(value & 0x7fU); value >>= 7U; if (value != 0U) byte = static_cast<std::uint8_t>(byte | 0x80U); encoded.push_back(byte); } while (value != 0U);
        encoded.insert(encoded.end(), replacement.first.begin(), replacement.first.end()); encoded.push_back(0U);
        if (encoded.size() != strings_[string_idx].encoded_size) throw std::length_error("in-place string replacement must preserve encoded item size");
        const auto offset = strings_[string_idx].data_offset;
        std::copy(encoded.begin(), encoded.end(), result.begin() + offset);
    }
    UpdateDexChecksums(result);
    return result;
}

std::vector<std::uint8_t> DexFile::ReplaceStrings(
    const std::map<std::uint32_t, std::pair<std::string, std::uint32_t>>& replacements) const {
    EnsureStandaloneWritable();
    if (replacements.empty()) return bytes_;
    std::map<std::uint32_t, std::vector<std::uint8_t>> encoded_replacements;
    for (const auto& [string_idx, replacement] : replacements) {
        if (string_idx >= strings_.size()) throw std::out_of_range("string index out of range");
        if (replacement.first.find('\0') != std::string::npos) throw std::invalid_argument("MUTF-8 replacement has embedded NUL");
        if (Utf16Units(replacement.first).size() != replacement.second) {
            throw std::invalid_argument("replacement utf16_length does not match MUTF-8 payload");
        }
        std::vector<std::uint8_t> encoded;
        auto value = replacement.second;
        do { auto byte = static_cast<std::uint8_t>(value & 0x7fU); value >>= 7U; if (value != 0U) byte = static_cast<std::uint8_t>(byte | 0x80U); encoded.push_back(byte); } while (value != 0U);
        encoded.insert(encoded.end(), replacement.first.begin(), replacement.first.end()); encoded.push_back(0U);
        encoded_replacements.emplace(string_idx, std::move(encoded));
    }

    const auto map_end = static_cast<std::uint64_t>(header_.map_off) + 4U +
                         static_cast<std::uint64_t>(map_.size()) * 12U;
    if (map_end != bytes_.size()) {
        throw std::runtime_error("DEX map list is not the final section; rebuilding strings requires full relocation");
    }

    std::vector<std::uint8_t> result(bytes_.begin(), bytes_.begin() + header_.map_off);
    for (const auto& item : map_) {
        if (item.type != 0x2002U) continue;
        std::size_t old_string_end = item.offset;
        for (std::uint32_t i = 0; i < item.size; ++i) {
            const auto old_string = ReadString(bytes_, static_cast<std::uint32_t>(old_string_end));
            old_string_end += old_string.encoded_size;
        }
        std::fill(result.begin() + item.offset, result.begin() + old_string_end, 0U);
    }
    const auto new_string_data_off = static_cast<std::uint32_t>(result.size());
    for (std::uint32_t string_idx = 0; string_idx < strings_.size(); ++string_idx) {
        const auto new_offset = static_cast<std::uint32_t>(result.size());
        PatchU32(result, static_cast<std::size_t>(header_.string_ids_off) + string_idx * 4U,
                 new_offset);
        const auto replacement = encoded_replacements.find(string_idx);
        if (replacement != encoded_replacements.end()) {
            result.insert(result.end(), replacement->second.begin(), replacement->second.end());
        } else {
            const auto& original = strings_[string_idx];
            result.insert(result.end(), bytes_.begin() + original.data_offset,
                          bytes_.begin() + original.data_offset + original.encoded_size);
        }
    }
    while ((result.size() & 3U) != 0U) result.push_back(0U);
    const auto new_map_off = static_cast<std::uint32_t>(result.size());
    auto map_copy = map_;
    for (auto& item : map_copy) {
        if (item.type == 0x1000U) item.offset = new_map_off;
        if (item.type == 0x2002U) {
            item.offset = new_string_data_off;
            item.size = static_cast<std::uint32_t>(strings_.size());
        }
    }
    std::sort(map_copy.begin(), map_copy.end(), [](const auto& left, const auto& right) {
        return std::tie(left.offset, left.type) < std::tie(right.offset, right.type);
    });
    AppendU32(result, static_cast<std::uint32_t>(map_copy.size()));
    for (const auto& item : map_copy) {
        AppendU16(result, item.type); AppendU16(result, 0U);
        AppendU32(result, item.size); AppendU32(result, item.offset);
    }
    PatchU32(result, 0x34U, new_map_off);
    PatchU32(result, 0x20U, static_cast<std::uint32_t>(result.size()));
    PatchU32(result, 0x68U, static_cast<std::uint32_t>(result.size()) - header_.data_off);
    if (version_ == 41U) PatchU32(result, 0x70U, static_cast<std::uint32_t>(result.size()));
    UpdateDexChecksums(result);
    return result;
}

std::vector<std::uint8_t> DexFile::StripDebugInfo() const {
    EnsureStandaloneWritable();
    std::vector<std::uint8_t> result = bytes_;
    const auto debug_item = std::find_if(
        map_.begin(), map_.end(),
        [](const DexMapItem& item) { return item.type == 0x2003U; });
    const auto has_debug_section = debug_item != map_.end();
    std::size_t debug_begin = 0U;
    std::size_t debug_end = 0U;
    if (has_debug_section) {
        debug_begin = debug_item->offset;
        debug_end = result.size();
        for (const auto& item : map_) {
            if (item.offset > debug_begin) {
                debug_end = std::min(debug_end,
                                     static_cast<std::size_t>(item.offset));
            }
        }
        if (debug_begin < header_.data_off || debug_begin >= debug_end ||
            debug_end > result.size()) {
            throw DexParseError(DexErrorCode::InvalidMap, debug_begin,
                                "invalid debug_info section range");
        }
    }
    bool saw_debug_reference = false;
    const auto write_zero = [&](std::uint32_t offset) {
        if (offset > result.size() || result.size() - offset < 12U) {
            throw DexParseError(DexErrorCode::OutOfBounds, offset,
                                "code_item debug_info_off exceeds file");
        }
        const auto debug_offset = ReadU32(result, offset + 8U);
        if (debug_offset != 0U) {
            saw_debug_reference = true;
            if (!has_debug_section || debug_offset < debug_begin ||
                debug_offset >= debug_end) {
                throw DexParseError(DexErrorCode::InvalidMap, debug_offset,
                                    "code_item debug_info_off is outside the mapped debug section");
            }
        }
        std::fill(result.begin() + offset + 8U, result.begin() + offset + 12U, 0U);
    };
    for (std::size_t class_index = 0; class_index < classes_.size(); ++class_index) {
        const auto& data = class_data(class_index);
        for (const auto& method : data.direct_methods) if (method.code_off != 0U) write_zero(method.code_off);
        for (const auto& method : data.virtual_methods) if (method.code_off != 0U) write_zero(method.code_off);
    }
    for (std::size_t class_index = 0; class_index < classes_.size(); ++class_index) {
        const auto class_offset = static_cast<std::size_t>(header_.class_defs_off) + class_index * 32U;
        std::fill(result.begin() + class_offset + 16U, result.begin() + class_offset + 20U, 0xffU);
    }
    if (has_debug_section) {
        // Erase the payload before dropping its map entry so line tables, local
        // names, parameter names, and file events cannot be recovered from an
        // otherwise-unreferenced byte range.
        std::fill(result.begin() + static_cast<std::ptrdiff_t>(debug_begin),
                  result.begin() + static_cast<std::ptrdiff_t>(debug_end), 0U);

        const auto map_bytes = 4U + map_.size() * 12U;
        const auto old_map_end = static_cast<std::size_t>(header_.map_off) +
                                 map_bytes;
        if (old_map_end != result.size()) {
            throw DexParseError(
                DexErrorCode::InvalidMap, header_.map_off,
                "debug stripping requires the DEX map list to be final");
        }
        if (header_.map_off > result.size() ||
            result.size() - header_.map_off < map_bytes) {
            throw DexParseError(DexErrorCode::InvalidMap, header_.map_off,
                                "map list exceeds file while stripping debug info");
        }
        const auto remaining_count = map_.size() - 1U;
        if (remaining_count > std::numeric_limits<std::uint32_t>::max()) {
            throw DexParseError(DexErrorCode::IntegerOverflow, header_.map_off,
                                "map item count exceeds DEX address space");
        }
        WriteU32(result, header_.map_off,
                 static_cast<std::uint32_t>(remaining_count));
        auto cursor = static_cast<std::size_t>(header_.map_off) + 4U;
        for (const auto& item : map_) {
            if (item.type == 0x2003U) continue;
            WriteU16(result, cursor, item.type);
            WriteU16(result, cursor + 2U, 0U);
            WriteU32(result, cursor + 4U, item.size);
            WriteU32(result, cursor + 8U, item.offset);
            cursor += 12U;
        }
        std::fill(result.begin() + static_cast<std::ptrdiff_t>(cursor),
                  result.begin() + static_cast<std::ptrdiff_t>(
                      static_cast<std::size_t>(header_.map_off) + map_bytes),
                  0U);
        result.resize(result.size() - 12U);
        PatchU32(result, 0x20U, static_cast<std::uint32_t>(result.size()));
        PatchU32(result, 0x68U,
                 static_cast<std::uint32_t>(result.size()) - header_.data_off);
        if (version_ == 41U) {
            PatchU32(result, 0x70U, static_cast<std::uint32_t>(result.size()));
        }
    } else if (saw_debug_reference) {
        throw DexParseError(DexErrorCode::InvalidMap, header_.map_off,
                            "DEX references debug info without a map entry");
    }
    UpdateDexChecksums(result);
    return result;
}

std::vector<std::uint8_t> DexFile::RewriteBogusBranches(
    double intensity, std::uint64_t seed, std::size_t& changed) const {
    EnsureStandaloneWritable();
    if (!std::isfinite(intensity) || intensity < 0.0 || intensity > 1.0) {
        throw std::invalid_argument("bogus branch intensity must be in [0,1]");
    }
    std::vector<std::uint8_t> result = bytes_;
    std::uint64_t state = seed;
    for (std::size_t class_index = 0; class_index < classes_.size(); ++class_index) {
        const auto& data = class_data(class_index);
        const auto rewrite_methods = [&](const auto& methods) {
            for (const auto& method : methods) {
                if (method.code_off == 0U) continue;
                const auto code = DecodeCodeItem(*this, method.code_off);
                if (code.registers_size == 0U) continue;
                for (std::size_t i = 0; i + 1U < code.instructions.size(); ++i) {
                    const auto& first = code.instructions[i];
                    const auto& second = code.instructions[i + 1U];
                    if (first.opcode != 0x00U || first.width != 1U || second.opcode != 0x00U || second.width != 1U) continue;
                    state ^= state << 7U; state ^= state >> 9U;
                    if ((state % 1000U) >= static_cast<std::uint64_t>(intensity * 1000.0)) continue;
                    const auto instruction_offset = static_cast<std::size_t>(method.code_off) + 16U + first.offset * 2U;
                    if (instruction_offset + 4U > result.size()) throw DexParseError(DexErrorCode::OutOfBounds, instruction_offset, "bogus branch exceeds code item");
                    WriteU16(result, instruction_offset, 0x0032U); // if-eq v0, v0, +2
                    WriteU16(result, instruction_offset + 2U, 0x0002U);
                    ++changed;
                    ++i;
                }
            }
        };
        rewrite_methods(data.direct_methods); rewrite_methods(data.virtual_methods);
    }
    UpdateDexChecksums(result);
    return result;
}

std::vector<std::uint8_t> DexFile::RewriteClassDataIndices(
    const std::vector<std::uint32_t>& field_remap,
    const std::vector<std::uint32_t>& method_remap) const {
    EnsureStandaloneWritable();
    if (field_remap.size() != fields_.size() || method_remap.size() != methods_.size()) throw std::invalid_argument("class_data remap size mismatch");
    std::vector<std::uint8_t> result = bytes_;
    auto write_uleb = [](std::vector<std::uint8_t>& out, std::uint32_t value) {
        do { auto byte = static_cast<std::uint8_t>(value & 0x7fU); value >>= 7U; if (value != 0U) byte = static_cast<std::uint8_t>(byte | 0x80U); out.push_back(byte); } while (value != 0U);
    };
    auto read_uleb = [&](std::size_t& cursor) { const auto value = ReadUlebChecked(bytes_, cursor); cursor += value.size; return value.value; };
    auto encode_fields = [&](const std::vector<DexEncodedField>& values) {
        std::vector<DexEncodedField> sorted = values;
        for (auto& value : sorted) value.field_idx = field_remap[value.field_idx];
        std::sort(sorted.begin(), sorted.end(), [](const auto& left, const auto& right) { return left.field_idx < right.field_idx; });
        std::vector<std::uint8_t> out; std::uint32_t previous = 0U;
        for (const auto& value : sorted) { write_uleb(out, value.field_idx - previous); write_uleb(out, value.access_flags); previous = value.field_idx; }
        return out;
    };
    auto encode_methods = [&](const std::vector<DexEncodedMethod>& values) {
        std::vector<DexEncodedMethod> sorted = values;
        for (auto& value : sorted) value.method_idx = method_remap[value.method_idx];
        std::sort(sorted.begin(), sorted.end(), [](const auto& left, const auto& right) { return left.method_idx < right.method_idx; });
        std::vector<std::uint8_t> out; std::uint32_t previous = 0U;
        for (const auto& value : sorted) { write_uleb(out, value.method_idx - previous); write_uleb(out, value.access_flags); write_uleb(out, value.code_off); previous = value.method_idx; }
        return out;
    };
    for (std::size_t class_index = 0; class_index < classes_.size(); ++class_index) {
        const auto source_offset = classes_[class_index].class_data_off;
        if (source_offset == 0U) continue;
        std::size_t cursor = source_offset;
        const auto static_count = read_uleb(cursor); const auto instance_count = read_uleb(cursor); const auto direct_count = read_uleb(cursor); const auto virtual_count = read_uleb(cursor);
        const auto& data = class_data(class_index);
        for (std::uint32_t i = 0; i < static_count; ++i) { (void)read_uleb(cursor); (void)read_uleb(cursor); }
        for (std::uint32_t i = 0; i < instance_count; ++i) { (void)read_uleb(cursor); (void)read_uleb(cursor); }
        for (std::uint32_t i = 0; i < direct_count; ++i) { (void)read_uleb(cursor); (void)read_uleb(cursor); (void)read_uleb(cursor); }
        for (std::uint32_t i = 0; i < virtual_count; ++i) { (void)read_uleb(cursor); (void)read_uleb(cursor); (void)read_uleb(cursor); }
        std::vector<std::uint8_t> encoded; write_uleb(encoded, static_count); write_uleb(encoded, instance_count); write_uleb(encoded, direct_count); write_uleb(encoded, virtual_count);
        const auto static_encoded = encode_fields(data.static_fields); const auto instance_encoded = encode_fields(data.instance_fields); const auto direct_encoded = encode_methods(data.direct_methods); const auto virtual_encoded = encode_methods(data.virtual_methods);
        encoded.insert(encoded.end(), static_encoded.begin(), static_encoded.end()); encoded.insert(encoded.end(), instance_encoded.begin(), instance_encoded.end()); encoded.insert(encoded.end(), direct_encoded.begin(), direct_encoded.end()); encoded.insert(encoded.end(), virtual_encoded.begin(), virtual_encoded.end());
        if (encoded.size() != cursor - source_offset) throw std::runtime_error("class_data remap changes encoded size; full data relocation required");
        std::copy(encoded.begin(), encoded.end(), result.begin() + source_offset);
    }
    UpdateDexChecksums(result);
    return result;
}

std::vector<std::uint8_t> DexFile::RewriteMemberIndicesRelocated(
    const std::vector<std::uint32_t>& field_remap,
    const std::vector<std::uint32_t>& method_remap) const {
    EnsureStandaloneWritable();
    if (field_remap.size() != fields_.size() || method_remap.size() != methods_.size()) throw std::invalid_argument("member remap size mismatch");
    auto inverse = [](const auto& values) {
        std::vector<std::uint32_t> result(values.size(), 0U); std::vector<bool> seen(values.size(), false);
        for (std::size_t old = 0; old < values.size(); ++old) { if (values[old] >= values.size() || seen[values[old]]) throw std::invalid_argument("member remap is not a permutation"); seen[values[old]] = true; result[values[old]] = static_cast<std::uint32_t>(old); }
        return result;
    };
    const auto old_field = inverse(field_remap); const auto old_method = inverse(method_remap);
    auto result = bytes_;
    auto read_uleb_at = [&](std::size_t& cursor) {
        const auto value = ReadUlebChecked(bytes_, cursor); cursor += value.size; return value.value;
    };
    auto patch_encoded_index = [&](std::size_t& cursor, std::uint8_t width, const std::vector<std::uint32_t>& remap) {
        if (width == 0U || width > 4U || cursor > bytes_.size() || bytes_.size() - cursor < width) throw DexParseError(DexErrorCode::Truncated, cursor, "encoded annotation index truncated");
        std::uint32_t old_value = 0U; for (std::uint8_t i = 0; i < width; ++i) old_value |= static_cast<std::uint32_t>(bytes_[cursor + i]) << (i * 8U);
        if (old_value >= remap.size()) throw DexParseError(DexErrorCode::InvalidIndex, cursor, "encoded annotation index invalid");
        const auto new_value = remap[old_value]; if (width < 4U && new_value >= (1U << (width * 8U))) throw std::runtime_error("encoded annotation index grew beyond its original width");
        for (std::uint8_t i = 0; i < width; ++i) result[cursor + i] = static_cast<std::uint8_t>(new_value >> (i * 8U));
        cursor += width;
    };
    auto consume_encoded_index = [&](std::size_t& cursor, std::uint8_t width,
                                     std::size_t count, std::string_view label) {
        if (width == 0U || width > 4U || cursor > bytes_.size() ||
            bytes_.size() - cursor < width) {
            throw DexParseError(DexErrorCode::Truncated, cursor,
                                std::string(label) + " encoded index truncated");
        }
        std::uint32_t value = 0U;
        for (std::uint8_t i = 0; i < width; ++i) {
            value |= static_cast<std::uint32_t>(bytes_[cursor + i]) << (i * 8U);
        }
        if (value >= count) {
            throw DexParseError(DexErrorCode::InvalidIndex, cursor,
                                std::string(label) + " encoded index invalid");
        }
        cursor += width;
    };
    std::function<void(std::size_t&)> encoded_value;
    encoded_value = [&](std::size_t& cursor) {
        if (cursor >= bytes_.size()) throw DexParseError(DexErrorCode::Truncated, cursor, "encoded_value header truncated");
        const auto header = bytes_[cursor++]; const auto value_type = header & 0x1fU; const auto width = static_cast<std::uint8_t>((header >> 5U) + 1U);
        switch (value_type) {
            case 0x15U: consume_encoded_index(cursor, width, protos_.size(), "method_type"); break;
            case 0x16U: consume_encoded_index(cursor, width, method_handles_.size(), "method_handle"); break;
            case 0x17U: consume_encoded_index(cursor, width, strings_.size(), "string"); break;
            case 0x18U: consume_encoded_index(cursor, width, types_.size(), "type"); break;
            case 0x19U: patch_encoded_index(cursor, width, field_remap); break;
            case 0x1aU: patch_encoded_index(cursor, width, method_remap); break;
            case 0x1bU: patch_encoded_index(cursor, width, field_remap); break;
            case 0x1cU: { const auto count = read_uleb_at(cursor); for (std::uint32_t i = 0; i < count; ++i) encoded_value(cursor); break; }
            case 0x1dU: { (void)read_uleb_at(cursor); const auto count = read_uleb_at(cursor); for (std::uint32_t i = 0; i < count; ++i) { (void)read_uleb_at(cursor); encoded_value(cursor); } break; }
            default:
                if (value_type == 0x1eU || value_type == 0x1fU) break;
                if (cursor > bytes_.size() || bytes_.size() - cursor < width) throw DexParseError(DexErrorCode::Truncated, cursor, "encoded_value payload truncated");
                cursor += width;
                break;
        }
    };
    for (const auto& item : map_) {
        if (item.type == 0x2004U) {
            std::size_t cursor = item.offset;
            for (std::uint32_t annotation = 0; annotation < item.size; ++annotation) {
                if (cursor >= bytes_.size()) throw DexParseError(DexErrorCode::Truncated, cursor, "annotation item truncated");
                ++cursor; (void)read_uleb_at(cursor); const auto count = read_uleb_at(cursor);
                for (std::uint32_t i = 0; i < count; ++i) { (void)read_uleb_at(cursor); encoded_value(cursor); }
            }
        } else if (item.type == 0x2005U) {
            std::size_t cursor = item.offset;
            for (std::uint32_t array = 0; array < item.size; ++array) { const auto count = read_uleb_at(cursor); for (std::uint32_t i = 0; i < count; ++i) encoded_value(cursor); }
        } else if (item.type == 0x2006U) {
            std::size_t cursor = item.offset;
            for (std::uint32_t directory = 0; directory < item.size; ++directory) {
                const auto directory_offset = cursor;
                const auto class_annotations = ReadU32(bytes_, cursor); cursor += 4U;
                const auto fields_size = ReadU32(bytes_, cursor); cursor += 4U;
                const auto methods_size = ReadU32(bytes_, cursor); cursor += 4U;
                const auto parameters_size = ReadU32(bytes_, cursor); cursor += 4U;
                if (fields_size > fields_.size()) throw std::runtime_error("annotations_directory fields_size exceeds field table");
                if (methods_size > methods_.size()) throw std::runtime_error("annotations_directory methods_size exceeds method table");
                if (parameters_size > methods_.size()) throw std::runtime_error("annotations_directory parameters_size exceeds method table");
                const auto entries = static_cast<std::uint64_t>(fields_size) + methods_size + parameters_size;
                if (cursor > bytes_.size() || entries > (bytes_.size() - cursor) / 8U) {
                    throw DexParseError(DexErrorCode::Truncated, cursor,
                                        "annotations_directory entries truncated");
                }
                const auto rewrite_entries = [&](std::uint32_t count,
                                                 const std::vector<std::uint32_t>& remap,
                                                 std::string_view label) {
                    const auto entries_offset = cursor;
                    std::vector<std::pair<std::uint32_t, std::uint32_t>> rewritten;
                    rewritten.reserve(count);
                    for (std::uint32_t i = 0; i < count; ++i) {
                        const auto old = ReadU32(bytes_, cursor);
                        const auto annotations_off = ReadU32(bytes_, cursor + 4U);
                        if (old >= remap.size()) {
                            throw std::runtime_error("annotations_directory " +
                                                     std::string(label) + " index out of range at " +
                                                     std::to_string(directory_offset));
                        }
                        rewritten.emplace_back(remap[old], annotations_off);
                        cursor += 8U;
                    }
                    std::sort(rewritten.begin(), rewritten.end());
                    for (std::size_t i = 1; i < rewritten.size(); ++i) {
                        if (rewritten[i - 1U].first == rewritten[i].first) {
                            throw std::runtime_error("annotations_directory has duplicate remapped " +
                                                     std::string(label) + " index");
                        }
                    }
                    for (std::size_t i = 0; i < rewritten.size(); ++i) {
                        PatchU32(result, entries_offset + i * 8U, rewritten[i].first);
                        PatchU32(result, entries_offset + i * 8U + 4U, rewritten[i].second);
                    }
                };
                rewrite_entries(fields_size, field_remap, "field");
                rewrite_entries(methods_size, method_remap, "method");
                rewrite_entries(parameters_size, method_remap, "parameter method");
                (void)class_annotations;
            }
        }
    }
    for (const auto& handle : method_handles_) {
        const auto& remap = handle.handle_type <= 3U ? field_remap : method_remap;
        if (handle.member_idx >= remap.size() || remap[handle.member_idx] > 0xffffU) {
            throw DexParseError(DexErrorCode::InvalidIndex, handle.item_offset + 4U,
                                "method_handle remapped member index is invalid");
        }
        PatchU16(result, handle.item_offset + 4U,
                 static_cast<std::uint16_t>(remap[handle.member_idx]));
    }
    for (std::uint32_t new_index = 0; new_index < old_field.size(); ++new_index) {
        const auto& value = fields_[old_field[new_index]]; const auto offset = static_cast<std::size_t>(header_.field_ids_off) + new_index * 8U;
        WriteU16(result, offset, value.class_idx); WriteU16(result, offset + 2U, value.type_idx); PatchU32(result, offset + 4U, value.name_idx);
    }
    for (std::uint32_t new_index = 0; new_index < old_method.size(); ++new_index) {
        const auto& value = methods_[old_method[new_index]]; const auto offset = static_cast<std::size_t>(header_.method_ids_off) + new_index * 8U;
        WriteU16(result, offset, value.class_idx); WriteU16(result, offset + 2U, value.proto_idx); PatchU32(result, offset + 4U, value.name_idx);
    }
    for (std::size_t class_index = 0; class_index < classes_.size(); ++class_index) {
        const auto& data = class_data(class_index);
        const auto check_supported = [&](const auto& methods) { for (const auto& method : methods) if (method.code_off != 0U) { /* code offsets remain stable */ } };
        check_supported(data.direct_methods); check_supported(data.virtual_methods);
        const auto patch_code = [&](const auto& methods) {
            for (const auto& method : methods) {
                if (method.code_off == 0U) continue;
                const auto code = DecodeCodeItem(*this, method.code_off);
                for (const auto& instruction : code.instructions) {
                    const auto opcode = instruction.opcode;
                    if ((opcode >= 0x52U && opcode <= 0x6dU) && instruction.code_units.size() >= 2U) {
                        const auto old_index = instruction.code_units[1U]; if (old_index >= field_remap.size()) throw DexParseError(DexErrorCode::InvalidIndex, method.code_off, "field operand out of range");
                        PatchU16(result, static_cast<std::size_t>(method.code_off) + 16U + (instruction.offset + 1U) * 2U, static_cast<std::uint16_t>(field_remap[old_index]));
                    } else if (((opcode >= 0x6eU && opcode <= 0x72U) || (opcode >= 0x74U && opcode <= 0x78U)) && instruction.code_units.size() >= 2U) {
                        const auto old_index = instruction.code_units[1U]; if (old_index >= method_remap.size()) throw DexParseError(DexErrorCode::InvalidIndex, method.code_off, "method operand out of range");
                        PatchU16(result, static_cast<std::size_t>(method.code_off) + 16U + (instruction.offset + 1U) * 2U, static_cast<std::uint16_t>(method_remap[old_index]));
                    } else if ((opcode == 0xfaU || opcode == 0xfbU) && instruction.code_units.size() >= 4U) {
                        const auto old_index = instruction.code_units[1U]; if (old_index >= method_remap.size()) throw DexParseError(DexErrorCode::InvalidIndex, method.code_off, "polymorphic method operand out of range");
                        PatchU16(result, static_cast<std::size_t>(method.code_off) + 16U + (instruction.offset + 1U) * 2U, static_cast<std::uint16_t>(method_remap[old_index]));
                    }
                }
            }
        };
        patch_code(data.direct_methods); patch_code(data.virtual_methods);
    }
    std::vector<std::vector<std::uint8_t>> encoded_classes(classes_.size());
    auto write_uleb = [](std::vector<std::uint8_t>& out, std::uint32_t value) { do { auto byte = static_cast<std::uint8_t>(value & 0x7fU); value >>= 7U; if (value != 0U) byte = static_cast<std::uint8_t>(byte | 0x80U); out.push_back(byte); } while (value != 0U); };
    auto encode_fields = [&](const auto& values) { std::vector<DexEncodedField> sorted = values; for (auto& value : sorted) value.field_idx = field_remap[value.field_idx]; std::sort(sorted.begin(), sorted.end(), [](const auto& left, const auto& right) { return left.field_idx < right.field_idx; }); std::vector<std::uint8_t> out; std::uint32_t previous = 0U; for (const auto& value : sorted) { write_uleb(out, value.field_idx - previous); write_uleb(out, value.access_flags); previous = value.field_idx; } return out; };
    auto encode_methods = [&](const auto& values) { std::vector<DexEncodedMethod> sorted = values; for (auto& value : sorted) value.method_idx = method_remap[value.method_idx]; std::sort(sorted.begin(), sorted.end(), [](const auto& left, const auto& right) { return left.method_idx < right.method_idx; }); std::vector<std::uint8_t> out; std::uint32_t previous = 0U; for (const auto& value : sorted) { write_uleb(out, value.method_idx - previous); write_uleb(out, value.access_flags); write_uleb(out, value.code_off); previous = value.method_idx; } return out; };
    std::uint32_t relocated_class_data_count = 0U;
    for (std::size_t class_index = 0; class_index < class_data_.size(); ++class_index) {
        if (classes_[class_index].class_data_off == 0U) continue;
        const auto& data = class_data_[class_index];
        auto& out = encoded_classes[class_index];
        write_uleb(out, static_cast<std::uint32_t>(data.static_fields.size())); write_uleb(out, static_cast<std::uint32_t>(data.instance_fields.size())); write_uleb(out, static_cast<std::uint32_t>(data.direct_methods.size())); write_uleb(out, static_cast<std::uint32_t>(data.virtual_methods.size())); const auto a = encode_fields(data.static_fields); const auto b = encode_fields(data.instance_fields); const auto c = encode_methods(data.direct_methods); const auto d = encode_methods(data.virtual_methods); out.insert(out.end(), a.begin(), a.end()); out.insert(out.end(), b.begin(), b.end()); out.insert(out.end(), c.begin(), c.end()); out.insert(out.end(), d.begin(), d.end());
        ++relocated_class_data_count;
    }
    for (const auto& definition : classes_) {
        if (definition.class_data_off == 0U) continue;
        std::size_t old_cursor = definition.class_data_off;
        const auto static_count = read_uleb_at(old_cursor);
        const auto instance_count = read_uleb_at(old_cursor);
        const auto direct_count = read_uleb_at(old_cursor);
        const auto virtual_count = read_uleb_at(old_cursor);
        for (std::uint32_t i = 0; i < static_count; ++i) { (void)read_uleb_at(old_cursor); (void)read_uleb_at(old_cursor); }
        for (std::uint32_t i = 0; i < instance_count; ++i) { (void)read_uleb_at(old_cursor); (void)read_uleb_at(old_cursor); }
        for (std::uint32_t i = 0; i < direct_count; ++i) { (void)read_uleb_at(old_cursor); (void)read_uleb_at(old_cursor); (void)read_uleb_at(old_cursor); }
        for (std::uint32_t i = 0; i < virtual_count; ++i) { (void)read_uleb_at(old_cursor); (void)read_uleb_at(old_cursor); (void)read_uleb_at(old_cursor); }
        std::fill(result.begin() + definition.class_data_off, result.begin() + old_cursor, 0U);
    }
    const auto old_map_end = static_cast<std::size_t>(header_.map_off) + 4U + map_.size() * 12U;
    if (old_map_end > result.size()) {
        throw DexParseError(DexErrorCode::InvalidMap, header_.map_off,
                            "old map exceeds DEX during member relocation");
    }
    std::fill(result.begin() + header_.map_off, result.begin() + old_map_end, 0U);
    auto cursor = result.size(); while ((cursor & 3U) != 0U) { result.push_back(0U); ++cursor; }
    const auto first_class_data = static_cast<std::uint32_t>(result.size());
    for (std::size_t class_index = 0; class_index < encoded_classes.size(); ++class_index) { if (classes_[class_index].class_data_off == 0U) continue; PatchU32(result, header_.class_defs_off + class_index * 32U + 24U, static_cast<std::uint32_t>(result.size())); result.insert(result.end(), encoded_classes[class_index].begin(), encoded_classes[class_index].end()); }
    while ((result.size() & 3U) != 0U) result.push_back(0U);
    const auto new_map_offset = static_cast<std::uint32_t>(result.size());
    std::vector<DexMapItem> map_copy = map_;
    bool found_class_data = false;
    for (auto& item : map_copy) if (item.type == 0x2000U) { item.offset = first_class_data; item.size = relocated_class_data_count; found_class_data = true; }
    if (!found_class_data && relocated_class_data_count != 0U) map_copy.push_back({0x2000U, relocated_class_data_count, first_class_data});
    for (auto& item : map_copy) if (item.type == 0x1000U) item.offset = new_map_offset;
    if (std::none_of(map_copy.begin(), map_copy.end(), [](const auto& item) { return item.type == 0x1000U; })) map_copy.push_back({0x1000U, 1U, new_map_offset});
    std::sort(map_copy.begin(), map_copy.end(), [](const auto& left, const auto& right) {
        return std::tie(left.offset, left.type) < std::tie(right.offset, right.type);
    });
    AppendU32(result, static_cast<std::uint32_t>(map_copy.size()));
    for (const auto& item : map_copy) { AppendU16(result, item.type); AppendU16(result, 0U); AppendU32(result, item.size); AppendU32(result, item.offset); }
    PatchU32(result, 0x34U, new_map_offset); PatchU32(result, 0x20U, static_cast<std::uint32_t>(result.size())); PatchU32(result, 0x68U, static_cast<std::uint32_t>(result.size()) - header_.data_off); if (version_ == 41U) PatchU32(result, 0x70U, static_cast<std::uint32_t>(result.size())); UpdateDexChecksums(result); return result;
}

} // namespace birch::dex
