#include "birch/guard/zip.h"

#include <algorithm>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <zlib.h>

namespace birch::guard {
namespace {

constexpr std::uint32_t kLocalHeader = 0x04034b50U;
constexpr std::uint32_t kCentralHeader = 0x02014b50U;
constexpr std::uint32_t kEndOfCentral = 0x06054b50U;

std::uint16_t ReadU16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) throw std::runtime_error("truncated ZIP uint16");
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U;
}

std::uint32_t ReadU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) throw std::runtime_error("truncated ZIP uint32");
    return static_cast<std::uint32_t>(bytes[offset]) |
           static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
           static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U |
           static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
}

void WriteU16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void WriteU32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32U; shift += 8U) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::vector<std::uint8_t> InflateRaw(std::span<const std::uint8_t> compressed,
                                     std::size_t expected_size) {
    if (expected_size > std::numeric_limits<uInt>::max() ||
        compressed.size() > std::numeric_limits<uInt>::max()) {
        throw std::runtime_error("ZIP entry exceeds zlib limits");
    }
    // zlib still needs writable output space to consume an empty stream's
    // end marker. A null/zero-sized output buffer returns Z_BUF_ERROR.
    std::vector<std::uint8_t> output(std::max<std::size_t>(expected_size, 1U));
    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(compressed.data());
    stream.avail_in = static_cast<uInt>(compressed.size());
    stream.next_out = output.data();
    stream.avail_out = static_cast<uInt>(output.size());
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) throw std::runtime_error("inflateInit2 failed");
    const auto status = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);
    if (status != Z_STREAM_END || stream.total_out != expected_size || stream.total_in != compressed.size()) {
        throw std::runtime_error("invalid deflate ZIP entry");
    }
    output.resize(expected_size);
    return output;
}

std::vector<std::uint8_t> DeflateRaw(std::span<const std::uint8_t> input) {
    if (input.size() > std::numeric_limits<uInt>::max()) throw std::runtime_error("ZIP entry too large");
    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(input.data());
    stream.avail_in = static_cast<uInt>(input.size());
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) throw std::runtime_error("deflateInit2 failed");
    std::vector<std::uint8_t> output(compressBound(static_cast<uLong>(input.size())));
    stream.next_out = output.data();
    stream.avail_out = static_cast<uInt>(output.size());
    const auto status = deflate(&stream, Z_FINISH);
    const auto size = stream.total_out;
    deflateEnd(&stream);
    if (status != Z_STREAM_END) throw std::runtime_error("deflate failed");
    output.resize(size);
    return output;
}

} // namespace

ZipArchive ZipArchive::Read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open APK/ZIP: " + path.string());
    const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
    return Read(bytes);
}

ZipArchive ZipArchive::Read(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 22U) throw std::runtime_error("ZIP is too small");
    std::size_t eocd = bytes.size() - 22U;
    const auto minimum = bytes.size() > (0xffffU + 22U) ? bytes.size() - (0xffffU + 22U) : 0U;
    while (true) {
        if (ReadU32(bytes, eocd) == kEndOfCentral &&
            eocd + 22U + ReadU16(bytes, eocd + 20U) == bytes.size()) break;
        if (eocd == minimum) throw std::runtime_error("ZIP EOCD not found");
        --eocd;
    }
    const auto disk = ReadU16(bytes, eocd + 4U);
    const auto central_disk = ReadU16(bytes, eocd + 6U);
    const auto disk_entry_count = ReadU16(bytes, eocd + 8U);
    const auto entry_count = ReadU16(bytes, eocd + 10U);
    const auto central_size = ReadU32(bytes, eocd + 12U);
    const auto central_offset = ReadU32(bytes, eocd + 16U);
    if (disk != 0U || central_disk != 0U || entry_count == 0xffffU ||
        central_size == 0xffffffffU || central_offset == 0xffffffffU) {
        throw std::runtime_error("ZIP64 or multi-disk archives are not supported");
    }
    if (disk_entry_count != entry_count) throw std::runtime_error("inconsistent ZIP entry counts");
    if (static_cast<std::uint64_t>(central_offset) + central_size > bytes.size() ||
        static_cast<std::uint64_t>(central_offset) + central_size > eocd) {
        throw std::runtime_error("ZIP central directory exceeds file");
    }
    ZipArchive result;
    std::size_t cursor = central_offset;
    const auto central_end = static_cast<std::uint64_t>(central_offset) + central_size;
    std::set<std::string, std::less<>> names;
    for (std::uint16_t i = 0; i < entry_count; ++i) {
        if (cursor > central_end || central_end - cursor < 46U) {
            throw std::runtime_error("truncated ZIP central directory");
        }
        if (ReadU32(bytes, cursor) != kCentralHeader) throw std::runtime_error("invalid ZIP central entry");
        const auto flags = ReadU16(bytes, cursor + 8U);
        const auto compression = ReadU16(bytes, cursor + 10U);
        const auto crc = ReadU32(bytes, cursor + 16U);
        const auto compressed_size = ReadU32(bytes, cursor + 20U);
        const auto uncompressed_size = ReadU32(bytes, cursor + 24U);
        const auto name_length = ReadU16(bytes, cursor + 28U);
        const auto extra_length = ReadU16(bytes, cursor + 30U);
        const auto comment_length = ReadU16(bytes, cursor + 32U);
        const auto local_offset = ReadU32(bytes, cursor + 42U);
        const auto local_cursor = static_cast<std::size_t>(local_offset);
        if (compressed_size == 0xffffffffU || uncompressed_size == 0xffffffffU ||
            local_offset == 0xffffffffU) throw std::runtime_error("ZIP64 entries are not supported");
        if (static_cast<std::uint64_t>(cursor) + 46U + name_length + extra_length + comment_length > central_end) {
            throw std::runtime_error("ZIP central entry exceeds directory");
        }
        // Bit 3 means that the local header may carry zero CRC/size fields
        // and a data descriptor follows the payload.  The central directory
        // already supplies the authoritative CRC and sizes, so the entry can
        // be read safely without scanning for the descriptor.  Keep rejecting
        // encryption and unsupported compression methods.
        if ((flags & 0x0001U) != 0U ||
            (compression != 0U && compression != 8U)) {
            throw std::runtime_error("encrypted/unsupported ZIP entry");
        }
        const std::string name(reinterpret_cast<const char*>(bytes.data() + cursor + 46U), name_length);
        if (name.empty() || name.find('\0') != std::string::npos || name.find("../") != std::string::npos || name.starts_with("/")) {
            throw std::runtime_error("unsafe ZIP entry name");
        }
        if (!names.insert(name).second) throw std::runtime_error("duplicate ZIP entry name: " + name);
        if (static_cast<std::uint64_t>(local_offset) + 30U > bytes.size() ||
            ReadU32(bytes, local_cursor) != kLocalHeader) throw std::runtime_error("invalid ZIP local entry");
        const auto local_name_length = ReadU16(bytes, local_cursor + 26U);
        const auto local_extra_length = ReadU16(bytes, local_cursor + 28U);
        const auto data_offset = static_cast<std::uint64_t>(local_offset) + 30U + local_name_length + local_extra_length;
        if (data_offset + compressed_size > central_offset) throw std::runtime_error("ZIP entry data exceeds local-file area");
        if (ReadU16(bytes, local_cursor + 6U) != flags ||
            ReadU16(bytes, local_cursor + 8U) != compression ||
            local_name_length != name_length ||
            !std::equal(name.begin(), name.end(),
                reinterpret_cast<const char*>(bytes.data() + local_cursor + 30U))) {
            throw std::runtime_error("ZIP local/central entry headers disagree");
        }
        if ((flags & 0x0008U) == 0U &&
            (ReadU32(bytes, local_cursor + 14U) != crc ||
             ReadU32(bytes, local_cursor + 18U) != compressed_size ||
             ReadU32(bytes, local_cursor + 22U) != uncompressed_size)) {
            throw std::runtime_error("ZIP local/central entry sizes or CRC disagree");
        }
        if (compression == 0U && compressed_size != uncompressed_size) {
            throw std::runtime_error("stored ZIP entry has inconsistent sizes");
        }
        std::vector<std::uint8_t> data;
        if (compression == 0U) {
            data.assign(bytes.begin() + data_offset, bytes.begin() + data_offset + compressed_size);
        } else {
            data = InflateRaw(bytes.subspan(static_cast<std::size_t>(data_offset), compressed_size), uncompressed_size);
        }
        if (crc32(0U, data.data(), static_cast<uInt>(data.size())) != crc) throw std::runtime_error("ZIP CRC mismatch");
        ZipEntry entry;
        entry.name = name; entry.data = std::move(data); entry.compression = static_cast<ZipCompression>(compression);
        entry.flags = flags; entry.mod_time = ReadU16(bytes, cursor + 12U); entry.mod_date = ReadU16(bytes, cursor + 14U);
        entry.external_attributes = ReadU32(bytes, cursor + 38U);
        entry.local_offset = local_offset;
        entry.data_offset = static_cast<std::uint32_t>(data_offset);
        result.entries_.push_back(std::move(entry));
        cursor += 46U + name_length + extra_length + comment_length;
    }
    if (cursor != central_end) throw std::runtime_error("ZIP central directory size/count mismatch");
    return result;
}

void ZipArchive::Add(ZipEntry entry) {
    if (entry.name.empty() || entry.name.find('\0') != std::string::npos ||
        entry.name.find("../") != std::string::npos || entry.name.starts_with('/')) {
        throw std::invalid_argument("unsafe ZIP entry name");
    }
    if (Find(entry.name) != nullptr) throw std::invalid_argument("duplicate ZIP entry: " + entry.name);
    entries_.push_back(std::move(entry));
}

void ZipArchive::RenameEntry(std::string_view old_name, std::string new_name) {
    auto found = std::find_if(entries_.begin(), entries_.end(), [&](const auto& entry) { return entry.name == old_name; });
    if (found == entries_.end()) throw std::out_of_range("ZIP entry not found: " + std::string(old_name));
    if (new_name.empty() || new_name.find('\0') != std::string::npos || new_name.find("../") != std::string::npos || new_name.starts_with('/')) {
        throw std::invalid_argument("unsafe ZIP entry name");
    }
    const auto duplicate = std::find_if(entries_.begin(), entries_.end(), [&](const auto& entry) {
        return &entry != &*found && entry.name == new_name;
    });
    if (duplicate != entries_.end()) throw std::invalid_argument("duplicate ZIP entry: " + new_name);
    found->name = std::move(new_name);
}

bool ZipArchive::RemoveEntry(std::string_view name) noexcept {
    const auto found = std::find_if(entries_.begin(), entries_.end(),
                                    [&](const auto& entry) { return entry.name == name; });
    if (found == entries_.end()) return false;
    entries_.erase(found);
    return true;
}

const ZipEntry* ZipArchive::Find(std::string_view name) const noexcept {
    const auto found = std::find_if(entries_.begin(), entries_.end(), [&](const auto& entry) { return entry.name == name; });
    return found == entries_.end() ? nullptr : &*found;
}

ZipEntry* ZipArchive::FindMutable(std::string_view name) noexcept {
    const auto found = std::find_if(entries_.begin(), entries_.end(), [&](const auto& entry) { return entry.name == name; });
    return found == entries_.end() ? nullptr : &*found;
}

std::vector<std::uint8_t> ZipArchive::Write() const {
    struct DirectoryEntry { std::uint32_t crc; std::uint32_t compressed; std::uint32_t uncompressed; std::uint32_t offset; std::vector<std::uint8_t> extra; };
    std::vector<DirectoryEntry> directory;
    std::vector<std::uint8_t> output;
    constexpr auto kZip32Limit = std::uint64_t{0xffffffffU};
    if (entries_.size() >= 0xffffU) throw std::runtime_error("ZIP has too many entries");
    const auto check_growth = [&](std::uint64_t amount) {
        if (output.size() >= kZip32Limit || amount >= kZip32Limit - output.size()) {
            throw std::runtime_error("ZIP32 archive size/offset limit exceeded");
        }
    };
    std::set<std::string, std::less<>> names;
    for (const auto& entry : entries_) {
        if (entry.name.empty() || entry.name.size() > 0xffffU || entry.data.size() >= kZip32Limit) throw std::runtime_error("ZIP entry is too large");
        if (entry.name.find('\0') != std::string::npos || entry.name.find("../") != std::string::npos ||
            entry.name.starts_with('/') || !names.insert(entry.name).second) {
            throw std::runtime_error("unsafe or duplicate ZIP entry name");
        }
        if (entry.compression != ZipCompression::Stored && entry.compression != ZipCompression::Deflate) {
            throw std::runtime_error("unsupported ZIP compression");
        }
        auto compressed = entry.compression == ZipCompression::Deflate ? DeflateRaw(entry.data) : entry.data;
        if (compressed.size() >= kZip32Limit) throw std::runtime_error("compressed ZIP entry is too large");
        check_growth(30U + entry.name.size() + compressed.size());
        const auto offset = static_cast<std::uint32_t>(output.size());
        std::vector<std::uint8_t> extra;
        if (entry.alignment > 1U) {
            const auto remainder = (output.size() + 30U + entry.name.size()) % entry.alignment;
            auto padding = remainder == 0U ? 0U : entry.alignment - remainder;
            if (padding != 0U && padding < 4U) padding += entry.alignment;
            if (padding > 0xffffU) throw std::runtime_error("ZIP alignment extra field is too large");
            check_growth(30U + entry.name.size() + padding + compressed.size());
            if (padding != 0U) { extra.resize(padding, 0U); extra[0] = 0U; extra[1] = 0U; extra[2] = static_cast<std::uint8_t>((padding - 4U) & 0xffU); extra[3] = static_cast<std::uint8_t>((padding - 4U) >> 8U); }
        }
        const auto utf8 = std::any_of(entry.name.begin(), entry.name.end(), [](unsigned char c) { return c >= 0x80U; });
        WriteU32(output, kLocalHeader); WriteU16(output, 20U); WriteU16(output, utf8 ? 0x0800U : 0U); WriteU16(output, static_cast<std::uint16_t>(entry.compression));
        WriteU16(output, entry.mod_time); WriteU16(output, entry.mod_date); WriteU32(output, crc32(0U, entry.data.data(), static_cast<uInt>(entry.data.size())));
        WriteU32(output, static_cast<std::uint32_t>(compressed.size())); WriteU32(output, static_cast<std::uint32_t>(entry.data.size()));
        WriteU16(output, static_cast<std::uint16_t>(entry.name.size())); WriteU16(output, static_cast<std::uint16_t>(extra.size()));
        output.insert(output.end(), entry.name.begin(), entry.name.end()); output.insert(output.end(), extra.begin(), extra.end()); output.insert(output.end(), compressed.begin(), compressed.end());
        directory.push_back({crc32(0U, entry.data.data(), static_cast<uInt>(entry.data.size())), static_cast<std::uint32_t>(compressed.size()), static_cast<std::uint32_t>(entry.data.size()), offset, std::move(extra)});
    }
    const auto central_offset = static_cast<std::uint32_t>(output.size());
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const auto& entry = entries_[i]; const auto& item = directory[i];
        check_growth(46U + entry.name.size() + item.extra.size());
        const auto utf8 = std::any_of(entry.name.begin(), entry.name.end(), [](unsigned char c) { return c >= 0x80U; });
        WriteU32(output, kCentralHeader); WriteU16(output, 20U); WriteU16(output, 20U); WriteU16(output, utf8 ? 0x0800U : 0U); WriteU16(output, static_cast<std::uint16_t>(entry.compression));
        WriteU16(output, entry.mod_time); WriteU16(output, entry.mod_date); WriteU32(output, item.crc); WriteU32(output, item.compressed); WriteU32(output, item.uncompressed);
        WriteU16(output, static_cast<std::uint16_t>(entry.name.size())); WriteU16(output, static_cast<std::uint16_t>(item.extra.size())); WriteU16(output, 0U); WriteU16(output, 0U); WriteU16(output, 0U); WriteU32(output, entry.external_attributes); WriteU32(output, item.offset);
        output.insert(output.end(), entry.name.begin(), entry.name.end()); output.insert(output.end(), item.extra.begin(), item.extra.end());
    }
    const auto central_size = static_cast<std::uint32_t>(output.size()) - central_offset;
    check_growth(22U);
    WriteU32(output, kEndOfCentral); WriteU16(output, 0U); WriteU16(output, 0U); WriteU16(output, static_cast<std::uint16_t>(entries_.size())); WriteU16(output, static_cast<std::uint16_t>(entries_.size()));
    WriteU32(output, central_size); WriteU32(output, central_offset); WriteU16(output, 0U);
    return output;
}

} // namespace birch::guard
