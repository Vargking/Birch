#include "birch/guard/zip.h"

#include <cassert>
#include <stdexcept>

namespace {
std::uint32_t Read32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    std::uint32_t value{};
    for (unsigned i = 0U; i < 4U; ++i) value |= std::uint32_t{bytes.at(offset + i)} << (8U * i);
    return value;
}
void Put16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    for (unsigned i = 0U; i < 2U; ++i) bytes.at(offset + i) = static_cast<std::uint8_t>(value >> (8U * i));
}
void Put32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned i = 0U; i < 4U; ++i) bytes.at(offset + i) = static_cast<std::uint8_t>(value >> (8U * i));
}
template<class Action> void ExpectRejected(Action action) {
    bool rejected = false;
    try { action(); } catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
}
void CheckMalformedArchives() {
    birch::guard::ZipArchive source;
    source.Add({"x", {'a', 'b', 'c'}, birch::guard::ZipCompression::Stored});
    const auto good = source.Write();
    const auto eocd = good.size() - 22U;
    const auto central = Read32(good, eocd + 16U);
    const auto reject = [](const auto& bytes) {
        ExpectRejected([&] { (void)birch::guard::ZipArchive::Read(bytes); });
    };
    auto bad = good;
    bad[30U] = 'y'; // local and central names must agree
    reject(bad);
    bad = good;
    Put16(bad, 8U, 8U); // compression disagreement
    reject(bad);
    bad = good;
    Put32(bad, 22U, 4U); // matching but impossible stored-entry sizes
    Put32(bad, central + 24U, 4U);
    reject(bad);
    bad = good;
    Put32(bad, 14U, 0U); // local CRC is authoritative unless bit 3 is set
    reject(bad);
    bad = good;
    Put16(bad, eocd + 8U, 2U);
    reject(bad);
    bad = good;
    Put32(bad, eocd + 12U, 46U); // central size excludes its name
    reject(bad);
    bad = good;
    Put32(bad, central + 20U, 0xffffffffU); // unsupported ZIP64 sentinel
    reject(bad);
    bad = good;
    Put32(bad, central + 42U, central); // local entry points into central directory
    reject(bad);

    // Bit 3 permits zero local CRC/sizes and a post-data descriptor. The
    // central record remains authoritative; do not reject valid streamed ZIPs.
    auto streamed = good;
    Put16(streamed, 6U, 8U);
    Put32(streamed, 14U, 0U);
    Put32(streamed, 18U, 0U);
    Put32(streamed, 22U, 0U);
    std::vector<std::uint8_t> descriptor(16U);
    Put32(descriptor, 0U, 0x08074b50U);
    Put32(descriptor, 4U, Read32(good, central + 16U));
    Put32(descriptor, 8U, 3U);
    Put32(descriptor, 12U, 3U);
    streamed.insert(streamed.begin() + central, descriptor.begin(), descriptor.end());
    Put16(streamed, central + 16U + 8U, 8U);
    Put32(streamed, eocd + 16U + 16U, central + 16U);
    assert(birch::guard::ZipArchive::Read(streamed).Find("x")->data.size() == 3U);

    // A signature-looking sequence in a legal comment must not hide EOCD.
    auto commented = good;
    Put16(commented, eocd + 20U, 22U);
    commented.resize(commented.size() + 22U, 0U);
    Put32(commented, eocd + 22U, 0x06054b50U);
    Put16(commented, eocd + 22U + 20U, 1U);
    assert(birch::guard::ZipArchive::Read(commented).Find("x") != nullptr);

    birch::guard::ZipArchive duplicate;
    duplicate.Add({"x", {'a'}});
    duplicate.Add({"y", {'b'}});
    bad = duplicate.Write();
    const auto duplicate_central = Read32(bad, bad.size() - 6U);
    const auto second_central = duplicate_central + 47U;
    const auto second_local = Read32(bad, second_central + 42U);
    bad.at(second_central + 46U) = 'x';
    bad.at(second_local + 30U) = 'x';
    reject(bad);
    duplicate.FindMutable("y")->name = "x";
    ExpectRejected([&] { (void)duplicate.Write(); });

    source.FindMutable("x")->alignment = 1U << 24U;
    ExpectRejected([&] { (void)source.Write(); });
}
} // namespace

int main() {
    CheckMalformedArchives();
    birch::guard::ZipArchive source;
    source.Add({"x", {'a', 'b', 'c'}, birch::guard::ZipCompression::Stored});
    source.Add({"compressed", std::vector<std::uint8_t>(1000U, 0x41U), birch::guard::ZipCompression::Deflate});
    source.Add({"empty", {}, birch::guard::ZipCompression::Deflate});
    source.Add({"lib/arm64-v8a/libtest.so", {1U, 2U, 3U},
                birch::guard::ZipCompression::Stored,
                0U, 0U, 0U, 0U, 16384U});
    const auto encoded = source.Write();
    auto archive = birch::guard::ZipArchive::Read(encoded);
    assert(archive.entries().size() == 4U);
    assert(archive.Find("x") != nullptr);
    assert(archive.Find("x")->data.size() == 3U);
    assert(archive.Find("compressed")->data.size() == 1000U);
    assert(archive.Find("empty") != nullptr);
    assert(archive.Find("empty")->data.empty());
    const auto* native = archive.Find("lib/arm64-v8a/libtest.so");
    assert(native != nullptr);
    assert((native->data_offset % 16384U) == 0U);
    archive.RenameEntry("x", "res/drawable/\xe2\x80\x8b\xd6\xab.png");
    const auto unicode_zip = birch::guard::ZipArchive::Read(archive.Write());
    const auto* unicode = unicode_zip.Find("res/drawable/\xe2\x80\x8b\xd6\xab.png");
    assert(unicode != nullptr && (unicode->flags & 0x0800U) != 0U);
    archive.RenameEntry("res/drawable/\xe2\x80\x8b\xd6\xab.png", "x");
    assert(archive.RemoveEntry("x"));
    assert(archive.Find("x") == nullptr);
    assert(!archive.RemoveEntry("x"));
    return 0;
}
