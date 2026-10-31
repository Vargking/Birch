#include "birch/guard/apk.h"
#include "birch/guard/arsc.h"
#include "birch/guard/axml.h"
#include "birch/io/apk_entries.h"

#include <stdexcept>

namespace birch::guard {
namespace {

bool IsDexMagic(std::span<const std::uint8_t> bytes) {
    return bytes.size() >= 8U && bytes[0] == 'd' && bytes[1] == 'e' && bytes[2] == 'x' && bytes[3] == '\n';
}

} // namespace

ApkInspection InspectApk(const ZipArchive& archive) {
    const auto dex_names = io::DexEntryNames(archive);
    if (dex_names.empty() || dex_names.front() != "classes.dex") {
        throw std::runtime_error("APK has no primary classes.dex");
    }
    ApkInspection result;
    bool has_manifest = false;
    bool has_resources = false;
    std::size_t dex_index = 0;
    for (const auto& entry : archive.entries()) {
        ApkEntryInfo info;
        info.name = entry.name;
        const auto bytes = std::span<const std::uint8_t>(entry.data.data(), entry.data.size());
        if (entry.name == "AndroidManifest.xml") {
            (void)AxmlDocument::Parse(bytes);
            info.kind = AndroidBinaryKind::Manifest;
            has_manifest = true;
            ++result.manifest_count;
        } else if (entry.name == "resources.arsc") {
            (void)ArscTable::Parse(bytes);
            info.kind = AndroidBinaryKind::Resources;
            has_resources = true;
            ++result.resources_count;
        } else if (io::IsDexEntryName(entry.name)) {
            if (!IsDexMagic(bytes)) throw std::runtime_error("DEX entry has invalid magic: " + entry.name);
            const auto dex = dex::DexFile::Parse(bytes);
            info.kind = AndroidBinaryKind::Dex;
            info.dex_index = dex_index++;
            info.dex_version = dex.version();
            info.dex_checksum_valid = dex.VerifyChecksums();
            if (!info.dex_checksum_valid) throw std::runtime_error("DEX checksum mismatch: " + entry.name);
            ++result.dex_count;
        }
        result.entries.push_back(std::move(info));
    }
    if (!has_manifest) throw std::runtime_error("APK has no AndroidManifest.xml");
    if (!has_resources) throw std::runtime_error("APK has no resources.arsc");
    return result;
}

} // namespace birch::guard
