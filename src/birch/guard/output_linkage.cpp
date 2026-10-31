#include "output_linkage.h"

#include "birch/io/apk_entries.h"
#include "birch/io/file.h"

namespace birch::guard::detail {
namespace {

std::vector<dex::DexFile> ParseDexFiles(const ZipArchive& archive) {
    std::vector<dex::DexFile> files;
    for (const auto& entry : archive.entries()) {
        if (io::IsDexEntryName(entry.name)) files.push_back(dex::DexFile::Parse(entry.data));
    }
    return files;
}

std::vector<std::reference_wrapper<const dex::DexFile>> References(
    const std::vector<dex::DexFile>& files) {
    return {files.begin(), files.end()};
}

} // namespace

void OutputLinkage::VerifyDex(const std::filesystem::path& input,
    const dex::DexFile& output, const dex::DexFile* framework,
    const dex::LinkageRenames& renames) {
    const auto source = dex::DexFile::Parse(io::ReadBinaryFile(input));
    const auto baseline = dex::LinkageVerifier::Analyze({source}, framework, renames);
    dex::LinkageVerifier::VerifyNoNewFailures(baseline, {output}, framework);
}

void OutputLinkage::VerifyApk(const std::filesystem::path& input,
    const ZipArchive& output, const dex::DexFile* framework,
    const dex::LinkageRenames& renames) {
    const auto source_files = ParseDexFiles(ZipArchive::Read(input));
    const auto baseline = dex::LinkageVerifier::Analyze(References(source_files), framework, renames);
    const auto output_files = ParseDexFiles(output);
    dex::LinkageVerifier::VerifyNoNewFailures(baseline, References(output_files), framework);
}

} // namespace birch::guard::detail
