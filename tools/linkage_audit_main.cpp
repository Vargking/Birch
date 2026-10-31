#include "birch/dex/linkage_verifier.h"
#include "birch/guard/zip.h"
#include "birch/io/apk_entries.h"
#include "birch/io/file.h"

#include <iostream>
#include <optional>

int main(int argc, char** argv) {
    const bool verbose = argc > 1 && std::string_view(argv[argc - 1]) == "--verbose";
    const auto positional = argc - (verbose ? 1 : 0);
    if (positional < 2 || positional > 3) {
        std::cerr << "usage: BirchLinkageAudit <input.apk|input.dex> [android.dex] [--verbose]\n";
        return 2;
    }
    try {
        std::vector<birch::dex::DexFile> files;
        const std::filesystem::path input(argv[1]);
        if (input.extension() == ".dex") {
            files.push_back(birch::dex::DexFile::Parse(birch::io::ReadBinaryFile(input)));
        } else {
            const auto archive = birch::guard::ZipArchive::Read(input);
            for (const auto& entry : archive.entries()) {
                if (birch::io::IsDexEntryName(entry.name)) {
                    files.push_back(birch::dex::DexFile::Parse(entry.data));
                }
            }
        }
        if (files.empty()) throw std::runtime_error("no DEX files found");
        std::optional<birch::dex::DexFile> framework;
        if (positional == 3) framework = birch::dex::DexFile::Parse(birch::io::ReadBinaryFile(argv[2]));
        const std::vector<std::reference_wrapper<const birch::dex::DexFile>> refs{files.begin(), files.end()};
        const auto report = birch::dex::LinkageVerifier::Analyze(refs, framework ? &*framework : nullptr);
        std::cout << "DEX files: " << files.size() << "\nResolved references: " << report.resolved.size()
                  << "\nUnresolved references (including unknown dependencies): " << report.unresolved.size()
                  << "\nUnresolved executable/signature references: " << report.runtime_unresolved.size()
                  << "\nDefinite linkage failures: " << report.failures.size() << '\n';
        for (const auto& failure : report.failures) std::cout << failure << '\n';
        if (verbose) for (const auto& unresolved : report.unresolved) {
            std::cout << (report.runtime_unresolved.contains(unresolved) ? "unresolved runtime " : "unresolved table-only ")
                      << unresolved << '\n';
        }
        return report.failures.empty() ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "BirchLinkageAudit: " << error.what() << '\n';
        return 1;
    }
}
