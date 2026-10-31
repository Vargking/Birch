#include "technique_report.h"
#include "technique_catalog.h"
#include "birch/io/file.h"
#include "birch/io/path.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <stdexcept>

namespace birch::guard::detail {
namespace {
std::string NormalPath(const std::filesystem::path& path) {
    const auto utf8 = std::filesystem::weakly_canonical(std::filesystem::absolute(path)).generic_u8string();
    auto value = std::string(utf8.begin(), utf8.end());
#ifdef _WIN32
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
#endif
    return value;
}
}

void TechniqueReport::Add(const std::map<std::string, std::size_t, std::less<>>& counters) {
    for (const auto& [id, count] : counters) counters_[id] += count;
}
void TechniqueReport::Count(std::string id, std::size_t count) { counters_[std::move(id)] += count; }
std::filesystem::path TechniqueReport::Path(const std::filesystem::path& output) {
    auto path = output;
    path += ".techniques.txt";
    return path;
}
void TechniqueReport::ValidatePaths(const GuardConfig& config, const std::filesystem::path& input,
                                   const std::filesystem::path& output) {
    std::vector<std::filesystem::path> paths{input, output, Path(output)};
    if (config.output.write_mapping && !config.output.mapping_file.empty()) paths.push_back(io::Utf8Path(config.output.mapping_file));
    for (std::size_t i = 0; i < paths.size(); ++i) {
        for (std::size_t j = 0; j < i; ++j) {
            if (NormalPath(paths[i]) == NormalPath(paths[j]) ||
                (std::filesystem::exists(paths[i]) && std::filesystem::exists(paths[j]) &&
                 std::filesystem::equivalent(paths[i], paths[j]))) {
                throw std::invalid_argument("input/output/mapping/report paths must be distinct");
            }
        }
    }
}
std::string TechniqueReport::Render(const GuardConfig& config,
    const std::vector<std::string>& warnings, bool apk) const {
    std::ostringstream out;
    out << "BirchGuard applied-technique report\nFormat: 1\nOutput: " << (apk ? "APK (unsigned)" : "DEX")
        << "\nEffective seed: " << config.seed << "\n"
        << "Seed replay: " << (config.effective_seed ? "recorded effective seed" : "normal policy") << "\n"
        << "Completed: structural/type and differential linkage checks; NOT an Android device launch test.\n"
        << "Configured != applied: counters are instrumentation events, not a count of unique methods.\n"
        << "Not instrumented means no exact counter, NOT a claim of application.\n\n";
    for (const auto& [id, pass] : config.passes) {
        const auto found = counters_.find(id);
        const bool resource_flag = (id == "resources.name_rename" && config.resources.rename_names) ||
                                   (id == "resources.file_rename" && config.resources.rename_files);
        if (!pass.enabled && !resource_flag && found == counters_.end()) continue;
        out << '[' << id << "]\nRequested: " << (pass.enabled || resource_flag ? "yes" : "no (dependency)")
            << "; intensity=" << pass.intensity << "\nApplied events: ";
        if (found == counters_.end()) out << "not instrumented";
        else out << found->second << (found->second == 0U ? " (no eligible site / retained for compatibility)" : "");
        const auto description = DescribeTechnique(id);
        if (description.empty()) throw std::logic_error("missing technique description: " + id);
        out << "\nTechnique: " << description << "\n\n";
    }
    out << "Compatibility warnings (" << warnings.size() << "):\n";
    for (const auto& warning : warnings) out << "- " << warning << '\n';
    out << "\nMapping contains sensitive recovery information; distribute separately from the APK.\n";
    return out.str();
}
void TechniqueReport::Write(const GuardConfig& config, const std::filesystem::path& output,
                            const std::vector<std::string>& warnings, bool apk) const {
    io::WriteTextFile(Path(output), Render(config, warnings, apk));
}
}
