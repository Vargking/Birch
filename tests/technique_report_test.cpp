#include "technique_catalog.h"
#include "technique_report.h"
#include "birch/guard/pass.h"
#include "birch/io/file.h"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>

namespace {
template<class F> void Reject(F&& action) {
    bool rejected = false;
    try { action(); } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
}
}
int main() {
    using namespace birch::guard;
    for (const auto& pass : PassRegistry()) {
        const auto description = detail::DescribeTechnique(pass.id);
        assert(description.size() > 65U);
    }
    assert(detail::DescribeTechnique("not.a.pass").empty());
    auto config = GuardConfig::Defaults();
    config.passes.at("data.string_encryption").enabled = true;
    config.passes.at("predicate.crypto").enabled = true;
    config.output.write_mapping = false;
    detail::TechniqueReport report;
    report.Count("data.string_encryption", 0U);
    auto rendered = report.Render(config, {"retained dynamic resource names"}, true);
    assert(rendered.find("8 rounds r=0..7") != std::string::npos);
    assert(rendered.find("Applied events: 0 (no eligible site") != std::string::npos);
    assert(rendered.find("NOT AES") != std::string::npos);
    assert(rendered.find("unsigned") != std::string::npos);
    assert(rendered.find("NOT an Android device launch") != std::string::npos);
    assert(rendered.find("retained dynamic resource names") != std::string::npos);
    const auto root = std::filesystem::temp_directory_path() / ("birch-report-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(root);
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code ec; std::filesystem::remove_all(path, ec); } } cleanup{root};
    const auto input = root / "in.dex", output = root / "out.dex";
    birch::io::WriteTextFile(input, "fixture");
    detail::TechniqueReport::ValidatePaths(config, input, output);
    Reject([&] { detail::TechniqueReport::ValidatePaths(config, input, input); });
    Reject([&] { detail::TechniqueReport::ValidatePaths(config, detail::TechniqueReport::Path(output), output); });
    config.output.write_mapping = true;
    config.output.mapping_file = input.string();
    Reject([&] { detail::TechniqueReport::ValidatePaths(config, input, output); });
    const auto alias = root / "alias.dex";
    std::error_code ec;
    std::filesystem::create_hard_link(input, alias, ec);
    if (!ec) {
        config.output.mapping_file = alias.string();
        Reject([&] { detail::TechniqueReport::ValidatePaths(config, input, output); });
    }
    config.output.write_mapping = false;
    report.Write(config, output, {}, false);
    assert(std::filesystem::exists(detail::TechniqueReport::Path(output)));
    assert(!std::filesystem::exists(alias.string() + ".mapping.txt"));
    std::cout << "Technique coverage, algorithms, counters and path isolation passed\n";
}
