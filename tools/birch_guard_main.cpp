#include "birch/guard/pipeline.h"
#include "birch/guard/fake.h"
#include "birch/io/file.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {

void Usage() {
    std::cerr << "usage: BirchGuard --config <config.json> --inspect-apk <input.apk>\n"
              << "       BirchGuard --config <config.json> --transform-apk <input.apk> <output.apk>\n"
              << "       BirchGuard --config <config.json> --transform-dex <input.dex> <output.dex>\n"
              << "       BirchGuard --config <config.json> --prepare-fake-dex <output.dex>\n";
}

const char* StageName(birch::guard::ProgressStage stage) {
    using birch::guard::ProgressStage;
    switch (stage) {
        case ProgressStage::Load: return "load";
        case ProgressStage::Parse: return "parse";
        case ProgressStage::Scope: return "scope";
        case ProgressStage::Plan: return "plan";
        case ProgressStage::Transform: return "transform";
        case ProgressStage::Write: return "write";
        case ProgressStage::Verify: return "verify";
        case ProgressStage::Complete: return "complete";
        case ProgressStage::Error: return "error";
    }
    return "unknown";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--list-passes") {
            for (const auto& pass : birch::guard::PassRegistry()) {
                std::cout << pass.id << '\n';
            }
            return 0;
        }
        if (argc != 5 && argc != 6) {
            Usage();
            return 2;
        }
        std::filesystem::path config_path;
        std::filesystem::path input_path;
        std::filesystem::path output_path;
        bool transform = false;
        bool transform_dex = false;
        if (std::string_view(argv[1]) != "--config" || std::string_view(argv[3]) == "--config") {
            Usage();
            return 2;
        }
        config_path = argv[2];
        if (std::string_view(argv[3]) == "--prepare-fake-dex" && argc == 5) {
            const auto config = birch::guard::GuardConfig::Parse(
                birch::io::ReadTextFile(config_path));
            const auto bytes = birch::guard::BuildFakeDex({config.fake.package_prefix, config.fake.class_count, config.fake.methods_per_class, config.seed});
            birch::io::WriteBinaryFile(argv[4], bytes);
            std::cout << "wrote fake DEX: " << bytes.size() << " bytes\n";
            return 0;
        } else if (std::string_view(argv[3]) == "--inspect-apk" && argc == 5) {
            input_path = argv[4];
        } else if (std::string_view(argv[3]) == "--transform-apk" && argc == 6) {
            input_path = argv[4];
            output_path = argv[5];
            transform = true;
        } else if (std::string_view(argv[3]) == "--transform-dex" && argc == 6) {
            input_path = argv[4];
            output_path = argv[5];
            transform = true;
            transform_dex = true;
        } else {
            Usage();
            return 2;
        }
        const auto pipeline = birch::guard::GuardPipeline::FromJson(
            birch::io::ReadTextFile(config_path));
        if (transform) {
            const auto sink = [](const auto& event) {
                // Progress must remain live even when stdout is redirected to a log.
                std::cout << "[" << StageName(event.stage) << "] " << event.message << std::endl;
            };
            if (transform_dex) pipeline.TransformDex(input_path, output_path, sink);
            else pipeline.TransformApk(input_path, output_path, sink);
            return 0;
        }
        const auto report = pipeline.InspectApk(input_path, [](const auto& event) {
            std::cout << "[" << StageName(event.stage) << "] "
                      << static_cast<unsigned>(event.fraction * 100.0) << "% "
                      << event.message << '\n';
        });
        std::cout << "DEX files: " << report.inspection.dex_count << '\n'
                  << "protected classes: " << report.protected_classes << '\n'
                  << "kept classes: " << report.kept_classes << '\n'
                  << "enabled passes: " << report.enabled_passes.size() << '\n';
        for (const auto& pass : report.enabled_passes) std::cout << "  " << pass << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BirchGuard: " << error.what() << '\n';
        return 1;
    }
}
