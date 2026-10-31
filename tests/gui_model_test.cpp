#include "settings_model.h"
#include "job_controller.h"
#include "birch/dex/builder.h"
#include "birch/io/file.h"
#include "birch/io/path.h"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

namespace {
template<class F> void Reject(F&& action) {
    bool rejected = false;
    try { action(); } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
}
birch::gui::JobSnapshot Wait(birch::gui::JobController& job) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (job.Snapshot().running && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    auto result = job.Snapshot();
    assert(!result.running);
    return result;
}
}
int main() {
    using namespace birch;
    const auto root = std::filesystem::temp_directory_path() / ("birch-gui-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(root);
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code ec; std::filesystem::remove_all(path, ec); } } cleanup{root};
    dex::DexBuilder builder;
    dex::ClassSpec klass;
    klass.descriptor = "Lexample/Fixture;";
    klass.direct_methods.push_back({"answer", "I", {}, 0x0009U, {1U, 0U, 0U, {0x7012U, 0x000fU}}});
    builder.AddClass(std::move(klass));
    const auto input = root / "input.DEX", output = root / "output.DEX";
    io::WriteBinaryFile(input, builder.Build());
    gui::SettingsModel model;
    assert(model.protect_pattern.empty());
    assert(model.config.budget.max_added_blocks_per_method == 1024U);
    model.input = input.string(); model.output = output.string();
    Reject([&] { model.ValidateInputs(); });
    model.protect_pattern = "Lexample/**;";
    Reject([&] { model.ValidateInputs(); }); // APK resource passes cannot silently disappear.
    model.config.passes.at("resources.file_rename").enabled = false;
    model.config.passes.at("resources.name_rename").enabled = false;
    model.config.resources.rename_files = model.config.resources.rename_names = true;
    model.config.output.write_mapping = false;
    model.config.passes.at("data.string_encryption").intensity = 0.42;
    auto effective = model.BuildConfig();
    assert(!effective.resources.rename_files && !effective.resources.rename_names);
    assert(!effective.output.write_mapping);
    assert(effective.passes.at("data.string_encryption").intensity == 0.42);
    model.ValidateInputs();
    model.config.output.write_mapping = true;
    assert(model.BuildConfig().output.mapping_file == model.output + ".mapping.txt");
    model.mapping = (root / "private.txt").string();
    assert(model.BuildConfig().output.mapping_file == model.mapping);
    for (int preset = 0; preset < 3; ++preset) {
        model.preset = preset; model.ApplyPreset();
        assert(!model.config.passes.at("anti_analysis.debug_local_noise").enabled);
        assert(model.config.passes.at("cfg.flattening").intensity == model.intensity);
        assert(model.config.budget.max_added_blocks_per_method == (preset == 2 ? 1024U : preset == 1 ? 512U : 128U));
    }
    const auto json = root / "config.json";
    io::WriteTextFile(json, R"({"android_dex":"framework/android.dex","scope":{"protect":[{"pattern":"Lexample/**;"},{"pattern":"Lother/**;"}]},"output":{"write_mapping":true,"mapping_file":"private.txt"}})");
    model.config_path = json.string(); model.LoadConfig();
    assert(model.framework == "framework/android.dex"); // Same cwd semantics as CLI.
    assert(model.mapping == "private.txt");
    assert(model.BuildConfig().scope.protect.size() == 2U);

    auto config = guard::GuardConfig::Defaults();
    for (auto& [id, pass] : config.passes) { (void)id; pass.enabled = false; }
    config.scope.protect.push_back({"Lexample/**;"});
    config.output.write_mapping = false;
    gui::JobController job;
    job.Start(config, root / "missing.dex", output, false);
    const auto failed = Wait(job);
    assert(!failed.succeeded && failed.status.starts_with("Failed:"));
    job.Start(config, input, output, false);
    const auto quiet = Wait(job);
    assert(quiet.succeeded && quiet.log.size() == 1U);
    assert(std::filesystem::exists(output.string() + ".techniques.txt"));
    assert(!std::filesystem::exists(output.string() + ".mapping.txt"));
    job.Start(config, input, root / "live.DEX", true);
    const auto live = Wait(job);
    assert(live.succeeded && live.log.size() > 1U);
    assert(live.status.find("no device launch") != std::string::npos);
    const auto unicode = root / std::filesystem::path(std::u8string(u8"资源输入"));
    std::filesystem::create_directory(unicode);
    const auto unicode_input = unicode / "in.DEX", unicode_output = unicode / "out.DEX";
    const auto unicode_mapping = unicode / std::filesystem::path(std::u8string(u8"私有映射.txt"));
    io::WriteBinaryFile(unicode_input, builder.Build());
    config.android_dex = io::PathUtf8(unicode_input);
    config.output.write_mapping = true;
    config.output.mapping_file = io::PathUtf8(unicode_mapping);
    job.Start(config, unicode_input, unicode_output, false);
    assert(Wait(job).succeeded);
    assert(std::filesystem::exists(unicode_mapping));
    std::cout << "GUI settings, path semantics, independent controls and worker restart/progress passed\n";
}
