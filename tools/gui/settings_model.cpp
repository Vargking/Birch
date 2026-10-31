#include "settings_model.h"
#include "utf8_path.h"
#include "birch/io/file.h"
#include <stdexcept>

namespace birch::gui {
SettingsModel::SettingsModel() : config(guard::GuardConfig::Defaults()) { ApplyPreset(); }
void SettingsModel::ApplyPreset() {
    intensity = preset == 0 ? 0.35F : preset == 1 ? 0.7F : 1.0F;
    for (auto& [id, pass] : config.passes) {
        // Debug noise and stripping are mutually exclusive.
        pass.enabled = id != "anti_analysis.debug_local_noise";
        pass.intensity = intensity;
    }
    config.budget.max_code_units_per_method = 65000U;
    config.budget.max_registers_per_method = 255U;
    config.budget.max_added_blocks_per_method = preset == 2 ? 1024U : preset == 1 ? 512U : 128U;
    config.budget.max_added_try_regions_per_method = 256U;
    config.budget.max_method_growth_ratio = 10000.0;
    config.budget.max_dex_growth_ratio = 512.0;
    config.budget.max_analysis_blocks_per_method = 16384U;
    config.budget.max_call_depth_increase = 1024U;
    config.strength.target_analysis_cost_weeks = preset == 2 ? 52U : 0U;
    config.strength.reproducible_output = true;
    config.fake.class_count = preset == 2 ? 128U : 48U;
    config.fake.methods_per_class = preset == 2 ? 16U : 8U;
    config.resources.dictionary.clear();
}
void SettingsModel::LoadConfig() {
    auto loaded = guard::GuardConfig::Parse(io::ReadTextFile(Utf8Path(config_path)));
    // Match the CLI: relative paths in JSON are relative to the working directory.
    // Do not silently reinterpret an existing CLI config when importing it in the GUI.
    const auto loaded_framework = loaded.android_dex;
    const auto loaded_mapping = loaded.output.mapping_file;
    config = std::move(loaded);
    config.passes.at("resources.file_rename").enabled |= config.resources.rename_files;
    config.passes.at("resources.name_rename").enabled |= config.resources.rename_names;
    framework = loaded_framework;
    mapping = loaded_mapping;
    protect_pattern = config.scope.protect.empty() ? "" : config.scope.protect.front().pattern;
}
guard::GuardConfig SettingsModel::BuildConfig() const {
    auto result = config;
    result.android_dex = framework;
    if (result.scope.protect.empty()) result.scope.protect.push_back({protect_pattern});
    else result.scope.protect.front().pattern = protect_pattern;
    if (result.output.write_mapping) {
        result.output.mapping_file = mapping.empty() ? output + ".mapping.txt" : mapping;
    }
    // Resource controls are independent of legacy resource booleans loaded from JSON.
    result.resources.rename_files = result.passes.at("resources.file_rename").enabled;
    result.resources.rename_names = result.passes.at("resources.name_rename").enabled;
    result.Validate();
    return result;
}
void SettingsModel::ValidateInputs() const {
    if (input.empty() || output.empty()) throw std::invalid_argument("Select input and output paths.");
    if (protect_pattern.empty()) throw std::invalid_argument("Enter an explicit package/descriptor protection scope.");
    const auto in = Utf8Path(input);
    const auto out = Utf8Path(output);
    if (!std::filesystem::is_regular_file(in)) throw std::invalid_argument("Input file does not exist.");
    const auto extension = LowerExtension(in);
    if (extension != ".apk" && extension != ".dex") throw std::invalid_argument("Input must be .apk or .dex.");
    if (LowerExtension(out) != extension) throw std::invalid_argument("Input and output formats must match.");
    if (!out.parent_path().empty() && !std::filesystem::is_directory(out.parent_path())) throw std::invalid_argument("Output directory does not exist.");
    const auto effective = BuildConfig();
    if (extension == ".dex" && (effective.resources.rename_names || effective.resources.rename_files))
        throw std::invalid_argument("Resource passes require APK input. Explicitly disable both resource passes for DEX input.");
    if (effective.signing.enabled) throw std::invalid_argument("Built-in signing is unavailable. Disable signing in JSON and sign externally.");
}
}
