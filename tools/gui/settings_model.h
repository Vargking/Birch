#pragma once
#include "birch/guard/config.h"
#include <filesystem>
#include <string>

namespace birch::gui {
class SettingsModel final {
public:
    SettingsModel();
    guard::GuardConfig config;
    std::string input;
    std::string output;
    std::string config_path;
    std::string framework;
    std::string protect_pattern;
    std::string mapping;
    std::string error;
    bool live_progress{true};
    float intensity{1.0F};
    int preset{2};
    void ApplyPreset();
    void LoadConfig();
    [[nodiscard]] guard::GuardConfig BuildConfig() const;
    void ValidateInputs() const;
};
}
