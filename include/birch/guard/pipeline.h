#pragma once

#include "birch/guard/apk.h"
#include "birch/guard/config.h"

#include <filesystem>
#include <string>
#include <vector>
#include <functional>

namespace birch::guard {

struct GuardReport {
    ApkInspection inspection;
    std::vector<std::string> enabled_passes;
    std::size_t protected_classes{};
    std::size_t kept_classes{};
    std::vector<std::string> mapping_lines;
    std::vector<std::string> warnings;
};

enum class ProgressStage {
    Load,
    Parse,
    Scope,
    Plan,
    Transform,
    Write,
    Verify,
    Complete,
    Error,
};

struct ProgressEvent {
    ProgressStage stage{ProgressStage::Load};
    std::string pass;
    std::string file;
    std::size_t current{};
    std::size_t total{};
    double fraction{};
    std::string message;
};

using ProgressSink = std::function<void(const ProgressEvent&)>;

class GuardPipeline final {
public:
    static GuardPipeline FromJson(std::string_view config_json);
    static GuardPipeline FromConfig(GuardConfig config);

    [[nodiscard]] const GuardConfig& config() const noexcept { return config_; }
    GuardReport InspectApk(const std::filesystem::path& apk) const;
    GuardReport InspectApk(const std::filesystem::path& apk, ProgressSink sink) const;
    void TransformApk(const std::filesystem::path& input, const std::filesystem::path& output) const;
    void TransformApk(const std::filesystem::path& input, const std::filesystem::path& output,
                      ProgressSink sink) const;
    void TransformDex(const std::filesystem::path& input, const std::filesystem::path& output) const;
    void TransformDex(const std::filesystem::path& input, const std::filesystem::path& output,
                      ProgressSink sink) const;

private:
    explicit GuardPipeline(GuardConfig config) : config_(std::move(config)) {}
    GuardConfig config_;
};

} // namespace birch::guard
