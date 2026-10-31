#include "job_controller.h"
#include "utf8_path.h"
#include <stdexcept>

namespace birch::gui {
JobController::~JobController() { if (worker_.joinable()) worker_.join(); }
void JobController::Log(std::string message) {
    std::lock_guard lock(mutex_);
    state_.status = message;
    state_.log.push_back(std::move(message));
    if (state_.log.size() > 2000U) state_.log.pop_front();
}
JobSnapshot JobController::Snapshot() const {
    std::lock_guard lock(mutex_);
    return state_;
}
void JobController::Start(guard::GuardConfig config, std::filesystem::path input,
                          std::filesystem::path output, bool live_progress) {
    if (Snapshot().running) throw std::logic_error("a protection job is already running");
    if (worker_.joinable()) worker_.join();
    config.Validate();
    {
        std::lock_guard lock(mutex_);
        state_ = {};
        state_.running = true;
        state_.status = "Starting protection...";
    }
    try {
        worker_ = std::jthread([this, config = std::move(config), input = std::move(input),
                               output = std::move(output), live_progress] {
            bool succeeded = false;
            try {
                const auto pipeline = guard::GuardPipeline::FromConfig(config);
                const auto sink = [this](const guard::ProgressEvent& event) { Log(event.message); };
                guard::ProgressSink progress = live_progress ? guard::ProgressSink(sink) : guard::ProgressSink{};
                if (LowerExtension(input) == ".dex") pipeline.TransformDex(input, output, progress);
                else pipeline.TransformApk(input, output, progress);
                Log("Complete. Artifact and .techniques.txt written. APK output is unsigned; no device launch was performed.");
                succeeded = true;
            } catch (const std::exception& error) { Log(std::string("Failed: ") + error.what()); }
              catch (...) { Log("Failed: unknown error"); }
            std::lock_guard lock(mutex_);
            state_.running = false;
            state_.succeeded = succeeded;
        });
    } catch (...) {
        std::lock_guard lock(mutex_);
        state_.running = false;
        throw;
    }
}
}
