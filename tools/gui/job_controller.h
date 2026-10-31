#pragma once
#include "birch/guard/pipeline.h"
#include <deque>
#include <mutex>
#include <thread>

namespace birch::gui {
struct JobSnapshot {
    bool running{};
    bool succeeded{};
    std::string status{"Ready"};
    std::deque<std::string> log;
};
// A job owns a configuration snapshot. No UI/ImGui call runs on the worker.
class JobController final {
public:
    ~JobController();
    void Start(guard::GuardConfig config, std::filesystem::path input,
               std::filesystem::path output, bool live_progress);
    [[nodiscard]] JobSnapshot Snapshot() const;
private:
    void Log(std::string message);
    mutable std::mutex mutex_;
    JobSnapshot state_;
    std::jthread worker_;
};
}
