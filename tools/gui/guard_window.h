#pragma once
#include "settings_model.h"
#include "job_controller.h"
namespace birch::gui {
class GuardWindow final {
public:
    void Draw();
    [[nodiscard]] bool Running() const { return job_.Snapshot().running; }
    void SetDroppedInput(const char* path) { if (!Running()) settings_.input = path; }
private:
    void FilesPanel();
    void PassesPanel();
    void RunPanel(const JobSnapshot& snapshot);
    void BeginJob();
    SettingsModel settings_;
    JobController job_;
    std::string filter_;
    bool overwrite_confirmed_{};
};
}
