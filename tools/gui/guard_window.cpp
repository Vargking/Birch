#include "guard_window.h"
#include "utf8_path.h"
#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"
#include <algorithm>

namespace birch::gui {
namespace {
void Field(const char* label, std::string& value, const char* hint = nullptr) {
    ImGui::TextUnformatted(label);
    ImGui::SetNextItemWidth(-1);
    const auto id = std::string("##") + label;
    if (hint) ImGui::InputTextWithHint(id.c_str(), hint, &value);
    else ImGui::InputText(id.c_str(), &value);
}
bool AccentButton(const char* label, ImVec2 size = {}) {
    ImGui::PushStyleColor(ImGuiCol_Text, {1,1,1,1});
    const bool pressed = ImGui::Button(label, size);
    ImGui::PopStyleColor();
    return pressed;
}
}
void GuardWindow::FilesPanel() {
    ImGui::TextUnformatted("PROTECTION / FILES");
    ImGui::Separator();
    Field("Input APK / DEX", settings_.input, "Paste a path, or drop an APK onto this window");
    Field("Output APK / DEX", settings_.output, "Existing output requires confirmation");
    Field("Protected scope", settings_.protect_pattern, "Lcom/yourcompany/**;");
    if (settings_.config.scope.protect.size() > 1U)
        ImGui::TextWrapped("Editing the first scope; %zu additional JSON scopes remain active.", settings_.config.scope.protect.size() - 1U);
    Field("Android framework DEX (recommended)", settings_.framework);
    ImGui::Spacing();
    Field("Import JSON configuration (optional)", settings_.config_path);
    ImGui::TextWrapped("Relative JSON paths use the working directory, as in the CLI. Absolute paths are recommended.");
    if (AccentButton("Load configuration")) {
        try { settings_.LoadConfig(); settings_.error.clear(); }
        catch (const std::exception& error) { settings_.error = error.what(); }
    }
    ImGui::Separator();
    ImGui::Checkbox("Write private mapping", &settings_.config.output.write_mapping);
    if (settings_.config.output.write_mapping) Field("Mapping path (empty = output.mapping.txt)", settings_.mapping);
    ImGui::Checkbox("Live progress and logs", &settings_.live_progress);
    ImGui::Checkbox("Reproducible build parameters", &settings_.config.strength.reproducible_output);
    ImGui::TextWrapped("Technique report is always generated beside the output (.techniques.txt). Resource safety decisions are listed there.");
}
void GuardWindow::PassesPanel() {
    ImGui::TextUnformatted("PASSES / INDIVIDUAL CONTROL");
    ImGui::Separator();
    ImGui::SetNextItemWidth(170);
    ImGui::Combo("Preset", &settings_.preset, "Balanced\0Strong\0Maximum\0");
    ImGui::SameLine();
    if (AccentButton("Apply preset")) settings_.ApplyPreset();
    ImGui::SetNextItemWidth(180);
    ImGui::SliderFloat("Global intensity", &settings_.intensity, 0.05F, 1.0F, "%.2f");
    ImGui::SameLine();
    if (AccentButton("Apply to selected")) for (auto& [id, pass] : settings_.config.passes) {
        (void)id;
        if (pass.enabled) pass.intensity = settings_.intensity;
    }
    Field("Filter passes", filter_);
    if (AccentButton("Disable all")) {
        for (auto& [id, pass] : settings_.config.passes) { (void)id; pass.enabled = false; }
        settings_.config.strength.target_analysis_cost_weeks = 0;
    }
    ImGui::SameLine();
    ImGui::TextWrapped("Maximum retains the 1024 dead-state policy; unsafe combinations fail explicitly.");
    ImGui::BeginChild("pass-list", {0,0});
    for (auto& [id, pass] : settings_.config.passes) {
        if (!filter_.empty() && id.find(filter_) == std::string::npos) continue;
        ImGui::PushID(id.c_str());
        if (ImGui::Checkbox(id.c_str(), &pass.enabled)) {
            if (id == "strength.analysis_cost_budget" && !pass.enabled) settings_.config.strength.target_analysis_cost_weeks = 0;
            if (pass.enabled && id == "anti_analysis.debug_info_removal") settings_.config.passes.at("anti_analysis.debug_local_noise").enabled = false;
            if (pass.enabled && id == "anti_analysis.debug_local_noise") settings_.config.passes.at("anti_analysis.debug_info_removal").enabled = false;
        }
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 105);
        ImGui::SetNextItemWidth(110);
        float strength = static_cast<float>(pass.intensity);
        if (ImGui::SliderFloat("##intensity", &strength, 0.0F, 1.0F, "%.2f")) pass.intensity = strength;
        ImGui::PopID();
    }
    ImGui::EndChild();
}
void GuardWindow::BeginJob() {
    try {
        settings_.ValidateInputs();
        const auto config = settings_.BuildConfig();
        bool exists = std::filesystem::exists(Utf8Path(settings_.output)) ||
                      std::filesystem::exists(Utf8Path(settings_.output + ".techniques.txt"));
        if (config.output.write_mapping && !config.output.mapping_file.empty())
            exists = exists || std::filesystem::exists(Utf8Path(config.output.mapping_file));
        if (exists && !overwrite_confirmed_) { ImGui::OpenPopup("Replace output files?"); return; }
        job_.Start(config, Utf8Path(settings_.input), Utf8Path(settings_.output), settings_.live_progress);
        settings_.error.clear();
    } catch (const std::exception& error) { settings_.error = error.what(); }
    overwrite_confirmed_ = false;
}
void GuardWindow::RunPanel(const JobSnapshot& snapshot) {
    ImGui::TextUnformatted("BUILD / VERIFICATION");
    ImGui::Separator();
    ImGui::TextWrapped("%s", snapshot.status.c_str());
    if (snapshot.running) ImGui::TextDisabled("Working... Long model/code phases may be quiet. This is not a timed percentage.");
    ImGui::BeginDisabled(snapshot.running);
    if (AccentButton("Protect application", {250, 44})) BeginJob();
    ImGui::EndDisabled();
    if (ImGui::BeginPopupModal("Replace output files?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Existing artifact / mapping / report may be replaced. Continue?");
        if (AccentButton("Replace")) { overwrite_confirmed_ = true; ImGui::CloseCurrentPopup(); BeginJob(); }
        ImGui::SameLine();
        if (AccentButton("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    if (!settings_.error.empty()) ImGui::TextWrapped("Configuration error: %s", settings_.error.c_str());
    ImGui::TextWrapped("APK output is unsigned. Align/sign with Android SDK tools, then run acceptance tests on your device. Never ship mapping publicly.");
    ImGui::BeginChild("progress-log", {0,0});
    const bool bottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2;
    for (const auto& line : snapshot.log) ImGui::TextWrapped("%s", line.c_str());
    if (bottom) ImGui::SetScrollHereY(1);
    ImGui::EndChild();
}
void GuardWindow::Draw() {
    const auto snapshot = job_.Snapshot();
    const auto* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("BirchGuard", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
    ImGui::TextUnformatted("BirchGuard");
    ImGui::SameLine(); ImGui::TextDisabled("  /  Application protection studio");
    ImGui::TextDisabled("Shared CLI engine. Explicit safety gates. Local processing.");
    ImGui::Spacing();
    ImGui::BeginChild("settings", {390,0}, ImGuiChildFlags_AlwaysUseWindowPadding);
    ImGui::BeginDisabled(snapshot.running);
    FilesPanel();
    ImGui::EndDisabled();
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("workspace", {0,0}, ImGuiChildFlags_AlwaysUseWindowPadding);
    if (ImGui::BeginTabBar("workspace-tabs")) {
        if (ImGui::BeginTabItem("Protection passes")) {
            ImGui::BeginDisabled(snapshot.running); PassesPanel(); ImGui::EndDisabled(); ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Build & progress")) { RunPanel(snapshot); ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    ImGui::EndChild();
    ImGui::End();
}
}
