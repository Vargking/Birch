#include "ios_theme.h"
#include "imgui.h"
namespace birch::gui {
void ApplyIosTheme(float scale) {
    ImGui::StyleColorsLight();
    auto& s = ImGui::GetStyle();
    s.WindowRounding = 16; s.ChildRounding = 14; s.FrameRounding = 9;
    s.GrabRounding = 8; s.PopupRounding = 12; s.TabRounding = 9;
    s.WindowBorderSize = 0; s.ChildBorderSize = 0; s.FrameBorderSize = 0;
    s.WindowPadding = {24, 20}; s.FramePadding = {12, 9}; s.ItemSpacing = {12, 12};
    s.Colors[ImGuiCol_WindowBg] = {0.95F,0.95F,0.97F,1};
    s.Colors[ImGuiCol_ChildBg] = {1,1,1,1};
    s.Colors[ImGuiCol_FrameBg] = {0.94F,0.95F,0.97F,1};
    s.Colors[ImGuiCol_FrameBgHovered] = {0.88F,0.92F,0.99F,1};
    s.Colors[ImGuiCol_Text] = {0.1F,0.12F,0.18F,1};
    s.Colors[ImGuiCol_Button] = {0.0F,0.45F,1.0F,1};
    s.Colors[ImGuiCol_ButtonHovered] = {0.12F,0.53F,1.0F,1};
    s.Colors[ImGuiCol_ButtonActive] = {0,0.35F,0.87F,1};
    s.Colors[ImGuiCol_CheckMark] = {0,0.48F,1,1};
    s.Colors[ImGuiCol_SliderGrab] = {0,0.48F,1,1};
    s.Colors[ImGuiCol_Header] = {0.88F,0.93F,1,1};
    s.ScaleAllSizes(scale);
    s.FontScaleDpi = scale;
}
}
