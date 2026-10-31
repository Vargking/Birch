#include "guard_window.h"
#include "ios_theme.h"
#include "utf8_path.h"
#include "frame_capture.h"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#define GL_SILENCE_DEPRECATION
#include <GLFW/glfw3.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {
struct GlfwRuntime {
    GlfwRuntime() {
        glfwSetErrorCallback([](int code, const char* text) { std::fprintf(stderr, "GLFW %d: %s\n", code, text); });
        if (!glfwInit()) throw std::runtime_error("GLFW initialization failed");
    }
    ~GlfwRuntime() { glfwTerminate(); }
};
struct ImGuiRuntime {
    ImGuiRuntime() { IMGUI_CHECKVERSION(); ImGui::CreateContext(); }
    ~ImGuiRuntime() {
        if (renderer) ImGui_ImplOpenGL3_Shutdown();
        if (platform) ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext();
    }
    bool platform{}, renderer{};
};
}
int main(int argc, char** argv) {
    try {
        const bool capture = argc == 3 && std::strcmp(argv[1], "--screenshot") == 0;
        const bool smoke = capture || (argc == 2 && std::strcmp(argv[1], "--smoke-test") == 0);
        GlfwRuntime runtime;
#ifdef __APPLE__
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
        glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
        constexpr auto glsl = "#version 150";
#else
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
        constexpr auto glsl = "#version 130";
#endif
        if (smoke) glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);
        float scale_x = 1, scale_y = 1;
        if (auto* monitor = glfwGetPrimaryMonitor()) glfwGetMonitorContentScale(monitor, &scale_x, &scale_y);
        const auto scale = std::clamp(scale_x, 1.0F, 2.0F);
        std::unique_ptr<GLFWwindow, decltype(&glfwDestroyWindow)> window(
            glfwCreateWindow(static_cast<int>(1180 * scale), static_cast<int>(820 * scale), "BirchGuard Studio", nullptr, nullptr), glfwDestroyWindow);
        if (!window) throw std::runtime_error("Cannot create an OpenGL 3 window. Update the GPU driver.");
        glfwSetWindowSizeLimits(window.get(), 1000, 680, GLFW_DONT_CARE, GLFW_DONT_CARE);
        glfwMakeContextCurrent(window.get());
        glfwSwapInterval(1);
        ImGuiRuntime imgui;
        ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        ImGui::GetIO().IniFilename = nullptr;
        birch::gui::ApplyIosTheme(scale);
        ImGui::GetStyle().FontSizeBase = 16;
        imgui.platform = ImGui_ImplGlfw_InitForOpenGL(window.get(), true);
        if (!imgui.platform) throw std::runtime_error("ImGui platform backend failed");
        imgui.renderer = ImGui_ImplOpenGL3_Init(glsl);
        if (!imgui.renderer) throw std::runtime_error("ImGui renderer initialization failed");
        birch::gui::GuardWindow app;
        glfwSetWindowUserPointer(window.get(), &app);
        glfwSetDropCallback(window.get(), [](GLFWwindow* handle, int count, const char** paths) {
            if (count > 0) static_cast<birch::gui::GuardWindow*>(glfwGetWindowUserPointer(handle))->SetDroppedInput(paths[0]);
        });
        int frames = 0;
        while (!glfwWindowShouldClose(window.get())) {
            glfwPollEvents();
            if (glfwWindowShouldClose(window.get()) && app.Running()) glfwSetWindowShouldClose(window.get(), GLFW_FALSE);
            if (glfwGetWindowAttrib(window.get(), GLFW_ICONIFIED)) { glfwWaitEventsTimeout(0.05); continue; }
            ImGui_ImplOpenGL3_NewFrame(); ImGui_ImplGlfw_NewFrame(); ImGui::NewFrame();
            app.Draw();
            ImGui::Render();
            int width = 0, height = 0;
            glfwGetFramebufferSize(window.get(), &width, &height);
            glViewport(0, 0, width, height);
            glClearColor(0.95F, 0.95F, 0.97F, 1); glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            if (smoke && ++frames >= 3) {
                std::vector<unsigned char> pixels(static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4U);
                glReadPixels(0,0,width,height,GL_RGBA,GL_UNSIGNED_BYTE,pixels.data());
                const bool varied = std::any_of(pixels.begin(), pixels.end(), [](unsigned char c) { return c < 100; });
                if (glGetError() != GL_NO_ERROR || !varied) throw std::runtime_error("GUI framebuffer smoke test failed");
                if (capture) birch::gui::FrameCapture::SavePng(birch::gui::Utf8Path(argv[2]), width, height, pixels);
                std::puts("GUI smoke test: context, layout, fonts and non-empty framebuffer passed.");
                break;
            }
            glfwSwapBuffers(window.get());
        }
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "BirchGuard Studio: %s\n", error.what());
#ifdef _WIN32
        // A GUI-subsystem build has no console; retain a visible diagnostic.
        if (!(argc >= 2 && (std::strcmp(argv[1], "--smoke-test") == 0 || std::strcmp(argv[1], "--screenshot") == 0))) {
            MessageBoxA(nullptr, error.what(), "BirchGuard Studio", MB_OK | MB_ICONERROR);
        }
#endif
        return 1;
    }
}
