#pragma once
#include <cstdint>
#include <filesystem>
#include <span>

namespace birch::gui {
class FrameCapture final {
public:
    // OpenGL RGBA8 bottom-up framebuffer -> portable PNG, for visual regression evidence.
    static void SavePng(const std::filesystem::path& path, int width, int height,
                        std::span<const std::uint8_t> rgba);
};
}
