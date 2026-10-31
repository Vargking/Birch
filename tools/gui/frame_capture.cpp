#include "frame_capture.h"
#include "birch/io/file.h"
#include <zlib.h>
#include <array>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace birch::gui {
namespace {
void U32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}
void Chunk(std::vector<std::uint8_t>& png, std::string_view type, std::span<const std::uint8_t> payload) {
    U32(png, static_cast<std::uint32_t>(payload.size()));
    const auto start = png.size();
    png.insert(png.end(), type.begin(), type.end());
    png.insert(png.end(), payload.begin(), payload.end());
    U32(png, static_cast<std::uint32_t>(crc32(0, png.data() + start, static_cast<uInt>(payload.size() + 4U))));
}
}
void FrameCapture::SavePng(const std::filesystem::path& path, int width, int height,
                           std::span<const std::uint8_t> rgba) {
    if (width <= 0 || height <= 0 || width > 16384 || height > 16384 ||
        rgba.size() != static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4U)
        throw std::invalid_argument("Invalid screenshot framebuffer dimensions");
    const auto row = static_cast<std::size_t>(width) * 4U;
    std::vector<std::uint8_t> scanlines;
    scanlines.reserve((row + 1U) * static_cast<std::size_t>(height));
    for (int y = height - 1; y >= 0; --y) {
        scanlines.push_back(0U); // PNG filter: none.
        const auto begin = rgba.begin() + static_cast<std::ptrdiff_t>(static_cast<std::size_t>(y) * row);
        scanlines.insert(scanlines.end(), begin, begin + static_cast<std::ptrdiff_t>(row));
    }
    auto size = compressBound(static_cast<uLong>(scanlines.size()));
    std::vector<std::uint8_t> compressed(size);
    if (compress2(compressed.data(), &size, scanlines.data(), static_cast<uLong>(scanlines.size()), Z_BEST_SPEED) != Z_OK)
        throw std::runtime_error("Screenshot PNG compression failed");
    compressed.resize(size);
    std::vector<std::uint8_t> png{137,80,78,71,13,10,26,10}, header;
    U32(header, static_cast<std::uint32_t>(width)); U32(header, static_cast<std::uint32_t>(height));
    header.insert(header.end(), {8,6,0,0,0});
    Chunk(png, "IHDR", header); Chunk(png, "IDAT", compressed); Chunk(png, "IEND", {});
    io::WriteBinaryFile(path, png);
}
}
