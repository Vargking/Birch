#include "birch/io/file.h"

#include <fstream>
#include <iterator>
#include <stdexcept>

namespace birch::io {

std::vector<std::uint8_t> ReadBinaryFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open input: " + path.string());
    return {std::istreambuf_iterator<char>(input), {}};
}

std::string ReadTextFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open text input: " + path.string());
    return {std::istreambuf_iterator<char>(input), {}};
}

void WriteBinaryFile(const std::filesystem::path& path,
                     const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary);
    if (!output) throw std::runtime_error("cannot create output: " + path.string());
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.flush();
    output.close();
    if (!output) throw std::runtime_error("failed to write output: " + path.string());
}

void WriteTextFile(const std::filesystem::path& path, std::string_view text) {
    std::ofstream output(path, std::ios::binary);
    if (!output) throw std::runtime_error("cannot create text output: " + path.string());
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    output.flush();
    output.close();
    if (!output) throw std::runtime_error("failed to write text output: " + path.string());
}

} // namespace birch::io
