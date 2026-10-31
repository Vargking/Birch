#pragma once

#include "birch/dex/dex_file.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace birch::dex {

struct DexInput {
    std::string name;
    std::vector<std::uint8_t> bytes;
};

struct ClassHandle {
    std::size_t dex_index{};
    std::size_t class_index{};

    auto operator<=>(const ClassHandle&) const = default;
};

class DexProgram final {
public:
    static DexProgram Parse(std::vector<DexInput> inputs);

    [[nodiscard]] std::size_t dex_count() const noexcept { return units_.size(); }
    [[nodiscard]] const DexFile& dex(std::size_t index) const;
    [[nodiscard]] std::string_view dex_name(std::size_t index) const;
    [[nodiscard]] std::vector<ClassHandle> classes() const;
    [[nodiscard]] std::vector<ClassHandle> FindClassesWithPrefix(
        std::string_view descriptor_prefix) const;
    [[nodiscard]] std::string class_descriptor(ClassHandle handle) const;

private:
    struct Unit {
        std::string name;
        DexFile file;
    };
    std::vector<Unit> units_;
};

} // namespace birch::dex
