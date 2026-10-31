#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace birch::dex {

struct Leb128Value {
    std::uint32_t value{};
    std::size_t size{};
};

struct Sleb128Value {
    std::int32_t value{};
    std::size_t size{};
};

Leb128Value ReadUleb128(std::span<const std::uint8_t> bytes, std::size_t offset);
Sleb128Value ReadSleb128(std::span<const std::uint8_t> bytes, std::size_t offset);

} // namespace birch::dex
