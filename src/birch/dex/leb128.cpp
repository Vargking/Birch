#include "birch/dex/leb128.h"

#include <limits>
#include <stdexcept>

namespace birch::dex {
namespace {

[[noreturn]] void Fail(const char* message) {
    throw std::runtime_error(message);
}

} // namespace

Leb128Value ReadUleb128(std::span<const std::uint8_t> bytes, std::size_t offset) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 5; ++i) {
        if (offset + i >= bytes.size()) {
            Fail("truncated uleb128");
        }
        const std::uint8_t byte = bytes[offset + i];
        if (i == 4 && (byte & 0x70U) != 0U) {
            Fail("uleb128 overflow");
        }
        value |= static_cast<std::uint32_t>(byte & 0x7fU) << (i * 7U);
        if ((byte & 0x80U) == 0U) {
            return {value, i + 1};
        }
    }
    Fail("uleb128 is too long");
}

Sleb128Value ReadSleb128(std::span<const std::uint8_t> bytes, std::size_t offset) {
    std::uint32_t raw = 0;
    std::uint8_t last = 0;
    std::size_t count = 0;
    for (; count < 5; ++count) {
        if (offset + count >= bytes.size()) {
            Fail("truncated sleb128");
        }
        last = bytes[offset + count];
        if (count == 4 && (last & 0x70U) != 0U && (last & 0x70U) != 0x70U) {
            Fail("sleb128 overflow");
        }
        raw |= static_cast<std::uint32_t>(last & 0x7fU) << (count * 7U);
        if ((last & 0x80U) == 0U) {
            ++count;
            break;
        }
    }
    if (count == 5 && (last & 0x80U) != 0U) {
        Fail("sleb128 is too long");
    }
    if (count < 5 && (last & 0x40U) != 0U) {
        raw |= ~0U << (count * 7U);
    }
    return {static_cast<std::int32_t>(raw), count};
}

} // namespace birch::dex
