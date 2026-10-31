#pragma once

#include <bit>
#include <cstdint>
#include <stdexcept>

namespace birch::test::integer {

inline std::int32_t Signed(std::uint32_t value) {
    return std::bit_cast<std::int32_t>(value);
}
inline std::uint32_t Sign16(std::uint16_t value) {
    return static_cast<std::uint32_t>(static_cast<std::int32_t>(
        std::bit_cast<std::int16_t>(value)));
}
inline std::uint32_t Sign8(std::uint8_t value) {
    return static_cast<std::uint32_t>(static_cast<std::int32_t>(
        std::bit_cast<std::int8_t>(value)));
}
inline bool Compare(unsigned condition, std::uint32_t left, std::uint32_t right) {
    switch (condition) {
    case 0: return left == right;
    case 1: return left != right;
    case 2: return Signed(left) < Signed(right);
    case 3: return Signed(left) >= Signed(right);
    case 4: return Signed(left) > Signed(right);
    case 5: return Signed(left) <= Signed(right);
    default: throw std::runtime_error("invalid integer comparison");
    }
}
inline std::uint32_t Arithmetic(unsigned op, std::uint32_t left, std::uint32_t right) {
    switch (op) {
    case 0: return left + right;
    case 1: return left - right;
    case 2: return left * right;
    case 3:
    case 4:
        if (right == 0U) throw std::runtime_error("integer divide by zero");
        if (left == 0x80000000U && right == 0xffffffffU)
            return op == 3U ? left : 0U;
        return static_cast<std::uint32_t>(op == 3U ?
            Signed(left) / Signed(right) : Signed(left) % Signed(right));
    case 5: return left & right;
    case 6: return left | right;
    case 7: return left ^ right;
    case 8: return left << (right & 31U);
    case 9: return static_cast<std::uint32_t>(Signed(left) >> (right & 31U));
    case 10: return left >> (right & 31U);
    default: throw std::runtime_error("unsupported integer arithmetic");
    }
}

} // namespace birch::test::integer
